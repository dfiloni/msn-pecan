/**
 * Copyright (C) 2007-2009 Felipe Contreras
 * Copyright (C) 1998-2006 Pidgin (see pidgin-copyright)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "notification.h"
#include "pn_global.h"
#include "pn_log.h"
#include "pn_locale.h"
#include "pn_auth.h"
#include "pn_global.h"

#include "session.h"
#include "session_private.h"

#include "pn_auth_priv.h"

#include "cmd/cmdproc_private.h"
#include "cmd/command_private.h"
#include "cmd/transaction_private.h"
#include "cmd/msg_private.h"

#include "ab/pn_contactlist.h"
#include "ab/pn_contactlist_priv.h"
#include "ab/pn_contact_priv.h"
#include "ab/pn_group.h"
#include "ab/pn_service.h"

#include "io/pn_cmd_server.h"
#include "io/pn_http_server.h"
#include "io/pn_node_private.h"

#include "pn_error.h"
#include "pn_util.h"

#include <glib/gstdio.h>

#include <string.h>

/* libpurple stuff. */
#include <account.h>
#include <prefs.h>
#include <cipher.h>

static MsnTable *cbs_table;

typedef struct
{
    gchar *domain;
    gchar *name;
    gchar *group_guid;
} FQYTransData;

static void
open_cb (PnNode *conn,
         MsnNotification *notification)
{
    g_return_if_fail (conn != NULL);

    pn_log ("begin");

    pn_cmd_server_send (PN_CMD_SERVER (conn), "VER", "MSNP18 CVR0");

    pn_log ("end");
}

static void
close_cb (PnNode *conn,
          MsnNotification *notification)
{
    char *tmp;

    {
        if (conn->error)
        {
            const char *reason;
            reason = conn->error->message;

            pn_error ("connection error: (NS):reason=[%s]", reason);
            tmp = g_strdup_printf (_("Error on notification server:\n%s"), reason);

            g_clear_error (&conn->error);
        }
        else
        {
            pn_error ("connection error: (NS)");
            tmp = g_strdup_printf (_("Error on notification server:\nUnknown"));
        }
    }

    pn_node_close (PN_NODE (notification->conn));
    notification->closed = TRUE;
    msn_session_set_error (notification->session, MSN_ERROR_SERVCONN, tmp);

    g_free (tmp);
}

/**************************************************************************
 * Main
 **************************************************************************/

static void
error_handler (MsnCmdProc *cmdproc,
               MsnTransaction *trans,
               gint error)
{
    MsnNotification *notification;
    gchar *reason;

    notification = cmdproc->data;
    g_return_if_fail (notification);

    reason = pn_error_to_string (error);
    pn_error ("connection error: (NS):reason=[%s]", reason);

    switch (error)
    {
        case 913:
        case 208:
            /* non-fatal */
            break;
        default:
            {
                char *tmp;
                tmp = g_strdup_printf (_("Error on notification server:\n%s"), reason);
                msn_session_set_error (notification->session, MSN_ERROR_SERVCONN, tmp);
                g_free (tmp);
            }
    }

    g_free (reason);
}

MsnNotification *
msn_notification_new(MsnSession *session)
{
    MsnNotification *notification;

    g_return_val_if_fail(session != NULL, NULL);

    notification = g_new0(MsnNotification, 1);

    notification->session = session;

    {
        PnNode *conn;
        notification->conn = pn_cmd_server_new (PN_NODE_NS);
        conn = PN_NODE (notification->conn);

        {
            MsnCmdProc *cmdproc;
            cmdproc = g_object_get_data(G_OBJECT(notification->conn), "cmdproc");
            cmdproc->session = session;
            cmdproc->cbs_table = cbs_table;
            cmdproc->conn = conn;
            cmdproc->error_handler = error_handler;
            cmdproc->data = notification;

            notification->cmdproc = cmdproc;
        }

        conn->session = session;

        if (msn_session_get_bool (session, "use_http_method"))
        {
            if (session->http_conn)
            {
                /* A single http connection shared by all nodes */
                pn_node_link (conn, session->http_conn);
            }
            else
            {
                /* Each node has it's own http connection. */
                PnNode *foo;

                foo = PN_NODE (pn_http_server_new ("foo server"));
                foo->session = session;
                pn_node_link (conn, foo);
                g_object_unref (foo);
            }
        }

        notification->open_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), notification);
        notification->close_handler = g_signal_connect (conn, "close", G_CALLBACK (close_cb), notification);
        notification->error_handler = g_signal_connect (conn, "error", G_CALLBACK (close_cb), notification);
    }

    return notification;
}

void
msn_notification_destroy(MsnNotification *notification)
{
    if (!notification)
        return;

    pn_timer_free(notification->alive_timer);

    if (notification->cmdproc)
        notification->cmdproc->data = NULL;

    g_signal_handler_disconnect (notification->conn, notification->open_handler);
    g_signal_handler_disconnect (notification->conn, notification->close_handler);
    g_signal_handler_disconnect (notification->conn, notification->error_handler);

    pn_cmd_server_free (notification->conn);

    g_free(notification);
}

/**************************************************************************
 * Connect
 **************************************************************************/

gboolean
msn_notification_connect(MsnNotification *notification, const char *host, int port)
{
    g_return_val_if_fail(notification != NULL, FALSE);

    pn_node_connect (PN_NODE (notification->conn), host, port);

    return TRUE;
}

/**************************************************************************
 * Login
 **************************************************************************/

void
msn_got_login_params(MsnSession *session, const char *login_params, const char *sso_value)
{
    MsnCmdProc *cmdproc;

    cmdproc = session->notification->cmdproc;

    {
        gchar **tokens;
        tokens = g_strsplit (login_params, "&", 2);
        session->passport_cookie.t = g_strdup (tokens[0] + 2);
        session->passport_cookie.p = g_strdup (tokens[1] + 2);
        g_strfreev (tokens);
    }

    msn_cmdproc_send(cmdproc, "USR", "SSO S %s %s {%s}", login_params, sso_value, session->machineguid);
}

static void
cvr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    msn_cmdproc_send(cmdproc, "USR", "SSO I %s",
                     msn_session_get_username(cmdproc->session));
}

static gboolean
timeout (void *data)
{
    MsnNotification *ns = data;
    MsnCmdProc *cmdproc = ns->cmdproc;
    pn_timer_start(ns->alive_timer, 60);
    pn_timer_cancel(cmdproc->timer);
    msn_cmdproc_send_quick(cmdproc, "PNG", NULL, NULL);

    return FALSE;
}

static gboolean
alive_timeout (void *data)
{
    msn_session_set_error (data, MSN_ERROR_SERVCONN, "Timed out");
    return FALSE;
}

static void auth_cb (PnAuth *auth, void *data)
{
    char *tmp, *value;
    value = pn_auth_rps_encrypt (auth, (char *) data);
    tmp = g_strdup_printf("t=%s&p=%s",
                          auth->security_token.messengerclear_live_com_t,
                          auth->security_token.messengerclear_live_com_p);
    msn_got_login_params (auth->session, tmp, value);
    g_free(tmp);
    g_free(value);
}

static void
usr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;

    session = cmdproc->session;

    if (!g_ascii_strcasecmp(cmd->params[1], "OK"))
    {
        /* OK */
        pn_service_session_request  (session->service_session,
                                     PN_REQ_MEMBERLISTS, NULL, NULL, NULL);
        if (!msn_session_get_bool (session, "use_http_method")) {
            MsnNotification *ns = cmdproc->data;
            ns->alive_timer = pn_timer_new (alive_timeout, session);
            msn_cmdproc_set_timeout(cmdproc, 30, timeout, ns);
        }
    }
    else if (!g_ascii_strcasecmp(cmd->params[1], "SSO"))
    {
        session->auth = pn_auth_new(session);
        session->auth->login_policy = g_strdup (cmd->params[3]);
        pn_auth_get_ticket (session->auth, 0, auth_cb, cmd->params[4]);
    }
}

static void
usr_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    MsnErrorType msnerr = 0;

    switch (error)
    {
        case 500:
        case 601:
        case 910:
        case 921:
            msnerr = MSN_ERROR_SERV_UNAVAILABLE;
            break;
        case 911:
            msnerr = MSN_ERROR_AUTH;
            break;
        default:
            return;
            break;
    }

    msn_session_set_error(cmdproc->session, msnerr, NULL);
}

static void
add_new_contact (struct MsnSession *session, char *email, int network_id,
                 gchar *group_guid)
{
    struct pn_contact *contact;

    contact = pn_contact_new (session->contactlist);
    pn_contact_set_passport (contact, email);
    pn_contact_set_network_id (contact, network_id);
    pn_contact_set_list_op (contact, MSN_LIST_AL_OP);

    pn_service_session_request (session->service_session,
                                PN_ADD_CONTACT, email,
                                network_id == 32 ? "yahoo" : NULL, group_guid);

    if (group_guid)
        pn_contact_add_group_id (contact, group_guid);
}

static void
uum_error_post (MsnCmdProc *cmdproc, MsnCommand *cmd,
                char *payload, size_t len)
{
    pn_info ("UUM error, payload=[%s]", payload);
}

static void
uum_error (MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    MsnCommand *cmd;
    cmd = cmdproc->last_cmd;

    if (error == 509)
    {
        /* TODO: improve this to show unsent message */
        PurpleAccount *account;
        PurpleConversation *conv;
        char *error_str;

        account = msn_session_get_user_data (cmdproc->session);
        conv = purple_find_conversation_with_account (PURPLE_CONV_TYPE_IM,
                                                      trans->data, account);
        if (!conv)
            conv = purple_conversation_new (PURPLE_CONV_TYPE_IM,
                                            account, trans->data);
        error_str = g_strdup (_("Messages to this contact cannot be sent "
                                "due to a temporany error in MSN servers.")); 
        purple_conversation_write (conv, NULL, error_str,
                                   PURPLE_MESSAGE_ERROR, time (NULL));
    }
    else
        pn_warning ("command=[%s],error=%i",
                    msn_transaction_to_string (trans), error);

    if (cmd->params[1])
    {
        cmd->payload_len = atoi(cmd->params[1]);
        cmd->payload_cb = uum_error_post;
    }
}

static void
fqy_error_post (MsnCmdProc *cmdproc, MsnCommand *cmd,
                char *payload, size_t len)
{
    pn_info ("FQY error, payload=[%s]", payload);
}

static void
fqy_error (MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
    MsnCommand *cmd;
    cmd = cmdproc->last_cmd;

    if (error == 508)
    {
        FQYTransData *data;
        char *email;

        data = trans->data;
        email = g_strdup_printf ("%s@%s", data->name, data->domain);
        add_new_contact (cmdproc->session, email,
                         strstr (email, "@yahoo.") ? 32 : 1, data->group_guid);
        g_free (email);
        g_free (data->domain);
        g_free (data->name);
        g_free (data->group_guid);
    }
    else
        pn_warning ("command=[%s],error=%i",
                    msn_transaction_to_string (trans), error);

    if (cmd->params[1])
    {
        cmd->payload_len = atoi(cmd->params[1]);
        cmd->payload_cb = fqy_error_post;
    }
}

static void
ver_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    gboolean protocol_supported = FALSE;
    const gchar *proto_str;
    guint i;

    session = cmdproc->session;

    proto_str = "MSNP18";

    for (i = 1; i < cmd->param_count; i++)
    {
        if (!strcmp(cmd->params[i], proto_str))
        {
            protocol_supported = TRUE;
            break;
        }
    }

    if (!protocol_supported)
    {
        msn_session_set_error(session, MSN_ERROR_UNSUPPORTED_PROTOCOL,
                              NULL);
        return;
    }

    msn_cmdproc_send(cmdproc, "CVR",
                     "0x0409 winnt 5.1 i386 MSNMSGR 8.1.0178 msmsgs %s",
                     msn_session_get_username(session));
}

/**************************************************************************
 * Log out
 **************************************************************************/

static void
out_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    if (!g_ascii_strcasecmp(cmd->params[0], "OTH"))
        msn_session_set_error(cmdproc->session, MSN_ERROR_SIGN_OTHER,
                              NULL);
    else if (!g_ascii_strcasecmp(cmd->params[0], "SSD"))
        msn_session_set_error(cmdproc->session, MSN_ERROR_SERV_DOWN, NULL);
}

void
msn_notification_close(MsnNotification *notification)
{
    g_return_if_fail(notification != NULL);

    if (!notification->closed)
    {
        msn_cmdproc_send_quick (notification->cmdproc, "OUT", NULL, NULL);
        pn_node_close (PN_NODE (notification->conn));
    }
}

/**************************************************************************
 * Messages
 **************************************************************************/

static void
msg_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
             size_t len)
{
    MsnMessage *msg;

    msg = msn_message_new_from_cmd(cmd);

    msn_message_parse_payload(msg, payload, len);
#ifdef PECAN_DEBUG_NS
    msn_message_show_readable(msg, "Notification", TRUE);
#endif

    msn_cmdproc_process_msg(cmdproc, msg);

    msn_message_unref(msg);
}

static void
msg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    /* NOTE: cmd is not always cmdproc->last_cmd, sometimes cmd is a queued
     * command and we are processing it */

    if (cmd->payload == NULL)
    {
        cmdproc->last_cmd->payload_cb  = msg_cmd_post;
        cmd->payload_len = atoi(cmd->params[2]);
    }
    else
    {
        g_return_if_fail(cmd->payload_cb != NULL);

        cmd->payload_cb(cmdproc, cmd, cmd->payload, cmd->payload_len);
    }
}



static void
ubm_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    /* NOTE: cmd is not always cmdproc->last_cmd, sometimes cmd is a queued
     * command and we are processing it */

    if (cmd->payload == NULL)
    {
        cmdproc->last_cmd->payload_cb  = msg_cmd_post;
        cmd->payload_len = atoi(cmd->params[5]);
    }
    else
    {
        g_return_if_fail(cmd->payload_cb != NULL);

        cmd->payload_cb(cmdproc, cmd, cmd->payload, cmd->payload_len);
    }
}

/**************************************************************************
 * Challenges
 **************************************************************************/

static void
chl_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnTransaction *trans;
    gchar buf[32];

    pn_handle_challenge (cmd->params[1], "PROD0119GSJUC$18", "ILTXC!4IXB5FB*PX", buf);

    /* trans = msn_transaction_new(cmdproc, "QRY", "%s 32", "PROD0038W!61ZTF9"); */
    trans = msn_transaction_new (cmdproc, "QRY", "%s 32", "PROD0119GSJUC$18");

    msn_transaction_set_payload (trans, buf, 32);

    msn_cmdproc_send_trans (cmdproc, trans);
}

/**************************************************************************
 * Buddy Lists
 **************************************************************************/

static void
qng_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnNotification *ns = cmdproc->data;
    pn_timer_stop(ns->alive_timer);
    pn_timer_start(cmdproc->timer, atoi(cmd->params[0]));
}

static void
fln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    struct pn_contact *user;
    gchar *passport, **user_str;

    user_str = g_strsplit (cmd->params[0], ":", 2);
    passport = g_strdup (user_str[1]);
    g_strfreev (user_str);
    user = pn_contactlist_find_contact (cmdproc->session->contactlist, passport);
    g_free (passport);
    pn_contact_set_state(user, NULL);
    pn_contact_update(user);

#if defined(PECAN_CVR)
    g_hash_table_remove(cmdproc->session->links, cmd->params[0]);
#endif /* defined(PECAN_CVR) */
}

#if 0
static void
iln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    struct pn_contact *user;
    const char *state, *passport;
    gchar *friendly;

    session = cmdproc->session;

    state    = cmd->params[1];
    passport = cmd->params[2];
    friendly = pn_url_decode(cmd->params[4]);

    if (strcmp (passport, session->username) == 0)
        return;

    user = pn_contactlist_find_contact(session->contactlist, passport);

    pn_contact_set_state(user, state);
    pn_contact_set_friendly_name(user, friendly);

    if (cmd->param_count >= 6)
    {
        gchar **client_id_str;
        gulong client_id;
        client_id_str = g_strsplit (cmd->params[5], ":", 2);
        client_id = strtoul (client_id_str[0], NULL, 10);
        pn_contact_set_client_id (user, client_id);
        g_strfreev (client_id_str);
    }

#if defined(PECAN_CVR)
    if (msn_session_get_bool (session, "use_userdisplay"))
    {
        if (cmd->param_count == 7)
        {
            struct pn_msnobj *obj;
            gchar *tmp;
            tmp = pn_url_decode (cmd->params[6]);
            obj = pn_msnobj_new_from_string (tmp);
            pn_contact_set_object(user, obj);
            g_free (tmp);
        }
    }
#endif /* defined(PECAN_CVR) */

    pn_contact_update(user);

    g_free (friendly);
}
#endif

static void
ipg_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
    pn_info ("incoming page: [%s]", payload);
}

static void
ipg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    cmd->payload_len = atoi(cmd->params[0]);
    cmdproc->last_cmd->payload_cb = ipg_cmd_post;
}

static void
nln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    struct pn_contact *user;
    unsigned long clientid;
    const char *state;
    gchar *friendly, **client_id_str, *passport, **user_str;

    session = cmdproc->session;

    state    = cmd->params[0];
    user_str = g_strsplit (cmd->params[1], ":", 2);
    passport = g_strdup (user_str[1]);
    g_strfreev (user_str);
    friendly = pn_url_decode(cmd->params[2]);

    if (strcmp (passport, session->username) == 0)
        goto leave;

    user = pn_contactlist_find_contact(session->contactlist, passport);

    if (!user)
    {
        pn_error ("unknown user: passport=[%s]", passport);
        goto leave;
    }

    pn_contact_set_friendly_name(user, friendly);

    client_id_str = g_strsplit (cmd->params[3], ":", 2);
    clientid = strtoul (client_id_str[0], NULL, 10);
    g_strfreev (client_id_str);
    if (!pn_contact_get_client_id (user))
        pn_contact_set_client_id (user, clientid);
    user->mobile = (clientid & PN_CLIENT_CAP_MSNMOBILE);

    pn_contact_set_state(user, state);

#if defined(PECAN_CVR)
    if (msn_session_get_bool (session, "use_userdisplay"))
    {
        if (cmd->param_count == 5)
        {
            struct pn_msnobj *obj;
            gchar *tmp;
            tmp = pn_url_decode(cmd->params[4]);
            obj = pn_msnobj_new_from_string(tmp);
            pn_contact_set_object(user, obj);
            g_free (tmp);
        }
        else
        {
            pn_contact_set_object(user, NULL);
        }
    }
#endif /* defined(PECAN_CVR) */

    pn_contact_update(user);

    /* store the friendly name on the server. */
    /* if (!msn_session_get_bool (session, "use_server_alias"))
        msn_cmdproc_send (cmdproc, "SBP", "%s %s %s", pn_contact_get_guid (user), "MFN", cmd->params[2]); */

leave:
    g_free (passport);
    g_free (friendly);
}

static void
contact_update (struct pn_contact *contact,
                gpointer user_data)
{
    if (contact->status == PN_STATUS_OFFLINE)
        return;

#if defined(PECAN_CVR)
    pn_contact_update_object (contact);
#endif /* defined(PECAN_CVR) */
}

static void
chg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    struct pn_contact *user;
    PecanStatus old_status;

    user = msn_session_get_contact (cmdproc->session);
    old_status = user->status;
    pn_contact_set_state (user, cmd->params[1]);

    if (old_status == PN_STATUS_HIDDEN)
    {
        /* now we are able to send messages and do p2p */

        pn_contactlist_foreach_contact (cmdproc->session->contactlist, contact_update, NULL);
    }
}

static void
not_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
    pn_info ("incoming notification: [%s]", payload);
}

static void
not_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    cmd->payload_len = atoi(cmd->params[0]);
    cmdproc->last_cmd->payload_cb = not_cmd_post;
}

#if 0
static void
rea_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    const char *who;
    const char *alias;

    session = cmdproc->session;
    who = cmd->params[2];
    alias = purple_url_decode(cmd->params[3]);

    if (strcmp(who, purple_account_get_username (session->account)) == 0)
    {
        /* This is for us. */
        PurpleConnection *gc;
        gc = session->account->gc;
        purple_connection_set_display_name(gc, alias);
    }
    else
    {
        /* This is for a buddy. */
        struct pn_contact *user;
        user = pn_contactlist_find_contact(session->contactlist, who);
        if (user)
        {
            pn_contact_set_store_name(user, alias);
        }
        else
        {
            pn_error ("unknown user: who=[%s]", who);
            return;
        }
    }
}
#endif

static void
sbp_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSession *session;
    const gchar *contact_guid;
    const gchar *type;
    const gchar *value;
    struct pn_contact *contact;

    session = cmdproc->session;
    contact_guid = cmd->params[1];
    type = cmd->params[2];
    value = cmd->params[3];

    contact = pn_contactlist_find_contact_by_guid (session->contactlist, contact_guid);

    if (contact)
    {
        if (strcmp (type, "MFN") == 0)
        {
            gchar *tmp;
            tmp = pn_url_decode (value);
            if (msn_session_get_bool (session, "use_server_alias"))
                pn_contact_set_store_name (contact, tmp);
            g_free (tmp);
        }
    }
}

static void
prp_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session = cmdproc->session;
    PurpleConnection *gc;
    PurpleAccount *account;
    const gchar *type, *value;
    struct pn_contact *user;

    g_return_if_fail(cmd->param_count >= 3);

    account = msn_session_get_user_data (session);
    gc = purple_account_get_connection (account);

    type = cmd->params[1];
    user = msn_session_get_contact (session);

    if (cmd->param_count == 3)
    {
        gchar *tmp;
        value = cmd->params[2];
        tmp = pn_url_decode (value);
        if (!strcmp(type, "PHH"))
            pn_contact_set_home_phone(user, tmp);
        else if (!strcmp(type, "PHW"))
            pn_contact_set_work_phone(user, tmp);
        else if (!strcmp(type, "PHM"))
            pn_contact_set_mobile_phone(user, tmp);
        else if (!strcmp(type, "MFN"))
            purple_connection_set_display_name(gc, tmp);
        g_free (tmp);
    }
    else
    {
        if (!strcmp(type, "PHH"))
            pn_contact_set_home_phone(user, NULL);
        else if (!strcmp(type, "PHW"))
            pn_contact_set_work_phone(user, NULL);
        else if (!strcmp(type, "PHM"))
            pn_contact_set_mobile_phone(user, NULL);
    }
}

static void
adl_cmd_read_payload (MsnCmdProc *cmdproc,
                      MsnCommand *cmd,
                      gchar *payload,
                      gsize len)
{
    gchar *cur, *end, *domain, *name, *email, *t;
    struct pn_contact *contact;

    cur = strstr (payload, "<d n=\"") + 6;
    end = strchr (cur, '\"');
    domain = g_strndup (cur, end - cur);
    cur = strstr (end, "<c n=\"") + 6;
    end = strchr (cur, '\"');
    name = g_strndup (cur, end - cur);
    cur = strstr (end, "t=\"") + 3;
    end = strchr (cur, '\"');
    t = g_strndup (cur, end - cur);

    email = g_strdup_printf ("%s@%s", name, domain);
    g_free (domain);
    g_free (name);

    contact = pn_contact_new (cmdproc->session->contactlist);
    pn_contact_set_passport (contact, email);
    pn_contact_set_network_id (contact, atoi(t));
    pn_contact_set_list_op (contact, MSN_LIST_NULL_OP);
    pn_contactlist_got_new_entry (cmdproc->session, contact, email);

    g_free (t);
    g_free (email);
}

static void
adl_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    if (!g_ascii_strcasecmp(cmd->params[1], "OK"))
    {
        /* OK */
        MsnSession *session;

        session = cmdproc->session;

        if (!session->logged_in)
            msn_session_finish_login (session);
    }
    else
    {
        cmd->payload_len = atoi(cmd->params[1]);
        cmdproc->last_cmd->payload_cb = adl_cmd_read_payload;
    }
}

static void
fqy_cmd_post (MsnCmdProc *cmdproc,
              MsnCommand *cmd,
              gchar *payload,
              gsize len)
{
    FQYTransData *data;
    char *cur, *end, *t, *email;

    data = cmd->trans->data;
    cur = strstr (payload, "t=\"") + 3;
    end = strchr (cur, '\"');
    t = g_strndup (cur, end - cur);

    email = g_strdup_printf ("%s@%s", data->name, data->domain);
    add_new_contact (cmdproc->session, email, atoi (t), data->group_guid);
    g_free (email);
    g_free (t);
    g_free (data->domain);
    g_free (data->name);
    g_free (data->group_guid);
}

static void
fqy_cmd (MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    cmdproc->last_cmd->payload_cb = fqy_cmd_post;
    cmd->payload_len = atoi(cmd->params[1]);
}

static void
ubx_cmd_post (MsnCmdProc *cmdproc,
              MsnCommand *cmd,
              gchar *payload,
              gsize len)
{
    MsnSession *session;
    struct pn_contact *contact;
    gchar *passport, **user_str;

    session = cmdproc->session;

    user_str = g_strsplit (cmd->params[0], ":", 2);
    passport = g_strdup (user_str[1]);
    g_strfreev (user_str);
    contact = pn_contactlist_find_contact (session->contactlist, passport);
    g_free (passport);

    if (contact)
    {
        gchar *psm = NULL, *current_media = NULL;
        const gchar *start;
        const gchar *end;

        start = g_strstr_len (payload, len, "<PSM>");
        if (start)
        {
            start += 5;
            end = g_strstr_len (start, len - (start - payload), "</PSM>");

            /* check that the closing <PSM> tag is there, and that the PSM
             * isn't empty */
            if (end > start)
            {
                psm = g_strndup (start, end - start);
                pn_contact_set_personal_message (contact, psm);
                g_free (psm);
            }
        }

        start = g_strstr_len (payload, len, "<CurrentMedia>");
        if (start)
        {
            start += 14;
            end = g_strstr_len (start, len - (start - payload), "</CurrentMedia>");

            if (end > start)
                current_media = g_strndup (start, end - start);
        }

        pn_contact_set_current_media (contact, current_media);
        g_free (current_media);

        pn_contact_update (contact);
    }
}

static void
ubx_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    cmdproc->last_cmd->payload_cb = ubx_cmd_post;
    cmd->payload_len = atoi (cmd->params[1]);
}

static void
gcf_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    cmdproc->last_cmd->payload_cb = NULL;
    cmd->payload_len = atoi (cmd->params[1]);
}

/**************************************************************************
 * Misc commands
 **************************************************************************/

static void
url_cmd (MsnCmdProc *cmdproc,
         MsnCommand *cmd)
{
    MsnSession *session;
    PurpleConnection *connection;
    PurpleAccount *account;
    const gchar *rru;
    const gchar *url;
    gchar creds[64];
    glong tmp_timestamp;

    session = cmdproc->session;
    account = msn_session_get_user_data (session);
    connection = purple_account_get_connection (account);

    rru = cmd->params[1];
    url = cmd->params[2];

    session->passport_info.mail_url_timestamp = time (NULL);
    tmp_timestamp = session->passport_info.mail_url_timestamp - session->passport_info.sl;

    {
        PurpleCipher *cipher;
        PurpleCipherContext *context;
        guchar digest[16];
        gchar *buf;

        buf = g_strdup_printf ("%s%ld%s",
                               session->passport_info.mspauth ? session->passport_info.mspauth : "BOGUS",
                               tmp_timestamp,
                               purple_connection_get_password (connection));

        cipher = purple_ciphers_find_cipher ("md5");
        context = purple_cipher_context_new (cipher, NULL);

        purple_cipher_context_append (context, (const guchar *) buf, strlen (buf));
        purple_cipher_context_digest (context, sizeof (digest), digest, NULL);
        purple_cipher_context_destroy (context);

        g_free (buf);

        memset (creds, 0, sizeof (creds));

        {
            gchar buf2[3];
            gint i;

            for (i = 0; i < 16; i++)
            {
                g_snprintf (buf2, sizeof (buf2), "%02x", digest[i]);
                strcat (creds, buf2);
            }
        }
    }

    g_free (session->passport_info.mail_url);

    session->passport_info.mail_url = g_strdup_printf ("%s&auth=%s&creds=%s&sl=%ld&username=%s&mode=ttl&sid=%s&id=2&rru=%ssvc_mail&js=yes",
                                                       url,
                                                       session->passport_info.mspauth,
                                                       creds,
                                                       tmp_timestamp,
                                                       msn_session_get_username (session),
                                                       session->passport_info.sid,
                                                       rru);

    /* The user wants to check his email */
    if (cmd->trans && cmd->trans->data)
    {
        purple_notify_uri (connection, session->passport_info.mail_url);
        return;
    }

    if (purple_account_get_check_mail (account))
    {
        static gboolean is_initial = TRUE;

        if (!is_initial)
            return;

        if (session->inbox_unread_count > 0)
        {
            const gchar *passport;
            const gchar *main_url;

            passport = msn_session_get_username (session);
            main_url = session->passport_info.mail_url;

            purple_notify_emails (connection, session->inbox_unread_count, FALSE, NULL, NULL,
                                  &passport, &main_url, NULL, NULL);
        }

        is_initial = FALSE;
    }
}

/**************************************************************************
 * Switchboards
 **************************************************************************/

static void
rng_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    MsnSession *session;
    MsnSwitchBoard *swboard;
    char *host, *passport;
    int port;
    const char *id;

    session = cmdproc->session;

    if (strchr (cmd->params[4], ';'))
    {
        gchar **user_str;
        user_str = g_strsplit (cmd->params[4], ";", 2);
        passport = g_strdup (user_str[0]);
        g_strfreev (user_str);
    }
    else
        passport = g_strdup (cmd->params[4]);

    if (strcmp (passport, session->username) == 0)
    {
        g_free (passport);
        return;
    }

    msn_parse_socket(cmd->params[1], &host, &port);

    swboard = msn_switchboard_new(session);
    msn_switchboard_set_invited(swboard, TRUE);
    msn_switchboard_set_session_id(swboard, cmd->params[0]);
    msn_switchboard_set_auth_key(swboard, cmd->params[3]);

    if (g_hash_table_lookup (session->conversations, passport)) {
        swboard->chat_id = session->conv_seq++;

        g_hash_table_insert (session->chats, GINT_TO_POINTER (swboard->chat_id), swboard);

        /* we should not leave chats on timeouts */
        pn_timer_free(swboard->timer);
        swboard->timer = NULL;

        id = "chat";

        g_free (passport);
    }
    else {
        id = swboard->im_user = passport;

        g_hash_table_insert (session->conversations, g_strdup (id), swboard);
    }

    pn_node_set_id(swboard->cmdproc->conn, session->conn_count++, id);

    if (!msn_switchboard_connect(swboard, host, port))
        msn_switchboard_close(swboard);

    g_free(host);
}

static void
xfr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
    char *host;
    int port;

    if (strcmp(cmd->params[1], "SB") && strcmp(cmd->params[1], "NS"))
    {
        /* Maybe we can have a generic bad command error. */
        pn_error ("bad XFR command: params=[%s]", cmd->params[1]);
        return;
    }

    msn_parse_socket(cmd->params[2], &host, &port);

    if (!strcmp(cmd->params[1], "SB"))
    {
        pn_error ("this shouldn't be handled here");
    }
    else if (!strcmp(cmd->params[1], "NS"))
    {
        MsnSession *session;

        session = cmdproc->session;

        msn_notification_connect(session->notification, host, port);
    }

    g_free(host);
}

/**************************************************************************
 * Message Types
 **************************************************************************/

static void
plain_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    PurpleConnection *gc;
    PurpleAccount *account;
    const char *body;
    char *body_str;
    char *body_enc;
    char *body_final;
    size_t body_len;
    char *passport;
    const char *value;

    account = msn_session_get_user_data (cmdproc->session);
    gc = purple_account_get_connection (account);

    body = msn_message_get_bin_data(msg, &body_len);
    body_str = g_strndup(body, body_len);
    body_enc = g_markup_escape_text(body_str, -1);
    g_free(body_str);

    passport = g_strdup (msg->remote_user);

    if ((value = msn_message_get_attr(msg, "X-MMS-IM-Format")) != NULL)
    {
        char *pre, *post;

        msn_parse_format(value, &pre, &post);

        body_final = g_strdup_printf("%s%s%s", pre ? pre : "",
                                     body_enc ? body_enc : "", post ? post : "");

        g_free(pre);
        g_free(post);
        g_free(body_enc);
    }
    else
    {
        body_final = body_enc;
    }

    serv_got_im (gc, passport, body_final, 0, time (NULL));

    g_free(body_final);
    g_free(passport);
}

static void
profile_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    MsnSession *session;
    const char *value;

    session = cmdproc->session;

    if (strcmp(msg->remote_user, "Hotmail"))
    {
        pn_warning ("unofficial message");
        return;
    }

    if ((value = msn_message_get_attr(msg, "kv")) != NULL)
    {
        g_free(session->passport_info.kv);
        session->passport_info.kv = g_strdup(value);
    }

    if ((value = msn_message_get_attr(msg, "sid")) != NULL)
    {
        g_free(session->passport_info.sid);
        session->passport_info.sid = g_strdup(value);
    }

    if ((value = msn_message_get_attr(msg, "MSPAuth")) != NULL)
    {
        g_free(session->passport_info.mspauth);
        session->passport_info.mspauth = g_strdup(value);
    }

    if ((value = msn_message_get_attr(msg, "ClientIP")) != NULL)
    {
        g_free(session->passport_info.client_ip);
        session->passport_info.client_ip = g_strdup(value);
    }

    if ((value = msn_message_get_attr(msg, "ClientPort")) != NULL)
        session->passport_info.client_port = g_ntohs(atoi(value));

    if ((value = msn_message_get_attr(msg, "LoginTime")) != NULL)
        session->passport_info.sl = atol(value);

    if ((value = msn_message_get_attr(msg, "EmailEnabled")) != NULL)
        session->passport_info.email_enabled = atol(value);
}

static void
initial_mdata_msg (MsnCmdProc *cmdproc,
                   MsnMessage *msg)
{
    MsnSession *session;
    GHashTable *table;

    session = cmdproc->session;

    if (strcmp (msg->remote_user, "Hotmail"))
    {
        pn_warning ("unofficial message");
        return;
    }

    table = msn_message_get_hashtable_from_body (msg);

    {
        gchar *mdata;
        mdata = g_hash_table_lookup (table, "Mail-Data");

        if (mdata)
        {
            gchar *iu = NULL;
            const gchar *start;
            const gchar *end;
            guint len;

            len = strlen (mdata);
            start = g_strstr_len (mdata, len, "<IU>");

            if (start)
            {
                start += strlen ("<IU>");
                end = g_strstr_len (start, len - (start - mdata), "</IU>");

                if (end > start)
                    iu = g_strndup (start, end - start);
            }

            if (iu)
            {
                session->inbox_unread_count = atoi (iu);

                g_free (iu);
            }

            do
            {
                start = g_strstr_len (start, len - (start - mdata), "<M>");

                if (start)
                {
                    start += strlen ("<M>");
                    end = g_strstr_len (start, len - (start - mdata), "</M>");

                    if (end > start)
                    {
                        gchar *read_set;

#if 0
                        {
                            gchar *field;
                            gchar *tmp;
                            tmp = pn_get_xml_field ("N", start, end);
                            field = purple_mime_decode_field (tmp);
                            g_print ("field={%s}\n", field);
                            g_free (field);
                            g_free (tmp);
                        }
#endif

                        read_set = pn_get_xml_field ("RS", start, end);

                        if (strcmp (read_set, "0") == 0)
                        {
                            gchar *passport;
                            gchar *message_id;
                            struct pn_contact *contact;

                            passport = pn_get_xml_field ("E", start, end);
                            contact = pn_contactlist_find_contact (session->contactlist, passport);

                            message_id = pn_get_xml_field ("I", start, end);

                            if (contact && !(pn_contact_is_blocked (contact)))
                                pn_oim_session_request (session->oim_session,
                                                        passport,
                                                        message_id,
                                                        PN_RECEIVE_OIM);

                            g_free (passport);
                            g_free (message_id);
                        }

                        g_free (read_set);
                        start = end + strlen ("</M>");
                    }
                }
            } while (start);
        }

        {
            PurpleAccount *account;

            account = msn_session_get_user_data (session);

            if (purple_account_get_check_mail (account) &&
                session->passport_info.email_enabled == 1)
            {
                msn_cmdproc_send (cmdproc, "URL", "%s", "INBOX");
            }
        }
    }

    g_hash_table_destroy(table);
}

static void
oim_msg (MsnCmdProc *cmdproc,
         MsnMessage *msg)
{
    GHashTable *table;
    gchar *mdata;

    table = msn_message_get_hashtable_from_body (msg);

    mdata = g_hash_table_lookup (table, "Mail-Data");

    if (mdata)
    {
        MsnSession *session;
        const gchar *start;
        const gchar *end;
        guint len;

        session = cmdproc->session;

        len = strlen (mdata);
        start = g_strstr_len (mdata, len, "<M>");

        while (start)
        {
            start += strlen ("<M>");
            end = g_strstr_len (start, len - (start - mdata), "</M>");

            if (end > start)
            {
                gchar *read_set;

                read_set = pn_get_xml_field ("RS", start, end);

                if (strcmp (read_set, "0") == 0)
                {
                    gchar *passport;
                    gchar *message_id;
                    struct pn_contact *contact;

                    passport = pn_get_xml_field ("E", start, end);
                    contact = pn_contactlist_find_contact (session->contactlist, passport);

                    message_id = pn_get_xml_field ("I", start, end);

                    if (contact && !(pn_contact_is_blocked (contact)))
                        pn_oim_session_request (session->oim_session, passport, message_id,
                                                PN_RECEIVE_OIM);

                    g_free (passport);
                    g_free (message_id);
                }

                g_free (read_set);
                start = end + strlen ("</M>");
            }

            start = g_strstr_len (start, len - (start - mdata), "<M>");
        }
    }
}

static void
email_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    MsnSession *session;
    PurpleAccount *account;
    GHashTable *table;
    char *from, *subject, *tmp;

    session = cmdproc->session;
    account = msn_session_get_user_data (session);

    if (!purple_account_get_check_mail (account))
        return;

    if (strcmp(msg->remote_user, "Hotmail"))
    {
        pn_warning ("unofficial message");
        return;
    }

    if (!session->passport_info.mail_url)
    {
        pn_error ("no url");
        return;
    }

    table = msn_message_get_hashtable_from_body(msg);

    from = subject = NULL;

    tmp = g_hash_table_lookup(table, "From");
    if (tmp != NULL)
        from = purple_mime_decode_field(tmp);

    tmp = g_hash_table_lookup(table, "Subject");
    if (tmp != NULL)
        subject = purple_mime_decode_field(tmp);

    {
        PurpleConnection *connection;
        connection = purple_account_get_connection (account);
        /** @todo go to the extact email */
        purple_notify_email (connection,
                             (subject ? subject : ""),
                             (from ?  from : ""),
                             msn_session_get_username (session),
                             session->passport_info.mail_url, NULL, NULL);
    }

    g_free(from);
    g_free(subject);

    g_hash_table_destroy(table);
}

static void
system_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
    GHashTable *table;
    const char *type_s;

    if (strcmp(msg->remote_user, "Hotmail"))
    {
        pn_warning ("unofficial message");
        return;
    }

    table = msn_message_get_hashtable_from_body(msg);

    if ((type_s = g_hash_table_lookup(table, "Type")) != NULL)
    {
        int type = atoi(type_s);
        gchar *msg;
        int minutes;

        switch (type)
        {
            case 1:
                minutes = atoi(g_hash_table_lookup(table, "Arg1"));
                msg = g_strdup_printf(_("The MSN server will shut down for maintenance "
                                        "in %d minutes. You will automatically be "
                                        "signed out at that time.  Please finish any "
                                        "conversations in progress.\n\nAfter the "
                                        "maintenance has been completed, you will be "
                                        "able to successfully sign in."), minutes);
                break;
            default:
                msg = NULL;
                break;
        }

        if (msg)
        {
            PurpleAccount *account;
            PurpleConnection *connection;
            account = msn_session_get_user_data (cmdproc->session);
            connection = purple_account_get_connection (account);
            purple_notify_info (connection, NULL, msg, NULL);
            g_free (msg);
        }
    }

    g_hash_table_destroy(table);
}

void
msn_notification_add_buddy(MsnNotification *notification, const char *list,
                           const char *who, const gchar *user_guid, const char *store_name,
                           const gchar *group_guid)
{
    MsnCmdProc *cmdproc;

    cmdproc = notification->cmdproc;

    /* moogman: 
     * If old_group_name == NULL, then ADC cmd is different.
     * If a new buddy (as opposed to a buddy move), ADC cmd is different. 
     * If !Fl, then do same as "new". */
    if (user_guid && group_guid)
    {
        /* Buddy already in FL. Add it to group_guid. */
        pn_service_session_request  (cmdproc->session->service_session,
                                     PN_ADD_CONTACT_GROUP, group_guid,
                                     user_guid, NULL);
    }
    else if (strcmp(list, "FL") == 0)
    {
        /* Add buddy to our FL. */
        /* FunkTastic Foo! */
        FQYTransData *data;
        gchar *payload, *tmp;
        MsnTransaction *trans;
        data = g_new0 (FQYTransData, 1);
        tmp = strchr (who, '@') + 1;
        data->domain = g_strdup (tmp);
        data->name = g_strndup (who, tmp - who - 1);
        data->group_guid = group_guid ? g_strdup (group_guid) : NULL;

        payload = g_strdup_printf ("<ml><d n=\"%s\">"
                                   "<c n=\"%s\" /></d></ml>",
                                   data->domain,
                                   data->name);

        trans = msn_transaction_new (cmdproc, "FQY", "%zu", strlen (payload));
        msn_transaction_set_payload (trans, payload, strlen (payload));
        msn_transaction_set_data (trans, data);
        msn_cmdproc_send_trans (cmdproc, trans);
    }
}

void
msn_notification_rem_buddy(MsnNotification *notification, const char *list,
                           const char *who, const gchar *user_guid, const gchar *group_guid)
{
    MsnCmdProc *cmdproc;

    cmdproc = notification->cmdproc;

    /* moogman: If user is only in one group, set group_guid == NULL (force a complete remove).
     * It seems as if we don't need to do the above check. I've tested it as it is and it seems 
     * to work fine. However, a note is left here incase things change. */
    if (group_guid)
    {
        pn_service_session_request  (cmdproc->session->service_session,
                                     PN_RM_CONTACT_GROUP, user_guid,
                                     group_guid, NULL);
    }
    else
    {
        pn_service_session_request  (cmdproc->session->service_session,
                                     PN_RM_CONTACT_AB, user_guid, NULL, NULL);
    }
}

/**************************************************************************
 * Init
 **************************************************************************/

void
msn_notification_init(void)
{
    /* TODO: check prp, blp */

    cbs_table = msn_table_new();

    /* Synchronous */
    msn_table_add_cmd(cbs_table, "CHG", "CHG", chg_cmd);
    /* msn_table_add_cmd(cbs_table, "CHG", "ILN", iln_cmd); */ /* Not supported in MSNP18 */
    /* msn_table_add_cmd(cbs_table, "ADC", "ILN", iln_cmd); */
    msn_table_add_cmd(cbs_table, "USR", "USR", usr_cmd);
    msn_table_add_cmd(cbs_table, "USR", "XFR", xfr_cmd);
    msn_table_add_cmd(cbs_table, "CVR", "CVR", cvr_cmd);
    msn_table_add_cmd(cbs_table, "VER", "VER", ver_cmd);
    /* msn_table_add_cmd(cbs_table, "REA", "REA", rea_cmd); */
    msn_table_add_cmd(cbs_table, "SBP", "SBP", sbp_cmd);
    msn_table_add_cmd(cbs_table, "PRP", "PRP", prp_cmd);
    /* msn_table_add_cmd(cbs_table, "BLP", "BLP", blp_cmd); */
    msn_table_add_cmd(cbs_table, "BLP", "BLP", NULL);
    msn_table_add_cmd(cbs_table, "XFR", "XFR", xfr_cmd);
    msn_table_add_cmd(cbs_table, "ADL", "ADL", adl_cmd);

    /* Asynchronous */
    msn_table_add_cmd(cbs_table, NULL, "IPG", ipg_cmd);
    msn_table_add_cmd(cbs_table, NULL, "MSG", msg_cmd);
    msn_table_add_cmd(cbs_table, NULL, "UBM", ubm_cmd);
    msn_table_add_cmd(cbs_table, NULL, "NOT", not_cmd);

    msn_table_add_cmd(cbs_table, NULL, "ADL", adl_cmd);
    msn_table_add_cmd(cbs_table, NULL, "FQY", fqy_cmd);
    msn_table_add_cmd(cbs_table, NULL, "CHL", chl_cmd);
    msn_table_add_cmd(cbs_table, NULL, "RML", NULL);
    msn_table_add_cmd(cbs_table, NULL, "QRY", NULL);
    msn_table_add_cmd(cbs_table, NULL, "QNG", qng_cmd);
    msn_table_add_cmd(cbs_table, NULL, "FLN", fln_cmd);
    msn_table_add_cmd(cbs_table, NULL, "NLN", nln_cmd);
    /* msn_table_add_cmd(cbs_table, NULL, "ILN", iln_cmd); */
    msn_table_add_cmd(cbs_table, NULL, "OUT", out_cmd);
    msn_table_add_cmd(cbs_table, NULL, "RNG", rng_cmd);
    msn_table_add_cmd(cbs_table, NULL, "GCF", gcf_cmd);

    msn_table_add_cmd(cbs_table, NULL, "UBX", ubx_cmd);

    msn_table_add_cmd(cbs_table, NULL, "URL", url_cmd);

    /* avoid unhandled command warnings */
    msn_table_add_cmd(cbs_table, NULL, "UUX", NULL);
    msn_table_add_cmd(cbs_table, NULL, "SBS", NULL);

    msn_table_add_cmd(cbs_table, "fallback", "XFR", xfr_cmd);

    /* msn_table_add_error(cbs_table, "REA", rea_error); */
    msn_table_add_error(cbs_table, "USR", usr_error);
    msn_table_add_error(cbs_table, "FQY", fqy_error);
    msn_table_add_error(cbs_table, "UUM", uum_error);

    msn_table_add_msg_type(cbs_table,
                           "text/plain",
                           plain_msg);
    msn_table_add_msg_type(cbs_table,
                           "text/x-msmsgsprofile",
                           profile_msg);
    msn_table_add_msg_type(cbs_table,
                           "text/x-msmsgsinitialmdatanotification",
                           initial_mdata_msg);
    msn_table_add_msg_type(cbs_table,
                           "text/x-msmsgsoimnotification",
                           oim_msg);
    msn_table_add_msg_type(cbs_table,
                           "text/x-msmsgsemailnotification",
                           email_msg);
    msn_table_add_msg_type(cbs_table,
                           "application/x-msmsgssystemmessage",
                           system_msg);
    msn_table_add_msg_type(cbs_table,
                           "application/x-msmsgsinitialmdatanotification",
                           NULL);
}

void
msn_notification_end(void)
{
    msn_table_destroy(cbs_table);
}
