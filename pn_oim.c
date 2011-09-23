/**
 * Copyright (C) 2008-2009 Felipe Contreras
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

#include <time.h>

#include "pn_oim.h"
#include "pn_auth.h"
#include "io/pn_ssl_conn.h"
#include "io/pn_parser.h"

#include "pn_util.h"
#include "pn_locale.h"
#include "pn_auth_priv.h"
#include "ab/pn_contact_priv.h"

#include "io/pn_node_private.h"
#include "session_private.h"
#include <string.h> /* for strlen */
#include <stdlib.h> /* for atoi */

#include "pn_log.h"

#ifdef HAVE_LIBPURPLE
#include <util.h> /* for base64_dec */
#include <conversation.h> /* for conversation_new */
#endif /* HAVE_LIBPURPLE */

struct PecanOimSession
{
    MsnSession *session;
    GQueue *request_queue; /* TODO maybe this is not needed any more */
};

typedef struct OimRequest OimRequest;

struct OimRequest
{
    PecanOimSession *oim_session;
    gchar *passport;
    PnParser *parser;
    guint parser_state;
    gsize content_size;
    OimRequestType type;

    /* receiving/deleting stuff */
    gchar *message_id;

    gulong open_sig_handler;
    PnNode *conn;
};

static inline OimRequest *
oim_request_new (PecanOimSession *oim_session,
                 const gchar *passport,
                 const gchar *message_id,
                 OimRequestType type)
{
    OimRequest *oim_request;

    oim_request = g_new0 (OimRequest, 1);
    oim_request->oim_session = oim_session;
    oim_request->passport = g_strdup (passport);
    oim_request->message_id = g_strdup (message_id);
    oim_request->type = type;

    return oim_request;
}

static inline void
oim_request_free (OimRequest *oim_request)
{
    if (oim_request->open_sig_handler)
        g_signal_handler_disconnect (oim_request->conn, oim_request->open_sig_handler);

    pn_node_free (oim_request->conn);
    pn_parser_free (oim_request->parser);
    g_free (oim_request->passport);
    g_free (oim_request->message_id);
    g_free (oim_request);
}

PecanOimSession *
pn_oim_session_new (MsnSession *session)
{
    PecanOimSession *oim_session;

    oim_session = g_new0 (PecanOimSession, 1);
    oim_session->session = session;
    oim_session->request_queue = g_queue_new ();

    return oim_session;
}

void
pn_oim_session_free (PecanOimSession *oim_session)
{
    if (!oim_session)
        return;

    {
        OimRequest *oim_request;
        while ((oim_request = g_queue_pop_head (oim_session->request_queue)))
        {
            oim_request_free (oim_request);
        }
    }
    g_queue_free (oim_session->request_queue);

    g_free (oim_session);
}

static inline void
send_receive_request (PnNode *conn,
                      OimRequest *oim_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = oim_request->oim_session->session->auth;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                            "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                            "<soap:Header>"
                            "<PassportCookie xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
                            "<t>%s</t>"
                            "<p>%s</p>"
                            "</PassportCookie>"
                            "</soap:Header>"
                            "<soap:Body>"
                            "<GetMessage xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
                            "<messageId>%s</messageId>"
                            "<alsoMarkAsRead>%s</alsoMarkAsRead>"
                            "</GetMessage>"
                            "</soap:Body>"
                            "</soap:Envelope>",
                            auth->security_token.messenger_msn_com_t,
                            auth->security_token.messenger_msn_com_p,
                            oim_request->message_id,
                            "false");

    body_len = strlen (body);

    header = g_strdup_printf ("POST /rsi/rsi.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.hotmail.msn.com/ws/2004/09/oim/rsi/GetMessage\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: %s\r\n"
                              "Connection: Keep-Alive\r\n"
                              "Cache-Control: no-cache\r\n"
                              /* "Cookie: MSPAuth=%s\r\n" */
                              "\r\n%s",
                              body_len,
                              "rsi.hotmail.com",
                              /* session->passport_info.mspauth, */
                              body);

    g_free (body);

    pn_debug ("header=[%s]", header);
    /* pn_debug ("body=[%s]", body); */

    {
        gsize len;
        pn_node_write (conn, header, strlen (header), &len, NULL);
        pn_debug ("write_len=%zu", len);
    }

    g_free (header);

    pn_log ("end");
}

static inline void
send_delete_request (PnNode *conn,
                     OimRequest *oim_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = oim_request->oim_session->session->auth;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                            "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                            "<soap:Header>"
                            "<PassportCookie xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
                            "<t>%s</t>"
                            "<p>%s</p>"
                            "</PassportCookie>"
                            "</soap:Header>"
                            "<soap:Body>"
                            "<DeleteMessages xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
                            "<messageIds>"
                            "<messageId>%s</messageId>"
                            "</messageIds>"
                            "</DeleteMessages>"
                            "</soap:Body>"
                            "</soap:Envelope>",
                            auth->security_token.messenger_msn_com_t,
                            auth->security_token.messenger_msn_com_p,
                            oim_request->message_id);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /rsi/rsi.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.hotmail.msn.com/ws/2004/09/oim/rsi/DeleteMessages\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: %s\r\n"
                              "Connection: Keep-Alive\r\n"
                              "Cache-Control: no-cache\r\n"
                              "\r\n%s",
                              body_len,
                              "rsi.hotmail.com",
                              body);

    g_free (body);

    pn_debug ("header=[%s]", header);
    /* pn_debug ("body=[%s]", body); */

    {
        gsize len;
        pn_node_write (conn, header, strlen (header), &len, NULL);
        pn_debug ("write_len=%zu", len);
    }

    g_free (header);

    pn_log ("end");
}

static void
open_cb (PnNode *conn,
         OimRequest *oim_request)
{
    g_return_if_fail (conn);

    pn_log ("begin");

    g_signal_handler_disconnect (conn, oim_request->open_sig_handler);
    oim_request->open_sig_handler = 0;

    if (oim_request->type == PN_RECEIVE_OIM)
        send_receive_request (conn, oim_request);
    else if (oim_request->type == PN_DELETE_OIM)
        send_delete_request (conn, oim_request);

    pn_log ("end");
}

static inline void oim_process_requests (PecanOimSession *oim_session);

static inline void
next_request (PecanOimSession *oim_session)
{
    OimRequest *oim_request;

    oim_request = g_queue_pop_head (oim_session->request_queue);

    if (oim_request)
    {
        if (oim_request->type == PN_RECEIVE_OIM)
        {
            g_queue_push_tail (oim_session->request_queue,
                               oim_request_new (oim_session, oim_request->passport,
                               oim_request->message_id, PN_DELETE_OIM));
        }

        oim_request_free (oim_request);
    }

    oim_process_requests (oim_session);
}

static char *strstr_fwd(const char *haystack, const char *needle)
{
    char *t = strstr(haystack, needle);
    if (t)
        t += strlen(needle);
    return t;
}

static void
process_body_receive (OimRequest *oim_request,
                      char *body,
                      gsize length)
{
    gchar *message = NULL;
    gchar *cur;
    time_t date = 0;

    pn_debug("body=[%.*s]", (int) length, body);

    cur = strstr(body, "Date: ");
    if (cur) {
        gchar *end;
        cur = strchr (cur, ' ') + 1;
        end = strchr (cur, '\n');
        cur = g_strndup (cur, end - cur);
        date = pn_parse_date(cur);
        g_free (cur);
    }

    cur = strstr_fwd (body, "\r\n\r\n");
    if (!cur)
        cur = strstr_fwd (body, "\n\n");
    if (cur) {
        gchar *end;
        end = strstr (cur, "\r\n\r\n");
        if (!end)
            end = strstr (cur, "\n\n");
        if (!end)
            end = strstr (cur, "</GetMessageResult>");
        if (end)
            *end = '\0';
        message = (gchar *) purple_base64_decode (cur, NULL);
    }

    if (message)
    {
        PurpleConversation *conv;
        pn_debug ("oim: passport=[%s],msg=[%s]", oim_request->passport, message);
        conv = purple_conversation_new (PURPLE_CONV_TYPE_IM,
                                        msn_session_get_user_data (oim_request->oim_session->session),
                                        oim_request->passport);

        purple_conversation_write (conv, NULL, message,
                                   PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_DELAYED, date);

        g_free (message);
    }
}

static void
process_body_delete (OimRequest *oim_request,
                     char *body,
                     gsize length)
{
    pn_debug("body=[%.*s]", (int) length, body);

    if (strstr (body, "Schema validation error"))
        pn_error ("deleting oim=[%s]: schema validation error", oim_request->message_id);
}

static inline void
handle_failure (OimRequest *oim_request)
{
    struct pn_contact *contact;
    contact = pn_contactlist_find_contact (oim_request->oim_session->session->contactlist,
                                           oim_request->passport);
    contact->sent_oims--;
}

static void
read_cb (PnNode *conn,
         gpointer data)
{
    OimRequest *oim_request;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *str = NULL;

    oim_request = data;

    while (oim_request->parser_state == 0)
    {
        gsize terminator_pos;

        status = pn_parser_read_line (oim_request->parser, &str, NULL, &terminator_pos, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (str)
        {
            str[terminator_pos] = '\0';

            if (strncmp (str, "Content-Length: ", 16) == 0)
                oim_request->content_size = atoi(str + 16);

            /* now comes the content */
            if (str[0] == '\0') {
                oim_request->parser_state++;
                break;
            }

            g_free (str);
        }
    }

    if (oim_request->parser_state == 1)
    {
        gchar *body;

        status = pn_parser_read (oim_request->parser, &body, oim_request->content_size, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (oim_request->type == PN_RECEIVE_OIM)
            process_body_receive (oim_request, body, oim_request->content_size);
        else if (oim_request->type == PN_DELETE_OIM)
            process_body_delete (oim_request, body, oim_request->content_size);

        g_free(body);
    }

leave:
    pn_node_close (conn);
    next_request (oim_request->oim_session);
}

static void auth_cb (PnAuth *auth, void *data)
{
    PnSslConn *ssl_conn;
    PnNode *conn;
    OimRequest *oim_request = data;

    ssl_conn = pn_ssl_conn_new ("oim", PN_NODE_NULL);

    conn = PN_NODE (ssl_conn);
    conn->session = oim_request->oim_session->session;

    oim_request->parser = pn_parser_new (conn);
    pn_ssl_conn_set_read_cb (ssl_conn, read_cb, oim_request);

    pn_node_connect (conn, "rsi.hotmail.com", 443);

    oim_request->conn = conn;
    oim_request->open_sig_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), oim_request);
}

static inline void
oim_process_requests (PecanOimSession *oim_session)
{
    OimRequest *oim_request;

    oim_request = g_queue_peek_head (oim_session->request_queue);

    if (!oim_request)
        return;

    pn_auth_get_ticket (oim_session->session->auth, 4, auth_cb, oim_request);
}

void
pn_oim_session_request (PecanOimSession *oim_session,
                        const gchar *passport,
                        const gchar *message_id,
                        OimRequestType type)
{
    gboolean initial;

    initial = g_queue_is_empty (oim_session->request_queue);

    g_queue_push_tail (oim_session->request_queue,
                       oim_request_new (oim_session, passport, message_id, type));

    if (initial)
    {
        oim_process_requests (oim_session);
    }
}
