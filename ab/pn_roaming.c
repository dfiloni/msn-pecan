/**
 * Copyright (C) 2008-2009 Felipe Contreras
 * Copyright (C) 2011 Devid Antonio Filoni
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

#include "pn_roaming.h"
#include "pn_auth.h"
#include "io/pn_ssl_conn.h"
#include "io/pn_parser.h"

#include "cmd/cmdproc.h"

#include "pn_auth_priv.h"

#include "io/pn_node_private.h"
#include "session_private.h"
#include <string.h> /* for strlen */
#include <stdlib.h> /* for atoi */

#include <account.h>

#include "pn_log.h"

struct PecanRoamingSession
{
    MsnSession *session;
    GQueue *request_queue;

    gchar *cachekey;
    gchar *resource_id;
};

typedef struct RoamingRequest RoamingRequest;

struct RoamingRequest
{
    PecanRoamingSession *roaming_session;
    PnParser *parser;
    guint parser_state;
    gsize content_size;
    RoamingRequestType type;

    gchar *value;
    gchar *extra_value;

    gulong open_sig_handler;
    PnNode *conn;
};

static inline RoamingRequest *
roaming_request_new (PecanRoamingSession *roaming_session,
                     RoamingRequestType type,
                     const gchar *value,
                     const gchar *extra_value)
{
    RoamingRequest *roaming_request;

    roaming_request = g_new0 (RoamingRequest, 1);
    roaming_request->roaming_session = roaming_session;
    if (value)
        roaming_request->value = g_strdup (value);
    if (extra_value)
        roaming_request->extra_value = g_strdup (extra_value);
    roaming_request->type = type;

    return roaming_request;
}

static inline void
roaming_request_free (RoamingRequest *roaming_request)
{
    if (roaming_request->open_sig_handler)
        g_signal_handler_disconnect (roaming_request->conn, roaming_request->open_sig_handler);

    pn_node_free (roaming_request->conn);
    pn_parser_free (roaming_request->parser);

    g_free (roaming_request->value);
    g_free (roaming_request->extra_value);

    g_free (roaming_request);
}

PecanRoamingSession *
pn_roaming_session_new (MsnSession *session)
{
    PecanRoamingSession *roaming_session;

    roaming_session = g_new0 (PecanRoamingSession, 1);
    roaming_session->session = session;
    roaming_session->request_queue = g_queue_new ();

    return roaming_session;
}

void
pn_roaming_session_free (PecanRoamingSession *roaming_session)
{
    if (!roaming_session)
        return;

    {
        RoamingRequest *roaming_request;
        while ((roaming_request = g_queue_pop_head (roaming_session->request_queue)))
        {
            roaming_request_free (roaming_request);
        }
    }
    g_queue_free (roaming_session->request_queue);

    g_free (roaming_session->cachekey);
    g_free (roaming_session->resource_id);

    g_free (roaming_session);
}

static inline void
send_get_profile_request (PnNode *conn,
                              RoamingRequest *roaming_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = roaming_request->roaming_session->session->auth;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n"
                            "<soap:Header>\r\n"
                            "<StorageApplicationHeader xmlns=\"http://www.msn.com/webservices/storage/w10\">\r\n"
                            "<ApplicationID>Messenger Client 8.5</ApplicationID>\r\n"
                            "<Scenario>RoamingSeed</Scenario>\r\n"
                            "</StorageApplicationHeader>\r\n"
                            "<StorageUserHeader xmlns=\"http://www.msn.com/webservices/storage/w10\"><Puid>0</Puid>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</StorageUserHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<GetProfile xmlns=\"http://www.msn.com/webservices/storage/w10\">\r\n"
                            "<profileHandle>\r\n"
                            "<Alias>\r\n"
                            "<Name>%s</Name>\r\n"
                            "<NameSpace>MyCidStuff</NameSpace>\r\n"
                            "</Alias>\r\n"
                            "<RelationshipName>MyProfile</RelationshipName>\r\n"
                            "</profileHandle>\r\n"
                            "<profileAttributes>\r\n"
                            "<ResourceID>true</ResourceID>\r\n"
                            "<DateModified>true</DateModified>\r\n"
                            "<ExpressionProfileAttributes>\r\n"
                            "<ResourceID>true</ResourceID>\r\n"
                            "<DateModified>true</DateModified>\r\n"
                            "<DisplayName>true</DisplayName>\r\n"
                            "<DisplayNameLastModified>true</DisplayNameLastModified>\r\n"
                            "<PersonalStatus>true</PersonalStatus>\r\n"
                            "<PersonalStatusLastModified>true</PersonalStatusLastModified>\r\n"
                            "<StaticUserTilePublicURL>true</StaticUserTilePublicURL>\r\n"
                            "<Photo>true</Photo>\r\n"
                            "<Flags>true</Flags>\r\n"
                            "</ExpressionProfileAttributes>\r\n"
                            "</profileAttributes>\r\n"
                            "</GetProfile>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            auth->security_token.storage_msn_com,
                            roaming_request->roaming_session->session->cid);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /storageservice/SchematizedStore.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/storage/w10/GetProfile\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: storage.msn.com\r\n"
                              "Connection: Keep-Alive\r\n"
                              "Cache-Control: no-cache\r\n"
                              "\r\n%s",
                              body_len,
                              body);

    g_free (body);

    pn_debug ("header=[%s]", header);

    {
        gsize len;
        pn_node_write (conn, header, strlen (header), &len, NULL);
        pn_debug ("write_len=%zu", len);
    }

    g_free (header);

    pn_log ("end");
}

static inline void
send_update_profile_request (PnNode *conn,
                             RoamingRequest *roaming_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = roaming_request->roaming_session->session->auth;
    gchar *friendly = roaming_request->value;
    gchar *psm = roaming_request->extra_value;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<AffinityCacheHeader xmlns=\"http://www.msn.com/webservices/storage/w10\">\r\n"
                            "<CacheKey>%s</CacheKey>\r\n"
                            "</AffinityCacheHeader>\r\n"
                            "<StorageApplicationHeader xmlns=\"http://www.msn.com/webservices/storage/w10\">\r\n"
                            "<ApplicationID>Messenger Client 8.5</ApplicationID>\r\n"
                            "<Scenario>RoamingIdentityChanged</Scenario>\r\n"
                            "</StorageApplicationHeader>\r\n"
                            "<StorageUserHeader xmlns=\"http://www.msn.com/webservices/storage/w10\">\r\n"
                            "<Puid>0</Puid>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</StorageUserHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<UpdateProfile xmlns=\"http://www.msn.com/webservices/storage/w10\">\r\n"
                            "<profile>\r\n"
                            "<ResourceID>%s</ResourceID>\r\n"
                            "<ExpressionProfile>\r\n"
                            "<FreeText>Update</FreeText>\r\n"
                            "%s%s%s\r\n"
                            "%s%s%s"
                            "<Flags>0</Flags>\r\n"
                            "</ExpressionProfile>\r\n"
                            "</profile>\r\n"
                            "</UpdateProfile>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            roaming_request->roaming_session->cachekey,
                            auth->security_token.storage_msn_com,
                            roaming_request->roaming_session->resource_id,
                            friendly ? "<DisplayName>" : "",
                            friendly ? friendly : "",
                            friendly ? "</DisplayName>\r\n" : "",
                            psm ? "<PersonalStatus>" : "",
                            psm ? psm : "",
                            psm ? "</PersonalStatus>\r\n" : "");

    body_len = strlen (body);

    header = g_strdup_printf ("POST /storageservice/SchematizedStore.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/storage/w10/UpdateProfile\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: storage.msn.com\r\n"
                              "Connection: Keep-Alive\r\n"
                              "Cache-Control: no-cache\r\n"
                              "\r\n%s",
                              body_len,
                              body);

    g_free (body);

    pn_debug ("header=[%s]", header);

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
         RoamingRequest *roaming_request)
{
    g_return_if_fail (conn);

    pn_log ("begin");

    g_signal_handler_disconnect (conn, roaming_request->open_sig_handler);
    roaming_request->open_sig_handler = 0;

    if (roaming_request->type == PN_GET_PROFILE)
        send_get_profile_request (conn, roaming_request);
    else if (roaming_request->type == PN_UPDATE_PROFILE)
        send_update_profile_request (conn, roaming_request);

    pn_log ("end");
}

static inline void roaming_process_requests (PecanRoamingSession *roaming_session);

static inline void
next_request (PecanRoamingSession *roaming_session)
{
    RoamingRequest *roaming_request;

    roaming_request = g_queue_pop_head (roaming_session->request_queue);
    roaming_request_free (roaming_request);

    roaming_process_requests (roaming_session);
}
static void
process_get_profile (RoamingRequest *roaming_request,
                     char *body)
{
    gchar *cur, *end, *value;

    cur = strstr (body, "<ResourceID>");
    if (cur)
    {

        cur = strchr (cur, '>') + 1;
        end = strstr (cur, "</ResourceID>");
        roaming_request->roaming_session->resource_id = g_strndup (cur, end - cur);
    }

    cur = strstr (body, "<DisplayName>");
    if (cur)
    {

        cur = strchr (cur, '>') + 1;
        end = strstr (cur, "</DisplayName>");
        value = g_strndup (cur, end - cur);

        if (value)
        {
            msn_session_set_prp (roaming_request->roaming_session->session,
                                 "MFN", value);

            g_free (value);
        }
    }

#ifndef PECAN_USE_PSM
    cur = strstr (body, "<PersonalStatus>");
    if (cur)
    {
        PurpleAccount *account;
        account = msn_session_get_user_data (roaming_request->roaming_session->session);

        cur = strchr (cur, '>') + 1;
        end = strstr (cur, "</PersonalStatus>");
        value = g_strndup (cur, end - cur);

        if (value)
        {
            purple_account_set_string(account, "personal_message", value);

            g_free (value);
        }
    }
#endif /* PECAN_USE_PSM */
}

static void
read_cb (PnNode *conn,
         gpointer data)
{
    RoamingRequest *roaming_request;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *str = NULL;

    roaming_request = data;

    while (roaming_request->parser_state == 0)
    {
        gsize terminator_pos;

        status = pn_parser_read_line (roaming_request->parser, &str, NULL, &terminator_pos, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (str)
        {
            str[terminator_pos] = '\0';

            if (strncmp (str, "Content-Length: ", 16) == 0)
                roaming_request->content_size = atoi(str + 16);

            /* now comes the content */
            if (str[0] == '\0') {
                roaming_request->parser_state++;
                break;
            }

            g_free (str);
        }
    }

    if (roaming_request->parser_state == 1)
    {
        gchar *body;

        status = pn_parser_read (roaming_request->parser, &body, roaming_request->content_size, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        pn_debug ("%s", body);

        if (roaming_request->type == PN_GET_PROFILE)
        {
            gchar *cur, *end;
            cur = strstr (body, "<CacheKey>");
            if (cur)
            {
                cur = strchr (cur, '>') + 1;
                end = strstr (cur, "</CacheKey>");

                if (roaming_request->roaming_session->cachekey)
                    g_free (roaming_request->roaming_session->cachekey);
                roaming_request->roaming_session->cachekey = g_strndup (cur, end - cur);
            }
        }

        if (roaming_request->type == PN_GET_PROFILE)
            process_get_profile (roaming_request, body);
        /* else if (roaming_request->type == PN_UPDATE_PROFILE) */

        g_free(body);
    }

leave:
    pn_node_close (conn);
    next_request (roaming_request->roaming_session);
}

static void auth_cb (PnAuth *auth, void *data)
{
    PnSslConn *ssl_conn;
    PnNode *conn;
    RoamingRequest *roaming_request = data;

    ssl_conn = pn_ssl_conn_new ("ab_roaming", PN_NODE_NULL);

    conn = PN_NODE (ssl_conn);
    conn->session = roaming_request->roaming_session->session;

    roaming_request->parser = pn_parser_new (conn);
    pn_ssl_conn_set_read_cb (ssl_conn, read_cb, roaming_request);

    pn_node_connect (conn, "storage.msn.com", 443);

    roaming_request->conn = conn;
    roaming_request->open_sig_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), roaming_request);
}

static inline void
roaming_process_requests (PecanRoamingSession *roaming_session)
{
    RoamingRequest *roaming_request;

    roaming_request = g_queue_peek_head (roaming_session->request_queue);

    if (!roaming_request)
        return;

    pn_auth_get_ticket (roaming_session->session->auth, 3, auth_cb, roaming_request);
}

void
pn_roaming_session_request (PecanRoamingSession *roaming_session,
                            RoamingRequestType type,
                            const gchar *value,
                            const gchar *extra_value)
{
    gboolean initial;

    initial = g_queue_is_empty (roaming_session->request_queue);

    g_queue_push_tail (roaming_session->request_queue,
                       roaming_request_new (roaming_session, type,
                                            value, extra_value));

    if (initial)
    {
        roaming_process_requests (roaming_session);
    }
}
