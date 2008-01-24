/*
 * Copyright (C) 2006-2008 Felipe Contreras.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "conn_end_http.h"
#include "msn_log.h"
#include "msn_io.h"

/*
 * Documentation for the HTTP connection method is available at:
 * http://www.hypothetic.org/docs/msn/general/http_connections.php
 *
 * Basically one http connection can be used to communicate with different
 * servers (NS, SB). Only one request can be sent at a time.
 */

/* For read/write. */
#include <unistd.h>

static ConnEndObjectClass *parent_class = NULL;

typedef struct
{
    ConnEndHttpObject *conn_end_http;
    gchar *body;
    gsize body_len;
} HttpQueueData;

static void
process_queue (ConnEndHttpObject *conn_end_http,
               GError **error)
{
    conn_end_http->waiting_response = FALSE;

    {
        HttpQueueData *queue_data;

        queue_data = g_queue_pop_head (conn_end_http->write_queue);

        if (queue_data)
        {
            conn_end_object_write (CONN_END_OBJECT (queue_data->conn_end_http),
                                   queue_data->body,
                                   queue_data->body_len,
                                   NULL,
                                   error);

            g_free (queue_data->body);
            g_free (queue_data);
        }
    }
}

/* ConnEndHttpObject. */

ConnEndHttpObject *
conn_end_http_object_new (void)
{
    ConnEndHttpObject *conn_end_http;
    conn_end_http = CONN_END_HTTP_OBJECT (g_type_create_instance (CONN_END_HTTP_OBJECT_TYPE));
    return conn_end_http;
}

void
conn_end_http_object_free (ConnEndHttpObject *conn_end_http)
{
    g_return_if_fail (conn_end_http != NULL);
    g_object_unref (G_OBJECT (conn_end_http));
}

/* ConnEndHttpObject implementation. */

static gboolean
http_poll (gpointer data)
{
    ConnEndHttpObject *conn_end_http;
    ConnEndObject *conn_end;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_written = 0;

    gchar *header;
    gchar *params;
    gchar *auth = NULL;

    g_return_val_if_fail (data != NULL, FALSE);

    conn_end = data;
    conn_end_http = data;

    msn_debug ("channel=%p", conn_end->channel);

    g_return_val_if_fail (conn_end_http->session_id != NULL, FALSE);

    if (conn_end_http->waiting_response)
    {
        /* There's no need to poll if we're already waiting for a response */
        return TRUE;
    }

    params = g_strdup_printf ("Action=poll&SessionID=%s",
                              conn_end_http->session_id);

    header = g_strdup_printf ("POST http://%s/gateway/gateway.dll?%s HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "Accept-Language: en-us\r\n"
                              "User-Agent: MSMSGS\r\n"
                              "Host: %s\r\n"
                              "Proxy-Connection: Keep-Alive\r\n"
                              "%s" /* Proxy auth */
                              "Connection: Keep-Alive\r\n"
                              "Pragma: no-cache\r\n"
                              "Content-Type: application/x-msn-messenger\r\n"
                              "Content-Length: 0\r\n\r\n",
                              conn_end_http->hostname,
                              params,
                              conn_end_http->hostname,
                              auth ? auth : "");

#ifdef MSN_DEBUG_HTTP
    msn_debug ("header=[%s]", header);
#endif

    g_free (params);

    status = msn_io_write_full (conn_end->channel, header, strlen (header), &bytes_written, &tmp_error);

    g_io_channel_flush (conn_end->channel, &tmp_error);

    g_free (header);

    if (status == G_IO_STATUS_NORMAL);
    {
        msn_log ("bytes_written=%d", bytes_written);
        conn_end_http->waiting_response = TRUE;
    }

    return TRUE;
}

static void
connect_cb (gpointer data,
            gint source,
            const gchar *error_message)
{
    ConnEndObject *conn_end;
    ConnEndHttpObject *conn_end_http;

    msn_log ("begin");

    conn_end = data;
    conn_end->connect_data = NULL;
    conn_end_http = data;

    if (source >= 0)
    {
        GIOChannel *channel;

        conn_end->channel = channel = g_io_channel_unix_new (source);

        g_io_channel_set_line_term (channel, "\r\n", 2);

        conn_end_http->timeout_id = g_timeout_add (2 * 1000, http_poll, conn_end);
    }

    {
        ConnEndObjectClass *class;
        class = g_type_class_peek (CONN_END_OBJECT_TYPE);
        g_signal_emit (G_OBJECT (conn_end), class->open_sig, 0, conn_end);
    }

    msn_log ("end");
}

static void
connect_impl (ConnEndObject *conn_end)
{
    ConnEndHttpObject *conn_end_http;
    g_return_if_fail (conn_end->foo_data != NULL);

    conn_end_http = CONN_END_HTTP_OBJECT (conn_end);

    msn_info ("foo");

    if (!conn_end->channel)
    {
        conn_end->connect_data = purple_proxy_connect (NULL, ((MsnSession *) (conn_end->foo_data))->account,
                                                       conn_end_http->hostname, 80, connect_cb, conn_end);
        return;
    }
}

static void
close_impl (ConnEndObject *conn_end)
{
    ConnEndHttpObject *conn_end_http;

    conn_end_http = CONN_END_HTTP_OBJECT (conn_end);

    if (!conn_end->channel)
    {
        msn_warning ("not connected: conn_end=%p", conn_end);
        return;
    }

    if (conn_end->connect_data)
    {
        purple_proxy_connect_cancel (conn_end->connect_data);
        conn_end->connect_data = NULL;
    }

    if (conn_end_http->timeout_id)
    {
        g_source_remove (conn_end_http->timeout_id);
        conn_end_http->timeout_id = 0;
    }

    msn_info ("channel shutdown: %p", conn_end->channel);
    g_io_channel_shutdown (conn_end->channel, FALSE, NULL);
    g_io_channel_unref (conn_end->channel);
    conn_end->channel = NULL;

    g_free (conn_end->hostname);
    conn_end->hostname = NULL;

    g_free (conn_end_http->session_id);
    conn_end_http->session_id = NULL;

    conn_end_http->parser_state = 0;
    conn_end_http->waiting_response = FALSE;

    {
        HttpQueueData *http_data;
        while ((http_data = g_queue_pop_head (conn_end_http->write_queue)))
        {
            g_free (http_data->body);
            g_free (http_data);
        }
    }
}

static GIOStatus
read_impl (ConnEndObject *conn_end,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **error)
{
    ConnEndHttpObject *conn_end_http;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_read = 0;

    msn_debug ("channel=%p", conn_end->channel);

    conn_end_http = CONN_END_HTTP_OBJECT (conn_end);

    {
        gchar *str = NULL;
        gchar **tokens = NULL;

        if (conn_end_http->parser_state == 0)
        {
            gint code;

            {
                gsize terminator_pos;
                status = g_io_channel_read_line (conn_end->channel,
                                                 &str, NULL, &terminator_pos, &tmp_error);
                if (str)
                    str[terminator_pos] = '\0';
            }

            if (tmp_error)
            {
                msn_debug ("error reading: %s", tmp_error->message);
                goto leave;
            }

            if (status == G_IO_STATUS_AGAIN)
                return status;

#ifdef MSN_DEBUG_HTTP
            msn_debug ("str=[%s]", str);
#endif

            tokens = g_strsplit (str, " ", 3);

            if (!(tokens[0] && (strcmp (tokens[0], "HTTP/1.1") == 0)))
            {
                msn_debug ("error reading: parse error");
                tmp_error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                                 "Parse error");
                goto leave;
            }

            if (!(tokens[1]))
            {
                msn_debug ("error reading: parse error");
                tmp_error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                                 "Parse error");
                goto leave;
            }

            code = atoi (tokens[1]);

            if (code != 200 && code != 100)
            {
                msn_debug ("error reading: %d %s", code, tokens[2]);
                tmp_error = g_error_new (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                         "%s",  tokens[2]);
                goto leave;
            }

            g_strfreev (tokens);
            tokens = NULL;
            g_free (str);
            str = NULL;

            conn_end_http->parser_state++;
        }

        if (conn_end_http->parser_state == 1)
        {
            while (TRUE)
            {
                {
                    gsize terminator_pos;
                    status = g_io_channel_read_line (conn_end->channel,
                                                     &str, NULL, &terminator_pos, &tmp_error);
                    if (str)
                        str[terminator_pos] = '\0';
                }

                if (tmp_error)
                {
                    msn_debug ("error reading: %s", tmp_error->message);
                    goto leave;
                }

                if (status == G_IO_STATUS_AGAIN)
                    return status;

                if (str[0] == '\0')
                    break;

#ifdef MSN_DEBUG_HTTP
                msn_debug ("str=[%s]", str);
#endif

                tokens = g_strsplit (str, ": ", 2);

                if (!(tokens[0] && tokens[1]))
                {
                    msn_debug ("error reading: parse error");
                    tmp_error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                                     "Parse error");
                    goto leave;
                }

                if (strcmp (tokens[0], "Content-Length") == 0)
                {
                    conn_end_http->content_length = atoi (tokens[1]);
                }
                else if (strcmp (tokens[0], "X-MSN-Messenger") == 0)
                {
                    gchar **tokens_b;
                    gint i;

                    tokens_b = g_strsplit (tokens[1], "; ", -1);

                    for (i = 0; tokens_b[i]; i++)
                    {
                        char **tokens_c;

                        tokens_c = g_strsplit (tokens_b[i], "=", 2);

                        if (strcmp (tokens_c[0], "SessionID") == 0)
                        {
                            conn_end_http->session_id = g_strdup (tokens_c[1]);
                        }
                        else if (strcmp (tokens_c[0], "GW-IP") == 0)
                        {
                            g_free (conn_end_http->hostname);
                            conn_end_http->hostname = g_strdup (tokens_c[1]);
                        }
                        else if (strcmp (tokens_c[0], "Session") == 0)
                        {
                            if (strcmp (tokens_c[1], "close") == 0)
                            {
                                conn_end_object_close (conn_end);
                            }
                        }

                        g_strfreev (tokens_c);
                    }

                    g_strfreev (tokens_b);
                }

                g_strfreev (tokens);
                tokens = NULL;
                g_free (str);
                str = NULL;
            }

            conn_end_http->parser_state++;
        }

        if (conn_end_http->parser_state == 2)
        {
            status = msn_io_read (conn_end->channel, buf, MIN (conn_end_http->content_length, count), &bytes_read, &tmp_error);

            msn_log ("status=%d", status);
            msn_log ("bytes_read=%d", bytes_read);

            if (ret_bytes_read)
                *ret_bytes_read = bytes_read;

            conn_end_http->content_length -= bytes_read;

            msn_log ("con_len=%d,read=%d", conn_end_http->content_length, bytes_read);

            if (conn_end_http->content_length == 0)
                conn_end_http->parser_state = 0;
        }

leave:
        g_strfreev (tokens);
        g_free (str);
    }

    process_queue (conn_end_http, &tmp_error);

    if (tmp_error)
        g_propagate_error (error, tmp_error);

    return status;
}

static GIOStatus
write_impl (ConnEndObject *conn_end,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    ConnEndHttpObject *conn_end_http;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_written = 0;

    msn_debug ("channel=%p", conn_end->channel);

    conn_end_http = CONN_END_HTTP_OBJECT (conn_end);

    if (conn_end_http->waiting_response)
    {
        HttpQueueData *http_data;

        http_data = g_new0 (HttpQueueData, 1);

        http_data->conn_end_http = conn_end_http;
        http_data->body = g_memdup (buf, count);
        http_data->body_len = count;

        g_queue_push_tail (conn_end_http->write_queue, http_data);

        return status;
    }

    {
        gchar *params;
        gchar *header;
        gchar *auth = NULL;

        if (conn_end_http->session_id)
        {
            params = g_strdup_printf ("SessionID=%s",
                                      conn_end_http->session_id);
        }
        else
        {
            params = g_strdup_printf ("Action=open&Server=%s&IP=%s",
                                     (gchar *) conn_end->foo_data_2,
                                      conn_end->hostname);
        }

        header = g_strdup_printf ("POST http://%s/gateway/gateway.dll?%s HTTP/1.1\r\n"
                                  "Accept: */*\r\n"
                                  "Accept-Language: en-us\r\n"
                                  "User-Agent: MSMSGS\r\n"
                                  "Host: %s\r\n"
                                  "Proxy-Connection: Keep-Alive\r\n"
                                  "%s" /* Proxy auth */
                                  "Connection: Keep-Alive\r\n"
                                  "Pragma: no-cache\r\n"
                                  "Content-Type: application/x-msn-messenger\r\n"
                                  "Content-Length: %d\r\n\r\n",
                                  conn_end_http->hostname,
                                  params,
                                  conn_end_http->hostname,
                                  auth ? auth : "",
                                  count);

#ifdef MSN_DEBUG_HTTP
        msn_debug ("header=[%s]", header);
#endif

        g_free (params);

        status = msn_io_write_full (conn_end->channel, header, strlen (header), &bytes_written, &tmp_error);
    }

    status = msn_io_write_full (conn_end->channel, buf, count, &bytes_written, &tmp_error);

    g_io_channel_flush (conn_end->channel, &tmp_error);

    if (status == G_IO_STATUS_NORMAL);
    {
        msn_log ("bytes_written=%d", bytes_written);
        conn_end_http->waiting_response = TRUE;
    }

    if (ret_bytes_written)
        *ret_bytes_written = bytes_written;

    if (tmp_error)
        g_propagate_error (error, tmp_error);

    return status;
}

/* GObject stuff. */

static void
conn_end_http_object_dispose (GObject *obj)
{
    ConnEndHttpObject *conn_end_http = (ConnEndHttpObject *) obj;

    if (!conn_end_http->dispose_has_run)
    {
        conn_end_http->dispose_has_run = TRUE;
        conn_end_object_close (CONN_END_OBJECT (conn_end_http));

        g_free (conn_end_http->hostname);
        conn_end_http->hostname = NULL;

        g_queue_free (conn_end_http->write_queue);
        conn_end_http->write_queue = NULL;
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);
}

static void
conn_end_http_object_finalize (GObject *obj)
{
    /* Chain up to the parent class */
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

void
conn_end_http_object_class_init (gpointer g_class, gpointer class_data)
{
    ConnEndObjectClass *conn_end_class = CONN_END_OBJECT_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_end_class->connect = &connect_impl;
    conn_end_class->close = &close_impl;
    conn_end_class->read = &read_impl;
    conn_end_class->write = &write_impl;

    gobject_class->dispose = conn_end_http_object_dispose;
    gobject_class->finalize = conn_end_http_object_finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

void
conn_end_http_object_instance_init (GTypeInstance *instance, gpointer g_class)
{
    ConnEndHttpObject *conn_end_http = CONN_END_HTTP_OBJECT (instance);

    conn_end_http->dispose_has_run = FALSE;
    conn_end_http->hostname = g_strdup ("gateway.messenger.hotmail.com");
    conn_end_http->write_queue = g_queue_new ();
}

GType
conn_end_http_object_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        static const GTypeInfo type_info =
        {
            sizeof (ConnEndHttpObjectClass),
            NULL, /* base_init */
            NULL, /* base_finalize */
            conn_end_http_object_class_init, /* class_init */
            NULL, /* class_finalize */
            NULL, /* class_data */
            sizeof (ConnEndHttpObject),
            0, /* n_preallocs */
            conn_end_http_object_instance_init /* instance_init */
        };

        type = g_type_register_static (CONN_END_OBJECT_TYPE, "ConnEndHttpObjectType", &type_info, 0);
    }

    return type;
}
