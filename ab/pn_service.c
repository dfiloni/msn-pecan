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

#include "pn_service.h"
#include "pn_auth.h"
#include "pn_util.h"
#include "io/pn_ssl_conn.h"
#include "io/pn_parser.h"

#include "cmd/cmdproc.h"

#include "pn_auth_priv.h"
#include "ab/pn_contact_priv.h"

#include "io/pn_node_private.h"
#include "session_private.h"
#include <string.h> /* for strlen */
#include <stdlib.h> /* for atoi */

#include "pn_log.h"

#ifdef HAVE_LIBPURPLE
#include <account.h>
#endif /* HAVE_LIBPURPLE */

#include "pn_group.h"
#include "notification.h"

struct PecanServiceSession
{
    MsnSession *session;
    GQueue *request_queue;

    gchar *cachekey;
};

typedef struct ServiceRequest ServiceRequest;

struct ServiceRequest
{
    PecanServiceSession *service_session;
    PnParser *parser;
    guint parser_state;
    gsize content_size;
    ServiceRequestType type;

    gchar *value;
    gchar *extra_value;

    gpointer data;

    gulong open_sig_handler;
    PnNode *conn;
};

static inline ServiceRequest *
service_request_new (PecanServiceSession *service_session,
                     ServiceRequestType type,
                     const gchar *value,
                     const gchar *extra_value,
                     gpointer data)
{
    ServiceRequest *service_request;

    service_request = g_new0 (ServiceRequest, 1);
    service_request->service_session = service_session;
    if (value)
        service_request->value = g_strdup (value);
    if (extra_value)
        service_request->extra_value = g_strdup (extra_value);
    service_request->data = data;
    service_request->type = type;

    return service_request;
}

static inline void
service_request_free (ServiceRequest *service_request)
{
    if (service_request->open_sig_handler)
        g_signal_handler_disconnect (service_request->conn, service_request->open_sig_handler);

    pn_node_free (service_request->conn);
    pn_parser_free (service_request->parser);

    g_free (service_request->value);
    g_free (service_request->extra_value);

    g_free (service_request);
}

PecanServiceSession *
pn_service_session_new (MsnSession *session)
{
    PecanServiceSession *service_session;

    service_session = g_new0 (PecanServiceSession, 1);
    service_session->session = session;
    service_session->request_queue = g_queue_new ();

    return service_session;
}

void
pn_service_session_free (PecanServiceSession *service_session)
{
    if (!service_session)
        return;

    {
        ServiceRequest *service_request;
        while ((service_request = g_queue_pop_head (service_session->request_queue)))
        {
            service_request_free (service_request);
        }
    }
    g_queue_free (service_session->request_queue);

    g_free (service_session->cachekey);

    g_free (service_session);
}

static inline void
send_req_memberlists_request (PnNode *conn,
                              ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n"
                            "<soap:Header xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId xmlns=\"http://www.msn.com/webservices/AddressBook\">CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration xmlns=\"http://www.msn.com/webservices/AddressBook\">false</IsMigration>\r\n"
                            "<PartnerScenario xmlns=\"http://www.msn.com/webservices/AddressBook\">Initial</PartnerScenario>\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest xmlns=\"http://www.msn.com/webservices/AddressBook\">false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n"
                            "<FindMembership xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<serviceFilter xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<Types xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ServiceType xmlns=\"http://www.msn.com/webservices/AddressBook\">Messenger</ServiceType>\r\n"
                            "<ServiceType xmlns=\"http://www.msn.com/webservices/AddressBook\">Invitation</ServiceType>\r\n"
                            "<ServiceType xmlns=\"http://www.msn.com/webservices/AddressBook\">SocialNetwork</ServiceType>\r\n"
                            "<ServiceType xmlns=\"http://www.msn.com/webservices/AddressBook\">Space</ServiceType>\r\n"
                            "<ServiceType xmlns=\"http://www.msn.com/webservices/AddressBook\">Profile</ServiceType>\r\n"
                            "</Types>\r\n"
                            "</serviceFilter>\r\n"
                            "</FindMembership>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            auth->security_token.contacts_msn_com);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/SharingService.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/FindMembership\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
send_req_ab_request (PnNode *conn,
                     ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>Initial</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<ABFindAll xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<abId>00000000-0000-0000-0000-000000000000</abId>\r\n"
                            "<abView>Full</abView>\r\n"
                            "<deltasOnly>false</deltasOnly>\r\n"
                            "<lastChange>0001-01-01T00:00:00.0000000-08:00</lastChange>\r\n"
                            "</ABFindAll>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/abservice.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/ABFindAll\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
send_add_contact_request (PnNode *conn,
                          ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;
    gchar *contact_info;

    if (service_request->extra_value &&
        strcmp (service_request->extra_value, "yahoo") == 0)
        contact_info = g_strdup_printf ("<emails><ContactEmail>\r\n"
                                        "<contactEmailType>Messenger2</contactEmailType>\r\n"
                                        "<email>%s</email>\r\n"
                                        "<isMessengerEnabled>true</isMessengerEnabled>\r\n"
                                        "<Capability>0</Capability>\r\n"
                                        "<MessengerEnabledExternally>false</MessengerEnabledExternally>\r\n"
                                        "<propertiesChanged/>\r\n"
                                        "</ContactEmail></emails>\r\n",
                                        service_request->value);
    else
        contact_info = g_strdup_printf ("<contactType>LivePending</contactType>\r\n"
                                        "<passportName>%s</passportName>\r\n"
                                        "<isMessengerUser>true</isMessengerUser>\r\n",
                                        service_request->value);

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>ContactSave</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<ABContactAdd xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<abId>00000000-0000-0000-0000-000000000000</abId>\r\n"
                            "<contacts>\r\n"
                            "<Contact xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<contactInfo>\r\n"
                            "%s"
                            "</contactInfo>\r\n"
                            "</Contact>\r\n"
                            "</contacts>\r\n"
                            "<options>\r\n"
                            "<EnableAllowListManagement>true</EnableAllowListManagement>\r\n"
                            "</options>\r\n"
                            "</ABContactAdd>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            contact_info);

    g_free (contact_info);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/abservice.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/ABContactAdd\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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

static inline void next_request (PecanServiceSession *service_session);

static inline void
send_rm_contact_ab_request (PnNode *conn,
                            ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>Timer</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<ABContactDelete xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<abId>00000000-0000-0000-0000-000000000000</abId>\r\n"
                            "<contacts>\r\n"
                            "<Contact>\r\n"
                            "<contactId>%s</contactId>\r\n"
                            "</Contact>\r\n"
                            "</contacts>\r\n"
                            "</ABContactDelete>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            service_request->value);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/abservice.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/ABContactDelete\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
rm_role_contact_request (PnNode *conn,
                         ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;
    gchar *member_role, *member;

    if (service_request->type == PN_RM_CONTACT_ALLOW)
        member_role = "Allow";
    else if (service_request->type == PN_RM_CONTACT_BLOCK)
        member_role = "Block";
    else if (service_request->type == PN_RM_CONTACT_PENDING)
        member_role = "Pending";

    if (service_request->extra_value &&
        strcmp (service_request->extra_value, "yahoo") == 0)
        member = g_strdup_printf ("<Member xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"EmailMember\">\r\n"
                                  "<Type>Email</Type>\r\n"
                                  "<State>Accepted</State>\r\n"
                                  "<Email>%s</Email>\r\n"
                                  "</Member>\r\n",
                                  service_request->value);
    else
        member = g_strdup_printf ("<Member xsi:type=\"PassportMember\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\r\n"
                                  "<Type>Passport</Type>\r\n"
                                  "<State>Accepted</State>\r\n"
                                  "<PassportName>%s</PassportName>\r\n"
                                  "</Member>\r\n",
                                  service_request->value);

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>BlockUnblock</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<DeleteMember xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<serviceHandle>\r\n"
                            "<Id>0</Id>\r\n"
                            "<Type>Messenger</Type>\r\n"
                            "<ForeignId></ForeignId>\r\n"
                            "</serviceHandle>\r\n"
                            "<memberships>\r\n"
                            "<Membership>\r\n"
                            "<MemberRole>%s</MemberRole>\r\n"
                            "<Members>\r\n"
                            "%s"
                            "</Members>\r\n"
                            "</Membership>\r\n"
                            "</memberships>\r\n"
                            "</DeleteMember>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            member_role,
                            member);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/SharingService.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/DeleteMember\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
add_role_contact_request (PnNode *conn,
                          ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;
    gchar *member_role, *member;

    if (service_request->type == PN_ADD_CONTACT_ALLOW)
        member_role = "Allow";
    else if (service_request->type == PN_ADD_CONTACT_BLOCK)
        member_role = "Block";
    else if (service_request->type == PN_ADD_CONTACT_PENDING)
        member_role = "Pending";

    if (service_request->extra_value &&
        strcmp (service_request->extra_value, "yahoo") == 0)
        member = g_strdup_printf ("<Member xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"EmailMember\">\r\n"
                                  "<Type>Email</Type>\r\n"
                                  "<State>Accepted</State>\r\n"
                                  "<Email>%s</Email>\r\n"
                                  "</Member>\r\n",
                                  service_request->value);
    else
        member = g_strdup_printf ("<Member xsi:type=\"PassportMember\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\r\n"
                                  "<Type>Passport</Type>\r\n"
                                  "<State>Accepted</State>\r\n"
                                  "<PassportName>%s</PassportName>\r\n"
                                  "</Member>\r\n",
                                  service_request->value);

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>BlockUnblock</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<AddMember xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<serviceHandle>\r\n"
                            "<Id>0</Id>\r\n"
                            "<Type>Messenger</Type>\r\n"
                            "<ForeignId></ForeignId>\r\n"
                            "</serviceHandle>\r\n"
                            "<memberships>\r\n"
                            "<Membership>\r\n"
                            "<MemberRole>%s</MemberRole>\r\n"
                            "<Members>\r\n"
                            "%s"
                            "</Members>\r\n"
                            "</Membership>\r\n"
                            "</memberships>\r\n"
                            "</AddMember>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            member_role,
                            member);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/SharingService.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/AddMember\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
send_add_group_request (PnNode *conn,
                        ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>GroupSave</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<ABGroupAdd xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<abId>00000000-0000-0000-0000-000000000000</abId>\r\n"
                            "<groupAddOptions>\r\n"
                            "<fRenameOnMsgrConflict>false</fRenameOnMsgrConflict>\r\n"
                            "</groupAddOptions>\r\n"
                            "<groupInfo>\r\n"
                            "<GroupInfo>\r\n"
                            "<name>%s</name>\r\n"
                            "<groupType>C8529CE2-6EAD-434d-881F-341E17DB3FF8</groupType>\r\n"
                            "<fMessenger>false</fMessenger>\r\n"
                            "<annotations>\r\n"
                            "<Annotation>\r\n"
                            "<Name>MSN.IM.Display</Name>\r\n"
                            "<Value>1</Value>\r\n"
                            "</Annotation>\r\n"
                            "</annotations>\r\n"
                            "</GroupInfo>\r\n"
                            "</groupInfo>\r\n"
                            "</ABGroupAdd>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            service_request->value);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/abservice.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/ABGroupAdd\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
send_rm_group_request (PnNode *conn,
                       ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>Timer</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<ABGroupDelete xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<abId>00000000-0000-0000-0000-000000000000</abId>\r\n"
                            "<groupFilter>\r\n"
                            "<groupIds>\r\n"
                            "<guid>%s</guid>\r\n"
                            "</groupIds>\r\n"
                            "</groupFilter>\r\n"
                            "</ABGroupDelete>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            service_request->value);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/abservice.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/ABGroupDelete\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
send_add_contact_group_request (PnNode *conn,
                                ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>GroupSave</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<ABGroupContactAdd xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<abId>00000000-0000-0000-0000-000000000000</abId>\r\n"
                            "<groupFilter>\r\n"
                            "<groupIds>\r\n"
                            "<guid>%s</guid>\r\n"
                            "</groupIds>\r\n"
                            "</groupFilter>\r\n"
                            "<contacts>\r\n"
                            "<Contact>\r\n"
                            "<contactId>%s</contactId>\r\n"
                            "</Contact>\r\n"
                            "</contacts>\r\n"
                            "</ABGroupContactAdd>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            service_request->value,
                            service_request->extra_value);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/abservice.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/ABGroupContactAdd\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
send_rm_contact_group_request (PnNode *conn,
                               ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                            "<soap:Header>"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>"
                            "<IsMigration>false</IsMigration>"
                            "<PartnerScenario>GroupSave</PartnerScenario>"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>"
                            "<TicketToken>%s</TicketToken>"
                            "</ABAuthHeader>"
                            "</soap:Header>"
                            "<soap:Body>"
                            "<ABGroupContactDelete xmlns=\"http://www.msn.com/webservices/AddressBook\">"
                            "<abId>00000000-0000-0000-0000-000000000000</abId>"
                            "<contacts>"
                            "<Contact>"
                            "<contactId>%s</contactId>"
                            "</Contact>"
                            "</contacts>"
                            "<groupFilter>"
                            "<groupIds>"
                            "<guid>%s</guid>"
                            "</groupIds>"
                            "</groupFilter>"
                            "</ABGroupContactDelete>"
                            "</soap:Body>"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            service_request->value,
                            service_request->extra_value);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/abservice.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/ABGroupContactDelete\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
send_rename_group_request (PnNode *conn,
                               ServiceRequest *service_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;
    PnAuth *auth = service_request->service_session->session->auth;
    gchar *cachekey = service_request->service_session->cachekey;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            "<soap:Header>\r\n"
                            "<ABApplicationHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>\r\n"
                            "<IsMigration>false</IsMigration>\r\n"
                            "<PartnerScenario>GroupSave</PartnerScenario>\r\n"
                            "%s%s%s\r\n"
                            "</ABApplicationHeader>\r\n"
                            "<ABAuthHeader xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<ManagedGroupRequest>false</ManagedGroupRequest>\r\n"
                            "<TicketToken>%s</TicketToken>\r\n"
                            "</ABAuthHeader>\r\n"
                            "</soap:Header>\r\n"
                            "<soap:Body>\r\n"
                            "<ABGroupUpdate xmlns=\"http://www.msn.com/webservices/AddressBook\">\r\n"
                            "<abId>00000000-0000-0000-0000-000000000000</abId>\r\n"
                            "<groups>\r\n"
                            "<Group>\r\n"
                            "<groupId>%s</groupId>\r\n"
                            "<groupInfo>\r\n"
                            "<name>%s</name>\r\n"
                            "</groupInfo>\r\n"
                            "<propertiesChanged>GroupName</propertiesChanged>\r\n"
                            "</Group>\r\n"
                            "</groups>\r\n"
                            "</ABGroupUpdate>\r\n"
                            "</soap:Body>\r\n"
                            "</soap:Envelope>",
                            cachekey ? "<CacheKey>" : "",
                            cachekey ? cachekey : "",
                            cachekey ? "</CacheKey>" : "",
                            auth->security_token.contacts_msn_com,
                            service_request->value,
                            service_request->extra_value);

    body_len = strlen (body);

    header = g_strdup_printf ("POST /abservice/abservice.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.msn.com/webservices/AddressBook/ABGroupUpdate\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: contacts.msn.com\r\n"
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
send_rml_command (ServiceRequest *service_request)
{
    gchar *payload;
    MsnSession *session;
    MsnCmdProc *cmdproc;
    MsnTransaction *trans;
    struct pn_contact *contact;
    PurpleAccount *account;

    session = service_request->service_session->session;

    account = msn_session_get_user_data (session);
    cmdproc = session->notification->cmdproc;
    contact = pn_contactlist_find_contact (session->contactlist, service_request->value);

    if (contact)
    {
        if (contact->list_op & MSN_LIST_AL_OP)
            purple_privacy_permit_remove (account, service_request->value, TRUE);
        if (contact->list_op & MSN_LIST_BL_OP)
            purple_privacy_deny_remove (account, service_request->value, TRUE);

        pn_contact_set_list_op (contact, MSN_LIST_NULL_OP);

        gchar *domain, *name;
        domain = strchr (service_request->value, '@');
        name = g_strndup (service_request->value, domain - service_request->value);
        payload = g_strdup_printf ("<ml>"
                                   "<d n=\"%s\">"
                                   "<c n=\"%s\" l=\"%d\" t=\"%d\" />"
                                   "</d>"
                                   "</ml>",
                                   domain + 1,
                                   name,
                                   contact->list_op,
                                   contact->networkid);

        trans = msn_transaction_new (cmdproc, "RML", "%zu", strlen (payload));
        msn_transaction_set_payload (trans, payload, strlen (payload));
        msn_cmdproc_send_trans (cmdproc, trans);

        g_free (name);
    }
}

static inline void
send_updated_adl_command (ServiceRequest *service_request)
{
    gchar *payload;
    MsnCmdProc *cmdproc;
    MsnTransaction *trans;
    struct pn_contact *contact;

    cmdproc = service_request->service_session->session->notification->cmdproc;

    contact = pn_contactlist_find_contact (service_request->service_session->session->contactlist, service_request->value);

    if (contact)
    {
        gchar *domain, *name;

        pn_contact_set_list_op (contact, MSN_LIST_AL_OP);

        domain = strchr (service_request->value, '@');
        name = g_strndup (service_request->value, domain - service_request->value);
        payload = g_strdup_printf ("<ml>"
                                   "<d n=\"%s\">"
                                   "<c n=\"%s\" l=\"%d\" t=\"%d\" />"
                                   "</d>"
                                   "</ml>",
                                   domain + 1,
                                   name,
                                   contact->list_op,
                                   contact->networkid);

        trans = msn_transaction_new (cmdproc, "ADL", "%zu", strlen (payload));
        msn_transaction_set_payload (trans, payload, strlen (payload));
        msn_cmdproc_send_trans (cmdproc, trans);

        g_free (name);
    }
}

static void
open_cb (PnNode *conn,
         ServiceRequest *service_request)
{
    g_return_if_fail (conn);

    pn_log ("begin");

    g_signal_handler_disconnect (conn, service_request->open_sig_handler);
    service_request->open_sig_handler = 0;

    if (service_request->type == PN_REQ_MEMBERLISTS)
        send_req_memberlists_request (conn, service_request);
    else if (service_request->type == PN_REQ_AB)
        send_req_ab_request (conn, service_request);
    else if (service_request->type == PN_ADD_CONTACT)
    {
        send_updated_adl_command (service_request);
        send_add_contact_request (conn, service_request);
    }
    else if (service_request->type == PN_RM_CONTACT_AB)
    {
        send_rml_command (service_request);
        send_rm_contact_ab_request (conn, service_request);
    }
    else if (service_request->type == PN_RM_CONTACT_ALLOW)
        rm_role_contact_request (conn, service_request);
    else if (service_request->type == PN_ADD_CONTACT_BLOCK)
        add_role_contact_request (conn, service_request);
    else if (service_request->type == PN_RM_CONTACT_BLOCK)
        rm_role_contact_request (conn, service_request);
    else if (service_request->type == PN_ADD_CONTACT_ALLOW)
        add_role_contact_request (conn, service_request);
    else if (service_request->type == PN_RM_CONTACT_PENDING)
        rm_role_contact_request (conn, service_request);
    else if (service_request->type == PN_ADD_CONTACT_PENDING)
        add_role_contact_request (conn, service_request);
    else if (service_request->type == PN_ADD_GROUP)
        send_add_group_request (conn, service_request);
    else if (service_request->type == PN_RM_GROUP)
        send_rm_group_request (conn, service_request);
    else if (service_request->type == PN_ADD_CONTACT_GROUP)
    {
        if (service_request->value && service_request->extra_value)
            send_add_contact_group_request (conn, service_request);
    }
    else if (service_request->type == PN_RM_CONTACT_GROUP)
        send_rm_contact_group_request (conn, service_request);
    else if (service_request->type == PN_RENAME_GROUP)
        send_rename_group_request (conn, service_request);

    pn_log ("end");
}

static inline void service_process_requests (PecanServiceSession *service_session);

static inline void
next_request (PecanServiceSession *service_session)
{
    ServiceRequest *service_request;

    service_request = g_queue_pop_head (service_session->request_queue);
    service_request_free (service_request);

    service_process_requests (service_session);
}

/* Send ADL */
/* TODO: rewrite this. Also this should be < 7500 bytes, if it isn't send two (or more) ADL */
static inline void
send_login_adl_command (struct MsnSession *session)
{
    PurpleAccount *account;
    GSList *buddies;
    gchar *payload, *tmp;
    MsnCmdProc *cmdproc;
    MsnTransaction *trans;

    cmdproc = session->notification->cmdproc;

    account = msn_session_get_user_data (session);
    payload = g_strdup ("<ml l=\"1\">");

    buddies = purple_find_buddies (account, NULL);
    for (buddies = purple_find_buddies (account, NULL); buddies;
         buddies = g_slist_delete_link (buddies, buddies))
    {
        PurpleBuddy *buddy = buddies->data;
        const gchar *buddy_name = purple_buddy_get_name (buddy);
        struct pn_contact *contact;

        contact = pn_contactlist_find_contact (session->contactlist, buddy_name);

        if (contact)
        {
            gchar *domain, *name;
            tmp = payload;
            domain = strchr (buddy_name, '@');
            name = g_strndup (buddy_name, domain - buddy_name);
            payload = g_strdup_printf ("%s"
                                       "<d n=\"%s\">"
                                       "<c n=\"%s\" l=\"%d\" t=\"%d\" />"
                                       "</d>",
                                       tmp,
                                       domain + 1,
                                       name,
                                       contact->list_op,
                                       contact->networkid);
            g_free (tmp);
            g_free (name);
        }
        else
            pn_error ("contact not found: %s", buddy_name);
    }
    tmp = payload;
    payload = g_strdup_printf ("%s</ml>", tmp);
    g_free (tmp);

    trans = msn_transaction_new (cmdproc, "ADL", "%zu", strlen (payload));
    msn_transaction_set_payload (trans, payload, strlen (payload));
    msn_cmdproc_send_trans (cmdproc, trans);
}

static void
process_body_req_memberlists (ServiceRequest *service_request,
                              char *body)
{
    gchar *cur, *next = NULL;
    PurpleAccount *account;
    MsnSession *session;

    session = service_request->service_session->session;
    account = msn_session_get_user_data (service_request->service_session->session);

    cur = strstr (body, "<Membership><MemberRole>Allow</MemberRole>");
    if (cur)
        next = strstr (cur, "</Membership>");
    while (cur && cur < next)
    {
        gchar *passport = NULL;
        cur = pn_parse_xml_tag (cur, "PassportName", &passport);
        if (passport)
        {
            struct pn_contact *contact;

            contact = pn_contact_new (session->contactlist);
            pn_contact_set_passport (contact, passport);
            pn_contact_set_list_op (contact, MSN_LIST_AL_OP);
            purple_privacy_deny_remove (account, passport, TRUE);
            purple_privacy_permit_add (account, passport, TRUE);
            contact->networkid = 1;

            g_free (passport);
        }

    }

    cur = strstr (body, "<Membership><MemberRole>Allow</MemberRole>");
    if (cur)
        next = strstr (cur, "</Membership>");
    while (cur && cur < next)
    {
        gchar *email = NULL;
        cur = pn_parse_xml_tag (cur, "Email", &email);
        if (email)
        {
            struct pn_contact *contact;

            contact = pn_contact_new (session->contactlist);
            pn_contact_set_passport (contact, email);
            pn_contact_set_list_op (contact, MSN_LIST_AL_OP);
            purple_privacy_deny_remove (account, email, TRUE);
            purple_privacy_permit_add (account, email, TRUE);
            contact->networkid = 32;

            g_free (email);
        }
    }

    cur = strstr (body, "<Membership><MemberRole>Block</MemberRole>");
    if (cur)
        next = strstr (cur, "</Membership>");
    while (cur && cur < next)
    {
        gchar *passport = NULL;
        cur = pn_parse_xml_tag (cur, "PassportName", &passport);
        if (passport)
        {
            struct pn_contact *contact;

            contact = pn_contact_new (session->contactlist);
            pn_contact_set_passport (contact, passport);
            pn_contact_set_list_op (contact, MSN_LIST_BL_OP);
            purple_privacy_permit_remove (account, passport, TRUE);
            purple_privacy_deny_add (account, passport, TRUE);
            contact->networkid = 1;

            g_free (passport);
        }
    }

    cur = strstr (body, "<Membership><MemberRole>Block</MemberRole>");
    if (cur)
        next = strstr (cur, "</Membership>");
    while (cur && cur < next)
    {
        gchar *email = NULL;
        cur = pn_parse_xml_tag (cur, "Email", &email);
        if (email)
        {
            struct pn_contact *contact;

            contact = pn_contact_new (session->contactlist);
            pn_contact_set_passport (contact, email);
            pn_contact_set_list_op (contact, MSN_LIST_BL_OP);
            purple_privacy_permit_remove (account, email, TRUE);
            purple_privacy_deny_add (account, email, TRUE);
            contact->networkid = 32;

            g_free (email);
        }
    }

    cur = strstr (body, "<Membership><MemberRole>Pending</MemberRole>");
    if (cur)
        next = strstr (cur, "</Membership>");
    while (cur && cur < next)
    {
        gchar *passport, *end;
        struct pn_contact *contact;
        gint network_id = 1;

        end = pn_parse_xml_tag (cur, "PassportName", &passport);
        if (!passport || end > next)
        {
            g_free (passport);
            end = pn_parse_xml_tag (cur, "Email", &passport);
            network_id = 32;
        }

        contact = pn_contactlist_find_contact (session->contactlist, passport);
        if (!contact)
        {
            contact = pn_contact_new (session->contactlist);
            pn_contact_set_passport (contact, passport);
            pn_contact_set_list_op (contact, MSN_LIST_NULL_OP);
            contact->networkid = network_id;
            pn_contactlist_got_new_entry (session, contact, passport);
        }

        g_free (passport);

        cur = strstr (end, "<Membership><MemberRole>Pending</MemberRole>");
        if (cur)
            next = strstr (cur, "</Membership>");
    }

    msn_session_set_prp (session,
                         "MFN", msn_session_get_username (session));

    {
        cur = pn_parse_xml_tag (body, "CreatorCID", &session->cid);
        pn_roaming_session_request (session->roaming_session,
                                    PN_GET_PROFILE, NULL, NULL);
    }

    pn_service_session_request (service_request->service_session,
                                PN_REQ_AB, NULL, NULL, NULL);
}

static void
process_body_req_ab (ServiceRequest *service_request,
                     char *body)
{
    gchar *cur, *next = NULL;
    PurpleAccount *account;
    MsnSession *session;

    session = service_request->service_session->session;
    account = msn_session_get_user_data (service_request->service_session->session);

    cur = strstr (body, "<Group>");
    while (cur)
    {
        gchar *guid = NULL;
        cur = pn_parse_xml_tag (cur, "groupId", &guid);
        if (guid)
        {
            gchar *name = NULL;
            cur = pn_parse_xml_tag (cur, "name", &name);
            if (name)
            {
                pn_group_new (session->contactlist, name, guid);
                g_free (name);
            }

            g_free (guid);
        }
        cur = strstr (cur, "<Group>");
    }

    cur = strstr (body, "<Contact>");
    if (cur)
        next = strstr (cur, "</Contact>");
    while (cur && cur < next)
    {
        gchar *contact_id;
        cur = pn_parse_xml_tag (cur, "contactId", &contact_id);
        if (contact_id)
        {
            gchar *passport, *end, *name, *guid = NULL;
            struct pn_contact *contact;
            gint network_id = 1;

            end = pn_parse_xml_tag (cur, "passportName", &passport);
            if (!passport || end > next)
            {
                g_free (passport);
                end = pn_parse_xml_tag (cur, "email", &passport);
                network_id = 32;
            }
            /* TODO: more than one group can be set in <groupIds> */
            if (strstr (cur, "<guid>"))
            {
                end = pn_parse_xml_tag (cur, "guid", &guid);
                if (end > next)
                {
                    g_free (guid);
                    guid = NULL;
                }
            }
            end = pn_parse_xml_tag (cur, "displayName", &name);
            if (!name || end > next)
            {
                g_free (name);
                end = pn_parse_xml_tag (cur, "quickName", &name);
            }

            if (strcmp (passport, session->username) != 0)
            {
                contact = pn_contactlist_find_contact (session->contactlist,
                                                       passport);
                if (!contact)
                {
                    contact = pn_contact_new (session->contactlist);
                    pn_contact_set_passport (contact, passport);
                    pn_contact_set_list_op (contact, MSN_LIST_AL_OP);
                    purple_privacy_deny_remove (account, passport, TRUE);
                    purple_privacy_permit_add (account, passport, TRUE);;
                    contact->networkid = network_id;
                }
                contact->guid = g_strdup (contact_id);
                pn_contact_set_friendly_name (contact, name);
                pn_contact_add_group_id (contact, guid);
            }

            g_free (passport);
            g_free (guid);
            g_free (name);
            g_free (contact_id);
        }
        cur = strstr (next, "<Contact>");
        if (cur)
            next = strstr (cur, "</Contact>");
    }

    send_login_adl_command (service_request->service_session->session);
}

static void
process_body_add_contact (ServiceRequest *service_request,
                          char *body)
{
    gchar *cur;

    cur = strstr (body, "<ABContactAddResult><guid>");
    if (cur)
    {
        gchar *guid = NULL;
        cur = pn_parse_xml_tag (cur, "guid", &guid);

        if (guid)
        {
            MsnSession *session;
            struct pn_contact *contact;
            session = service_request->service_session->session;
            contact = pn_contactlist_find_contact (session->contactlist,
                                                   service_request->value);
            if (contact)
            {
                contact->guid = guid;
                pn_service_session_request (session->service_session,
                                            PN_ADD_CONTACT_GROUP, guid,
                                            service_request->data, NULL);
            }
            else
                g_free (guid);
        }
    }
}

static void
process_body_add_group (ServiceRequest *service_request,
                        char *body)
{
    gchar *cur;

    cur = strstr (body, "<ABGroupAddResult><guid>");
    if (cur)
    {
        gchar *guid = NULL;
        cur = pn_parse_xml_tag (cur, "guid", &guid);

        if (guid)
        {
            MsnSession *session;
            session = service_request->service_session->session;

            pn_group_new (session->contactlist, service_request->value, guid);

            if (service_request->data)
            {
                gchar *old_group_name = g_strdup (service_request->data);

                pn_contactlist_move_buddy (session->contactlist,
                                           service_request->extra_value,
                                           old_group_name,
                                           service_request->value);

                g_free (old_group_name);
            }

            g_free (guid);
        }
    }
}

static void
read_cb (PnNode *conn,
         gpointer data)
{
    ServiceRequest *service_request;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *str = NULL;

    service_request = data;

    while (service_request->parser_state == 0)
    {
        gsize terminator_pos;

        status = pn_parser_read_line (service_request->parser, &str, NULL, &terminator_pos, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (str)
        {
            str[terminator_pos] = '\0';

            if (strncmp (str, "Content-Length: ", 16) == 0)
                service_request->content_size = atoi(str + 16);

            /* now comes the content */
            if (str[0] == '\0') {
                service_request->parser_state++;
                break;
            }

            g_free (str);
        }
    }

    if (service_request->parser_state == 1)
    {
        gchar *body;

        status = pn_parser_read (service_request->parser, &body, service_request->content_size, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (strstr (body, "<faultstring>") &&
            !strstr (body, "MemberAlreadyExists")) /* ignore this error */
        {
            gchar *error;

            pn_parse_xml_tag (body, "faultstring", &error);
            pn_error ("service: error=[%s]", error);
            g_free (body);
            goto leave;
        }
        else
            pn_debug ("%s", body);

        {
            gchar *cur;
            cur = strstr (body, "<CacheKeyChanged>true</CacheKeyChanged>");
            if (cur)
            {
                g_free (service_request->service_session->cachekey);
                cur = pn_parse_xml_tag (cur, "CacheKey",
                                        &service_request->service_session->cachekey);
            }
        }

        if (service_request->type == PN_REQ_MEMBERLISTS)
            process_body_req_memberlists (service_request, body);
        else if (service_request->type == PN_REQ_AB)
            process_body_req_ab (service_request, body);
        else if (service_request->type == PN_ADD_CONTACT)
            process_body_add_contact (service_request, body);
        /* else if (service_request->type == PN_RM_CONTACT_AB) */
        else if (service_request->type == PN_RM_CONTACT_ALLOW)
        {
            pn_service_session_request (service_request->service_session,
                                        PN_ADD_CONTACT_BLOCK,
                                        service_request->value,
                                        service_request->extra_value, NULL);
        }
        /* else if (service_request->type == PN_ADD_CONTACT_BLOCK) */
        else if (service_request->type == PN_RM_CONTACT_BLOCK)
        {
            pn_service_session_request (service_request->service_session,
                                        PN_ADD_CONTACT_ALLOW,
                                        service_request->value,
                                        service_request->extra_value, NULL);
        }
        /* else if (service_request->type == PN_ADD_CONTACT_ALLOW) */
        /* else if (service_request->type == PN_RM_CONTACT_PENDING) */
        /* else if (service_request->type == PN_ADD_CONTACT_PENDING) */
        else if (service_request->type == PN_ADD_GROUP)
            process_body_add_group (service_request, body);
        else if (service_request->type == PN_RM_GROUP)
            pn_contactlist_remove_group_id (service_request->service_session->session->contactlist,
                                            service_request->value);
        /* else if (service_request->type == PN_ADD_CONTACT_GROUP) */
        /* else if (service_request->type == PN_RM_CONTACT_GROUP) */
        /* else if (service_request->type == PN_RENAME_GROUP) */

        g_free(body);
    }

leave:
    pn_node_close (conn);
    next_request (service_request->service_session);
}

static void auth_cb (PnAuth *auth, void *data)
{
    PnSslConn *ssl_conn;
    PnNode *conn;
    ServiceRequest *service_request = data;

    ssl_conn = pn_ssl_conn_new ("ab_service", PN_NODE_NULL);

    conn = PN_NODE (ssl_conn);
    conn->session = service_request->service_session->session;

    service_request->parser = pn_parser_new (conn);
    pn_ssl_conn_set_read_cb (ssl_conn, read_cb, service_request);

    pn_node_connect (conn, "contacts.msn.com", 443);

    service_request->conn = conn;
    service_request->open_sig_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), service_request);
}

static inline void
service_process_requests (PecanServiceSession *service_session)
{
    ServiceRequest *service_request;

    service_request = g_queue_peek_head (service_session->request_queue);

    if (!service_request)
        return;

    pn_auth_get_ticket (service_session->session->auth, 2, auth_cb, service_request);
}

void
pn_service_session_request (PecanServiceSession *service_session,
                            ServiceRequestType type,
                            const gchar *value,
                            const gchar *extra_value,
                            gpointer data)
{
    gboolean initial;

    initial = g_queue_is_empty (service_session->request_queue);

    g_queue_push_tail (service_session->request_queue,
                       service_request_new (service_session, type,
                                            value, extra_value, data));

    if (initial)
    {
        service_process_requests (service_session);
    }
}
