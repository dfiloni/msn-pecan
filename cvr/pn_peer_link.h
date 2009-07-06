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

#ifndef PN_PEERLINK_H
#define PN_PEERLINK_H

typedef struct PnPeerLink PnPeerLink;

struct MsnSession;
struct MsnSwitchboard;
struct MsnSlpMessage;
struct MsnDirectConn;
struct MsnMessage;
struct MsnSlpSession;

struct _PurpleXfer;

#include <glib.h>

#include "slpcall.h"
#include "cvr/pn_msnobj.h"

typedef void (*MsnSlpCb) (MsnSlpCall *slpcall, const guchar *data, gsize size);
typedef void (*MsnSlpEndCb) (MsnSlpCall *slpcall, struct MsnSession *session);

struct PnPeerLink
{
    char *local_user;
    char *remote_user;

    int slp_seq_id;
    int slp_session_id;

    GList *slp_calls;
    GList *slp_msgs;

    GQueue *slp_msg_queue;
    struct MsnSession *session;
    struct MsnSwitchBoard *swboard;
    struct MsnDirectConn *directconn;

    unsigned int ref_count;
};

PnPeerLink *pn_peer_link_new(struct MsnSession *session,
                             const char *username);
void pn_peer_link_free(PnPeerLink *link);
PnPeerLink *pn_peer_link_ref(PnPeerLink *link);
PnPeerLink *pn_peer_link_unref(PnPeerLink *link);

void pn_peer_link_add_slpcall(PnPeerLink *link,
                              MsnSlpCall *slpcall);
void pn_peer_link_remove_slpcall(PnPeerLink *link,
                                 MsnSlpCall *slpcall);
MsnSlpCall *pn_peer_link_find_slp_call(PnPeerLink *link,
                                       const char *id);
void pn_peer_link_queue_slpmsg(PnPeerLink *link,
                               struct MsnSlpMessage *slpmsg);
void pn_peer_link_send_slpmsg(PnPeerLink *link,
                              struct MsnSlpMessage *slpmsg);
void pn_peer_link_unleash(PnPeerLink *link);
void pn_peer_link_process_msg(PnPeerLink *link,
                              struct MsnMessage *msg);

void pn_peer_link_request_object(PnPeerLink *link,
                                 const char *info,
                                 MsnSlpCb cb,
                                 MsnSlpEndCb end_cb,
                                 const PnMsnObj *obj);

PnPeerLink *msn_session_find_peer_link(struct MsnSession *session,
                                       const char *who);
PnPeerLink *msn_session_get_peer_link(struct MsnSession *session,
                                      const char *username);

#endif /* PN_PEERLINK_H */