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

#ifndef PN_SERVICE_H
#define PN_SERVICE_H

typedef enum
{
    PN_REQ_MEMBERLISTS,
    PN_REQ_AB,
    PN_ADD_CONTACT,
    PN_RM_CONTACT_AB,
    PN_RM_CONTACT_ALLOW,
    PN_ADD_CONTACT_BLOCK,
    PN_RM_CONTACT_BLOCK,
    PN_ADD_CONTACT_ALLOW,
    PN_RM_CONTACT_PENDING,
    PN_ADD_CONTACT_PENDING,
    PN_ADD_GROUP,
    PN_RM_GROUP,
    PN_ADD_CONTACT_GROUP,
    PN_RM_CONTACT_GROUP,
    PN_RENAME_GROUP
} ServiceRequestType;

typedef struct PecanServiceSession PecanServiceSession;

#include "session.h"

struct MsnSession;

PecanServiceSession *pn_service_session_new (MsnSession *session);
void pn_service_session_free (PecanServiceSession *service_session);
void pn_service_session_request (PecanServiceSession *service_session,
                                 ServiceRequestType type,
                                 const gchar *value,
                                 const gchar *extra_value,
                                 gpointer data);

#endif /* PN_SERVICE_H */
