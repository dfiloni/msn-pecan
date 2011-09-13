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

#ifndef PN_ROAMING_H
#define PN_ROAMING_H

typedef enum
{
    PN_GET_PROFILE,
    PN_UPDATE_PROFILE
} RoamingRequestType;

typedef struct PecanRoamingSession PecanRoamingSession;

#include "session.h"

struct MsnSession;

PecanRoamingSession *pn_roaming_session_new (MsnSession *session);
void pn_roaming_session_free (PecanRoamingSession *roaming_session);
void pn_roaming_session_request (PecanRoamingSession *roaming_session,
                                 RoamingRequestType type,
                                 const gchar *value,
                                 const gchar *extra_value);

#endif /* PN_ROAMING_H */
