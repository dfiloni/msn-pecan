/**
 * Copyright (C) 2007-2009 Felipe Contreras.
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

#ifndef MSN_NOTIFICATION_H
#define MSN_NOTIFICATION_H

#include <glib.h>

typedef struct MsnNotification MsnNotification;

#include "io/pn_cmd_server.h"
#include "io/pn_node.h"

struct MsnSession;
struct MsnCmdProc;
struct pn_timer;

struct MsnNotification
{
    struct MsnSession *session;
    struct MsnCmdProc *cmdproc;
    PnCmdServer *conn;

    gboolean in_use;
    gulong open_handler;
    gulong close_handler;
    gulong error_handler;

    gboolean closed;
    struct pn_timer *alive_timer;
};

void msn_notification_end (void);
void msn_notification_init (void);

void msn_notification_add_buddy (MsnNotification *notification, const char *list, const char *who, const gchar *user_guid, const char *store_name, const gchar *group_guid);
void msn_notification_rem_buddy (MsnNotification *notification, const char *list, const char *who, const gchar *user_guid, const gchar *group_guid);
MsnNotification *msn_notification_new (struct MsnSession *session);
void msn_notification_destroy (MsnNotification *notification);
gboolean msn_notification_connect (MsnNotification *notification, const char *host, int port);
void msn_notification_disconnect (MsnNotification *notification);

/**
 * Closes a notification server.
 *
 * @param notification The notification object to close.
 */
void msn_notification_close (MsnNotification *notification);

void msn_got_login_params (struct MsnSession *session, const char *login_params, const char *sso_value);

#endif /* MSN_NOTIFICATION_H */
