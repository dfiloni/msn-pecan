/**
 * Copyright (C) 2007-2009 Felipe Contreras
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

#include "pn_log.h"
#include "pn_printf.h"

#ifdef PN_DEBUG

/* #define PURPLE_DEBUG */
/* #define PN_DEBUG_FILE */

#include <fcntl.h>
#include <unistd.h>

#include <glib/gstdio.h>

#ifdef PURPLE_DEBUG
/* libpurple stuff. */
#include <debug.h>
#endif /* PURPLE_DEBUG */

#ifndef PECAN_LOG_LEVEL
#define PECAN_LOG_LEVEL PN_LOG_LEVEL_INFO
#endif

static inline const gchar *
log_level_to_string (PecanLogLevel level)
{
    switch (level)
    {
        case PN_LOG_LEVEL_NONE: return "NONE"; break;
        case PN_LOG_LEVEL_ERROR: return "ERROR"; break;
        case PN_LOG_LEVEL_WARNING: return "WARNING"; break;
        case PN_LOG_LEVEL_INFO: return "INFO"; break;
        case PN_LOG_LEVEL_DEBUG: return "DEBUG"; break;
        case PN_LOG_LEVEL_LOG: return "LOG"; break;
        default: return "Unknown"; break;
    }
}

#ifdef PN_DUMP_FILE
void
pn_dump_file (const gchar *buffer,
              gsize len)
{
    gint fd;
    static guint c;
    gchar *basename;
    gchar *fullname;

    basename = pn_strdup_printf ("pecan-%.6u.bin", c++);

    fullname = g_build_filename (g_get_tmp_dir (), basename, NULL);

    g_free (basename);

    fd = g_open (fullname, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

    if (fd)
    {
        write (fd, buffer, len);
        close (fd);
    }
}
#endif /* PN_DUMP_FILE */

void
pn_base_log_helper (guint level,
                    const gchar *file,
                    const gchar *function,
                    gint line,
                    const gchar *fmt,
                    ...)
{
    gchar *tmp;
    va_list args;

    if (level > PECAN_LOG_LEVEL)
        return;

    va_start (args, fmt);

    tmp = pn_strdup_vprintf (fmt, args);

#if defined(PN_DEBUG_FILE)
    {
        static FILE *logfile;
        if (!logfile)
        {
            gint fd;
            fd = g_file_open_tmp ("msn-pecan-XXXXXX", NULL, NULL);
            if (fd)
                logfile = fdopen (fd, "w");
        }
        if (logfile)
        {
            g_fprintf (logfile, "%s\t%s:%d:%s()\t%s\n",
                       log_level_to_string (level),
                       file, line, function,
                       tmp);
        }
    }
#elif defined(PURPLE_DEBUG)
    {
        PurpleDebugLevel purple_level;

        switch (level)
        {
            case PN_LOG_LEVEL_ERROR:
                purple_level = PURPLE_DEBUG_ERROR; break;
            case PN_LOG_LEVEL_WARNING:
                purple_level = PURPLE_DEBUG_WARNING; break;
            case PN_LOG_LEVEL_INFO:
                purple_level = PURPLE_DEBUG_INFO; break;
            case PN_LOG_LEVEL_DEBUG:
                purple_level = PURPLE_DEBUG_MISC; break;
            case PN_LOG_LEVEL_LOG:
                purple_level = PURPLE_DEBUG_MISC; break;
            default:
                purple_level = PURPLE_DEBUG_MISC; break;
        }

        purple_debug (purple_level, "msn-pecan", "%s:%d:%s() %s\n", file, line, function, tmp);
    }
#else
    pn_print ("%s %s:%d:%s() %s\n",
              log_level_to_string (level),
              file, line, function,
              tmp);
#endif
    g_free (tmp);

    va_end (args);
}

#endif /* PN_DEBUG */