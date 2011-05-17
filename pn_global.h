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

#ifndef PN_GLOBAL_H
#define PN_GLOBAL_H

#define PN_BUF_LEN 8192
#define PN_MAX_MESSAGE_LENGTH 1564

typedef enum {
    PN_CLIENT_CAP_WIN_MOBILE = 0x01, /* CapabilityMobileOnline */
    PN_CLIENT_CAP_MSN8USER = 0x02, /* CapabilityMSN8User */
    PN_CLIENT_CAP_INK_GIF = 0x04, /* CapabilityRendersGif */
    PN_CLIENT_CAP_INK_ISF = 0x08, /* CapabilityRendersIsf */
    PN_CLIENT_CAP_VIDEO_CHAT = 0x10, /* CapabilityWebCamDetected */
    PN_CLIENT_CAP_BASE = 0x20, /* CapabilitySupportsChunking */
    PN_CLIENT_CAP_MSNMOBILE = 0x40, /* CapabilityMobileEnabled */
    PN_CLIENT_CAP_MSNDIRECT = 0x80, /* CapabilityDirectDevice */
    PN_CLIENT_CAP_WEBMSGR = 0x200, /* CapabilityWebIMClient */
    PN_CLIENT_CAP_TGW = 0x800, /* CapabilityConnectedViaTGW */
    PN_CLIENT_CAP_SPACE = 0x1000, /* CapabilityHasSpace */
    PN_CLIENT_CAP_MCE = 0x2000, /* CapabilityMCEUser */
    PN_CLIENT_CAP_DIRECTIM = 0x4000, /* CapabilitySupportsDirectIM */
    PN_CLIENT_CAP_WINKS = 0x8000, /* CapabilitySupportsWinks */
    PN_CLIENT_CAP_SEARCH = 0x10000,
    PN_CLIENT_CAP_BOT = 0x20000, /* CapabilityIsBot */
    PN_CLIENT_CAP_VOICE_CLIP = 0x40000, /* CapabilitySupportsVoiceIM */
    PN_CLIENT_CAP_SCHANNEL = 0x80000, /* CapabilitySupportsSChannel */
    PN_CLIENT_CAP_SIP_INVITE = 0x100000, /* CapabilitySupportsSipInvite */
    PN_CLIENT_CAP_SDRIVE = 0x400000, /* CapabilitySupportsSDrive */
    PN_CLIENT_CAP_ONECARE = 0x1000000, /* CapabilityHasOnecare */
    PN_CLIENT_CAP_P2P_TURN = 0x2000000, /* CapabilityP2PSupportsTurn */
    PN_CLIENT_CAP_P2P_BOOTSTRAP = 0x4000000, /* CapabilityP2PBootstrapViaUUN */
} PnClientCaps;

typedef enum {
    PN_CLIENT_VER_6_0 = 0x10000000, /* CapabilityMsgrVersion1 */
    PN_CLIENT_VER_6_1 = 0x20000000, /* CapabilityMsgrVersion2 */
    PN_CLIENT_VER_6_2 = 0x30000000, /* CapabilityMsgrVersion3 */
    PN_CLIENT_VER_7_0 = 0x40000000, /* CapabilityMsgrVersion4 */
    PN_CLIENT_VER_7_5 = 0x50000000, /* CapabilityMsgrVersion5 */
    PN_CLIENT_VER_8_0 = 0x60000000, /* CapabilityMsgrVersion6 */
    PN_CLIENT_VER_8_1 = 0x70000000, /* CapabilityMsgrVersion7 */
    PN_CLIENT_VER_8_5 = 0x80000000, /* CapabilityMsgrVersion8 */
    PN_CLIENT_VER_9_0 = 0x90000000, /* CapabilityMsgrVersion9 */
    PN_CLIENT_VER_2009 = 0xA0000000, /* CapabilityMsgrVersion10 */
    PN_CLIENT_VER_2011 = 0xB0000000, /* CapabilityMsgrVersion11 */
} PnClientVerId;

#endif /* PN_GLOBAL_H */
