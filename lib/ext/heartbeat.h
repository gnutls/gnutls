/*
 * Copyright (C) 2002-2012 Free Software Foundation, Inc.
 *
 * Author: Olga Smolenchuk
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef EXT_HEARTBEAT_H
#define EXT_HEARTBEAT_H

#include <gnutls_extensions.h>

#define HEARTBEAT_REQUEST 1
#define HEARTBEAT_RESPONSE 2

#define MAX_HEARTBEAT_LENGTH 16384
#define HEARTBEAT_TIMEOUT 1000
#define MAX_HEARTBEAT_TIMEOUT 60000

#define PEER_ALLOWED_TO_SEND 1
#define PEER_NOT_ALLOWED_TO_SEND 2

#define HEARTBEAT_DEFAULT_POLICY PEER_NOT_ALLOWED_TO_SEND

extern extension_entry_st ext_mod_heartbeat;

typedef union
{
  uint32_t num;
  struct
  {
    uint8_t local:1;
    uint8_t remote:1;
  } set;
} heartbeat_policy_t;

int _gnutls_heartbeat_policy_set (gnutls_session_t session, unsigned policy);
int gnutls_heartbeat_allow (gnutls_session_t session);
int gnutls_heartbeat_deny (gnutls_session_t session);
unsigned _gnutls_heartbeat_policy_get (gnutls_session_t session);
int _gnutls_heartbeat_handle (gnutls_session_t session, mbuffer_st * bufel);
ssize_t _gnutls_heartbeat_send_data (gnutls_session_t session,
                                     const void *data, size_t data_size,
                                     int request);
ssize_t gnutls_heartbeat_ping (gnutls_session_t session, size_t data_size);
ssize_t gnutls_heartbeat_ping_rnd (gnutls_session_t session);
int _gnutls_heartbeat_enabled (gnutls_session_t session, int local);
int gnutls_heartbeat_enabled_local (gnutls_session_t session);
int gnutls_heartbeat_enabled_remote (gnutls_session_t session);
int gnutls_heartbeat_timeout (gnutls_session_t session, int check_only);
const char * _gnutls_heartbeat (int policy);
#endif
