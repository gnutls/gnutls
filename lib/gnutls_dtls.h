/*
 * Copyright (C) 2009 Free Software Foundation (copyright assignement pending)
 *
 * Author: Jonathan Bastien-Filiatrault
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#ifndef DTLS_H
# define DTLS_H

#include "gnutls_int.h"

int _gnutls_dtls_handshake_enqueue(gnutls_session_t session,
				   opaque *data,
				   uint32_t datasize,
				   gnutls_handshake_description_t type,
				   uint16_t sequence);

int _gnutls_dtls_transmit(gnutls_session_t session);
void _gnutls_dtls_clear_outgoing_buffer(gnutls_session_t session);

#endif
