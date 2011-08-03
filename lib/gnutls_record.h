/*
 * Copyright (C) 2000-2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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

#ifndef GNUTLS_RECORD_H
#define GNUTLS_RECORD_H

#include <gnutls/gnutls.h>
#include <gnutls_buffers.h>

ssize_t _gnutls_send_int (gnutls_session_t session, content_type_t type,
                          gnutls_handshake_description_t htype,
                          unsigned int epoch_rel, const void *data,
                          size_t sizeofdata, unsigned int mflags);
ssize_t _gnutls_recv_int (gnutls_session_t session, content_type_t type,
                          gnutls_handshake_description_t, opaque * data,
                          size_t sizeofdata, void* seq);

int _gnutls_get_max_decrypted_data(gnutls_session_t session);

#endif
