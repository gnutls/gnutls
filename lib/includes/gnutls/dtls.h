/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 *
 */

/* This file contains the types and prototypes for the X.509
 * certificate and CRL handling functions.
 */

#ifndef GNUTLS_DTLS_H
#define GNUTLS_DTLS_H

#include <gnutls/gnutls.h>

#ifdef __cplusplus
extern "C"
{
#endif

void gnutls_dtls_set_timeouts (gnutls_session_t session, unsigned int retrans_timeout,
  unsigned int total_timeout);

unsigned int gnutls_dtls_get_mtu (gnutls_session_t session);
void gnutls_dtls_set_mtu (gnutls_session_t session, unsigned int mtu);

#ifdef __cplusplus
}
#endif

#endif                          /* GNUTLS_DTLS_H */

