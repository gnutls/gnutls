/* -*- c -*-
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* This file contains the types and prototypes for all the
 * high level functionality of the gnutls main library.
 *
 * If the optional C++ binding was built, it is available in
 * gnutls/gnutlsxx.h.
 *
 * The openssl compatibility layer (which is under the GNU GPL
 * license) is in gnutls/openssl.h.
 *
 * The low level cipher functionality is in gnutls/crypto.h.
 */


#ifndef GNUTLS_FIPS140_H
#define GNUTLS_FIPS140_H

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */


int gnutls_fips140_mode_enabled(void);


/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif
