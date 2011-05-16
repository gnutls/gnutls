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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#ifndef AUTH_ECDH_COMMON
#define AUTH_ECDH_COMMON

#include <gnutls_auth.h>

int _gnutls_gen_ecdh_common_client_kx (gnutls_session_t, gnutls_buffer_st*);
int _gnutls_proc_ecdh_common_client_kx (gnutls_session_t session,
                                      opaque * data, size_t _data_size,
                                      ecc_curve_t curve);
int _gnutls_ecdh_common_print_server_kx (gnutls_session_t, gnutls_buffer_st* data,
                                         ecc_curve_t curve);
int _gnutls_proc_ecdh_common_server_kx (gnutls_session_t session, opaque * data,
                                      size_t _data_size);



#endif
