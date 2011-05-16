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
#ifndef EXT_ECC_H
#define EXT_ECC_H

#include <gnutls_extensions.h>

extern extension_entry_st ext_mod_supported_ecc;
extern extension_entry_st ext_mod_supported_ecc_pf;

int _gnutls_num_to_ecc (int num);
int _gnutls_ecc_to_num (ecc_curve_t);
int
_gnutls_session_supports_ecc_curve (gnutls_session_t session, int ecc_type);

#endif
