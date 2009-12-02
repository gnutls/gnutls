/*
 * Copyright (C) 2009 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
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

#include <gnutls_errors.h>
#include <gnutls_int.h>
#include <gnutls/crypto.h>
#include <crypto.h>
#include <gnutls_mpi.h>
#include <gnutls_pk.h>
#include <random.h>
#include <gnutls_cipher_int.h>

int
gnutls_crypto_single_mac_register2 (int priority, ...)
{
      return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int gnutls_crypto_mac_register2 (int priority, ...)
{
      return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

