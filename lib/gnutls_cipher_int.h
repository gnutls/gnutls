/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2008 Free Software Foundation
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

#ifndef GNUTLS_CIPHER_INT
# define GNUTLS_CIPHER_INT

#include <gnutls/crypto.h>

extern int crypto_cipher_prio;
extern gnutls_crypto_cipher_st _gnutls_cipher_ops;

typedef struct {
  gnutls_crypto_single_cipher_st* cc;
  void* ctx;
} reg_hd;

typedef struct {
	int registered; /* true or false(0) */
	union {
		void* gc; /* when not registered */
		reg_hd rh; /* when registered */
	} hd;
} cipher_hd_st;

int _gnutls_cipher_init (cipher_hd_st*, gnutls_cipher_algorithm_t cipher,
				 const gnutls_datum_t * key,
				 const gnutls_datum_t * iv);
int _gnutls_cipher_encrypt (const cipher_hd_st *handle, void *text, int textlen);
int _gnutls_cipher_decrypt (const cipher_hd_st *handle, void *ciphertext,
			    int ciphertextlen);
void _gnutls_cipher_deinit (cipher_hd_st* handle);

#endif /* GNUTLS_CIPHER_INT */
