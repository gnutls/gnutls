/*
 *      Copyright (C) 2004 Simon Josefsson
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef GNUTLS_CIPHER_INT
# define GNUTLS_CIPHER_INT

#define cipher_hd_t gc_cipher
#define GNUTLS_CIPHER_FAILED NULL

cipher_hd_t _gnutls_cipher_init(gnutls_cipher_algorithm_t cipher,
				const gnutls_datum_t * key,
				const gnutls_datum_t * iv);
int _gnutls_cipher_encrypt(cipher_hd_t handle, void *text, int textlen);
int _gnutls_cipher_decrypt(cipher_hd_t handle, void *ciphertext,
			   int ciphertextlen);
void _gnutls_cipher_deinit(cipher_hd_t handle);

#endif				/* GNUTLS_CIPHER_INT */
