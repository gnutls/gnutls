/*
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

#ifndef GNUTLS_HASH_INT_H
# define GNUTLS_HASH_INT_H

#include <gnutls_int.h>

#ifdef USE_MHASH
# include <mhash.h>
#endif

/* for message digests */

typedef struct {
#ifdef USE_MHASH
	MHASH handle;
#else
	GCRY_MD_HD handle;
#endif
	MACAlgorithm algorithm;
	void* key;
	int keysize;
} GNUTLS_MAC_HANDLE_INT;
typedef GNUTLS_MAC_HANDLE_INT* GNUTLS_MAC_HANDLE;
typedef GNUTLS_MAC_HANDLE GNUTLS_HASH_HANDLE;

#define GNUTLS_HASH_FAILED NULL
#define GNUTLS_MAC_FAILED NULL

GNUTLS_MAC_HANDLE gnutls_hmac_init( MACAlgorithm algorithm, void* key, int keylen);
int gnutls_hmac_get_algo_len(MACAlgorithm algorithm);
int gnutls_hmac(GNUTLS_MAC_HANDLE handle, const void* text, int textlen);
void gnutls_hmac_deinit( GNUTLS_MAC_HANDLE handle, void* digest);

GNUTLS_MAC_HANDLE gnutls_mac_init_ssl3( MACAlgorithm algorithm, void* key, int keylen);
void gnutls_mac_deinit_ssl3( GNUTLS_MAC_HANDLE handle, void* digest);

GNUTLS_HASH_HANDLE gnutls_hash_init(MACAlgorithm algorithm);
int gnutls_hash_get_algo_len(MACAlgorithm algorithm);
int gnutls_hash(GNUTLS_HASH_HANDLE handle, const void* text, int textlen);
void gnutls_hash_deinit(GNUTLS_HASH_HANDLE handle, void* digest);

int gnutls_ssl3_generate_random(void *secret, int secret_len, void *random, int random_len, int bytes, opaque* ret);

void gnutls_mac_deinit_ssl3_handshake(GNUTLS_MAC_HANDLE handle, void* digest, opaque* key, uint32 key_size);

GNUTLS_HASH_HANDLE gnutls_hash_copy(GNUTLS_HASH_HANDLE handle);

#endif /* GNUTLS_HASH_INT_H */
