/*
 * Copyright (C) 2008 Free Software Foundation
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

#if INTERNAL_GNUTLS_CRYPTO_H_ENABLE_UNSUPPORTED_API

#ifndef GNUTLS_CRYPTO_H
# define GNUTLS_CRYPTO_H

typedef struct gnutls_crypto_cipher {
  int (*init)( void** ctx);
  int (*setkey)( void* ctx, const void * key, int keysize);
  int (*setiv)(void* ctx, const void* iv, int ivsize);
  int (*encrypt)(void* ctx, const void* plain, int plainsize, void* encr, int encrsize);
  int (*decrypt)(void* ctx, const void* encr, int encrsize, void* plain, int plainsize);
  void (*deinit)( void* ctx);
} gnutls_crypto_cipher_st;

typedef struct gnutls_crypto_mac {
  int (*init)( void** ctx);
  int (*setkey)( void* ctx, const void * key, int keysize);
  int (*hash)( void* ctx, const void * text, int textsize);
  int (*copy)( void** dst_ctx, void* src_ctx);
  int (*output) ( void* src_ctx, void* digest, int digestsize);
  void (*deinit)( void* ctx);
} gnutls_crypto_mac_st;

typedef enum gnutls_rnd_level
{
  GNUTLS_RND_KEY = 0,
  GNUTLS_RND_RANDOM = 1, /* unpredictable */
  GNUTLS_RND_NONCE = 2,
} gnutls_rnd_level_t;

typedef struct gnutls_crypto_rnd {
  int (*init)( void** ctx);
  int (*rnd) ( void* ctx, int /* gnutls_rnd_level_t */ level, void* data, int datasize);
  void (*deinit)( void* ctx);
} gnutls_crypto_rnd_st;

/* the same... setkey should be null */
typedef gnutls_crypto_mac_st gnutls_crypto_digest_st;

/* priority: infinity for backend algorithms, 90 for kernel algorithms - lowest wins 
 */
int gnutls_crypto_cipher_register( gnutls_cipher_algorithm_t algorithm, int priority, gnutls_crypto_cipher_st* s);
int gnutls_crypto_mac_register( gnutls_mac_algorithm_t algorithm, int priority, gnutls_crypto_mac_st* s);
int gnutls_crypto_digest_register( gnutls_digest_algorithm_t algorithm, int priority, gnutls_crypto_digest_st* s);
int gnutls_crypto_rnd_register( int priority, gnutls_crypto_rnd_st* s);

#endif

#endif
