/* gc.h --- Header file for implementation agnostic crypto wrapper API.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 *
 * This file is part of GC.
 *
 * GC is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * GC is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GC; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#ifndef GC_H
#define GC_H

/* Get size_t. */
#include <stddef.h>

#define GC_MD5_LEN 16
#define GC_SHA1_LEN 20

enum Gc_rc
{
  GC_OK = 0,
  GC_MALLOC_ERROR,
  GC_INIT_ERROR,
  GC_RANDOM_ERROR,
  GC_INVALID_CIPHER,
  GC_INVALID_HASH,
  GC_PKCS5_INVALID_ITERATION_COUNT,
  GC_PKCS5_INVALID_DERIVED_KEY_LENGTH,
  GC_PKCS5_DERIVED_KEY_TOO_LONG
};
typedef enum Gc_rc Gc_rc;

enum Gc_hash
{
  GC_MD5,
  GC_SHA1,
  GC_RMD160
};
typedef enum Gc_hash Gc_hash;

enum Gc_cipher
{
  GC_AES128,
  GC_AES256,
  GC_3DES,
  GC_DES,
  GC_ARCFOUR128,
  GC_ARCFOUR40,
  GC_ARCTWO40
};
typedef enum Gc_cipher Gc_cipher;

enum Gc_cipher_mode
{
  GC_CBC,
  GC_STREAM
};
typedef enum Gc_cipher_mode Gc_cipher_mode;

enum Gc_hash_mode
{
  GC_HMAC = 1
};
typedef enum Gc_hash_mode Gc_hash_mode;

typedef void *gc_hash;
typedef void *gc_cipher;

extern int gc_init (void);
extern void gc_done (void);

/* Randomness. */
extern int gc_nonce (char *data, size_t datalen);
extern int gc_pseudo_random (char *data, size_t datalen);
extern int gc_random (char *data, size_t datalen);

/* Memory allocation (avoid). */
typedef void *(*gc_malloc_t) (size_t n);
typedef int (*gc_secure_check_t) (const void *);
typedef void *(*gc_realloc_t) (void *p, size_t n);
typedef void (*gc_free_t) (void *);
extern void gc_set_allocators (gc_malloc_t func_malloc,
			       gc_malloc_t secure_malloc,
			       gc_secure_check_t secure_check,
			       gc_realloc_t func_realloc,
			       gc_free_t func_free);

/* Ciphers. */
extern int gc_cipher_open (int cipher, int mode, gc_cipher * outhandle);
extern int gc_cipher_setkey (gc_cipher handle, size_t keylen,
			     const char *key);
extern int gc_cipher_setiv (gc_cipher handle, size_t ivlen, const char *iv);
extern int gc_cipher_encrypt_inline (gc_cipher handle, size_t len,
				     char *data);
extern int gc_cipher_decrypt_inline (gc_cipher handle, size_t len,
				     char *data);
extern int gc_cipher_close (gc_cipher handle);

/* Hashes. */
extern int gc_hash_open (int hash, int mode, gc_hash * outhandle);
extern int gc_hash_clone (gc_hash handle, gc_hash * outhandle);
extern size_t gc_hash_digest_length (int hash);
extern void gc_hash_hmac_setkey (gc_hash handle, size_t len, const char *key);
extern void gc_hash_write (gc_hash handle, size_t len, const char *data);
extern const char *gc_hash_read (gc_hash handle);
extern void gc_hash_close (gc_hash handle);

/* One-call interface. */
extern int gc_hash_buffer (int hash, const char *in, size_t inlen, char *out);
extern int gc_md5 (const char *in, size_t inlen, char out[GC_MD5_LEN]);
extern int gc_hmac_md5 (const char *key, size_t keylen,
			const char *in, size_t inlen,
			char outhash[GC_MD5_LEN]);
extern int gc_hmac_sha1 (const char *key, size_t keylen,
			 const char *in, size_t inlen,
			 char outhash[GC_SHA1_LEN]);

/* PKCS5 KDF. */
extern int gc_pkcs5_pbkdf2_sha1 (const char *P, size_t Plen,
				 const char *S, size_t Slen,
				 unsigned int c, unsigned int dkLen,
				 char *DK);

#endif /* GC_H */
