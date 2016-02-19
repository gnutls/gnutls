/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* Here lie nettle's wrappers for cipher support.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>
#include <nettle/aes.h>
#include <nettle/camellia.h>
#include <nettle/arcfour.h>
#include <nettle/arctwo.h>
#include <nettle/salsa20.h>
#include <nettle/des.h>
#include <nettle/nettle-meta.h>
#include <nettle/cbc.h>
#include <nettle/gcm.h>
#ifndef USE_NETTLE3
#include <gcm-camellia.h>
#endif
#include <fips.h>
#include "gnettle.h"

/* Functions that refer to the nettle library.
 */

#define MAX_BLOCK_SIZE 32

#ifdef USE_NETTLE3
typedef void (*encrypt_func) (void *, nettle_cipher_func, size_t,
			      uint8_t *, size_t, uint8_t *,
			      const uint8_t *);
typedef void (*decrypt_func) (void *, nettle_cipher_func, size_t,
			      uint8_t *, size_t, uint8_t *,
			      const uint8_t *);
typedef void (*auth_func) (void *, size_t, const uint8_t *);

typedef void (*tag_func) (void *, size_t, uint8_t *);

#else
typedef void (*encrypt_func) (void *, nettle_crypt_func, unsigned,
			      uint8_t *, unsigned, uint8_t *,
			      const uint8_t *);
typedef void (*decrypt_func) (void *, nettle_crypt_func, unsigned,
			      uint8_t *, unsigned, uint8_t *,
			      const uint8_t *);
typedef void (*auth_func) (void *, unsigned, const uint8_t *);

typedef void (*tag_func) (void *, unsigned, uint8_t *);

#endif
typedef void (*setkey_func) (void *, unsigned, const uint8_t *);

#ifdef USE_NETTLE3
static void
stream_encrypt(void *ctx, nettle_cipher_func func, size_t block_size,
	       uint8_t * iv, size_t length, uint8_t * dst,
	       const uint8_t * src)
#else
static void
stream_encrypt(void *ctx, nettle_crypt_func func, unsigned block_size,
	       uint8_t * iv, unsigned length, uint8_t * dst,
	       const uint8_t * src)
#endif
{
	func(ctx, length, dst, src);
}

struct nettle_cipher_ctx {
	union {
		struct aes_ctx aes;
#ifdef USE_NETTLE3
		struct camellia128_ctx camellia128;
		struct camellia192_ctx camellia192;
		struct camellia256_ctx camellia256;
		struct gcm_camellia128_ctx camellia128_gcm;
		struct gcm_camellia256_ctx camellia256_gcm;
#else
		struct camellia_ctx camellia;
		struct _gcm_camellia_ctx camellia_gcm;
#endif
		struct arcfour_ctx arcfour;
		struct arctwo_ctx arctwo;
		struct des3_ctx des3;
		struct des_ctx des;
		struct gcm_aes_ctx aes_gcm;
		struct salsa20_ctx salsa20;
	} ctx;
	void *ctx_ptr;
	uint8_t iv[MAX_BLOCK_SIZE];
	gnutls_cipher_algorithm_t algo;
	size_t block_size;
#ifdef  USE_NETTLE3
	nettle_cipher_func *i_encrypt;
	nettle_cipher_func *i_decrypt;
#else
	nettle_crypt_func *i_encrypt;
	nettle_crypt_func *i_decrypt;
#endif
	encrypt_func encrypt;
	decrypt_func decrypt;
	auth_func auth;
	tag_func tag;
	int enc;
};

#ifdef USE_NETTLE3
static void _aes_gcm_encrypt(void *_ctx, nettle_cipher_func * f,
			     size_t block_size, uint8_t * iv,
			     size_t length, uint8_t * dst,
 			     const uint8_t * src)
#else
static void _aes_gcm_encrypt(void *_ctx, nettle_crypt_func f,
			     unsigned block_size, uint8_t * iv,
			     unsigned length, uint8_t * dst,
			     const uint8_t * src)
#endif
{
	gcm_aes_encrypt(_ctx, length, dst, src);
}

#ifdef USE_NETTLE3
static void _aes_gcm_decrypt(void *_ctx, nettle_cipher_func * f,
			     size_t block_size, uint8_t * iv,
			     size_t length, uint8_t * dst,
 			     const uint8_t * src)
#else
static void _aes_gcm_decrypt(void *_ctx, nettle_crypt_func f,
			     unsigned block_size, uint8_t * iv,
			     unsigned length, uint8_t * dst,
			     const uint8_t * src)
#endif
{
	gcm_aes_decrypt(_ctx, length, dst, src);
}

#ifdef USE_NETTLE3
static void _camellia128_gcm_encrypt(void *_ctx, nettle_cipher_func * f,
				  size_t block_size, uint8_t * iv,
				  size_t length, uint8_t * dst,
 				  const uint8_t * src)
{
	gcm_camellia128_encrypt(_ctx, length, dst, src);
}

static void _camellia128_gcm_decrypt(void *_ctx, nettle_cipher_func * f,
				  size_t block_size, uint8_t * iv,
				  size_t length, uint8_t * dst,
				  const uint8_t * src)
{
	gcm_camellia128_decrypt(_ctx, length, dst, src);
}

static void _camellia256_gcm_encrypt(void *_ctx, nettle_cipher_func * f,
				  size_t block_size, uint8_t * iv,
				  size_t length, uint8_t * dst,
				  const uint8_t * src)
{
	gcm_camellia256_encrypt(_ctx, length, dst, src);
}

static void _camellia256_gcm_decrypt(void *_ctx, nettle_cipher_func * f,
				  size_t block_size, uint8_t * iv,
				  size_t length, uint8_t * dst,
				  const uint8_t * src)
{
	gcm_camellia256_decrypt(_ctx, length, dst, src);
}
#else
static void _camellia_gcm_encrypt(void *_ctx, nettle_crypt_func f,
				  unsigned block_size, uint8_t * iv,
				  unsigned length, uint8_t * dst,
				  const uint8_t * src)
{
	_gcm_camellia_encrypt(_ctx, length, dst, src);
}

static void _camellia_gcm_decrypt(void *_ctx, nettle_crypt_func f,
				  unsigned block_size, uint8_t * iv,
				  unsigned length, uint8_t * dst,
				  const uint8_t * src)
{
	_gcm_camellia_decrypt(_ctx, length, dst, src);
}
#endif

static int wrap_nettle_cipher_exists(gnutls_cipher_algorithm_t algo)
{
	switch (algo) {
	case GNUTLS_CIPHER_AES_128_GCM:
	case GNUTLS_CIPHER_AES_256_GCM:
	case GNUTLS_CIPHER_AES_128_CBC:
	case GNUTLS_CIPHER_AES_192_CBC:
	case GNUTLS_CIPHER_AES_256_CBC:
	case GNUTLS_CIPHER_3DES_CBC:
		return 1;
	case GNUTLS_CIPHER_CAMELLIA_128_GCM:
	case GNUTLS_CIPHER_CAMELLIA_256_GCM:
	case GNUTLS_CIPHER_CAMELLIA_128_CBC:
	case GNUTLS_CIPHER_CAMELLIA_192_CBC:
	case GNUTLS_CIPHER_CAMELLIA_256_CBC:
	case GNUTLS_CIPHER_DES_CBC:
	case GNUTLS_CIPHER_ARCFOUR_128:
	case GNUTLS_CIPHER_SALSA20_256:
	case GNUTLS_CIPHER_ESTREAM_SALSA20_256:
	case GNUTLS_CIPHER_ARCFOUR_40:
	case GNUTLS_CIPHER_RC2_40_CBC:
		if (_gnutls_fips_mode_enabled() != 0)
			return 0;
		else
			return 1;
	default:
		return 0;
	}
}

static int
wrap_nettle_cipher_init(gnutls_cipher_algorithm_t algo, void **_ctx,
			int enc)
{
	struct nettle_cipher_ctx *ctx;

	ctx = gnutls_calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ctx->algo = algo;
	ctx->enc = enc;

	switch (algo) {
	case GNUTLS_CIPHER_AES_128_GCM:
	case GNUTLS_CIPHER_AES_256_GCM:
		ctx->encrypt = _aes_gcm_encrypt;
		ctx->decrypt = _aes_gcm_decrypt;
#ifdef USE_NETTLE3
		ctx->i_encrypt = (nettle_cipher_func *) aes_encrypt;
#else
		ctx->i_encrypt = (nettle_crypt_func *) aes_encrypt;
#endif
		ctx->auth = (auth_func) gcm_aes_update;
		ctx->tag = (tag_func) gcm_aes_digest;
		ctx->ctx_ptr = &ctx->ctx.aes_gcm;
		ctx->block_size = AES_BLOCK_SIZE;
		break;
	case GNUTLS_CIPHER_AES_128_CBC:
	case GNUTLS_CIPHER_AES_192_CBC:
	case GNUTLS_CIPHER_AES_256_CBC:
#ifdef USE_NETTLE3
		ctx->encrypt = (encrypt_func) cbc_encrypt;
		ctx->decrypt = (decrypt_func) cbc_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) aes_encrypt;
		ctx->i_decrypt = (nettle_cipher_func *) aes_decrypt;
#else
		ctx->encrypt = cbc_encrypt;
		ctx->decrypt = cbc_decrypt;
		ctx->i_encrypt = (nettle_crypt_func *) aes_encrypt;
		ctx->i_decrypt = (nettle_crypt_func *) aes_decrypt;
#endif
		ctx->ctx_ptr = &ctx->ctx.aes;
		ctx->block_size = AES_BLOCK_SIZE;
		break;
	case GNUTLS_CIPHER_3DES_CBC:
#ifdef USE_NETTLE3
		ctx->encrypt = (encrypt_func) cbc_encrypt;
		ctx->decrypt = (decrypt_func) cbc_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) des3_encrypt;
		ctx->i_decrypt = (nettle_cipher_func *) des3_decrypt;
#else
		ctx->encrypt = cbc_encrypt;
		ctx->decrypt = cbc_decrypt;
		ctx->i_encrypt = (nettle_crypt_func *) des3_encrypt;
		ctx->i_decrypt = (nettle_crypt_func *) des3_decrypt;
#endif
		ctx->ctx_ptr = &ctx->ctx.des3;
		ctx->block_size = DES3_BLOCK_SIZE;
		break;
	case GNUTLS_CIPHER_CAMELLIA_128_GCM:
#ifdef USE_NETTLE3
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		ctx->encrypt = _camellia128_gcm_encrypt;
		ctx->decrypt = _camellia128_gcm_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) camellia128_crypt;
		ctx->auth = (auth_func) gcm_camellia128_update;
		ctx->tag = (tag_func) gcm_camellia128_digest;
		ctx->ctx_ptr = &ctx->ctx.camellia128_gcm;
		ctx->block_size = CAMELLIA_BLOCK_SIZE;
		break;
#endif
	case GNUTLS_CIPHER_CAMELLIA_256_GCM:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

#ifdef USE_NETTLE3
		ctx->encrypt = _camellia256_gcm_encrypt;
		ctx->decrypt = _camellia256_gcm_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) camellia256_crypt;
		ctx->auth = (auth_func) gcm_camellia256_update;
		ctx->tag = (tag_func) gcm_camellia256_digest;
		ctx->ctx_ptr = &ctx->ctx.camellia256_gcm;
#else
		ctx->encrypt = _camellia_gcm_encrypt;
		ctx->decrypt = _camellia_gcm_decrypt;
		ctx->i_encrypt = (nettle_crypt_func *) camellia_crypt;
		ctx->auth = (auth_func) _gcm_camellia_update;
		ctx->tag = (tag_func) _gcm_camellia_digest;
		ctx->ctx_ptr = &ctx->ctx.camellia_gcm;
#endif
		ctx->block_size = CAMELLIA_BLOCK_SIZE;
		break;
	case GNUTLS_CIPHER_CAMELLIA_128_CBC:
#ifdef USE_NETTLE3
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		ctx->encrypt = (encrypt_func) cbc_encrypt;
		ctx->decrypt = (decrypt_func) cbc_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) camellia128_crypt;
		ctx->i_decrypt = (nettle_cipher_func *) camellia128_crypt;
		ctx->ctx_ptr = &ctx->ctx.camellia128;
		ctx->block_size = CAMELLIA_BLOCK_SIZE;
		break;
#endif
	case GNUTLS_CIPHER_CAMELLIA_192_CBC:
#ifdef USE_NETTLE3
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		ctx->encrypt = (encrypt_func) cbc_encrypt;
		ctx->decrypt = (decrypt_func) cbc_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) camellia192_crypt;
		ctx->i_decrypt = (nettle_cipher_func *) camellia192_crypt;
		ctx->ctx_ptr = &ctx->ctx.camellia192;
		ctx->block_size = CAMELLIA_BLOCK_SIZE;
		break;
#endif
	case GNUTLS_CIPHER_CAMELLIA_256_CBC:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

#ifdef USE_NETTLE3
		ctx->encrypt = (encrypt_func) cbc_encrypt;
		ctx->decrypt = (decrypt_func) cbc_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) camellia256_crypt;
		ctx->i_decrypt = (nettle_cipher_func *) camellia256_crypt;
		ctx->ctx_ptr = &ctx->ctx.camellia256;
#else
		ctx->encrypt = cbc_encrypt;
		ctx->decrypt = cbc_decrypt;
		ctx->i_encrypt = (nettle_crypt_func *) camellia_crypt;
		ctx->i_decrypt = (nettle_crypt_func *) camellia_crypt;
		ctx->ctx_ptr = &ctx->ctx.camellia;
#endif
		ctx->block_size = CAMELLIA_BLOCK_SIZE;
		break;
	case GNUTLS_CIPHER_DES_CBC:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
#ifdef USE_NETTLE3
		ctx->encrypt = (encrypt_func) cbc_encrypt;
		ctx->decrypt = (decrypt_func) cbc_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) des_encrypt;
		ctx->i_decrypt = (nettle_cipher_func *) des_decrypt;
#else
		ctx->encrypt = cbc_encrypt;
		ctx->decrypt = cbc_decrypt;
		ctx->i_encrypt = (nettle_crypt_func *) des_encrypt;
		ctx->i_decrypt = (nettle_crypt_func *) des_decrypt;
#endif
		ctx->ctx_ptr = &ctx->ctx.des;
		ctx->block_size = DES_BLOCK_SIZE;
		break;
	case GNUTLS_CIPHER_ARCFOUR_128:
	case GNUTLS_CIPHER_ARCFOUR_40:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		ctx->encrypt = stream_encrypt;
		ctx->decrypt = stream_encrypt;
#ifdef USE_NETTLE3
		ctx->i_encrypt = (nettle_cipher_func *) arcfour_crypt;
		ctx->i_decrypt = (nettle_cipher_func *) arcfour_crypt;
#else
		ctx->i_encrypt = (nettle_crypt_func *) arcfour_crypt;
		ctx->i_decrypt = (nettle_crypt_func *) arcfour_crypt;
#endif
		ctx->ctx_ptr = &ctx->ctx.arcfour;
		ctx->block_size = 1;
		break;
	case GNUTLS_CIPHER_SALSA20_256:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		ctx->encrypt = stream_encrypt;
		ctx->decrypt = stream_encrypt;
#ifdef USE_NETTLE3
		ctx->i_encrypt = (nettle_cipher_func *) salsa20_crypt;
		ctx->i_decrypt = (nettle_cipher_func *) salsa20_crypt;
#else
		ctx->i_encrypt = (nettle_crypt_func *) salsa20_crypt;
		ctx->i_decrypt = (nettle_crypt_func *) salsa20_crypt;
#endif
		ctx->ctx_ptr = &ctx->ctx.salsa20;
		ctx->block_size = 1;
		break;
	case GNUTLS_CIPHER_ESTREAM_SALSA20_256:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		ctx->encrypt = stream_encrypt;
		ctx->decrypt = stream_encrypt;
#ifdef USE_NETTLE3
		ctx->i_encrypt = (nettle_cipher_func *) salsa20r12_crypt;
		ctx->i_decrypt = (nettle_cipher_func *) salsa20r12_crypt;
#else
		ctx->i_encrypt = (nettle_crypt_func *) salsa20r12_crypt;
		ctx->i_decrypt = (nettle_crypt_func *) salsa20r12_crypt;
#endif
		ctx->ctx_ptr = &ctx->ctx.salsa20;
		ctx->block_size = 1;
		break;
	case GNUTLS_CIPHER_RC2_40_CBC:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

#ifdef USE_NETTLE3
		ctx->encrypt = (encrypt_func) cbc_encrypt;
		ctx->decrypt = (decrypt_func) cbc_decrypt;
		ctx->i_encrypt = (nettle_cipher_func *) arctwo_encrypt;
		ctx->i_decrypt = (nettle_cipher_func *) arctwo_decrypt;
#else
		ctx->encrypt = cbc_encrypt;
		ctx->decrypt = cbc_decrypt;
		ctx->i_encrypt = (nettle_crypt_func *) arctwo_encrypt;
		ctx->i_decrypt = (nettle_crypt_func *) arctwo_decrypt;
#endif
		ctx->ctx_ptr = &ctx->ctx.arctwo;
		ctx->block_size = ARCTWO_BLOCK_SIZE;
		break;
	default:
		gnutls_assert();
		gnutls_free(ctx);
		return GNUTLS_E_INVALID_REQUEST;
	}

	*_ctx = ctx;

	return 0;
}

static int
wrap_nettle_cipher_setkey(void *_ctx, const void *key, size_t keysize)
{
	struct nettle_cipher_ctx *ctx = _ctx;
	uint8_t des_key[DES3_KEY_SIZE];

	switch (ctx->algo) {
	case GNUTLS_CIPHER_AES_128_GCM:
	case GNUTLS_CIPHER_AES_256_GCM:
		gcm_aes_set_key(&ctx->ctx.aes_gcm, keysize, key);
		break;
	case GNUTLS_CIPHER_AES_128_CBC:
	case GNUTLS_CIPHER_AES_192_CBC:
	case GNUTLS_CIPHER_AES_256_CBC:
		if (ctx->enc)
			aes_set_encrypt_key(ctx->ctx_ptr, keysize, key);
		else
			aes_set_decrypt_key(ctx->ctx_ptr, keysize, key);
		break;
	case GNUTLS_CIPHER_CAMELLIA_128_CBC:
#ifdef USE_NETTLE3
		if (ctx->enc)
			camellia128_set_encrypt_key(ctx->ctx_ptr,
						 key);
		else
			camellia128_set_decrypt_key(ctx->ctx_ptr,
						 key);
		break;
#endif
	case GNUTLS_CIPHER_CAMELLIA_192_CBC:
#ifdef USE_NETTLE3
		if (ctx->enc)
			camellia192_set_encrypt_key(ctx->ctx_ptr,
						 key);
		else
			camellia192_set_decrypt_key(ctx->ctx_ptr,
						 key);
		break;
#endif
	case GNUTLS_CIPHER_CAMELLIA_256_CBC:
#ifdef USE_NETTLE3
		if (ctx->enc)
			camellia256_set_encrypt_key(ctx->ctx_ptr,
						 key);
		else
			camellia256_set_decrypt_key(ctx->ctx_ptr,
						 key);
		break;
#else
		if (ctx->enc)
			camellia_set_encrypt_key(ctx->ctx_ptr, keysize,
						 key);
		else
			camellia_set_decrypt_key(ctx->ctx_ptr, keysize,
						 key);
		break;
#endif
	case GNUTLS_CIPHER_3DES_CBC:
		if (keysize != DES3_KEY_SIZE) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}

		des_fix_parity(keysize, des_key, key);

		if (des3_set_key(ctx->ctx_ptr, des_key) != 1) {
			gnutls_assert();
		}
		zeroize_temp_key(des_key, sizeof(des_key));

		break;
	case GNUTLS_CIPHER_CAMELLIA_128_GCM:
#ifdef USE_NETTLE3
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		gcm_camellia128_set_key(&ctx->ctx.camellia128_gcm, key);
		break;
#endif
	case GNUTLS_CIPHER_CAMELLIA_256_GCM:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

#ifdef USE_NETTLE3
		gcm_camellia256_set_key(&ctx->ctx.camellia256_gcm, key);
#else
		_gcm_camellia_set_key(&ctx->ctx.camellia_gcm, keysize,
				      key);
#endif
		break;
	case GNUTLS_CIPHER_DES_CBC:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		if (keysize != DES_KEY_SIZE) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}

		des_fix_parity(keysize, des_key, key);

		if (des_set_key(ctx->ctx_ptr, des_key) != 1) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}
		zeroize_temp_key(des_key, sizeof(des_key));
		break;
	case GNUTLS_CIPHER_ARCFOUR_128:
	case GNUTLS_CIPHER_ARCFOUR_40:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		arcfour_set_key(ctx->ctx_ptr, keysize, key);
		break;
	case GNUTLS_CIPHER_SALSA20_256:
	case GNUTLS_CIPHER_ESTREAM_SALSA20_256:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		salsa20_set_key(ctx->ctx_ptr, keysize, key);
		break;
	case GNUTLS_CIPHER_RC2_40_CBC:
		if (_gnutls_fips_mode_enabled() != 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		arctwo_set_key(ctx->ctx_ptr, keysize, key);
		break;
	default:
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	return 0;
}

static int
wrap_nettle_cipher_setiv(void *_ctx, const void *iv, size_t ivsize)
{
	struct nettle_cipher_ctx *ctx = _ctx;

	switch (ctx->algo) {
	case GNUTLS_CIPHER_AES_128_GCM:
	case GNUTLS_CIPHER_AES_256_GCM:
		if (_gnutls_fips_mode_enabled() != 0 && ivsize < GCM_IV_SIZE)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		gcm_aes_set_iv(&ctx->ctx.aes_gcm, 
				ivsize, iv);
		break;
	case GNUTLS_CIPHER_CAMELLIA_128_GCM:
#ifdef USE_NETTLE3
		gcm_camellia128_set_iv(&ctx->ctx.camellia128_gcm,
				     ivsize, iv);
		break;
#endif
	case GNUTLS_CIPHER_CAMELLIA_256_GCM:
#ifdef USE_NETTLE3
		gcm_camellia256_set_iv(&ctx->ctx.camellia256_gcm,
 				     ivsize, iv);
#else
		_gcm_camellia_set_iv(&ctx->ctx.camellia_gcm,
				     ivsize, iv);
#endif
		break;
	case GNUTLS_CIPHER_SALSA20_256:
	case GNUTLS_CIPHER_ESTREAM_SALSA20_256:
		if (ivsize != SALSA20_IV_SIZE)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		salsa20_set_iv(&ctx->ctx.salsa20, iv);
		break;
	default:
		if (ivsize > ctx->block_size)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		memcpy(ctx->iv, iv, ivsize);
	}

	return 0;
}

static int
wrap_nettle_cipher_decrypt(void *_ctx, const void *encr, size_t encrsize,
			   void *plain, size_t plainsize)
{
	struct nettle_cipher_ctx *ctx = _ctx;

#ifndef USE_NETTLE3
	if (encrsize > UINT_MAX)
		return gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);
#endif

	ctx->decrypt(ctx->ctx_ptr, ctx->i_decrypt, ctx->block_size,
		     ctx->iv, encrsize, plain, encr);

	return 0;
}

static int
wrap_nettle_cipher_encrypt(void *_ctx, const void *plain, size_t plainsize,
			   void *encr, size_t encrsize)
{
	struct nettle_cipher_ctx *ctx = _ctx;

#ifndef USE_NETTLE3
	if (plainsize > UINT_MAX)
		return gnutls_assert_val(GNUTLS_E_ENCRYPTION_FAILED);
#endif

	ctx->encrypt(ctx->ctx_ptr, ctx->i_encrypt, ctx->block_size,
		     ctx->iv, plainsize, encr, plain);

	return 0;
}

static int
wrap_nettle_cipher_auth(void *_ctx, const void *plain, size_t plainsize)
{
	struct nettle_cipher_ctx *ctx = _ctx;

	ctx->auth(ctx->ctx_ptr, plainsize, plain);

	return 0;
}

static void wrap_nettle_cipher_tag(void *_ctx, void *tag, size_t tagsize)
{
	struct nettle_cipher_ctx *ctx = _ctx;

	ctx->tag(ctx->ctx_ptr, tagsize, tag);

}

static void wrap_nettle_cipher_close(void *_ctx)
{
	struct nettle_cipher_ctx *ctx = _ctx;

	zeroize_temp_key(ctx, sizeof(*ctx));
	gnutls_free(ctx);
}

gnutls_crypto_cipher_st _gnutls_cipher_ops = {
	.init = wrap_nettle_cipher_init,
	.exists = wrap_nettle_cipher_exists,
	.setiv = wrap_nettle_cipher_setiv,
	.setkey = wrap_nettle_cipher_setkey,
	.encrypt = wrap_nettle_cipher_encrypt,
	.decrypt = wrap_nettle_cipher_decrypt,
	.deinit = wrap_nettle_cipher_close,
	.auth = wrap_nettle_cipher_auth,
	.tag = wrap_nettle_cipher_tag,
};
