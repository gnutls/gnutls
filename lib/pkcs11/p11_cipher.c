/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Author: Zoltan Fridrich
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "gnutls_int.h"
#include "cipher_int.h"
#include "p11_cipher.h"
#include "p11_provider.h"

#include <minmax.h>

#define P11_KIT_FUTURE_UNSTABLE_API
#include <p11-kit/iter.h>
#include "pkcs11_int.h"

struct p11_cipher_ctx;
typedef int (*init_params_func)(struct p11_cipher_ctx *ctx);
typedef int (*set_params_func)(struct p11_cipher_ctx *ctx, const void *iv,
			       size_t iv_size, const void *auth,
			       size_t auth_size, size_t tag_size);
typedef void (*free_params_func)(struct p11_cipher_ctx *ctx);
typedef int (*get_iv_func)(struct p11_cipher_ctx *ctx, void *iv,
			   size_t iv_size);
typedef int (*set_key_func)(struct p11_cipher_ctx *ctx, const void *key,
			    size_t key_size);

struct p11_cipher_st {
	gnutls_cipher_algorithm_t alg;
	ck_mechanism_type_t mech;

	size_t key_size;
	size_t max_iv_size;

	init_params_func init_params;
	set_params_func set_params;
	free_params_func free_params;
	get_iv_func get_iv;
	set_key_func set_encrypt_key;
	set_key_func set_decrypt_key;

	bool available;
};

union p11_cipher_params {
	uint8_t iv[MAX_CIPHER_IV_SIZE];
	struct ck_gcm_params gcm;
};

struct p11_cipher_ctx {
	const struct p11_cipher_st *cipher;
	ck_session_handle_t session;
	bool enc;
	union p11_cipher_params params;
	size_t params_size;
	ck_object_handle_t key;
};

/*************************************************/
/****** PKCS#11 Cipher specific functions ********/
/*************************************************/

static int init_iv_params(struct p11_cipher_ctx *ctx)
{
	gnutls_memset(&ctx->params, 0, sizeof(ctx->params));
	ctx->params_size = 0;
	return 0;
}

static void free_iv_params(struct p11_cipher_ctx *ctx)
{
	init_iv_params(ctx);
}

static int set_iv_params(struct p11_cipher_ctx *ctx, const void *iv,
			 size_t iv_size, const void *auth, size_t auth_size,
			 size_t tag_size)
{
	if (iv_size != ctx->cipher->max_iv_size)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	memcpy(ctx->params.iv, iv, iv_size);
	ctx->params_size = iv_size;
	return 0;
}

static int get_iv_params(struct p11_cipher_ctx *ctx, void *iv, size_t iv_size)
{
	if (iv_size < ctx->params_size)
		return gnutls_assert_val(GNUTLS_E_SHORT_MEMORY_BUFFER);

	memcpy(iv, ctx->params.iv, ctx->params_size);
	return (int)ctx->params_size;
}

static int init_gcm_params(struct p11_cipher_ctx *ctx)
{
	gnutls_memset(&ctx->params, 0, sizeof(ctx->params));
	ctx->params_size = sizeof(struct ck_gcm_params);
	return 0;
}

static void free_gcm_params(struct p11_cipher_ctx *ctx)
{
	gnutls_free(ctx->params.gcm.iv_ptr);
	gnutls_free(ctx->params.gcm.aad_ptr);
	init_gcm_params(ctx);
}

static int set_gcm_params(struct p11_cipher_ctx *ctx, const void *iv,
			  size_t iv_size, const void *auth, size_t auth_size,
			  size_t tag_size)
{
	uint8_t *_iv = NULL;
	uint8_t *_auth = NULL;

	if (iv_size == 0 || iv_size > ctx->cipher->max_iv_size || tag_size > 16)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	_iv = gnutls_malloc(iv_size);
	if (_iv == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	memcpy(_iv, iv, iv_size);

	if (auth_size != 0) {
		_auth = gnutls_malloc(auth_size);
		if (_auth == NULL) {
			gnutls_free(_iv);
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		}
		memcpy(_auth, auth, auth_size);
	}

	free_gcm_params(ctx);
	ctx->params.gcm.iv_ptr = _iv;
	ctx->params.gcm.iv_len = iv_size;
	ctx->params.gcm.aad_ptr = _auth;
	ctx->params.gcm.aad_len = auth_size;
	ctx->params.gcm.tag_bits = tag_size * 8;
	return 0;
}

static int get_gcm_iv_params(struct p11_cipher_ctx *ctx, void *iv,
			     size_t iv_size)
{
	if (ctx->params.gcm.iv_ptr == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	if (iv_size < ctx->params.gcm.iv_len)
		return gnutls_assert_val(GNUTLS_E_SHORT_MEMORY_BUFFER);

	memcpy(iv, ctx->params.gcm.iv_ptr, ctx->params.gcm.iv_len);
	return (int)ctx->params.gcm.iv_len;
}

static int aes_set_key(struct p11_cipher_ctx *ctx, const void *key,
		       size_t key_size)
{
	ck_rv_t rv;
	struct ck_function_list *module = _p11_provider_get_module();
	ck_object_handle_t obj = CK_INVALID_HANDLE;
	ck_object_class_t attr_class = CKO_SECRET_KEY;
	ck_key_type_t attr_key_type = CKK_AES;
	bool attr_true = true;
	unsigned char label[] = "AES secret key";
	struct ck_attribute attrs[] = {
		{ CKA_CLASS, &attr_class, sizeof(attr_class) },
		{ CKA_KEY_TYPE, &attr_key_type, sizeof(attr_key_type) },
		{ CKA_TOKEN, &attr_true, sizeof(attr_true) },
		{ CKA_ENCRYPT, &attr_true, sizeof(attr_true) },
		{ CKA_DECRYPT, &attr_true, sizeof(attr_true) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, (unsigned char *)key, key_size }
	};
	unsigned long n_attrs = sizeof(attrs) / sizeof(attrs[0]);

	if (key_size != ctx->cipher->key_size)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	rv = module->C_CreateObject(ctx->session, attrs, n_attrs, &obj);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	ctx->key = obj;
	return 0;
}

#define P11_CIPHERS_COUNT (sizeof(p11_ciphers) / sizeof(p11_ciphers[0]))
static struct p11_cipher_st p11_ciphers[] = {
	{
		.alg = GNUTLS_CIPHER_AES_128_CBC,
		.mech = CKM_AES_CBC,
		.key_size = 16,
		.max_iv_size = 16,
		.init_params = init_iv_params,
		.set_params = set_iv_params,
		.free_params = free_iv_params,
		.get_iv = get_iv_params,
		.set_encrypt_key = aes_set_key,
		.set_decrypt_key = aes_set_key,
	},
	{
		.alg = GNUTLS_CIPHER_AES_192_CBC,
		.mech = CKM_AES_CBC,
		.key_size = 24,
		.max_iv_size = 16,
		.init_params = init_iv_params,
		.set_params = set_iv_params,
		.free_params = free_iv_params,
		.get_iv = get_iv_params,
		.set_encrypt_key = aes_set_key,
		.set_decrypt_key = aes_set_key,
	},
	{
		.alg = GNUTLS_CIPHER_AES_256_CBC,
		.mech = CKM_AES_CBC,
		.key_size = 32,
		.max_iv_size = 16,
		.init_params = init_iv_params,
		.set_params = set_iv_params,
		.free_params = free_iv_params,
		.get_iv = get_iv_params,
		.set_encrypt_key = aes_set_key,
		.set_decrypt_key = aes_set_key,
	},
	{
		.alg = GNUTLS_CIPHER_AES_128_GCM,
		.mech = CKM_AES_GCM,
		.key_size = 16,
		.max_iv_size = 12,
		.init_params = init_gcm_params,
		.set_params = set_gcm_params,
		.free_params = free_gcm_params,
		.get_iv = get_gcm_iv_params,
		.set_encrypt_key = aes_set_key,
		.set_decrypt_key = aes_set_key,
	},
	{
		.alg = GNUTLS_CIPHER_AES_192_GCM,
		.mech = CKM_AES_GCM,
		.key_size = 24,
		.max_iv_size = 12,
		.init_params = init_gcm_params,
		.set_params = set_gcm_params,
		.free_params = free_gcm_params,
		.get_iv = get_gcm_iv_params,
		.set_encrypt_key = aes_set_key,
		.set_decrypt_key = aes_set_key,
	},
	{
		.alg = GNUTLS_CIPHER_AES_256_GCM,
		.mech = CKM_AES_GCM,
		.key_size = 32,
		.max_iv_size = 12,
		.init_params = init_gcm_params,
		.set_params = set_gcm_params,
		.free_params = free_gcm_params,
		.get_iv = get_gcm_iv_params,
		.set_encrypt_key = aes_set_key,
		.set_decrypt_key = aes_set_key,
	},
};

int _p11_ciphers_init(struct ck_function_list *module, ck_slot_id_t slot)
{
	unsigned i, j;
	ck_rv_t rv;
	ck_mechanism_type_t *mechs = NULL;
	unsigned long mech_count = 0;
	struct ck_mechanism_info *infos = NULL;

	rv = module->C_GetMechanismList(slot, NULL, &mech_count);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	if (mech_count == 0)
		return 0;

	mechs = _gnutls_reallocarray(NULL, mech_count,
				     sizeof(ck_mechanism_type_t));
	if (mechs == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	rv = module->C_GetMechanismList(slot, mechs, &mech_count);
	if (rv != CKR_OK) {
		gnutls_free(mechs);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	infos = _gnutls_reallocarray(NULL, mech_count,
				     sizeof(struct ck_mechanism_info));
	if (infos == NULL) {
		gnutls_free(mechs);
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	for (i = 0; i < mech_count; ++i) {
		rv = module->C_GetMechanismInfo(slot, mechs[i], infos + i);
		if (rv != CKR_OK) {
			gnutls_free(mechs);
			gnutls_free(infos);
			return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		}
	}

	for (i = 0; i < P11_CIPHERS_COUNT; ++i) {
		for (j = 0; j < mech_count; ++j) {
			if (mechs[j] == p11_ciphers[i].mech &&
			    infos[j].min_key_size <= p11_ciphers[i].key_size &&
			    infos[j].max_key_size >= p11_ciphers[i].key_size) {
				p11_ciphers[i].available = true;
				break;
			}
		}
	}

	gnutls_free(mechs);
	gnutls_free(infos);
	return 0;
}

void _p11_ciphers_deinit(void)
{
	unsigned i;

	for (i = 0; i < P11_CIPHERS_COUNT; ++i)
		p11_ciphers[i].available = false;
}

/*************************************************/
/*************** Wrapper functions ***************/
/*************************************************/

static int wrap_p11_cipher_init(gnutls_cipher_algorithm_t alg, void **_ctx,
				int enc)
{
	unsigned i;
	struct p11_cipher_ctx *ctx = NULL;
	const struct p11_cipher_st *cipher = NULL;
	ck_session_handle_t session = CK_INVALID_HANDLE;

	for (i = 0; i < P11_CIPHERS_COUNT; ++i) {
		if (p11_ciphers[i].alg == alg && p11_ciphers[i].available) {
			cipher = p11_ciphers + i;
			break;
		}
	}
	if (cipher == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	ctx = gnutls_calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	if (cipher->init_params(ctx) < 0) {
		gnutls_free(ctx);
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE) {
		cipher->free_params(ctx);
		gnutls_free(ctx);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	ctx->cipher = cipher;
	ctx->session = session;
	ctx->enc = enc;
	*_ctx = ctx;

	return 0;
}

static int wrap_p11_cipher_exists(gnutls_cipher_algorithm_t alg)
{
	unsigned i;

	for (i = 0; i < P11_CIPHERS_COUNT; ++i)
		if (p11_ciphers[i].alg == alg)
			return p11_ciphers[i].available;

	return 0;
}

static int wrap_p11_cipher_setiv(void *_ctx, const void *iv, size_t iv_size)
{
	struct p11_cipher_ctx *ctx = _ctx;

	return ctx->cipher->set_params(ctx, iv, iv_size, NULL, 0, 0);
}

static int wrap_p11_cipher_getiv(void *_ctx, void *iv, size_t iv_size)
{
	struct p11_cipher_ctx *ctx = _ctx;

	return ctx->cipher->get_iv(ctx, iv, iv_size);
}

static int wrap_p11_cipher_setkey(void *_ctx, const void *key, size_t key_size)
{
	struct p11_cipher_ctx *ctx = _ctx;

	return ctx->enc ? ctx->cipher->set_encrypt_key(ctx, key, key_size) :
			  ctx->cipher->set_decrypt_key(ctx, key, key_size);
}

static int wrap_p11_cipher_encrypt(void *_ctx, const void *plain,
				   size_t plain_size, void *enc,
				   size_t enc_size)
{
	struct p11_cipher_ctx *ctx = _ctx;
	ck_rv_t rv;
	struct ck_function_list *module = _p11_provider_get_module();
	struct ck_mechanism m = { ctx->cipher->mech, &ctx->params,
				  ctx->params_size };

	rv = module->C_EncryptInit(ctx->session, &m, ctx->key);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	rv = module->C_Encrypt(ctx->session, (unsigned char *)plain, plain_size,
			       enc, (unsigned long *)&enc_size);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	return 0;
}

static int wrap_p11_cipher_decrypt(void *_ctx, const void *enc, size_t enc_size,
				   void *plain, size_t plain_size)
{
	struct p11_cipher_ctx *ctx = _ctx;
	ck_rv_t rv;
	uint8_t *tmp = NULL;
	uint32_t is_err;
	size_t copy_size;
	unsigned long expected_size = 0;
	struct ck_function_list *module = _p11_provider_get_module();
	struct ck_mechanism m = { ctx->cipher->mech, &ctx->params,
				  ctx->params_size };

	rv = module->C_DecryptInit(ctx->session, &m, ctx->key);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	rv = module->C_Decrypt(ctx->session, (unsigned char *)enc, enc_size,
			       NULL, &expected_size);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	tmp = gnutls_malloc(expected_size);
	if (tmp == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	copy_size = MIN(plain_size, expected_size);
	rv = module->C_Decrypt(ctx->session, (unsigned char *)enc, enc_size,
			       tmp, &expected_size);
	memcpy(plain, tmp, copy_size);
	gnutls_free(tmp);

	is_err = rv != CKR_OK;
	return (int)((is_err * UINT_MAX) & GNUTLS_E_PKCS11_ERROR);
}

static int wrap_p11_cipher_aead_encrypt(void *_ctx, const void *iv,
					size_t iv_size, const void *auth,
					size_t auth_size, size_t tag_size,
					const void *plain, size_t plain_size,
					void *enc, size_t enc_size)
{
	struct p11_cipher_ctx *ctx = _ctx;

	ctx->cipher->set_params(ctx, iv, iv_size, auth, auth_size, tag_size);
	return wrap_p11_cipher_encrypt(_ctx, plain, plain_size, enc, enc_size);
}

static int wrap_p11_cipher_aead_decrypt(void *_ctx, const void *iv,
					size_t iv_size, const void *auth,
					size_t auth_size, size_t tag_size,
					const void *enc, size_t enc_size,
					void *plain, size_t plain_size)
{
	struct p11_cipher_ctx *ctx = _ctx;

	ctx->cipher->set_params(ctx, iv, iv_size, auth, auth_size, tag_size);
	return wrap_p11_cipher_decrypt(_ctx, enc, enc_size, plain, plain_size);
}

static void wrap_p11_cipher_deinit(void *_ctx)
{
	struct p11_cipher_ctx *ctx = _ctx;

	_p11_provider_close_session(ctx->session);
	ctx->cipher->free_params(ctx);
	gnutls_memset(ctx, 0, sizeof(*ctx));
	gnutls_free(ctx);
}

static int wrap_p11_cipher_auth(void *_ctx, const void *plain,
				size_t plain_size)
{
	return 0;
}

static void wrap_p11_cipher_tag(void *_ctx, void *tag, size_t tag_size)
{
}

gnutls_crypto_cipher_st _gnutls_p11_cipher_ops = {
	.init = wrap_p11_cipher_init,
	.exists = wrap_p11_cipher_exists,
	.setiv = wrap_p11_cipher_setiv,
	.getiv = wrap_p11_cipher_getiv,
	.setkey = wrap_p11_cipher_setkey,
	.encrypt = wrap_p11_cipher_encrypt,
	.decrypt = wrap_p11_cipher_decrypt,
	.aead_encrypt = wrap_p11_cipher_aead_encrypt,
	.aead_decrypt = wrap_p11_cipher_aead_decrypt,
	.deinit = wrap_p11_cipher_deinit,
	.auth = wrap_p11_cipher_auth,
	.tag = wrap_p11_cipher_tag,
};
