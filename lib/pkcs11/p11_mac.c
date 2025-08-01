/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Author: Zoltan Fridrich
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "datum.h"
#include "ecc.h"
#include "errors.h"
#include "gnutls_int.h"
#include "p11_mac.h"
#include "p11_provider.h"
#include "x509/x509_int.h"

#include <p11-kit/pkcs11.h>

struct p11_mac_ctx;
typedef int (*init_params_func)(struct p11_mac_ctx *);
typedef void (*free_params_func)(struct p11_mac_ctx *);
typedef int (*finalize_params_func)(struct p11_mac_ctx *, const void *, size_t);
typedef int (*set_nonce_func)(struct p11_mac_ctx *, const void *, size_t);
typedef int (*set_key_func)(struct p11_mac_ctx *, const void *, size_t);

/*************************************************/
/************** Structs and Unions ***************/
/*************************************************/

struct p11_mac_st {
	gnutls_mac_algorithm_t alg;
	CK_MECHANISM_TYPE mech;

	size_t length;
	CK_KEY_TYPE key_type;
	size_t key_size;
	size_t max_iv_size;

	init_params_func init_params;
	free_params_func free_params;
	finalize_params_func finalize_params;
	set_nonce_func set_nonce;
	set_key_func set_key;

	bool available;
};

union p11_mac_params {
	CK_GCM_PARAMS gcm;
};

struct p11_mac_ctx {
	const struct p11_mac_st *mac;
	CK_SESSION_HANDLE session;
	union p11_mac_params params;
	size_t params_size;
	CK_OBJECT_HANDLE key;
	bool sign_init;
};

struct p11_digest_st {
	gnutls_digest_algorithm_t alg;
	CK_MECHANISM_TYPE mech;
	size_t length;
	bool available;
};

struct p11_digest_ctx {
	const struct p11_digest_st *digest;
	CK_SESSION_HANDLE session;
};

/*************************************************/
/********* Algorithm specific functions **********/
/*************************************************/

static int set_secret_key(struct p11_mac_ctx *ctx, const void *key,
			  size_t key_size)
{
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS attr_class = CKO_SECRET_KEY;
	CK_KEY_TYPE attr_key_type = ctx->mac->key_type;
	CK_BBOOL attr_true = CK_TRUE;
	CK_UTF8CHAR label[] = "secret key";
	CK_ATTRIBUTE attrs[] = { { CKA_CLASS, &attr_class, sizeof(attr_class) },
				 { CKA_KEY_TYPE, &attr_key_type,
				   sizeof(attr_key_type) },
				 { CKA_SIGN, &attr_true, sizeof(attr_true) },
				 { CKA_LABEL, label, sizeof(label) - 1 },
				 { CKA_VALUE, (CK_BYTE *)key, key_size } };
	CK_ULONG n_attrs = sizeof(attrs) / sizeof(attrs[0]);

	if (module->C_CreateObject(ctx->session, attrs, n_attrs, &obj) !=
	    CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	ctx->key = obj;
	return 0;
}

static int set_gmac_iv(struct p11_mac_ctx *ctx, const void *iv, size_t iv_size)
{
	uint8_t *_iv = NULL;

	if (iv_size == 0 || iv_size > ctx->mac->max_iv_size)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	_iv = gnutls_malloc(iv_size);
	if (_iv == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	memcpy(_iv, iv, iv_size);

	gnutls_free(ctx->params.gcm.pIv);
	ctx->params.gcm.pIv = _iv;
	ctx->params.gcm.ulIvLen = iv_size;
	return 0;
}

static int set_gmac_aad(struct p11_mac_ctx *ctx, const void *aad,
			size_t aad_size)
{
	uint8_t *_aad = NULL;

	if (aad == NULL || aad_size == 0)
		return 0;

	_aad = gnutls_malloc(aad_size);
	if (_aad == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	memcpy(_aad, aad, aad_size);

	gnutls_free(ctx->params.gcm.pAAD);
	ctx->params.gcm.pAAD = _aad;
	ctx->params.gcm.ulAADLen = aad_size;
	return 0;
}

static int init_gmac_params(struct p11_mac_ctx *ctx)
{
	zeroize_temp_key(&ctx->params, sizeof(ctx->params));
	ctx->params_size = sizeof(CK_GCM_PARAMS);
	ctx->params.gcm.ulTagBits = ctx->mac->length * 8;
	return 0;
}

static void free_gmac_params(struct p11_mac_ctx *ctx)
{
	gnutls_free(ctx->params.gcm.pIv);
	gnutls_free(ctx->params.gcm.pAAD);
	zeroize_temp_key(&ctx->params, sizeof(ctx->params));
	ctx->params_size = 0;
}

/*************************************************/
/**************** Algorithm maps *****************/
/*************************************************/

#define P11_MACS_COUNT (sizeof(p11_macs) / sizeof(p11_macs[0]))
static struct p11_mac_st p11_macs[] = {
	{
		.alg = GNUTLS_MAC_SHA1,
		.mech = CKM_SHA_1_HMAC,
		.length = 20,
		.key_size = 20,
		.key_type = CKK_SHA_1_HMAC,
		.set_key = &set_secret_key,
	},
	{
		.alg = GNUTLS_MAC_SHA224,
		.mech = CKM_SHA224_HMAC,
		.length = 28,
		.key_size = 28,
		.key_type = CKK_SHA224_HMAC,
		.set_key = &set_secret_key,
	},
	{
		.alg = GNUTLS_MAC_SHA256,
		.mech = CKM_SHA256_HMAC,
		.length = 32,
		.key_size = 32,
		.key_type = CKK_SHA256_HMAC,
		.set_key = &set_secret_key,
	},
	{
		.alg = GNUTLS_MAC_SHA384,
		.mech = CKM_SHA384_HMAC,
		.length = 48,
		.key_size = 48,
		.key_type = CKK_SHA384_HMAC,
		.set_key = &set_secret_key,
	},
	{
		.alg = GNUTLS_MAC_SHA512,
		.mech = CKM_SHA512_HMAC,
		.length = 64,
		.key_size = 64,
		.key_type = CKK_SHA512_HMAC,
		.set_key = &set_secret_key,
	},
	{
		.alg = GNUTLS_MAC_AES_CMAC_128,
		.mech = CKM_AES_CMAC,
		.length = 16,
		.key_size = 16,
		.key_type = CKK_AES,
		.set_key = &set_secret_key,
	},
	{
		.alg = GNUTLS_MAC_AES_CMAC_256,
		.mech = CKM_AES_CMAC,
		.length = 16,
		.key_size = 32,
		.key_type = CKK_AES,
		.set_key = &set_secret_key,
	},
	{
		.alg = GNUTLS_MAC_AES_GMAC_128,
		.mech = CKM_AES_GMAC,
		.length = 16,
		.key_size = 16,
		.key_type = CKK_AES,
		.set_key = &set_secret_key,
		.init_params = &init_gmac_params,
		.free_params = &free_gmac_params,
		.finalize_params = &set_gmac_aad,
		.set_nonce = &set_gmac_iv,
	},
	{
		.alg = GNUTLS_MAC_AES_GMAC_192,
		.mech = CKM_AES_GMAC,
		.length = 16,
		.key_size = 24,
		.key_type = CKK_AES,
		.set_key = &set_secret_key,
		.init_params = &init_gmac_params,
		.free_params = &free_gmac_params,
		.finalize_params = &set_gmac_aad,
		.set_nonce = &set_gmac_iv,
	},
	{
		.alg = GNUTLS_MAC_AES_GMAC_256,
		.mech = CKM_AES_GMAC,
		.length = 16,
		.key_size = 32,
		.key_type = CKK_AES,
		.set_key = &set_secret_key,
		.init_params = &init_gmac_params,
		.free_params = &free_gmac_params,
		.finalize_params = &set_gmac_aad,
		.set_nonce = &set_gmac_iv,
	},
};

#define P11_DIGESTS_COUNT (sizeof(p11_digests) / sizeof(p11_digests[0]))
static struct p11_digest_st p11_digests[] = {
	{
		.alg = GNUTLS_DIG_SHA1,
		.mech = CKM_SHA_1,
		.length = 20,
	},
	{
		.alg = GNUTLS_DIG_SHA224,
		.mech = CKM_SHA224,
		.length = 28,
	},
	{
		.alg = GNUTLS_DIG_SHA256,
		.mech = CKM_SHA256,
		.length = 32,
	},
	{
		.alg = GNUTLS_DIG_SHA384,
		.mech = CKM_SHA384,
		.length = 48,
	},
	{
		.alg = GNUTLS_DIG_SHA512,
		.mech = CKM_SHA512,
		.length = 64,
	},
#ifdef CKM_SHA3_224
	{
		.alg = GNUTLS_DIG_SHA3_224,
		.mech = CKM_SHA3_224,
		.length = 28,
	},
#endif
#ifdef CKM_SHA3_256
	{
		.alg = GNUTLS_DIG_SHA3_256,
		.mech = CKM_SHA3_256,
		.length = 32,
	},
#endif
#ifdef CKM_SHA3_384
	{
		.alg = GNUTLS_DIG_SHA3_384,
		.mech = CKM_SHA3_384,
		.length = 48,
	},
#endif
#ifdef CKM_SHA3_512
	{
		.alg = GNUTLS_DIG_SHA3_512,
		.mech = CKM_SHA3_512,
		.length = 64,
	},
#endif
};

static inline const struct p11_mac_st *find_mac(gnutls_mac_algorithm_t alg)
{
	unsigned i;

	for (i = 0; i < P11_MACS_COUNT; ++i)
		if (p11_macs[i].alg == alg && p11_macs[i].available)
			return p11_macs + i;
	return NULL;
}

static inline const struct p11_digest_st *
find_digest(gnutls_digest_algorithm_t alg)
{
	unsigned i;

	for (i = 0; i < P11_DIGESTS_COUNT; ++i)
		if (p11_digests[i].alg == alg && p11_digests[i].available)
			return p11_digests + i;
	return NULL;
}

int _p11_macs_init(CK_FUNCTION_LIST *module, CK_SLOT_ID slot)
{
	unsigned i, j;
	CK_RV rv;
	CK_MECHANISM_TYPE *mechs = NULL;
	CK_ULONG mech_count = 0;

	rv = module->C_GetMechanismList(slot, NULL, &mech_count);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	if (mech_count == 0)
		return 0;

	mechs = _gnutls_reallocarray(NULL, mech_count,
				     sizeof(CK_MECHANISM_TYPE));
	if (mechs == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	rv = module->C_GetMechanismList(slot, mechs, &mech_count);
	if (rv != CKR_OK) {
		gnutls_free(mechs);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	for (i = 0; i < P11_MACS_COUNT; ++i) {
		for (j = 0; j < mech_count; ++j) {
			if (mechs[j] == p11_macs[i].mech) {
				p11_macs[i].available = true;
				break;
			}
		}
	}

	for (i = 0; i < P11_DIGESTS_COUNT; ++i) {
		for (j = 0; j < mech_count; ++j) {
			if (mechs[j] == p11_digests[i].mech) {
				p11_digests[i].available = true;
				break;
			}
		}
	}

	gnutls_free(mechs);
	return 0;
}

void _p11_macs_deinit(void)
{
	unsigned i;

	for (i = 0; i < P11_MACS_COUNT; ++i)
		p11_macs[i].available = false;

	for (i = 0; i < P11_DIGESTS_COUNT; ++i)
		p11_digests[i].available = false;
}

/*************************************************/
/***************** MAC functions *****************/
/*************************************************/

static inline int sign_init(struct p11_mac_ctx *ctx, const void *data,
			    size_t data_size)
{
	int ret;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_MECHANISM mech = { ctx->mac->mech, NULL, 0 };

	if (ctx->key == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	if (ctx->mac->finalize_params != NULL) {
		ret = ctx->mac->finalize_params(ctx, data, data_size);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	if (ctx->mac->init_params != NULL) {
		mech.pParameter = &ctx->params;
		mech.ulParameterLen = ctx->params_size;
	}

	if (module->C_SignInit(ctx->session, &mech, ctx->key) != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	return 0;
}

static int wrap_p11_mac_init(gnutls_mac_algorithm_t alg, void **_ctx)
{
	struct p11_mac_ctx *ctx = NULL;
	const struct p11_mac_st *mac = NULL;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	mac = find_mac(alg);
	if (mac == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	ctx = gnutls_calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	if (mac->init_params != NULL && mac->init_params(ctx)) {
		gnutls_free(ctx);
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE) {
		if (mac->free_params != NULL)
			mac->free_params(ctx);
		gnutls_free(ctx);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	ctx->mac = mac;
	ctx->session = session;
	ctx->key = CK_INVALID_HANDLE;
	ctx->sign_init = false;
	*_ctx = ctx;
	return 0;
}

static void wrap_p11_mac_deinit(void *_ctx)
{
	struct p11_mac_ctx *ctx = _ctx;

	_p11_provider_close_session(ctx->session);
	if (ctx->mac->free_params != NULL)
		ctx->mac->free_params(ctx);
	zeroize_temp_key(ctx, sizeof(*ctx));
	gnutls_free(ctx);
}

static int wrap_p11_mac_exists(gnutls_mac_algorithm_t alg)
{
	return find_mac(alg) != NULL;
}

static int wrap_p11_mac_set_key(void *_ctx, const void *key, size_t key_size)
{
	struct p11_mac_ctx *ctx = _ctx;

	if (ctx->mac->set_key == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	return ctx->mac->set_key(ctx, key, key_size);
}

static int wrap_p11_mac_set_nonce(void *_ctx, const void *nonce,
				  size_t nonce_size)
{
	struct p11_mac_ctx *ctx = _ctx;

	if (ctx->mac->set_nonce == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	return ctx->mac->set_nonce(ctx, nonce, nonce_size);
}

static int wrap_p11_mac_update(void *_ctx, const void *text, size_t text_size)
{
	struct p11_mac_ctx *ctx = _ctx;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	int ret;

	if (!ctx->sign_init) {
		ret = sign_init(ctx, text, text_size);
		if (ret < 0)
			return gnutls_assert_val(ret);
		ctx->sign_init = true;
	}

	if (module->C_SignUpdate(ctx->session, (CK_BYTE_PTR)text, text_size) !=
	    CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	return 0;
}

static int wrap_p11_mac_output(void *_ctx, void *digest, size_t _digest_size)
{
	struct p11_mac_ctx *ctx = _ctx;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_ULONG digest_size = ctx->mac->length;
	int ret;

	if (_digest_size < digest_size)
		return gnutls_assert_val(GNUTLS_E_SHORT_MEMORY_BUFFER);

	if (!ctx->sign_init) {
		ret = sign_init(ctx, NULL, 0);
		if (ret < 0)
			return gnutls_assert_val(ret);
		ctx->sign_init = true;
	}

	if (module->C_SignFinal(ctx->session, (CK_BYTE_PTR)digest,
				&digest_size) != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	return 0;
}

static int wrap_p11_mac_fast(gnutls_mac_algorithm_t alg, const void *nonce,
			     size_t nonce_size, const void *key,
			     size_t key_size, const void *text,
			     size_t text_size, void *digest)
{
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	struct p11_mac_ctx *ctx = NULL;
	CK_ULONG digest_size = 0;
	int ret = 0;

	ret = wrap_p11_mac_init(alg, (void **)&ctx);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (ctx->mac->set_nonce != NULL)
		ctx->mac->set_nonce(ctx, nonce, nonce_size);

	if (ctx->mac->set_key != NULL)
		ctx->mac->set_key(ctx, key, key_size);

	ret = sign_init(ctx, text, text_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	digest_size = ctx->mac->length;
	if (module->C_Sign(ctx->session, (CK_BYTE_PTR)text, text_size, digest,
			   &digest_size) != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

cleanup:
	wrap_p11_mac_deinit(ctx);
	return ret;
}

static void *wrap_p11_mac_copy(const void *_ctx)
{
	return NULL;
}

/*************************************************/
/**************** Hash functions *****************/
/*************************************************/

static int wrap_p11_hash_init(gnutls_digest_algorithm_t alg, void **_ctx)
{
	struct p11_digest_ctx *ctx = NULL;
	const struct p11_digest_st *digest = NULL;
	CK_MECHANISM mech = { 0 };
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();

	digest = find_digest(alg);
	if (digest == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	ctx = gnutls_calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE) {
		gnutls_free(ctx);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	mech.mechanism = digest->mech;
	if (module->C_DigestInit(session, &mech) != CKR_OK) {
		_p11_provider_close_session(session);
		gnutls_free(ctx);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	ctx->digest = digest;
	ctx->session = session;
	*_ctx = ctx;
	return 0;
}

static void wrap_p11_hash_deinit(void *_ctx)
{
	struct p11_digest_ctx *ctx = _ctx;

	_p11_provider_close_session(ctx->session);
	zeroize_temp_key(ctx, sizeof(*ctx));
	gnutls_free(ctx);
}

static int wrap_p11_hash_exists(gnutls_digest_algorithm_t alg)
{
	return find_digest(alg) != NULL;
}

static int wrap_p11_hash_update(void *_ctx, const void *text, size_t text_size)
{
	struct p11_digest_ctx *ctx = _ctx;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();

	if (module->C_DigestUpdate(ctx->session, (CK_BYTE_PTR)text,
				   text_size) != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	return 0;
}

static int wrap_p11_hash_output(void *_ctx, void *digest, size_t _digest_size)
{
	struct p11_digest_ctx *ctx = _ctx;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_ULONG digest_size = ctx->digest->length;

	if (_digest_size < digest_size)
		return gnutls_assert_val(GNUTLS_E_SHORT_MEMORY_BUFFER);

	if (module->C_DigestFinal(ctx->session, (CK_BYTE_PTR)digest,
				  &digest_size) != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	return 0;
}

static int wrap_p11_hash_fast(gnutls_digest_algorithm_t alg, const void *text,
			      size_t text_size, void *digest)
{
	const struct p11_digest_st *dig = NULL;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { 0 };
	CK_ULONG digest_size = 0;

	dig = find_digest(alg);
	if (dig == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	mech.mechanism = dig->mech;
	if (module->C_DigestInit(session, &mech) != CKR_OK) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	digest_size = dig->length;
	if (module->C_Digest(session, (CK_BYTE_PTR)text, text_size, digest,
			     &digest_size) != CKR_OK) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	_p11_provider_close_session(session);
	return 0;
}

static void *wrap_p11_hash_copy(const void *_ctx)
{
	return NULL;
}

/*************************************************/
/***************** KDF functions *****************/
/*************************************************/

#ifdef CKM_HKDF_DERIVE
static CK_OBJECT_HANDLE hkdf_import_key(CK_SESSION_HANDLE session,
					const void *key, size_t key_size)
{
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS attr_class = CKO_SECRET_KEY;
	CK_KEY_TYPE attr_key_type = CKK_HKDF;
	CK_BBOOL attr_true = CK_TRUE;
	CK_BBOOL attr_false = CK_FALSE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &attr_class, sizeof(attr_class) },
		{ CKA_KEY_TYPE, &attr_key_type, sizeof(attr_key_type) },
		{ CKA_SENSITIVE, &attr_false, sizeof(attr_false) },
		{ CKA_EXTRACTABLE, &attr_true, sizeof(attr_true) },
		{ CKA_SIGN, &attr_true, sizeof(attr_true) },
		{ CKA_VALUE, (CK_BYTE *)key, key_size }
	};
	CK_ULONG n_attrs = sizeof(attrs) / sizeof(attrs[0]);

	if (module->C_CreateObject(session, attrs, n_attrs, &obj) != CKR_OK)
		return CK_INVALID_HANDLE;

	return obj;
}
#endif

static int wrap_p11_hkdf_extract(gnutls_mac_algorithm_t _mac, const void *key,
				 size_t key_size, const void *salt,
				 size_t salt_size, void *output)
{
#ifdef CKM_HKDF_DERIVE
	const struct p11_mac_st *mac = NULL;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
	CK_HKDF_PARAMS params = { 0 };
	CK_MECHANISM mech = { CKM_HKDF_DERIVE, &params, sizeof(params) };
	CK_BBOOL attr_true = CK_TRUE;
	CK_BBOOL attr_false = CK_FALSE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_SENSITIVE, &attr_false, sizeof(attr_false) },
		{ CKA_EXTRACTABLE, &attr_true, sizeof(attr_true) },
		{ CKA_SIGN, &attr_true, sizeof(attr_true) }
	};
	CK_ULONG n_attrs = sizeof(attrs) / sizeof(attrs[0]);
	CK_ATTRIBUTE out = { CKA_VALUE, output, key_size };

	mac = find_mac(_mac);
	if (mac == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	if (key_size != mac->length)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	params.bExtract = CK_TRUE;
	params.prfHashMechanism = mac->mech;

	if (salt != NULL && salt_size != 0) {
		params.ulSaltType = CKF_HKDF_SALT_DATA;
		params.pSalt = (CK_BYTE_PTR)salt;
		params.ulSaltLen = salt_size;
	} else {
		params.ulSaltType = CKF_HKDF_SALT_NULL;
	}

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	base_key = hkdf_import_key(session, key, key_size);
	if (base_key == CK_INVALID_HANDLE) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	if (module->C_DeriveKey(session, &mech, base_key, attrs, n_attrs,
				&new_key) != CKR_OK) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	if (module->C_GetAttributeValue(session, new_key, &out, 1) != CKR_OK) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	_p11_provider_close_session(session);
#endif
	return 0;
}

static int wrap_p11_hkdf_expand(gnutls_mac_algorithm_t _mac, const void *key,
				size_t key_size, const void *info,
				size_t info_size, void *output, size_t length)
{
#ifdef CKM_HKDF_DERIVE
	const struct p11_mac_st *mac = NULL;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
	CK_HKDF_PARAMS params = { 0 };
	CK_MECHANISM mech = { CKM_HKDF_DERIVE, &params, sizeof(params) };
	CK_BBOOL attr_true = CK_TRUE;
	CK_BBOOL attr_false = CK_FALSE;
	CK_ULONG attr_len = length;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_SENSITIVE, &attr_false, sizeof(attr_false) },
		{ CKA_EXTRACTABLE, &attr_true, sizeof(attr_true) },
		{ CKA_SIGN, &attr_true, sizeof(attr_true) },
		{ CKA_VALUE_LEN, &attr_len, sizeof(attr_len) }
	};
	CK_ULONG n_attrs = sizeof(attrs) / sizeof(attrs[0]);
	CK_ATTRIBUTE out = { CKA_VALUE, output, length };

	mac = find_mac(_mac);
	if (mac == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	if (key_size != mac->length)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	params.bExpand = CK_TRUE;
	params.prfHashMechanism = mac->mech;

	if (info != NULL && info_size != 0) {
		params.pInfo = (CK_BYTE_PTR)info;
		params.ulInfoLen = info_size;
	}

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	base_key = hkdf_import_key(session, key, key_size);
	if (base_key == CK_INVALID_HANDLE) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	if (module->C_DeriveKey(session, &mech, base_key, attrs, n_attrs,
				&new_key) != CKR_OK) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	if (module->C_GetAttributeValue(session, new_key, &out, 1) != CKR_OK) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	_p11_provider_close_session(session);
#endif
	return 0;
}

static int wrap_p11_pbkdf2(gnutls_mac_algorithm_t _mac, const void *key,
			   size_t key_size, const void *salt, size_t salt_size,
			   unsigned iter_count, void *output, size_t length)
{
#ifdef CK_PKCS5_PBKD2_PARAMS2
	const struct p11_mac_st *mac = NULL;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
	CK_PKCS5_PBKD2_PARAMS2 params = { 0 };
	CK_MECHANISM mech = { CKM_PKCS5_PBKD2, &params, sizeof(params) };
	CK_BBOOL attr_true = CK_TRUE;
	CK_BBOOL attr_false = CK_FALSE;
	CK_KEY_TYPE attr_key_type;
	CK_ULONG attr_len = length;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_SENSITIVE, &attr_false, sizeof(attr_false) },
		{ CKA_EXTRACTABLE, &attr_true, sizeof(attr_true) },
		{ CKA_SIGN, &attr_true, sizeof(attr_true) },
		{ CKA_KEY_TYPE, &attr_key_type, sizeof(attr_key_type) },
		{ CKA_VALUE_LEN, &attr_len, sizeof(attr_len) }
	};
	CK_ULONG n_attrs = sizeof(attrs) / sizeof(attrs[0]);
	CK_ATTRIBUTE out = { CKA_VALUE, output, length };

	mac = find_mac(_mac);
	if (mac == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	if (length != mac->key_size)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	attr_key_type = mac->key_type;

	params.saltSource = CKZ_SALT_SPECIFIED;
	params.pSaltSourceData = (CK_BYTE_PTR)salt;
	params.ulSaltSourceDataLen = salt_size;
	params.pPassword = (CK_BYTE_PTR)key;
	params.ulPasswordLen = key_size;
	params.iterations = iter_count;

	switch (_mac) {
	case GNUTLS_MAC_SHA1:
		params.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
		break;
	case GNUTLS_MAC_SHA224:
		params.prf = CKP_PKCS5_PBKD2_HMAC_SHA224;
		break;
	case GNUTLS_MAC_SHA256:
		params.prf = CKP_PKCS5_PBKD2_HMAC_SHA256;
		break;
	case GNUTLS_MAC_SHA384:
		params.prf = CKP_PKCS5_PBKD2_HMAC_SHA384;
		break;
	case GNUTLS_MAC_SHA512:
		params.prf = CKP_PKCS5_PBKD2_HMAC_SHA512;
		break;
	default:
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	if (module->C_GenerateKey(session, &mech, attrs, n_attrs, &new_key) !=
	    CKR_OK) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	if (module->C_GetAttributeValue(session, new_key, &out, 1) != CKR_OK) {
		_p11_provider_close_session(session);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	_p11_provider_close_session(session);
#endif
	return 0;
}

gnutls_crypto_mac_st _gnutls_p11_mac_ops = {
	.init = wrap_p11_mac_init,
	.setkey = wrap_p11_mac_set_key,
	.setnonce = wrap_p11_mac_set_nonce,
	.hash = wrap_p11_mac_update,
	.output = wrap_p11_mac_output,
	.deinit = wrap_p11_mac_deinit,
	.fast = wrap_p11_mac_fast,
	.exists = wrap_p11_mac_exists,
	.copy = wrap_p11_mac_copy,
};

gnutls_crypto_digest_st _gnutls_p11_digest_ops = {
	.init = wrap_p11_hash_init,
	.hash = wrap_p11_hash_update,
	.output = wrap_p11_hash_output,
	.deinit = wrap_p11_hash_deinit,
	.fast = wrap_p11_hash_fast,
	.exists = wrap_p11_hash_exists,
	.copy = wrap_p11_hash_copy,
};

gnutls_crypto_kdf_st _gnutls_p11_kdf_ops = {
	.hkdf_extract = wrap_p11_hkdf_extract,
	.hkdf_expand = wrap_p11_hkdf_expand,
	.pbkdf2 = wrap_p11_pbkdf2,
};
