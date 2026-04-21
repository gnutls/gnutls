/*
 * Copyright © 2026 David Dudas
 *
 * Author: David Dudas <david.dudas03@e-uvt.ro>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "hpke/hpke-params.h"
#include "hpke/hpke-builders.h"
#include "hpke/hpke-key-management.h"
#include "hpke/hpke-hkdf.h"

#include "errors.h"

static const gnutls_datum_t info_hash_label = { (void *)"info_hash",
						sizeof("info_hash") - 1 };
static const gnutls_datum_t psk_id_hash_label = { (void *)"psk_id_hash",
						  sizeof("psk_id_hash") - 1 };
static const gnutls_datum_t secret_hash_label = { (void *)"secret",
						  sizeof("secret") - 1 };

#define HPKE_MAX_PARAMETER_SIZE 66
#define HPKE_PSK_MIN_SIZE 32
#define HPKE_SCHEDULING_SUITE_ID_SIZE 10
#define HPKE_IKM_LABEL_MAX_SIZE 256
#define HPKE_MAX_SALT_SIZE 64
#define HPKE_MAX_EAE_PRK_SIZE 64
#define HPKE_MAX_SHARED_SECRET_SIZE 64
#define HPKE_MAX_INFO_LABEL_SIZE 448
#define HPKE_MAX_DH_SIZE 132
#define HPKE_MAX_KEY_SCHEDULE_CONTEXT_SIZE \
	1 + HPKE_MAX_HASH_SIZE + HPKE_MAX_HASH_SIZE
#define HPKE_MAX_NONCE_SIZE 12
#define HPKE_MAX_LABELED_EXPORT_INFO_MAX_SIZE 22 + HPKE_MAX_PARAMETER_SIZE

struct gnutls_hpke_context_st {
	gnutls_hpke_mode_t mode;
	gnutls_hpke_role_t role;

	gnutls_hpke_kem_t kem;
	gnutls_hpke_kdf_t kdf;
	gnutls_hpke_aead_t aead;

	gnutls_datum_t ikme;

	gnutls_datum_t key;
	gnutls_datum_t base_nonce;
	gnutls_datum_t exporter_secret;
	uint64_t seq;
};

/* For testing purposes */
extern int _gnutls_hpke_get_seq(gnutls_hpke_context_t ctx, uint64_t *seq);
extern int _gnutls_hpke_set_ikme(gnutls_hpke_context_t ctx,
				 const gnutls_datum_t *ikme);

static bool is_auth_mode(gnutls_hpke_mode_t mode)
{
	return mode == GNUTLS_HPKE_MODE_AUTH ||
	       mode == GNUTLS_HPKE_MODE_AUTH_PSK;
}

static bool is_psk_mode(gnutls_hpke_mode_t mode)
{
	return mode == GNUTLS_HPKE_MODE_PSK ||
	       mode == GNUTLS_HPKE_MODE_AUTH_PSK;
}

static bool
is_key_curve_type_compatible_with_param_dhkem(gnutls_hpke_kem_t kem,
					      const gnutls_ecc_curve_t curve)
{
	const gnutls_ecc_curve_t expected_curve =
		_gnutls_hpke_kem_to_curve(kem);
	return curve == expected_curve;
}

static int validate_pubkey_for_kem(gnutls_pubkey_t pk, gnutls_hpke_kem_t kem)
{
	int ret;
	gnutls_pk_algorithm_t pk_algo;
	gnutls_ecc_curve_t curve;

	pk_algo = gnutls_pubkey_get_pk_algorithm(pk, NULL);
	if (pk_algo == GNUTLS_PK_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (pk_algo != _gnutls_hpke_get_kem_associated_pk_algorithm(kem)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = gnutls_pubkey_export_ecc_raw(pk, &curve, NULL, NULL);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	if (!is_key_curve_type_compatible_with_param_dhkem(kem, curve)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	return 0;
}

static int validate_privkey_for_kem(gnutls_privkey_t sk, gnutls_hpke_kem_t kem)
{
	int ret;
	unsigned int bits = 0;
	gnutls_pk_algorithm_t pk_algo;
	gnutls_ecc_curve_t curve;

	if (sk == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	pk_algo = gnutls_privkey_get_pk_algorithm(sk, &bits);
	if (pk_algo == GNUTLS_PK_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (pk_algo != _gnutls_hpke_get_kem_associated_pk_algorithm(kem)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = gnutls_privkey_export_ecc_raw(sk, &curve, NULL, NULL, NULL);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	if (!is_key_curve_type_compatible_with_param_dhkem(kem, curve)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	return 0;
}

static int get_shared_secret(gnutls_hpke_kem_t kem, gnutls_hpke_kdf_t kdf,
			     gnutls_hpke_mode_t mode, const gnutls_pubkey_t pkR,
			     const gnutls_pubkey_t pkS,
			     const gnutls_pubkey_t pkE,
			     const gnutls_datum_t *dh,
			     gnutls_datum_t *shared_secret)
{
	int ret = 0;

	unsigned char info_label_buf[HPKE_MAX_INFO_LABEL_SIZE] = { 0 };
	unsigned char suite_id_buf[HPKE_SUITE_ID_SIZE] = { 0 };
	unsigned char ikm_label_buf[HPKE_IKM_LABEL_MAX_SIZE];
	unsigned char salt_buf[HPKE_MAX_SALT_SIZE] = { 0 };
	unsigned char eae_prk_buf[HPKE_MAX_EAE_PRK_SIZE] = { 0 };

	gnutls_datum_t pkR_raw = { NULL, 0 };
	gnutls_datum_t pkS_raw = { NULL, 0 };
	gnutls_datum_t pkE_raw = { NULL, 0 };
	gnutls_datum_t info_label = { info_label_buf, 0 };
	gnutls_datum_t suite_id = { suite_id_buf, HPKE_SUITE_ID_SIZE };
	gnutls_datum_t ikm_label = { ikm_label_buf, 0 };
	gnutls_datum_t salt = { salt_buf, 0 };
	gnutls_datum_t eae_prk = { eae_prk_buf, 0 };

	const gnutls_mac_algorithm_t mac = _gnutls_hpke_kdf_to_mac(kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	const uint8_t Nh = gnutls_hmac_get_len(mac);
	if (Nh == 0) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	salt.size = Nh;
	eae_prk.size = Nh;

	_gnutls_hpke_build_kem_suite_id(kem, suite_id.data);
	_gnutls_hpke_build_ikm_label(&suite_id, dh, &ikm_label);

	ret = gnutls_hkdf_extract(mac, &ikm_label, &salt, eae_prk.data);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_pubkey_to_datum(pkE, &pkE_raw);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_pubkey_to_datum(pkR, &pkR_raw);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	if (is_auth_mode(mode)) {
		ret = _gnutls_hpke_pubkey_to_datum(pkS, &pkS_raw);
		if (ret != 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	_gnutls_hpke_build_info_label(&pkR_raw, pkS_raw.data ? &pkS_raw : NULL,
				      &pkE_raw, &suite_id, Nh, &info_label);

	shared_secret->size = Nh;
	ret = gnutls_hkdf_expand(mac, &eae_prk, &info_label,
				 shared_secret->data, shared_secret->size);
	if (ret < 0) {
		zeroize_key(shared_secret->data, shared_secret->size);
		shared_secret->size = 0;
		gnutls_assert_val(ret);
		goto cleanup;
	}

cleanup:
	zeroize_key(ikm_label.data, ikm_label.size);
	zeroize_key(eae_prk.data, eae_prk.size);
	zeroize_key(info_label.data, info_label.size);
	_gnutls_free_key_datum(&pkR_raw);
	_gnutls_free_key_datum(&pkS_raw);
	_gnutls_free_key_datum(&pkE_raw);

	return ret;
}

static int encap_get_dh(gnutls_hpke_mode_t mode,
			const gnutls_pubkey_t receiver_pubkey,
			const gnutls_privkey_t ephemeral_privkey,
			const gnutls_privkey_t sender_privkey,
			gnutls_datum_t *dh)
{
	int ret = 0;
	gnutls_datum_t dhE = { NULL, 0 };
	gnutls_datum_t dhS = { NULL, 0 };

	ret = gnutls_privkey_derive_secret(ephemeral_privkey, receiver_pubkey,
					   NULL, &dhE, 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	if (is_auth_mode(mode)) {
		ret = gnutls_privkey_derive_secret(
			sender_privkey, receiver_pubkey, NULL, &dhS, 0);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	memcpy(dh->data, dhE.data, dhE.size);
	dh->size = dhE.size;

	if (is_auth_mode(mode)) {
		memcpy(dh->data + dhE.size, dhS.data, dhS.size);
		dh->size += dhS.size;
	}

cleanup:
	_gnutls_free_key_datum(&dhS);
	_gnutls_free_key_datum(&dhE);

	return ret;
}

static int dhkem_encap(const gnutls_hpke_context_t ctx,
		       const gnutls_pubkey_t receiver_pubkey,
		       const gnutls_privkey_t sender_privkey,
		       gnutls_datum_t *enc, gnutls_datum_t *shared_secret)
{
	int ret = 0;
	gnutls_privkey_t ephemeral_privkey = NULL;
	gnutls_pubkey_t ephemeral_pubkey = NULL;
	gnutls_pubkey_t sender_pubkey = NULL;
	unsigned char dh_buf[HPKE_MAX_DH_SIZE];
	gnutls_datum_t dh = { dh_buf, 0 };
	gnutls_datum_t pubkey_raw = { NULL, 0 };

	ret = gnutls_pubkey_init(&ephemeral_pubkey);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = gnutls_privkey_init(&ephemeral_privkey);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_generate_keypair(&ctx->ikme, ctx->kem,
					    receiver_pubkey, ephemeral_privkey,
					    ephemeral_pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_pubkey_to_datum(ephemeral_pubkey, &pubkey_raw);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = encap_get_dh(ctx->mode, receiver_pubkey, ephemeral_privkey,
			   sender_privkey, &dh);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	if (is_auth_mode(ctx->mode)) {
		ret = gnutls_pubkey_init(&sender_pubkey);
		if (ret < 0) {
			ret = gnutls_assert_val(ret);
			goto cleanup;
		}
		ret = gnutls_pubkey_import_privkey(sender_pubkey,
						   sender_privkey, 0, 0);
		if (ret < 0) {
			ret = gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	ret = get_shared_secret(ctx->kem, ctx->kdf, ctx->mode, receiver_pubkey,
				sender_pubkey, ephemeral_pubkey, &dh,
				shared_secret);
	if (ret < 0) {
		if (shared_secret->size > 0) {
			zeroize_key(shared_secret, shared_secret->size);
			shared_secret->size = 0;
		}
		gnutls_assert_val(ret);
		goto cleanup;
	}

	*enc = _gnutls_take_datum(&pubkey_raw);

cleanup:
	zeroize_key(dh.data, dh.size);

	_gnutls_free_key_datum(&pubkey_raw);
	gnutls_pubkey_deinit(ephemeral_pubkey);
	gnutls_privkey_deinit(ephemeral_privkey);
	gnutls_pubkey_deinit(sender_pubkey);

	return ret;
}

static int decap_get_dh(gnutls_hpke_mode_t mode,
			const gnutls_pubkey_t ephemeral_pubkey,
			const gnutls_pubkey_t sender_pubkey,
			const gnutls_privkey_t receiver_privkey,
			gnutls_datum_t *dh)
{
	int ret;
	gnutls_datum_t dhS = { NULL, 0 };
	gnutls_datum_t dhE = { NULL, 0 };

	ret = gnutls_privkey_derive_secret(receiver_privkey, ephemeral_pubkey,
					   NULL, &dhE, 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	if (is_auth_mode(mode)) {
		ret = gnutls_privkey_derive_secret(
			receiver_privkey, sender_pubkey, NULL, &dhS, 0);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	memcpy(dh->data, dhE.data, dhE.size);
	dh->size = dhE.size;

	if (is_auth_mode(mode)) {
		memcpy(dh->data + dhE.size, dhS.data, dhS.size);
		dh->size += dhS.size;
	}

cleanup:
	_gnutls_free_key_datum(&dhE);
	_gnutls_free_key_datum(&dhS);

	return ret;
}

static int dhkem_decap(gnutls_hpke_kem_t kem, gnutls_hpke_kdf_t kdf,
		       gnutls_hpke_mode_t mode,
		       const gnutls_privkey_t receiver_privkey,
		       const gnutls_pubkey_t sender_pubkey,
		       const gnutls_datum_t *enc, gnutls_datum_t *shared_secret)
{
	int ret;

	gnutls_pubkey_t receiver_pubkey = NULL;
	gnutls_pubkey_t ephemeral_pubkey = NULL;
	gnutls_ecc_curve_t curve;
	unsigned char dh_buf[HPKE_MAX_DH_SIZE];
	gnutls_datum_t dh = { dh_buf, 0 };

	ret = gnutls_privkey_export_ecc_raw(receiver_privkey, &curve, NULL,
					    NULL, NULL);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	if (!is_key_curve_type_compatible_with_param_dhkem(kem, curve)) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	ret = gnutls_pubkey_init(&ephemeral_pubkey);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_datum_to_pubkey(curve, enc, ephemeral_pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = validate_pubkey_for_kem(ephemeral_pubkey, kem);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = decap_get_dh(mode, ephemeral_pubkey, sender_pubkey,
			   receiver_privkey, &dh);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = gnutls_pubkey_init(&receiver_pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = gnutls_pubkey_import_privkey(receiver_pubkey, receiver_privkey, 0,
					   0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = get_shared_secret(kem, kdf, mode, receiver_pubkey, sender_pubkey,
				ephemeral_pubkey, &dh, shared_secret);
	if (ret < 0) {
		if (shared_secret->size > 0) {
			zeroize_key(shared_secret, shared_secret->size);
			shared_secret->size = 0;
		}
		gnutls_assert_val(ret);
	}

cleanup:
	zeroize_key(dh.data, dh.size);

	gnutls_pubkey_deinit(receiver_pubkey);
	gnutls_pubkey_deinit(ephemeral_pubkey);

	return ret;
}

static int schedule(gnutls_hpke_context_t ctx,
		    const gnutls_datum_t *shared_secret,
		    const gnutls_datum_t *info, const gnutls_datum_t *psk,
		    const gnutls_datum_t *psk_id)
{
	int ret = 0;

	unsigned char psk_id_hash_buf[HPKE_MAX_HASH_SIZE] = { 0 };
	unsigned char info_hash_buf[HPKE_MAX_HASH_SIZE] = { 0 };
	unsigned char
		key_schedule_context_buf[HPKE_MAX_KEY_SCHEDULE_CONTEXT_SIZE] = {
			0
		};
	unsigned char secret_buf[HPKE_MAX_HASH_SIZE] = { 0 };
	unsigned char
		labeled_expand_info_buf[HPKE_MAX_LABELED_EXPAND_INFO_SIZE] = {
			0
		};
	unsigned char salt_buf[HPKE_MAX_SALT_SIZE] = { 0 };
	unsigned char suite_id_buf[HPKE_SCHEDULING_SUITE_ID_SIZE];

	gnutls_datum_t psk_id_hash = { psk_id_hash_buf, 0 };
	gnutls_datum_t info_hash = { info_hash_buf, 0 };
	gnutls_datum_t key_schedule_context = { key_schedule_context_buf, 0 };
	gnutls_datum_t secret = { secret_buf, 0 };
	gnutls_datum_t labeled_expand_info = { labeled_expand_info_buf, 0 };
	gnutls_datum_t suite_id = { suite_id_buf,
				    HPKE_SCHEDULING_SUITE_ID_SIZE };
	gnutls_datum_t salt = { salt_buf, 0 };

	const gnutls_mac_algorithm_t mac = _gnutls_hpke_kdf_to_mac(ctx->kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	const uint8_t Nh = gnutls_hmac_get_len(mac);
	if (Nh == 0) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	salt.size = Nh;

	_gnutls_hpke_build_suite_id_for_scheduling(ctx->kem, ctx->kdf,
						   ctx->aead, suite_id_buf);

	ret = _gnutls_hpke_labeled_extract(mac, &suite_id, &salt,
					   &psk_id_hash_label, psk_id,
					   &psk_id_hash);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_labeled_extract(mac, &suite_id, &salt,
					   &info_hash_label, info, &info_hash);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	_gnutls_hpke_build_key_context_for_scheduling(
		ctx->mode, &psk_id_hash, &info_hash, &key_schedule_context);

	ret = _gnutls_hpke_labeled_extract(mac, &suite_id, shared_secret,
					   &secret_hash_label, psk, &secret);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	_gnutls_hpke_build_suite_id_for_scheduling(ctx->kem, ctx->kdf,
						   ctx->aead, suite_id.data);

	if (ctx->aead != GNUTLS_HPKE_AEAD_EXPORT_ONLY) {
		const gnutls_cipher_algorithm_t cipher =
			_gnutls_hpke_aead_to_cipher(ctx->aead);

		const size_t Nk = gnutls_cipher_get_key_size(cipher);
		if (Nk == 0) {
			ret = gnutls_assert_val(GNUTLS_E_UNKNOWN_CIPHER_TYPE);
			goto cleanup;
		}

		ctx->key.data = gnutls_malloc(Nk);
		if (ctx->key.data == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			goto cleanup;
		}
		ctx->key.size = Nk;

		const gnutls_datum_t key_expand_label = { (void *)"key",
							  sizeof("key") - 1 };
		_gnutls_hpke_build_expand_info(&suite_id, &key_expand_label,
					       &key_schedule_context, Nk,
					       &labeled_expand_info);

		ret = gnutls_hkdf_expand(mac, &secret, &labeled_expand_info,
					 ctx->key.data, ctx->key.size);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}

		const uint8_t Nn = gnutls_cipher_get_iv_size(cipher);

		ctx->base_nonce.data = gnutls_malloc(Nn);
		if (ctx->base_nonce.data == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			goto error;
		}
		ctx->base_nonce.size = Nn;

		const gnutls_datum_t base_nonce_expand_label = {
			(void *)"base_nonce", sizeof("base_nonce") - 1
		};

		_gnutls_hpke_build_expand_info(&suite_id,
					       &base_nonce_expand_label,
					       &key_schedule_context, Nn,
					       &labeled_expand_info);
		ret = gnutls_hkdf_expand(mac, &secret, &labeled_expand_info,
					 ctx->base_nonce.data,
					 ctx->base_nonce.size);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}
	}

	ctx->exporter_secret.data = gnutls_malloc(Nh);
	if (ctx->exporter_secret.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}
	ctx->exporter_secret.size = Nh;

	const gnutls_datum_t exporter_secret_expand_label = {
		(void *)"exp", sizeof("exp") - 1
	};

	_gnutls_hpke_build_expand_info(&suite_id, &exporter_secret_expand_label,
				       &key_schedule_context, Nh,
				       &labeled_expand_info);
	ret = gnutls_hkdf_expand(mac, &secret, &labeled_expand_info,
				 ctx->exporter_secret.data,
				 ctx->exporter_secret.size);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	return ret;

error:
	_gnutls_free_key_datum(&ctx->key);
	_gnutls_free_key_datum(&ctx->base_nonce);
	_gnutls_free_key_datum(&ctx->exporter_secret);

cleanup:
	zeroize_key(psk_id_hash.data, psk_id_hash.size);
	zeroize_key(info_hash.data, info_hash.size);
	zeroize_key(secret.data, secret.size);
	zeroize_key(key_schedule_context.data, key_schedule_context.size);
	zeroize_key(labeled_expand_info.data, labeled_expand_info.size);

	return ret;
}

int gnutls_hpke_init(gnutls_hpke_context_t *ctx, gnutls_hpke_mode_t mode,
		     gnutls_hpke_role_t role, gnutls_hpke_kem_t kem,
		     gnutls_hpke_kdf_t kdf, gnutls_hpke_aead_t aead)
{
	if (ctx == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	*ctx = gnutls_malloc(sizeof(**ctx));
	if (*ctx == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	(*ctx)->mode = mode;
	(*ctx)->role = role;

	(*ctx)->kem = kem;
	(*ctx)->kdf = kdf;
	(*ctx)->aead = aead;

	(*ctx)->ikme.data = NULL;

	(*ctx)->key.data = NULL;
	(*ctx)->key.size = 0;
	(*ctx)->base_nonce.data = NULL;
	(*ctx)->base_nonce.size = 0;
	(*ctx)->exporter_secret.data = NULL;
	(*ctx)->exporter_secret.size = 0;
	(*ctx)->seq = 0;

	return 0;
}

int gnutls_hpke_deinit(gnutls_hpke_context_t ctx)
{
	if (ctx == NULL) {
		return 0;
	}

	_gnutls_free_key_datum(&ctx->key);
	_gnutls_free_key_datum(&ctx->base_nonce);
	_gnutls_free_key_datum(&ctx->exporter_secret);
	_gnutls_free_key_datum(&ctx->ikme);

	gnutls_free(ctx);
	return 0;
}

int gnutls_hpke_encap(gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
		      gnutls_datum_t *enc,
		      const gnutls_pubkey_t receiver_pubkey,
		      const gnutls_privkey_t sender_privkey,
		      const gnutls_datum_t *psk, const gnutls_datum_t *psk_id)
{
	int ret;
	if (ctx == NULL || enc == NULL || receiver_pubkey == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_SENDER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (info != NULL && info->size > HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (is_auth_mode(ctx->mode)) {
		if (sender_privkey == NULL) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}

		ret = validate_privkey_for_kem(sender_privkey, ctx->kem);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}
	}

	if (is_psk_mode(ctx->mode)) {
		if (psk == NULL || psk_id == NULL) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
		if (psk->size < HPKE_PSK_MIN_SIZE ||
		    psk->size > HPKE_MAX_PARAMETER_SIZE) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
		if (psk_id->size == 0 ||
		    psk_id->size > HPKE_MAX_PARAMETER_SIZE) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
	}

	if (ctx->key.data != NULL || ctx->base_nonce.data != NULL ||
	    ctx->exporter_secret.data != NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = validate_pubkey_for_kem(receiver_pubkey, ctx->kem);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	unsigned char shared_secret_buf[HPKE_MAX_SHARED_SECRET_SIZE];
	gnutls_datum_t shared_secret = { shared_secret_buf, 0 };

	if (_gnutls_is_kem_dh(ctx->kem)) {
		ret = dhkem_encap(ctx, receiver_pubkey, sender_privkey, enc,
				  &shared_secret);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}
	} // TODO: else if(is_mlkem(ctx->kem)) {}
	else {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = schedule(ctx, &shared_secret, info, psk, psk_id);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	goto cleanup;
error:
	if (enc->data != NULL) {
		gnutls_free(enc->data);
		enc->data = NULL;
		enc->size = 0;
	}
cleanup:
	if (shared_secret.size > 0) {
		zeroize_key(shared_secret.data, shared_secret.size);
	}

	return ret;
}

static void get_seq_nonce(const gnutls_datum_t *base_nonce, uint64_t seq,
			  unsigned char *nonce, size_t *nonce_size)
{
	memcpy(nonce, base_nonce->data, base_nonce->size);
	*nonce_size = base_nonce->size;

	for (size_t i = 0; i < 8; i++) {
		nonce[*nonce_size - 1 - i] ^=
			(uint8_t)((seq >> (8 * i)) & 0xff);
	}
}

int gnutls_hpke_seal(gnutls_hpke_context_t ctx, const gnutls_datum_t *aad,
		     const gnutls_datum_t *plaintext,
		     gnutls_datum_t *ciphertext)
{
	if (ctx == NULL || aad == NULL || plaintext == NULL ||
	    ciphertext == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_SENDER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->seq == UINT64_MAX) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->aead == GNUTLS_HPKE_AEAD_EXPORT_ONLY) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->key.data == NULL || ctx->base_nonce.data == NULL ||
	    ctx->exporter_secret.data == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	const gnutls_cipher_algorithm_t cipher =
		_gnutls_hpke_aead_to_cipher(ctx->aead);
	if (cipher == GNUTLS_CIPHER_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_CIPHER_TYPE);
	}

	const uint8_t Nn = gnutls_cipher_get_iv_size(cipher);
	if (ctx->base_nonce.size != Nn) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	int ret;
	gnutls_aead_cipher_hd_t hd = NULL;

	unsigned char nonce[HPKE_MAX_NONCE_SIZE] = { 0 };
	size_t nonce_size = 0;
	get_seq_nonce(&ctx->base_nonce, ctx->seq, nonce, &nonce_size);

	ret = gnutls_aead_cipher_init(&hd, cipher, &ctx->key);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	size_t tag_size = gnutls_cipher_get_tag_size(cipher);

	ciphertext->size = plaintext->size + tag_size;
	ciphertext->data = gnutls_malloc(ciphertext->size);
	if (!ciphertext->data) {
		ciphertext->size = 0;
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	size_t ciphertext_size = ciphertext->size;
	ret = gnutls_aead_cipher_encrypt(hd, nonce, nonce_size, aad->data,
					 aad->size, tag_size, plaintext->data,
					 plaintext->size, ciphertext->data,
					 &ciphertext_size);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}
	ciphertext->size = ciphertext_size;

	ctx->seq++;

cleanup:
	zeroize_key(nonce, nonce_size);

	if (ret < 0) {
		_gnutls_free_datum(ciphertext);
	}

	if (hd != NULL) {
		gnutls_aead_cipher_deinit(hd);
	}

	return ret;
}

int gnutls_hpke_decap(gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
		      const gnutls_datum_t *enc,
		      const gnutls_privkey_t receiver_privkey,
		      const gnutls_pubkey_t sender_pubkey,
		      const gnutls_datum_t *psk, const gnutls_datum_t *psk_id)
{
	int ret;
	if (ctx == NULL || enc == NULL || receiver_privkey == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_RECEIVER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (info != NULL && info->size > HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (is_auth_mode(ctx->mode)) {
		if (sender_pubkey == NULL) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}

		ret = validate_pubkey_for_kem(sender_pubkey, ctx->kem);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}
	}

	if (is_psk_mode(ctx->mode)) {
		if (psk == NULL || psk_id == NULL) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
		if (psk->size < HPKE_PSK_MIN_SIZE ||
		    psk->size > HPKE_MAX_PARAMETER_SIZE) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
		if (psk_id->size == 0 ||
		    psk_id->size > HPKE_MAX_PARAMETER_SIZE) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
	}

	if (ctx->key.data != NULL || ctx->base_nonce.data != NULL ||
	    ctx->exporter_secret.data != NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = validate_privkey_for_kem(receiver_privkey, ctx->kem);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	unsigned char shared_secret_buf[HPKE_MAX_SHARED_SECRET_SIZE];
	gnutls_datum_t shared_secret = { shared_secret_buf, 0 };

	if (_gnutls_is_kem_dh(ctx->kem)) {
		ret = dhkem_decap(ctx->kem, ctx->kdf, ctx->mode,
				  receiver_privkey, sender_pubkey, enc,
				  &shared_secret);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}
	// TODO: else if(is_mlkem(ctx->kem)) {}
	else {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = schedule(ctx, &shared_secret, info, psk, psk_id);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

cleanup:
	if (shared_secret.size > 0) {
		zeroize_key(shared_secret.data, shared_secret.size);
	}

	return ret;
}

int gnutls_hpke_open(gnutls_hpke_context_t ctx, const gnutls_datum_t *aad,
		     const gnutls_datum_t *ciphertext,
		     gnutls_datum_t *plaintext)
{
	if (ctx == NULL || aad == NULL || ciphertext == NULL ||
	    plaintext == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_RECEIVER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->seq == UINT64_MAX) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->aead == GNUTLS_HPKE_AEAD_EXPORT_ONLY) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->key.data == NULL || ctx->base_nonce.data == NULL ||
	    ctx->exporter_secret.data == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	const gnutls_cipher_algorithm_t cipher =
		_gnutls_hpke_aead_to_cipher(ctx->aead);
	if (cipher == GNUTLS_CIPHER_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_CIPHER_TYPE);
	}

	const uint8_t Nn = gnutls_cipher_get_iv_size(cipher);
	if (ctx->base_nonce.size != Nn) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	int ret;
	gnutls_aead_cipher_hd_t hd = NULL;

	unsigned char nonce[HPKE_MAX_NONCE_SIZE] = { 0 };
	size_t nonce_size = 0;
	get_seq_nonce(&ctx->base_nonce, ctx->seq, nonce, &nonce_size);

	ret = gnutls_aead_cipher_init(&hd, cipher, &ctx->key);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	size_t tag_size = gnutls_cipher_get_tag_size(cipher);
	if (ciphertext->size < tag_size) {
		ret = gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);
		goto cleanup;
	}

	size_t plaintext_size = ciphertext->size - tag_size;
	plaintext->size = plaintext_size;
	plaintext->data = gnutls_malloc(plaintext->size);
	if (!plaintext->data) {
		plaintext->size = 0;
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	ret = gnutls_aead_cipher_decrypt(hd, nonce, nonce_size, aad->data,
					 aad->size, tag_size, ciphertext->data,
					 ciphertext->size, plaintext->data,
					 &plaintext_size);
	if (ret != 0) {
		_gnutls_free_key_datum(plaintext);
		goto cleanup;
	}

	ctx->seq++;
cleanup:
	zeroize_key(nonce, nonce_size);

	if (hd != NULL) {
		gnutls_aead_cipher_deinit(hd);
	}

	return ret;
}

/*-
 * _gnutls_hpke_set_ikme:
 * @ctx: The HPKE context to set the ikmE for.
 * @ikme: A pointer to a gnutls_datum_t structure containing the ikmE value and its size.
 *
 * This function sets the ikmE in the HPKE context. It securely erases
 * any existing ikmE in the context before setting the new value. The
 * function checks that the provided ikmE is valid and that the
 * context is in a mode that supports ikmE and that the role of the
 * context is Sender.
 *
 * It returns 0 on success, or a negative error code on failure.
 -*/
int _gnutls_hpke_set_ikme(gnutls_hpke_context_t ctx, const gnutls_datum_t *ikme)
{
	int ret;

	if (ctx == NULL || ikme == NULL || ikme->data == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_SENDER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ikme->size == 0 || ikme->size > HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	_gnutls_free_key_datum(&ctx->ikme);
	ret = _gnutls_set_datum(&ctx->ikme, ikme->data, ikme->size);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	return 0;
}

int gnutls_hpke_derive_keypair(gnutls_hpke_kem_t kem, const gnutls_datum_t *ikm,
			       gnutls_privkey_t privkey, gnutls_pubkey_t pubkey)
{
	int ret;
	if (ikm == NULL || ikm->data == NULL || ikm->size == 0 ||
	    privkey == NULL || pubkey == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = _gnutls_hpke_keypair_from_ikm(kem, ikm, privkey, pubkey);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	return 0;
}

/*-
 * _gnutls_hpke_get_seq:
 * @ctx: The HPKE context to get the sequence number from.
 * @seq: A pointer to a uint64_t variable where the current sequence number will be stored.
 *
 * This function retrieves the current sequence number from the HPKE
 * context. The sequence number is used to derive unique nonces for
 * encryption and decryption operations in HPKE. The function checks
 * that the provided parameters are valid and that the context is
 * properly initialized.
 *
 * It returns 0 on success, or a negative error code on failure.
 -*/
int _gnutls_hpke_get_seq(gnutls_hpke_context_t ctx, uint64_t *seq)
{
	if (ctx == NULL || seq == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	*seq = ctx->seq;
	return 0;
}

int gnutls_hpke_export(gnutls_hpke_context_t ctx,
		       const gnutls_datum_t *exporter_context, size_t length,
		       gnutls_datum_t *secret)

{
	if (ctx == NULL || exporter_context == NULL || secret == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->exporter_secret.data == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (exporter_context->size > HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	int ret;
	unsigned char suite_id_buf[HPKE_SCHEDULING_SUITE_ID_SIZE];
	unsigned char
		labeled_export_info_buf[HPKE_MAX_LABELED_EXPORT_INFO_MAX_SIZE];

	gnutls_datum_t suite_id = { suite_id_buf,
				    HPKE_SCHEDULING_SUITE_ID_SIZE };
	gnutls_datum_t labeled_export_info = { labeled_export_info_buf, 0 };

	_gnutls_hpke_build_suite_id_for_scheduling(ctx->kem, ctx->kdf,
						   ctx->aead, suite_id.data);

	const gnutls_datum_t export_secret_label = { (void *)"sec",
						     sizeof("sec") - 1 };

	_gnutls_hpke_build_expand_info(&suite_id, &export_secret_label,
				       exporter_context, length,
				       &labeled_export_info);

	const gnutls_mac_algorithm_t mac = _gnutls_hpke_kdf_to_mac(ctx->kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	secret->data = gnutls_malloc(length);
	if (secret->data == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	ret = gnutls_hkdf_expand(mac, &ctx->exporter_secret,
				 &labeled_export_info, secret->data, length);
	if (ret < 0) {
		_gnutls_free_key_datum(secret);
		return gnutls_assert_val(ret);
	}

	secret->size = length;

	return 0;
}
