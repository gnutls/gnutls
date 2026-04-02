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

static const unsigned char psk_id_hash_label[] = "psk_id_hash";
static const unsigned char info_hash_label[] = "info_hash";
static const unsigned char secret_hash_label[] = "secret";
static const unsigned char key_expand_label[] = "key";
static const unsigned char base_nonce_expand_label[] = "base_nonce";
static const unsigned char exporter_secret_expand_label[] = "exp";
static const unsigned char export_secret_label[] = "sec";

#define GNUTLS_HPKE_MAX_PARAMETER_SIZE 66
#define GNUTLS_HPKE_PSK_MIN_SIZE 32
#define GNUTLS_SCHEDULING_SUITE_ID_SIZE 10
#define GNUTLS_HPKE_IKM_LABEL_MAX_SIZE 256
#define GNUTLS_HPKE_MAX_SALT_SIZE 64
#define GNUTLS_HPKE_MAX_EAE_PRK_SIZE 64
#define GNUTLS_HPKE_MAX_SHARED_SECRET_SIZE 64
#define GNUTLS_HPKE_MAX_INFO_LABEL_SIZE 448
#define GNUTLS_HPKE_MAX_DH_SIZE 132
#define GNUTLS_HPKE_MAX_KEY_SCHEDULE_CONTEXT_SIZE \
	1 + GNUTLS_HPKE_MAX_HASH_SIZE + GNUTLS_HPKE_MAX_HASH_SIZE
#define GNUTLS_HPKE_MAX_NONCE_SIZE 12
#define GNUTLS_HPKE_MAX_LABELED_EXPORT_INFO_MAX_SIZE \
	22 + GNUTLS_HPKE_MAX_PARAMETER_SIZE

struct gnutls_hpke_context_st {
	gnutls_hpke_mode_t mode;
	gnutls_hpke_role_t role;

	gnutls_hpke_kem_t kem;
	gnutls_hpke_kdf_t kdf;
	gnutls_hpke_aead_t aead;

	gnutls_datum_t *psk;
	gnutls_datum_t *psk_id;

	gnutls_datum_t *ikme;

	gnutls_pubkey_t sender_pubkey;
	gnutls_privkey_t sender_privkey;

	gnutls_datum_t key;
	gnutls_datum_t base_nonce;
	gnutls_datum_t exporter_secret;
	uint64_t seq;
};

static bool _gnutls_hpke_is_auth_mode(const gnutls_hpke_mode_t mode)
{
	return mode == GNUTLS_HPKE_MODE_AUTH ||
	       mode == GNUTLS_HPKE_MODE_AUTH_PSK;
}

static bool _gnutls_hpke_is_psk_mode(const gnutls_hpke_mode_t mode)
{
	return mode == GNUTLS_HPKE_MODE_PSK ||
	       mode == GNUTLS_HPKE_MODE_AUTH_PSK;
}

static bool _gnutls_is_key_curve_type_compatible_with_param_dhkem(
	const gnutls_hpke_kem_t kem, const gnutls_ecc_curve_t curve)
{
	const gnutls_ecc_curve_t expected_curve =
		_gnutls_hpke_kem_to_curve(kem);
	return curve == expected_curve;
}

static int _gnutls_hpke_validate_pubkey_for_kem(gnutls_pubkey_t pk,
						gnutls_hpke_kem_t kem)
{
	int ret;
	unsigned int bits = 0;
	gnutls_pk_algorithm_t pk_algo;
	gnutls_ecc_curve_t curve;

	if (pk == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	pk_algo = gnutls_pubkey_get_pk_algorithm(pk, &bits);
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

	if (!_gnutls_is_key_curve_type_compatible_with_param_dhkem(kem,
								   curve)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	return 0;
}

static int _gnutls_hpke_validate_privkey_for_kem(gnutls_privkey_t sk,
						 gnutls_hpke_kem_t kem)
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

	if (!_gnutls_is_key_curve_type_compatible_with_param_dhkem(kem,
								   curve)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	return 0;
}

static int _gnutls_hpke_get_shared_secret(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_mode_t mode, const gnutls_pubkey_t receiver_pubkey,
	const gnutls_pubkey_t sender_pubkey,
	const gnutls_pubkey_t ephemeral_pubkey, const unsigned char *dh,
	const size_t dh_size, unsigned char *shared_secret,
	size_t *shared_secret_size)
{
	int ret = 0;
	unsigned char receiver_pubkey_raw[GNUTLS_HPKE_MAX_DHKEM_PUBKEY_SIZE];
	size_t receiver_pubkey_raw_size = 0;
	unsigned char sender_pubkey_raw[GNUTLS_HPKE_MAX_DHKEM_PUBKEY_SIZE];
	size_t sender_pubkey_raw_size = 0;
	unsigned char ephemeral_pubkey_raw[GNUTLS_HPKE_MAX_DHKEM_PUBKEY_SIZE];
	size_t ephemeral_pubkey_raw_size = 0;
	unsigned char info_label[GNUTLS_HPKE_MAX_INFO_LABEL_SIZE] = { 0 };
	size_t info_label_size = 0;

	const gnutls_mac_algorithm_t mac = _gnutls_hpke_kdf_to_mac(kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	const uint8_t Nh = gnutls_hmac_get_len(mac);
	if (Nh == 0) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	unsigned char suite_id[GNUTLS_HPKE_SUITE_ID_SIZE] = { 0 };
	_gnutls_hpke_build_kem_suite_id(kem, suite_id);

	unsigned char ikm_label[GNUTLS_HPKE_IKM_LABEL_MAX_SIZE];
	size_t ikm_label_size = 0;
	_gnutls_hpke_build_ikm_label(suite_id, GNUTLS_HPKE_SUITE_ID_SIZE, dh,
				     dh_size, ikm_label, &ikm_label_size);

	gnutls_datum_t ikm_label_datum = { ikm_label, ikm_label_size };

	unsigned char salt[GNUTLS_HPKE_MAX_SALT_SIZE] = { 0 };
	gnutls_datum_t salt_datum = { salt, Nh };
	unsigned char eae_prk[GNUTLS_HPKE_MAX_EAE_PRK_SIZE] = { 0 };

	ret = gnutls_hkdf_extract(mac, &ikm_label_datum, &salt_datum, eae_prk);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_pubkey_to_datum(ephemeral_pubkey,
					   ephemeral_pubkey_raw,
					   &ephemeral_pubkey_raw_size);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_pubkey_to_datum(receiver_pubkey, receiver_pubkey_raw,
					   &receiver_pubkey_raw_size);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	if (_gnutls_hpke_is_auth_mode(mode)) {
		ret = _gnutls_hpke_pubkey_to_datum(sender_pubkey,
						   sender_pubkey_raw,
						   &sender_pubkey_raw_size);
		if (ret != 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	_gnutls_hpke_build_info_label(
		receiver_pubkey_raw, receiver_pubkey_raw_size,
		sender_pubkey_raw, sender_pubkey_raw_size, ephemeral_pubkey_raw,
		ephemeral_pubkey_raw_size, suite_id, GNUTLS_HPKE_SUITE_ID_SIZE,
		Nh, info_label, &info_label_size);

	gnutls_datum_t eae_prk_datum = { eae_prk, Nh };
	gnutls_datum_t info_label_datum = { info_label, info_label_size };
	*shared_secret_size = Nh;
	ret = gnutls_hkdf_expand(mac, &eae_prk_datum, &info_label_datum,
				 shared_secret, *shared_secret_size);
	if (ret < 0) {
		gnutls_memset(shared_secret, 0, *shared_secret_size);
		*shared_secret_size = 0;
		gnutls_assert_val(ret);
		goto cleanup;
	}

cleanup:

	gnutls_memset(ikm_label, 0, ikm_label_size);
	gnutls_memset(eae_prk, 0, Nh);
	gnutls_memset(info_label, 0, info_label_size);
	gnutls_memset(receiver_pubkey_raw, 0, receiver_pubkey_raw_size);
	gnutls_memset(sender_pubkey_raw, 0, sender_pubkey_raw_size);
	gnutls_memset(ephemeral_pubkey_raw, 0, ephemeral_pubkey_raw_size);

	return ret;
}

static int _gnutls_hpke_encap_get_dh(const gnutls_hpke_mode_t mode,
				     const gnutls_pubkey_t receiver_pubkey,
				     const gnutls_privkey_t ephemeral_privkey,
				     const gnutls_privkey_t sender_privkey,
				     unsigned char *dh, size_t *dh_size)
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

	if (_gnutls_hpke_is_auth_mode(mode)) {
		ret = gnutls_privkey_derive_secret(
			sender_privkey, receiver_pubkey, NULL, &dhS, 0);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	memcpy(dh, dhE.data, dhE.size);
	*dh_size = dhE.size;

	if (_gnutls_hpke_is_auth_mode(mode)) {
		memcpy(dh + dhE.size, dhS.data, dhS.size);
		*dh_size += dhS.size;
	}

cleanup:
	if (dhS.data != NULL) {
		gnutls_memset(dhS.data, 0, dhS.size);
		gnutls_free(dhS.data);
	}

	if (dhE.data != NULL) {
		gnutls_memset(dhE.data, 0, dhE.size);
		gnutls_free(dhE.data);
	}

	return ret;
}

static int _gnutls_hpke_dhkem_encap(const gnutls_hpke_context_t ctx,
				    const gnutls_pubkey_t receiver_pubkey,
				    gnutls_datum_t *enc,
				    unsigned char *shared_secret,
				    size_t *shared_secret_size)
{
	int ret = 0;
	gnutls_privkey_t ephemeral_privkey = NULL;
	gnutls_pubkey_t ephemeral_pubkey = NULL;
	gnutls_pubkey_t sender_pubkey = NULL;
	unsigned char dh[GNUTLS_HPKE_MAX_DH_SIZE];
	size_t dh_size = 0;

	ret = _gnutls_hpke_generate_keypair(ctx->ikme, ctx->kem,
					    receiver_pubkey, &ephemeral_privkey,
					    &ephemeral_pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	unsigned char pubkey_raw[GNUTLS_HPKE_MAX_DHKEM_PUBKEY_SIZE];
	size_t pubkey_raw_size = 0;
	ret = _gnutls_hpke_pubkey_to_datum(ephemeral_pubkey, pubkey_raw,
					   &pubkey_raw_size);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	enc->size = pubkey_raw_size;
	enc->data = gnutls_malloc(enc->size);
	if (enc->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	memcpy(enc->data, pubkey_raw, pubkey_raw_size);

	ret = _gnutls_hpke_encap_get_dh(ctx->mode, receiver_pubkey,
					ephemeral_privkey, ctx->sender_privkey,
					dh, &dh_size);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto error;
	}

	if (_gnutls_hpke_is_auth_mode(ctx->mode)) {
		ret = gnutls_pubkey_init(&sender_pubkey);
		if (ret < 0) {
			ret = gnutls_assert_val(ret);
			goto error;
		}
		ret = gnutls_pubkey_import_privkey(sender_pubkey,
						   ctx->sender_privkey, 0, 0);
		if (ret < 0) {
			ret = gnutls_assert_val(ret);
			goto error;
		}
	}

	ret = _gnutls_hpke_get_shared_secret(ctx->kem, ctx->kdf, ctx->mode,
					     receiver_pubkey, sender_pubkey,
					     ephemeral_pubkey, dh, dh_size,
					     shared_secret, shared_secret_size);
	if (ret < 0) {
		if (*shared_secret_size > 0) {
			gnutls_memset(shared_secret, 0, *shared_secret_size);
			*shared_secret_size = 0;
		}
		gnutls_assert_val(ret);
		goto error;
	}

	goto cleanup;

error:
	if (enc != NULL && enc->data != NULL) {
		gnutls_free(enc->data);
		enc->data = NULL;
		enc->size = 0;
	}

cleanup:
	gnutls_memset(dh, 0, dh_size);

	gnutls_pubkey_deinit(ephemeral_pubkey);
	gnutls_privkey_deinit(ephemeral_privkey);
	gnutls_pubkey_deinit(sender_pubkey);

	return ret;
}

static int _gnutls_hpke_decap_get_dh(const gnutls_hpke_mode_t mode,
				     const gnutls_pubkey_t ephemeral_pubkey,
				     const gnutls_pubkey_t sender_pubkey,
				     const gnutls_privkey_t receiver_privkey,
				     unsigned char *dh, size_t *dh_size)
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

	if (_gnutls_hpke_is_auth_mode(mode)) {
		ret = gnutls_privkey_derive_secret(
			receiver_privkey, sender_pubkey, NULL, &dhS, 0);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	memcpy(dh, dhE.data, dhE.size);
	*dh_size = dhE.size;

	if (_gnutls_hpke_is_auth_mode(mode)) {
		memcpy(dh + dhE.size, dhS.data, dhS.size);
		*dh_size += dhS.size;
	}

cleanup:
	if (dhE.data != NULL) {
		gnutls_memset(dhE.data, 0, dhE.size);
		gnutls_free(dhE.data);
	}

	if (dhS.data != NULL) {
		gnutls_memset(dhS.data, 0, dhS.size);
		gnutls_free(dhS.data);
	}

	return ret;
}

static int _gnutls_hpke_dhkem_decap(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_mode_t mode, const gnutls_privkey_t receiver_privkey,
	const gnutls_pubkey_t sender_pubkey, const gnutls_datum_t *enc,
	unsigned char *shared_secret, size_t *shared_secret_size)
{
	int ret;

	gnutls_pubkey_t receiver_pubkey = NULL;
	gnutls_pubkey_t ephemeral_pubkey = NULL;
	gnutls_ecc_curve_t curve;
	unsigned char dh[GNUTLS_HPKE_MAX_DH_SIZE];
	size_t dh_size = 0;

	ret = gnutls_privkey_export_ecc_raw(receiver_privkey, &curve, NULL,
					    NULL, NULL);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	if (!_gnutls_is_key_curve_type_compatible_with_param_dhkem(kem,
								   curve)) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	ret = _gnutls_hpke_datum_to_pubkey(curve, enc, &ephemeral_pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_validate_pubkey_for_kem(ephemeral_pubkey, kem);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_decap_get_dh(mode, ephemeral_pubkey, sender_pubkey,
					receiver_privkey, dh, &dh_size);
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

	ret = _gnutls_hpke_get_shared_secret(kem, kdf, mode, receiver_pubkey,
					     sender_pubkey, ephemeral_pubkey,
					     dh, dh_size, shared_secret,
					     shared_secret_size);
	if (ret < 0) {
		if (*shared_secret_size > 0) {
			gnutls_memset(shared_secret, 0, *shared_secret_size);
			*shared_secret_size = 0;
		}
		gnutls_assert_val(ret);
	}

cleanup:
	gnutls_memset(dh, 0, dh_size);

	gnutls_pubkey_deinit(receiver_pubkey);
	gnutls_pubkey_deinit(ephemeral_pubkey);

	return ret;
}

static int _gnutls_hpke_schedule(const unsigned char *shared_secret,
				 const size_t shared_secret_size,
				 const gnutls_datum_t *info,
				 gnutls_hpke_context_t ctx)
{
	int ret = 0;

	unsigned char psk_id_hash[GNUTLS_HPKE_MAX_HASH_SIZE] = { 0 };
	size_t psk_id_hash_size = 0;
	unsigned char info_hash[GNUTLS_HPKE_MAX_HASH_SIZE] = { 0 };
	size_t info_hash_size = 0;
	unsigned char key_schedule_context
		[GNUTLS_HPKE_MAX_KEY_SCHEDULE_CONTEXT_SIZE] = { 0 };
	size_t key_schedule_context_size = 0;
	unsigned char secret[GNUTLS_HPKE_MAX_HASH_SIZE] = { 0 };
	size_t secret_size = 0;
	unsigned char
		labeled_expand_info[GNUTLS_HPKE_MAX_LABELED_EXPAND_INFO_SIZE] = {
			0
		};
	size_t labeled_expand_info_size = 0;

	const gnutls_mac_algorithm_t mac = _gnutls_hpke_kdf_to_mac(ctx->kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	const uint8_t Nh = gnutls_hmac_get_len(mac);
	if (Nh == 0) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	unsigned char salt[GNUTLS_HPKE_MAX_SALT_SIZE] = { 0 };
	unsigned char suite_id[GNUTLS_SCHEDULING_SUITE_ID_SIZE];
	_gnutls_hpke_build_suite_id_for_scheduling(ctx->kem, ctx->kdf,
						   ctx->aead, suite_id);

	ret = _gnutls_hpke_labeled_extract(
		mac, suite_id, GNUTLS_SCHEDULING_SUITE_ID_SIZE, salt, Nh,
		psk_id_hash_label, sizeof(psk_id_hash_label) - 1, ctx->psk_id,
		psk_id_hash, &psk_id_hash_size);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_labeled_extract(mac, suite_id,
					   GNUTLS_SCHEDULING_SUITE_ID_SIZE,
					   salt, Nh, info_hash_label,
					   sizeof(info_hash_label) - 1, info,
					   info_hash, &info_hash_size);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	_gnutls_hpke_build_key_context_for_scheduling(
		ctx->mode, psk_id_hash, psk_id_hash_size, info_hash,
		info_hash_size, key_schedule_context,
		&key_schedule_context_size);

	ret = _gnutls_hpke_labeled_extract(
		mac, suite_id, GNUTLS_SCHEDULING_SUITE_ID_SIZE, shared_secret,
		shared_secret_size, secret_hash_label,
		sizeof(secret_hash_label) - 1, ctx->psk, secret, &secret_size);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	gnutls_datum_t secret_datum = { secret, secret_size };

	_gnutls_hpke_build_suite_id_for_scheduling(ctx->kem, ctx->kdf,
						   ctx->aead, suite_id);
	gnutls_datum_t expand_info = { NULL, 0 };

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

		_gnutls_hpke_build_expand_info(
			suite_id, GNUTLS_SCHEDULING_SUITE_ID_SIZE,
			key_expand_label, sizeof(key_expand_label) - 1,
			key_schedule_context, key_schedule_context_size, Nk,
			labeled_expand_info, &labeled_expand_info_size);
		expand_info.data = labeled_expand_info;
		expand_info.size = labeled_expand_info_size;

		ret = gnutls_hkdf_expand(mac, &secret_datum, &expand_info,
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

		_gnutls_hpke_build_expand_info(
			suite_id, GNUTLS_SCHEDULING_SUITE_ID_SIZE,
			base_nonce_expand_label,
			sizeof(base_nonce_expand_label) - 1,
			key_schedule_context, key_schedule_context_size, Nn,
			labeled_expand_info, &labeled_expand_info_size);
		expand_info.data = labeled_expand_info;
		expand_info.size = labeled_expand_info_size;
		ret = gnutls_hkdf_expand(mac, &secret_datum, &expand_info,
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

	_gnutls_hpke_build_expand_info(
		suite_id, GNUTLS_SCHEDULING_SUITE_ID_SIZE,
		exporter_secret_expand_label,
		sizeof(exporter_secret_expand_label) - 1, key_schedule_context,
		key_schedule_context_size, Nh, labeled_expand_info,
		&labeled_expand_info_size);
	expand_info.data = labeled_expand_info;
	expand_info.size = labeled_expand_info_size;
	ret = gnutls_hkdf_expand(mac, &secret_datum, &expand_info,
				 ctx->exporter_secret.data,
				 ctx->exporter_secret.size);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	return ret;

error:
	if (ctx->key.data != NULL) {
		gnutls_memset(ctx->key.data, 0, ctx->key.size);
		gnutls_free(ctx->key.data);
		ctx->key.data = NULL;
		ctx->key.size = 0;
	}

	if (ctx->base_nonce.data != NULL) {
		gnutls_memset(ctx->base_nonce.data, 0, ctx->base_nonce.size);
		gnutls_free(ctx->base_nonce.data);
		ctx->base_nonce.data = NULL;
		ctx->base_nonce.size = 0;
	}

	if (ctx->exporter_secret.data != NULL) {
		gnutls_memset(ctx->exporter_secret.data, 0,
			      ctx->exporter_secret.size);
		gnutls_free(ctx->exporter_secret.data);
		ctx->exporter_secret.data = NULL;
		ctx->exporter_secret.size = 0;
	}
cleanup:

	gnutls_memset(psk_id_hash, 0, psk_id_hash_size);
	gnutls_memset(info_hash, 0, info_hash_size);
	gnutls_memset(secret, 0, secret_size);
	gnutls_memset(key_schedule_context, 0, key_schedule_context_size);
	gnutls_memset(labeled_expand_info, 0, labeled_expand_info_size);

	return ret;
}

/**
 * gnutls_hpke_context_init:
 * @ctx: A pointer to the HPKE context to initialize.
 * @mode: The HPKE mode to use (Base, PSK, Auth, or AuthPSK).
 * @role: The role of the context (Sender or Receiver).
 * @kem: The KEM algorithm to use (e.g., DHKEM(X25519)).
 * @kdf: The KDF algorithm to use (e.g., HKDF-SHA256).
 * @aead: The AEAD algorithm to use (e.g., AES-128-GCM).
 * This function initializes the HPKE context with the specified parameters.
 * It allocates memory for the context and sets the initial values for the fields based on the provided parameters.
 * The context must be deinitialized using gnutls_hpke_context_deinit() when it
 * is no longer needed to free any allocated resources and securely erase sensitive information.
 * Returns: 0 on success, or a negative error code on failure
 */
int gnutls_hpke_context_init(gnutls_hpke_context_t *ctx,
			     const gnutls_hpke_mode_t mode,
			     const gnutls_hpke_role_t role,
			     const gnutls_hpke_kem_t kem,
			     const gnutls_hpke_kdf_t kdf,
			     const gnutls_hpke_aead_t aead)
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

	(*ctx)->psk = NULL;
	(*ctx)->psk_id = NULL;

	(*ctx)->ikme = NULL;

	(*ctx)->sender_pubkey = NULL;
	(*ctx)->sender_privkey = NULL;

	(*ctx)->key.data = NULL;
	(*ctx)->key.size = 0;
	(*ctx)->base_nonce.data = NULL;
	(*ctx)->base_nonce.size = 0;
	(*ctx)->exporter_secret.data = NULL;
	(*ctx)->exporter_secret.size = 0;
	(*ctx)->seq = 0;

	return 0;
}

/**
 * gnutls_hpke_context_deinit:
 * @ctx: The HPKE context to deinitialize.
 *
 * This function deinitializes the HPKE context and securely erases any
 * sensitive information contained within it, such as keys and secrets.
 * It is important to call this function when the HPKE context is no longer needed
 * to prevent sensitive data from lingering in memory.
 * Returns: 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_context_deinit(gnutls_hpke_context_t ctx)
{
	if (ctx == NULL) {
		return 0;
	}

	if (ctx->psk != NULL) {
		if (ctx->psk->data != NULL) {
			gnutls_memset(ctx->psk->data, 0, ctx->psk->size);
			gnutls_free(ctx->psk->data);
			ctx->psk->data = NULL;
			ctx->psk->size = 0;
		}
		gnutls_free(ctx->psk);
	}

	if (ctx->psk_id != NULL) {
		if (ctx->psk_id->data != NULL) {
			gnutls_memset(ctx->psk_id->data, 0, ctx->psk_id->size);
			gnutls_free(ctx->psk_id->data);
			ctx->psk_id->data = NULL;
			ctx->psk_id->size = 0;
		}
		gnutls_free(ctx->psk_id);
	}

	if (ctx->key.data != NULL) {
		gnutls_memset(ctx->key.data, 0, ctx->key.size);
		gnutls_free(ctx->key.data);
	}

	if (ctx->base_nonce.data != NULL) {
		gnutls_memset(ctx->base_nonce.data, 0, ctx->base_nonce.size);
		gnutls_free(ctx->base_nonce.data);
	}

	if (ctx->exporter_secret.data != NULL) {
		gnutls_memset(ctx->exporter_secret.data, 0,
			      ctx->exporter_secret.size);
		gnutls_free(ctx->exporter_secret.data);
	}

	gnutls_pubkey_deinit(ctx->sender_pubkey);
	gnutls_privkey_deinit(ctx->sender_privkey);

	if (ctx->ikme != NULL) {
		if (ctx->ikme->data != NULL) {
			gnutls_memset(ctx->ikme->data, 0, ctx->ikme->size);
			gnutls_free(ctx->ikme->data);
			ctx->ikme->data = NULL;
			ctx->ikme->size = 0;
		}

		gnutls_free(ctx->ikme);
		ctx->ikme = NULL;
	}

	gnutls_free(ctx);
	return 0;
}

/**
 * gnutls_hpke_context_set_psk:
 * @ctx: The HPKE context to set the PSK for.
 * @psk: A pointer to a gnutls_datum_t structure containing the PSK value and its size.
 * @psk_id: A pointer to a gnutls_datum_t structure containing the PSK identifier and its size.
 *
 * This function sets the PSK and its identifier in the HPKE context. 
 * It securely erases any existing PSK and PSK identifier in the context before setting the new values.
 * The function checks that the provided PSK and PSK identifier are valid and that the context is in
 * a mode that supports PSKs.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_context_set_psk(gnutls_hpke_context_t ctx,
				const gnutls_datum_t *psk,
				const gnutls_datum_t *psk_id)
{
	if (ctx == NULL || psk == NULL || psk_id == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (!_gnutls_hpke_is_psk_mode(ctx->mode)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (psk->size < GNUTLS_HPKE_PSK_MIN_SIZE ||
	    psk->size > GNUTLS_HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (psk_id->size == 0 ||
	    psk_id->size > GNUTLS_HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	int ret = 0;

	if (ctx->psk != NULL) {
		gnutls_memset(ctx->psk->data, 0, ctx->psk->size);
		gnutls_free(ctx->psk->data);
		ctx->psk->data = NULL;
		ctx->psk->size = 0;
		gnutls_free(ctx->psk);
		ctx->psk = NULL;
	}

	if (ctx->psk_id != NULL) {
		gnutls_memset(ctx->psk_id->data, 0, ctx->psk_id->size);
		gnutls_free(ctx->psk_id->data);
		ctx->psk_id->data = NULL;
		ctx->psk_id->size = 0;
		gnutls_free(ctx->psk_id);
		ctx->psk_id = NULL;
	}

	ctx->psk = gnutls_malloc(sizeof(*ctx->psk));
	if (ctx->psk == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}

	ctx->psk_id = gnutls_malloc(sizeof(*ctx->psk_id));
	if (ctx->psk_id == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}

	ctx->psk->size = psk->size;
	ctx->psk->data = gnutls_malloc(ctx->psk->size);
	if (ctx->psk->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}
	memcpy(ctx->psk->data, psk->data, psk->size);

	ctx->psk_id->size = psk_id->size;
	ctx->psk_id->data = gnutls_malloc(ctx->psk_id->size);
	if (ctx->psk_id->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}
	memcpy(ctx->psk_id->data, psk_id->data, psk_id->size);

	return ret;
error:
	if (ctx->psk != NULL) {
		if (ctx->psk->data != NULL) {
			gnutls_memset(ctx->psk->data, 0, ctx->psk->size);
			gnutls_free(ctx->psk->data);
			ctx->psk->data = NULL;
			ctx->psk->size = 0;
		}

		gnutls_free(ctx->psk);
		ctx->psk = NULL;
	}

	if (ctx->psk_id != NULL) {
		if (ctx->psk_id->data != NULL) {
			gnutls_memset(ctx->psk_id->data, 0, ctx->psk_id->size);
			gnutls_free(ctx->psk_id->data);
			ctx->psk_id->data = NULL;
			ctx->psk_id->size = 0;
		}

		gnutls_free(ctx->psk_id);
		ctx->psk_id = NULL;
	}

	return ret;
}

/**
 * gnutls_hpke_context_set_sender_privkey:
 * @ctx: The HPKE context to set the sender's private key for.
 * @sender_privkey: The sender's private key to set in the context.
 *
 * This function should be used by the sender in authenticated modes (Auth and AuthPSK) to set their private key in the
 * HPKE context.
 *
 * This function sets the sender's private key in the HPKE context. It securely erases any existing sender's private key
 * in the context before setting the new value. The function checks that the provided sender's private key is valid and
 * that the context is in a mode that supports authentication and that the role of the context is Sender.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_context_set_sender_privkey(gnutls_hpke_context_t ctx,
					   gnutls_privkey_t sender_privkey)
{
	if (ctx == NULL || sender_privkey == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (!_gnutls_hpke_is_auth_mode(ctx->mode)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_SENDER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	gnutls_privkey_deinit(ctx->sender_privkey);
	ctx->sender_privkey = NULL;

	return _gnutls_hpke_privkey_clone(sender_privkey, &ctx->sender_privkey);
}

/**
 * gnutls_hpke_context_set_sender_pubkey:
 * @ctx: The HPKE context to set the sender's public key for.
 * @sender_pubkey: The sender's public key to set in the context.
 *
 * This function should be used by the receiver in authenticated modes (Auth and AuthPSK) to set the sender's public key
 * in the HPKE context.
 *
 * This function sets the sender's public key in the HPKE context. It securely erases any existing sender's public key
 * in the context before setting the new value. The function checks that the provided sender's public key is valid and
 * that the context is in a mode that supports authentication and that the role of the context is Receiver.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_context_set_sender_pubkey(gnutls_hpke_context_t ctx,
					  gnutls_pubkey_t sender_pubkey)
{
	if (ctx == NULL || sender_pubkey == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (!_gnutls_hpke_is_auth_mode(ctx->mode)) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_RECEIVER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	gnutls_pubkey_deinit(ctx->sender_pubkey);
	ctx->sender_pubkey = NULL;

	return _gnutls_hpke_pubkey_clone(sender_pubkey, &ctx->sender_pubkey);
}

/**
 * gnutls_hpke_context_get_enc_size:
 * @ctx: The HPKE context to get the encapsulated key size for.
 *
 * This function returns the size of the encapsulated key (enc) that will be generated by gnutls_hpke_encap() for the
 * given HPKE context. The size of the encapsulated key depends on the KEM algorithm used in the context. For example,
 * for DHKEM(X25519), the encapsulated key size will be 32 bytes.
 *
 * It returns the size of the encapsulated key in bytes, or 0 if the context is NULL or if there is an error determining
 * the size.
 */
size_t gnutls_hpke_context_get_enc_size(const gnutls_hpke_context_t ctx)
{
	if (ctx == NULL) {
		return 0;
	}

	gnutls_ecc_curve_t curve = _gnutls_hpke_kem_to_curve(ctx->kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		return 0;
	}

	return gnutls_ecc_curve_get_size(curve);
}

/**
 * gnutls_hpke_encap:
 * @ctx: The HPKE context to use for encapsulation.
 * @info: A pointer to a gnutls_datum_t structure containing the application-specific information to be included in the
 * key schedule. This parameter is optional and can be NULL if no additional information is needed.
 * @enc: A pointer to a gnutls_datum_t structure where the encapsulated key will be stored. The function will allocate
 * memory for the encapsulated key, and the caller is responsible for freeing this memory using gnutls_free() when it is
 * no longer needed.
 * @receiver_pubkey: The receiver's public key to use for encapsulation. This must be a valid public key that is
 * compatible with the KEM algorithm specified in the HPKE context.
 *
 * This function performs the encapsulation operation of HPKE. It generates an encapsulated key (enc) that can be sent
 * to the receiver, who can then use it to derive the shared secret. The function checks that the context is properly
 * initialized and that the provided parameters are valid. It also checks that the context is in the correct role
 * (Sender) for encapsulation.
 *
 * This function must be used once per HPKE context and before any calls to gnutls_hpke_seal().
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_encap(gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
		      gnutls_datum_t *enc, gnutls_pubkey_t receiver_pubkey)
{
	int ret;
	if (ctx == NULL || enc == NULL || receiver_pubkey == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_SENDER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (info != NULL && info->size > GNUTLS_HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (_gnutls_hpke_is_auth_mode(ctx->mode)) {
		if (ctx->sender_privkey == NULL) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}

		ret = _gnutls_hpke_validate_privkey_for_kem(ctx->sender_privkey,
							    ctx->kem);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}
	}

	if (_gnutls_hpke_is_psk_mode(ctx->mode)) {
		if (ctx->psk == NULL || ctx->psk_id == NULL) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
	}

	if (ctx->key.data != NULL || ctx->base_nonce.data != NULL ||
	    ctx->exporter_secret.data != NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = _gnutls_hpke_validate_pubkey_for_kem(receiver_pubkey, ctx->kem);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	unsigned char shared_secret[GNUTLS_HPKE_MAX_SHARED_SECRET_SIZE];
	size_t shared_secret_size = 0;
	if (_gnutls_is_kem_dh(ctx->kem)) {
		ret = _gnutls_hpke_dhkem_encap(ctx, receiver_pubkey, enc,
					       shared_secret,
					       &shared_secret_size);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}
	} // TODO: else if(is_mlkem(ctx->kem)) {}
	else {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = _gnutls_hpke_schedule(shared_secret, shared_secret_size, info,
				    ctx);
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
	if (shared_secret_size > 0) {
		gnutls_memset(shared_secret, 0, shared_secret_size);
	}

	return ret;
}

static void _gnutls_hpke_get_seq_nonce(const gnutls_datum_t *base_nonce,
				       uint64_t seq, unsigned char *nonce,
				       size_t *nonce_size)
{
	memcpy(nonce, base_nonce->data, base_nonce->size);
	*nonce_size = base_nonce->size;

	for (size_t i = 0; i < 8; i++) {
		nonce[*nonce_size - 1 - i] ^=
			(uint8_t)((seq >> (8 * i)) & 0xff);
	}
}

/**
 * gnutls_hpke_seal:
 * @ctx: The HPKE context to use for sealing.
 * @aad: A pointer to a gnutls_datum_t structure containing the associated data (AAD) to be authenticated but not
 * encrypted.
 * @plaintext: A pointer to a gnutls_datum_t structure containing the plaintext data to be encrypted and authenticated.
 * @ciphertext: A pointer to a gnutls_datum_t structure where the resulting ciphertext will be stored. The function will
 * allocate memory for the ciphertext, and the caller is responsible for freeing this memory using gnutls_free() when it
 * is no longer needed.
 *
 * This function performs the sealing operation of HPKE. It encrypts the plaintext and computes an authentication tag
 * using the AEAD algorithm specified in the HPKE context.
 * The resulting ciphertext includes both the encrypted plaintext and the authentication tag.
 *
 * This function can be used multiple times with the same HPKE context, but the encapsulation function
 * (gnutls_hpke_encap) must be called once before the first call to this function to set up the necessary keys and
 * nonces in the context. Each call to this function will increment the sequence number in the context, which is used to
 * derive unique nonces for each encryption operation.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
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

	unsigned char nonce[GNUTLS_HPKE_MAX_NONCE_SIZE] = { 0 };
	size_t nonce_size = 0;
	_gnutls_hpke_get_seq_nonce(&ctx->base_nonce, ctx->seq, nonce,
				   &nonce_size);

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
	gnutls_memset(nonce, 0, nonce_size);

	if (ret < 0 && ciphertext->data != NULL) {
		gnutls_free(ciphertext->data);
		ciphertext->data = NULL;
		ciphertext->size = 0;
	}

	if (hd != NULL) {
		gnutls_aead_cipher_deinit(hd);
	}

	return ret;
}

/**
 * gnutls_hpke_decap:
 * @ctx: The HPKE context to use for decapsulation.
 * @info: A pointer to a gnutls_datum_t structure containing the application-specific information that was included in the
 * key schedule during encapsulation. This parameter is optional and can be NULL if no additional information was used.
 * @enc: A pointer to a gnutls_datum_t structure containing the encapsulated key received from the sender. This should be
 * the same encapsulated key that was generated by gnutls_hpke_encap() on the sender's side.
 * @receiver_privkey: The receiver's private key to use for decapsulation. This must be a valid private key that is
 * compatible with the KEM algorithm specified in the HPKE context and that corresponds to the receiver's public key used
 * during encapsulation.
 *
 * This function performs the decapsulation operation of HPKE. It takes the encapsulated key (enc) received from the
 * sender and uses it along with the receiver's private key to derive the shared secret. It then uses this shared secret
 * along with any provided application-specific information (info) to set up the necessary keys and nonces in the HPKE
 * context for subsequent sealing and opening operations.
 *
 * This function must be used once per HPKE context and before any calls to gnutls_hpke_open().
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_decap(gnutls_hpke_context_t ctx, const gnutls_datum_t *info,
		      const gnutls_datum_t *enc,
		      gnutls_privkey_t receiver_privkey)
{
	int ret;
	if (ctx == NULL || enc == NULL || receiver_privkey == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_RECEIVER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (info != NULL && info->size > GNUTLS_HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (_gnutls_hpke_is_auth_mode(ctx->mode)) {
		if (ctx->sender_pubkey == NULL) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}

		ret = _gnutls_hpke_validate_pubkey_for_kem(ctx->sender_pubkey,
							   ctx->kem);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}
	}

	if (_gnutls_hpke_is_psk_mode(ctx->mode)) {
		if (ctx->psk == NULL || ctx->psk_id == NULL) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
	}

	if (ctx->key.data != NULL || ctx->base_nonce.data != NULL ||
	    ctx->exporter_secret.data != NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = _gnutls_hpke_validate_privkey_for_kem(receiver_privkey, ctx->kem);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	unsigned char shared_secret[GNUTLS_HPKE_MAX_SHARED_SECRET_SIZE];
	size_t shared_secret_size = 0;
	if (_gnutls_is_kem_dh(ctx->kem)) {
		ret = _gnutls_hpke_dhkem_decap(ctx->kem, ctx->kdf, ctx->mode,
					       receiver_privkey,
					       ctx->sender_pubkey, enc,
					       shared_secret,
					       &shared_secret_size);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}
	// TODO: else if(is_mlkem(ctx->kem)) {}
	else {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = _gnutls_hpke_schedule(shared_secret, shared_secret_size, info,
				    ctx);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

cleanup:
	if (shared_secret_size > 0) {
		gnutls_memset(shared_secret, 0, shared_secret_size);
	}

	return ret;
}

/**
 * gnutls_hpke_open:
 * @ctx: The HPKE context to use for opening.
 * @aad: A pointer to a gnutls_datum_t structure containing the associated data (AAD) that was authenticated during
 * sealing. This should be the same AAD that was provided to gnutls_hpke_seal() on the sender's side.
 * @ciphertext: A pointer to a gnutls_datum_t structure containing the ciphertext received from the sender. This should
 * be the same ciphertext that was generated by gnutls_hpke_seal() on the sender's side.
 * @plaintext: A pointer to a gnutls_datum_t structure where the resulting plaintext will be stored. The function will
 * allocate memory for the plaintext, and the caller is responsible for freeing this memory using gnutls_free() when it
 * is no longer needed.
 *
 * This function performs the opening operation of HPKE. It takes the ciphertext received from the sender and uses the
 * keys and nonces set up in the HPKE context (after decapsulation) to decrypt the ciphertext and verify the
 * authentication tag. If the decryption and authentication are successful, the resulting plaintext is stored in the
 * provided gnutls_datum_t structure. If the decryption or authentication fails, the function securely erases any
 * allocated plaintext and returns an error code.
 *
 * This function can be used multiple times with the same HPKE context, but the decapsulation function
 * (gnutls_hpke_decap) must be called once before the first call to this function.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
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

	unsigned char nonce[GNUTLS_HPKE_MAX_NONCE_SIZE] = { 0 };
	size_t nonce_size = 0;
	_gnutls_hpke_get_seq_nonce(&ctx->base_nonce, ctx->seq, nonce,
				   &nonce_size);

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
		gnutls_memset(plaintext->data, 0, plaintext->size);
		gnutls_free(plaintext->data);
		plaintext->data = NULL;
		plaintext->size = 0;
		goto cleanup;
	}

	ctx->seq++;
cleanup:
	gnutls_memset(nonce, 0, nonce_size);

	if (hd != NULL) {
		gnutls_aead_cipher_deinit(hd);
	}

	return ret;
}

/**
 * gnutls_hpke_context_set_ikme:
 * @ctx: The HPKE context to set the IKME for.
 * @ikme: A pointer to a gnutls_datum_t structure containing the IKME value and its size.
 *
 * This function sets the IKME in the HPKE context. It securely erases any existing IKME in the context before setting
 * the new value. The function checks that the provided IKME is valid and that the context is in a mode that supports
 * IKME and that the role of the context is Sender.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_context_set_ikme(gnutls_hpke_context_t ctx,
				 const gnutls_datum_t *ikme)
{
	if (ctx == NULL || ikme == NULL || ikme->data == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role != GNUTLS_HPKE_ROLE_SENDER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ikme->size == 0 || ikme->size > GNUTLS_HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->ikme != NULL) {
		if (ctx->ikme->data != NULL) {
			gnutls_memset(ctx->ikme->data, 0, ctx->ikme->size);
			gnutls_free(ctx->ikme->data);
			ctx->ikme->data = NULL;
			ctx->ikme->size = 0;
		}
		gnutls_free(ctx->ikme);
		ctx->ikme = NULL;
	}

	ctx->ikme = gnutls_malloc(sizeof(*ctx->ikme));
	if (ctx->ikme == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	ctx->ikme->size = ikme->size;
	ctx->ikme->data = gnutls_malloc(ctx->ikme->size);
	if (ctx->ikme->data == NULL) {
		gnutls_free(ctx->ikme);
		ctx->ikme = NULL;
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	memcpy(ctx->ikme->data, ikme->data, ikme->size);

	return 0;
}

/**
 * gnutls_hpke_generate_keypair:
 * @kem: The KEM algorithm to use for key pair generation.
 * @ikm: A pointer to a gnutls_datum_t structure containing the input key material (IKM) to be used for key pair
 * generation. This should be a non-empty byte string that serves as the seed for key pair generation.
 * @privkey: A pointer to a gnutls_privkey_t variable where the generated private key will be stored. The function will initialize this variable with the generated private key.
 * @pubkey: A pointer to a gnutls_pubkey_t variable where the generated public key will be stored. The function will initialize this variable with the generated public key.
 *
 * This function generates a key pair (private key and public key) for the specified KEM algorithm using the provided
 * input key material (IKM). The IKM is used as a seed for the key generation process, allowing for deterministic key
 * pair generation if the same IKM is used. The function checks that the provided parameters are valid and that the KEM
 * algorithm is supported.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_generate_keypair(const gnutls_hpke_kem_t kem,
				 const gnutls_datum_t *ikm,
				 gnutls_privkey_t *privkey,
				 gnutls_pubkey_t *pubkey)
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

/**
 * gnutls_hpke_get_seq:
 * @ctx: The HPKE context to get the sequence number from.
 * @seq: A pointer to a uint64_t variable where the current sequence number will be stored.
 *
 * This function retrieves the current sequence number from the HPKE context. The sequence number is used to derive
 * unique nonces for encryption and decryption operations in HPKE. The function checks that the provided parameters are
 * valid and that the context is properly initialized.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_get_seq(gnutls_hpke_context_t ctx, uint64_t *seq)
{
	if (ctx == NULL || seq == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	*seq = ctx->seq;
	return 0;
}

/**
 * gnutls_hpke_set_seq:
 * @ctx: The HPKE context to set the sequence number for.
 * @seq: The sequence number to set in the context.
 *
 * This function sets the sequence number in the HPKE context. The sequence number is used to derive unique nonces for
 * encryption and decryption operations in HPKE. The function checks that the provided parameters are valid and that the
 * context is properly initialized and that the role of the context is Receiver, as only the receiver should be setting
 * the sequence number (the sender's sequence number is managed internally by gnutls_hpke_seal()).
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_set_seq(gnutls_hpke_context_t ctx, uint64_t seq)
{
	if (ctx == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->role == GNUTLS_HPKE_ROLE_SENDER) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ctx->seq = seq;
	return 0;
}

/**
 * gnutls_hpke_export:
 * @ctx: The HPKE context to use for exporting the secret.
 * @exporter_context: A pointer to a gnutls_datum_t structure containing the application-specific context to be included
 * in the export. 
 * @L: The length in bytes of the secret to be exported. This should be a positive integer that does not exceed the
 * maximum allowed size for HPKE exports.
 * @secret: A pointer to a gnutls_datum_t structure where the exported secret will be stored. The function will allocate
 * memory for the secret, and the caller is responsible for freeing this memory using gnutls_free() when it is no longer
 * needed.
 *
 * This function performs the export operation of HPKE. It derives a secret of length L bytes from the exporter secret in
 * the HPKE context, using the provided application-specific context and the KDF specified in the context. The
 * resulting secret is stored in the provided gnutls_datum_t structure. The function checks that the provided parameters
 * are valid and that the context is properly initialized and that there is an exporter secret available in the context.
 *
 * It returns 0 on success, or a negative error code on failure.
 */
int gnutls_hpke_export(gnutls_hpke_context_t ctx,
		       const gnutls_datum_t *exporter_context, const size_t L,
		       gnutls_datum_t *secret)

{
	if (ctx == NULL || exporter_context == NULL || secret == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (ctx->exporter_secret.data == NULL) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (exporter_context->size > GNUTLS_HPKE_MAX_PARAMETER_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	int ret;
	unsigned char suite_id[GNUTLS_SCHEDULING_SUITE_ID_SIZE];

	_gnutls_hpke_build_suite_id_for_scheduling(ctx->kem, ctx->kdf,
						   ctx->aead, suite_id);

	unsigned char
		labeled_export_info[GNUTLS_HPKE_MAX_LABELED_EXPORT_INFO_MAX_SIZE];
	size_t labeled_export_info_size = 0;

	_gnutls_hpke_build_expand_info(
		suite_id, GNUTLS_SCHEDULING_SUITE_ID_SIZE, export_secret_label,
		sizeof(export_secret_label) - 1, exporter_context->data,
		exporter_context->size, L, labeled_export_info,
		&labeled_export_info_size);

	const gnutls_mac_algorithm_t mac = _gnutls_hpke_kdf_to_mac(ctx->kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	gnutls_datum_t expand_info = { labeled_export_info,
				       labeled_export_info_size };
	secret->data = gnutls_malloc(L);
	if (secret->data == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	ret = gnutls_hkdf_expand(mac, &ctx->exporter_secret, &expand_info,
				 secret->data, L);
	if (ret < 0) {
		gnutls_memset(secret->data, 0, L);
		gnutls_free(secret->data);
		secret->data = NULL;
		secret->size = 0;
		return gnutls_assert_val(ret);
	}

	secret->size = L;

	return 0;
}
