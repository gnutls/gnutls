/*
 * Copyright © 2025 David Dudas
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
#endif

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include "utils.h"

#include <stdbool.h>
#include <stdint.h>

#define report_failure(msg, ret)                                            \
	fprintf(stderr, "%s(%s):%d %s: %s\n", __FILE__, __func__, __LINE__, \
		msg, gnutls_strerror(ret))

static int get_pk(const gnutls_ecc_curve_t curve)
{
	switch (curve) {
	case GNUTLS_ECC_CURVE_SECP256R1:
	case GNUTLS_ECC_CURVE_SECP384R1:
	case GNUTLS_ECC_CURVE_SECP521R1:
		return GNUTLS_PK_EC;
	case GNUTLS_ECC_CURVE_X25519:
		return GNUTLS_PK_ECDH_X25519;
	case GNUTLS_ECC_CURVE_X448:
		return GNUTLS_PK_ECDH_X448;
	default:
		return GNUTLS_PK_UNKNOWN;
	}
}

static int generate_privkey(const gnutls_ecc_curve_t curve,
			    gnutls_privkey_t *privkey)
{
	int ret;

	ret = gnutls_privkey_init(privkey);
	if (ret < 0) {
		report_failure("Failed to initialize private key", ret);
		return ret;
	}

	unsigned int bits = gnutls_ecc_curve_get_size(curve) * 8;
	const gnutls_pk_algorithm_t pk_algo = get_pk(curve);
	if (pk_algo == GNUTLS_PK_UNKNOWN) {
		ret = GNUTLS_E_INVALID_REQUEST;
		report_failure("Unsupported curve for private key generation",
			       ret);
		gnutls_privkey_deinit(*privkey);

		return ret;
	}

	ret = gnutls_privkey_generate(*privkey, pk_algo, bits, 0);
	if (ret < 0) {
		report_failure("Failed to generate private key", ret);
		gnutls_privkey_deinit(*privkey);

		return ret;
	}

	return GNUTLS_E_SUCCESS;
}

static const char *kem_to_string(const gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
		return "DHKEM_P256";
	case GNUTLS_HPKE_KEM_DHKEM_P384:
		return "DHKEM_P384";
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		return "DHKEM_P521";
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		return "DHKEM_X25519";
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return "DHKEM_X448";
	default:
		return "Unknown";
	}
}

static const char *kdf_to_string(const gnutls_hpke_kdf_t kdf)
{
	switch (kdf) {
	case GNUTLS_HPKE_KDF_HKDF_SHA256:
		return "HKDF_SHA256";
	case GNUTLS_HPKE_KDF_HKDF_SHA384:
		return "HKDF_SHA384";
	case GNUTLS_HPKE_KDF_HKDF_SHA512:
		return "HKDF_SHA512";
	default:
		return "Unknown";
	}
}

static const char *aead_to_string(const gnutls_hpke_aead_t aead)
{
	switch (aead) {
	case GNUTLS_HPKE_AEAD_AES_128_GCM:
		return "AES128GCM";
	case GNUTLS_HPKE_AEAD_AES_256_GCM:
		return "AES256GCM";
	case GNUTLS_HPKE_AEAD_CHACHA20_POLY1305:
		return "CHACHA20POLY1305";
	default:
		return "Unknown";
	}
}

static int initialize_pubkey(gnutls_pubkey_t *pubkey, gnutls_privkey_t privkey)
{
	int ret;

	ret = gnutls_pubkey_init(pubkey);
	if (ret < 0) {
		report_failure("Failed to initialize public key", ret);

		return ret;
	}

	ret = gnutls_pubkey_import_privkey(*pubkey, privkey, 0, 0);
	if (ret < 0) {
		report_failure("Failed to import public key from private key",
			       ret);
		gnutls_pubkey_deinit(*pubkey);

		return ret;
	}

	return GNUTLS_E_SUCCESS;
}

static gnutls_ecc_curve_t get_curve_from_kem(gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
		return GNUTLS_ECC_CURVE_SECP256R1;
	case GNUTLS_HPKE_KEM_DHKEM_P384:
		return GNUTLS_ECC_CURVE_SECP384R1;
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		return GNUTLS_ECC_CURVE_SECP521R1;
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		return GNUTLS_ECC_CURVE_X25519;
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return GNUTLS_ECC_CURVE_X448;
	default:
		return GNUTLS_ECC_CURVE_INVALID;
	}
}

static int generate_keys(gnutls_ecc_curve_t curve, gnutls_privkey_t *privkey,
			 gnutls_pubkey_t *pubkey)
{
	int ret;

	ret = generate_privkey(curve, privkey);
	if (ret < 0) {
		report_failure("Failed to generate private key", ret);
		return ret;
	}

	ret = initialize_pubkey(pubkey, *privkey);
	if (ret < 0) {
		report_failure("Failed to initialize public key", ret);
		gnutls_privkey_deinit(*privkey);

		return ret;
	}

	return GNUTLS_E_SUCCESS;
}

static bool compare_datum(const gnutls_datum_t *a, const gnutls_datum_t *b)
{
	if (a->size != b->size) {
		return false;
	}

	return memcmp(a->data, b->data, a->size) == 0;
}

static bool test_hpke_base(const gnutls_hpke_kem_t kem,
			   const gnutls_hpke_kdf_t kdf,
			   const gnutls_hpke_aead_t aead,
			   const gnutls_datum_t *info_used_by_sender,
			   const gnutls_datum_t *info_used_by_receiver,
			   const gnutls_datum_t *pkE_used_by_receiver)
{
	int ret;
	bool result = false;
	gnutls_privkey_t skR = NULL;
	gnutls_pubkey_t pkR = NULL;
	gnutls_datum_t pkE = { NULL, 0 };
	gnutls_datum_t encap_result_key = { NULL, 0 };
	gnutls_datum_t encap_base_nonce = { NULL, 0 };
	gnutls_datum_t encap_exporter_secret = { NULL, 0 };
	gnutls_datum_t decap_result_key = { NULL, 0 };
	gnutls_datum_t decap_base_nonce = { NULL, 0 };
	gnutls_datum_t decap_exporter_secret = { NULL, 0 };

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		report_failure("Invalid curve for the given KEM",
			       GNUTLS_E_INVALID_REQUEST);
		return false;
	}

	ret = generate_keys(curve, &skR, &pkR);
	if (ret < 0) {
		report_failure("Failed to generate keys", ret);
		goto cleanup;
	}

	const gnutls_hpke_encap_context_t encap_ctx = {
		.kem = kem,
		.kdf = kdf,
		.aead = aead,

		.info = info_used_by_sender,

		.receiver_pubkey = pkR,
	};

	ret = gnutls_hpke_encap(&encap_ctx, &pkE, &encap_result_key,
				&encap_base_nonce, &encap_exporter_secret);
	if (ret < 0) {
		report_failure("Failed to encapsulate public key", ret);
		goto cleanup;
	}

	const gnutls_hpke_decap_context_t decap_ctx = {
		.kem = kem,
		.kdf = kdf,
		.aead = aead,

		.info = info_used_by_receiver,
		.enc = pkE_used_by_receiver == NULL ? &pkE :
						      pkE_used_by_receiver,

		.receiver_privkey = skR,
	};

	ret = gnutls_hpke_decap(&decap_ctx, &decap_result_key,
				&decap_base_nonce, &decap_exporter_secret);
	if (ret < 0) {
		report_failure("Failed to decapsulate private key", ret);
		goto cleanup;
	}

	result = compare_datum(&encap_result_key, &decap_result_key) &&
		 compare_datum(&encap_base_nonce, &decap_base_nonce) &&
		 compare_datum(&encap_exporter_secret, &decap_exporter_secret);

cleanup:

	if (encap_result_key.data) {
		gnutls_free(encap_result_key.data);
	}

	if (decap_result_key.data) {
		gnutls_free(decap_result_key.data);
	}

	if (encap_base_nonce.data) {
		gnutls_free(encap_base_nonce.data);
	}

	if (decap_base_nonce.data) {
		gnutls_free(decap_base_nonce.data);
	}

	if (encap_exporter_secret.data) {
		gnutls_free(encap_exporter_secret.data);
	}

	if (decap_exporter_secret.data) {
		gnutls_free(decap_exporter_secret.data);
	}

	if (pkE.data) {
		gnutls_free(pkE.data);
	}

	if (pkR != NULL) {
		gnutls_pubkey_deinit(pkR);
	}

	if (skR != NULL) {
		gnutls_privkey_deinit(skR);
	}

	return result;
}

static bool test_hpke_psk(const gnutls_hpke_kem_t kem,
			  const gnutls_hpke_kdf_t kdf,
			  const gnutls_hpke_aead_t aead,
			  const gnutls_datum_t *info_used_by_sender,
			  const gnutls_datum_t *info_used_by_receiver,
			  const gnutls_datum_t *psk_used_by_sender,
			  const gnutls_datum_t *psk_used_by_receiver,
			  const gnutls_datum_t *pkE_used_by_receiver)
{
	int ret;
	bool result = false;
	gnutls_privkey_t skR = NULL;
	gnutls_pubkey_t pkR = NULL;
	gnutls_datum_t pkE = { NULL, 0 };
	gnutls_datum_t encap_result_key = { NULL, 0 };
	gnutls_datum_t encap_base_nonce = { NULL, 0 };
	gnutls_datum_t encap_exporter_secret = { NULL, 0 };
	gnutls_datum_t decap_result_key = { NULL, 0 };
	gnutls_datum_t decap_base_nonce = { NULL, 0 };
	gnutls_datum_t decap_exporter_secret = { NULL, 0 };

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		report_failure("Invalid curve for the given KEM",
			       GNUTLS_E_INVALID_REQUEST);
		return false;
	}

	ret = generate_keys(curve, &skR, &pkR);
	if (ret < 0) {
		report_failure("Failed to generate keys", ret);
		goto cleanup;
	}

	const gnutls_hpke_encap_context_t encap_ctx = {
		.kem = kem,
		.kdf = kdf,
		.aead = aead,

		.info = info_used_by_sender,
		.psk = psk_used_by_sender,
		.psk_id = &(gnutls_datum_t){ (unsigned char *)"psk_id", 6 },

		.receiver_pubkey = pkR,
	};

	ret = gnutls_hpke_encap(&encap_ctx, &pkE, &encap_result_key,
				&encap_base_nonce, &encap_exporter_secret);
	if (ret < 0) {
		report_failure("Failed to encapsulate public key", ret);
		goto cleanup;
	}

	const gnutls_hpke_decap_context_t decap_ctx = {
		.kem = kem,
		.kdf = kdf,
		.aead = aead,

		.info = info_used_by_receiver,
		.psk = psk_used_by_receiver,
		.psk_id = &(gnutls_datum_t){ (unsigned char *)"psk_id", 6 },

		.enc = pkE_used_by_receiver == NULL ? &pkE :
						      pkE_used_by_receiver,

		.receiver_privkey = skR,
	};

	ret = gnutls_hpke_decap(&decap_ctx, &decap_result_key,
				&decap_base_nonce, &decap_exporter_secret);
	if (ret < 0) {
		report_failure("Failed to decapsulate private key", ret);
		goto cleanup;
	}

	result = compare_datum(&encap_result_key, &decap_result_key) &&
		 compare_datum(&encap_base_nonce, &decap_base_nonce) &&
		 compare_datum(&encap_exporter_secret, &decap_exporter_secret);

cleanup:

	if (encap_result_key.data) {
		gnutls_free(encap_result_key.data);
	}

	if (decap_result_key.data) {
		gnutls_free(decap_result_key.data);
	}

	if (encap_base_nonce.data) {
		gnutls_free(encap_base_nonce.data);
	}

	if (decap_base_nonce.data) {
		gnutls_free(decap_base_nonce.data);
	}

	if (encap_exporter_secret.data) {
		gnutls_free(encap_exporter_secret.data);
	}

	if (decap_exporter_secret.data) {
		gnutls_free(decap_exporter_secret.data);
	}

	if (pkE.data) {
		gnutls_free(pkE.data);
	}

	if (pkR != NULL) {
		gnutls_pubkey_deinit(pkR);
	}

	if (skR != NULL) {
		gnutls_privkey_deinit(skR);
	}

	return result;
}

static bool test_hpke_auth(const gnutls_hpke_kem_t kem,
			   const gnutls_hpke_kdf_t kdf,
			   const gnutls_hpke_aead_t aead,
			   const gnutls_privkey_t skS,
			   const gnutls_pubkey_t pkS,
			   const gnutls_datum_t *info_used_by_sender,
			   const gnutls_datum_t *info_used_by_receiver,
			   const gnutls_datum_t *pkE_used_by_receiver)
{
	int ret;
	bool result = false;
	gnutls_privkey_t skR = NULL;
	gnutls_pubkey_t pkR = NULL;
	gnutls_datum_t pkE = { NULL, 0 };
	gnutls_datum_t encap_result_key = { NULL, 0 };
	gnutls_datum_t encap_base_nonce = { NULL, 0 };
	gnutls_datum_t encap_exporter_secret = { NULL, 0 };
	gnutls_datum_t decap_result_key = { NULL, 0 };
	gnutls_datum_t decap_base_nonce = { NULL, 0 };
	gnutls_datum_t decap_exporter_secret = { NULL, 0 };

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		report_failure("Invalid curve for the given KEM",
			       GNUTLS_E_INVALID_REQUEST);
		return false;
	}

	ret = generate_keys(curve, &skR, &pkR);
	if (ret < 0) {
		report_failure("Failed to generate keys", ret);
		goto cleanup;
	}

	const gnutls_hpke_encap_context_t encap_ctx = {
		.kem = kem,
		.kdf = kdf,
		.aead = aead,

		.info = info_used_by_sender,

		.sender_privkey = skS,
		.receiver_pubkey = pkR,
	};

	ret = gnutls_hpke_encap(&encap_ctx, &pkE, &encap_result_key,
				&encap_base_nonce, &encap_exporter_secret);
	if (ret < 0) {
		report_failure("Failed to encapsulate public key", ret);
		goto cleanup;
	}

	const gnutls_hpke_decap_context_t decap_ctx = {

		.kem = kem,
		.kdf = kdf,
		.aead = aead,

		.info = info_used_by_receiver,

		.enc = pkE_used_by_receiver == NULL ? &pkE :
						      pkE_used_by_receiver,
		.receiver_privkey = skR,
		.sender_pubkey = pkS,
	};

	ret = gnutls_hpke_decap(&decap_ctx, &decap_result_key,
				&decap_base_nonce, &decap_exporter_secret);
	if (ret < 0) {
		report_failure("Failed to decapsulate private key", ret);
		goto cleanup;
	}

	result = compare_datum(&encap_result_key, &decap_result_key) &&
		 compare_datum(&encap_base_nonce, &decap_base_nonce) &&
		 compare_datum(&encap_exporter_secret, &decap_exporter_secret);

cleanup:

	if (encap_result_key.data) {
		gnutls_free(encap_result_key.data);
	}

	if (decap_result_key.data) {
		gnutls_free(decap_result_key.data);
	}

	if (encap_base_nonce.data) {
		gnutls_free(encap_base_nonce.data);
	}

	if (decap_base_nonce.data) {
		gnutls_free(decap_base_nonce.data);
	}

	if (encap_exporter_secret.data) {
		gnutls_free(encap_exporter_secret.data);
	}

	if (decap_exporter_secret.data) {
		gnutls_free(decap_exporter_secret.data);
	}

	if (pkE.data) {
		gnutls_free(pkE.data);
	}

	if (pkR != NULL) {
		gnutls_pubkey_deinit(pkR);
	}

	if (skR != NULL) {
		gnutls_privkey_deinit(skR);
	}

	return result;
}

static bool test_hpke_psk_auth(const gnutls_hpke_kem_t kem,
			       const gnutls_hpke_kdf_t kdf,
			       const gnutls_hpke_aead_t aead,
			       const gnutls_privkey_t skS,
			       const gnutls_pubkey_t pkS,
			       const gnutls_datum_t *info_used_by_sender,
			       const gnutls_datum_t *info_used_by_receiver,
			       const gnutls_datum_t *psk_used_by_sender,
			       const gnutls_datum_t *psk_used_by_receiver,
			       const gnutls_datum_t *pkE_used_by_receiver)
{
	int ret;
	bool result = false;
	gnutls_privkey_t skR = NULL;
	gnutls_pubkey_t pkR = NULL;
	gnutls_datum_t pkE = { NULL, 0 };
	gnutls_datum_t encap_result_key = { NULL, 0 };
	gnutls_datum_t encap_base_nonce = { NULL, 0 };
	gnutls_datum_t encap_exporter_secret = { NULL, 0 };
	gnutls_datum_t decap_result_key = { NULL, 0 };
	gnutls_datum_t decap_base_nonce = { NULL, 0 };
	gnutls_datum_t decap_exporter_secret = { NULL, 0 };

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		report_failure("Invalid curve for the given KEM",
			       GNUTLS_E_INVALID_REQUEST);
		return false;
	}

	ret = generate_keys(curve, &skR, &pkR);
	if (ret < 0) {
		report_failure("Failed to generate keys", ret);
		goto cleanup;
	}

	const gnutls_hpke_encap_context_t encap_ctx = {
		.kem = kem,
		.kdf = kdf,
		.aead = aead,

		.info = info_used_by_sender,
		.psk = psk_used_by_sender,
		.psk_id = &(gnutls_datum_t){ (unsigned char *)"psk_id", 6 },

		.sender_privkey = skS,
		.receiver_pubkey = pkR,
	};

	ret = gnutls_hpke_encap(&encap_ctx, &pkE, &encap_result_key,
				&encap_base_nonce, &encap_exporter_secret);
	if (ret < 0) {
		report_failure("Failed to encapsulate public key", ret);
		goto cleanup;
	}

	const gnutls_hpke_decap_context_t decap_ctx = {
		.kem = kem,
		.kdf = kdf,
		.aead = aead,

		.info = info_used_by_receiver,
		.psk = psk_used_by_receiver,
		.psk_id = &(gnutls_datum_t){ (unsigned char *)"psk_id", 6 },

		.enc = pkE_used_by_receiver == NULL ? &pkE :
						      pkE_used_by_receiver,
		.receiver_privkey = skR,
		.sender_pubkey = pkS,
	};

	ret = gnutls_hpke_decap(&decap_ctx, &decap_result_key,
				&decap_base_nonce, &decap_exporter_secret);
	if (ret < 0) {
		report_failure("Failed to encapsulate public key", ret);
		goto cleanup;
	}

	result = compare_datum(&encap_result_key, &decap_result_key) &&
		 compare_datum(&encap_base_nonce, &decap_base_nonce) &&
		 compare_datum(&encap_exporter_secret, &decap_exporter_secret);

cleanup:

	if (encap_result_key.data) {
		gnutls_free(encap_result_key.data);
	}

	if (decap_result_key.data) {
		gnutls_free(decap_result_key.data);
	}

	if (encap_base_nonce.data) {
		gnutls_free(encap_base_nonce.data);
	}

	if (decap_base_nonce.data) {
		gnutls_free(decap_base_nonce.data);
	}

	if (encap_exporter_secret.data) {
		gnutls_free(encap_exporter_secret.data);
	}

	if (decap_exporter_secret.data) {
		gnutls_free(decap_exporter_secret.data);
	}

	if (pkE.data) {
		gnutls_free(pkE.data);
	}

	if (pkR != NULL) {
		gnutls_pubkey_deinit(pkR);
	}

	if (skR != NULL) {
		gnutls_privkey_deinit(skR);
	}

	return result;
}

static void test_hpke_base_mode_keys_should_match(const gnutls_hpke_kem_t kem,
						  const gnutls_hpke_kdf_t kdf,
						  const gnutls_hpke_aead_t aead)
{
	if (!test_hpke_base(kem, kdf, aead, NULL, NULL, NULL)) {
		fail("HPKE base mode test failed; params: %s, %s, %s\n",
		     kem_to_string(kem), kdf_to_string(kdf),
		     aead_to_string(aead));
	}
}

static int _gnutls_coord_pad_left(const gnutls_datum_t *in, const int out_size,
				  gnutls_datum_t *out)
{
	if ((int)in->size > out_size) {
		return GNUTLS_E_INVALID_REQUEST;
	}

	out->size = out_size;
	out->data = gnutls_malloc(out->size);
	if (out->data == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}

	memset(out->data, 0, out->size - in->size);
	memcpy(out->data + (out->size - in->size), in->data, in->size);

	return GNUTLS_E_SUCCESS;
}

static int _gnutls_pubkey_to_datum(const gnutls_pubkey_t pk,
				   gnutls_datum_t *datum)
{
	int ret = 0;
	gnutls_ecc_curve_t curve;
	gnutls_datum_t x = { NULL, 0 };
	gnutls_datum_t y = { NULL, 0 };
	gnutls_datum_t x_padded = { NULL, 0 };
	gnutls_datum_t y_padded = { NULL, 0 };

	ret = gnutls_pubkey_export_ecc_raw2(pk, &curve, &x, &y,
					    GNUTLS_EXPORT_FLAG_NO_LZ);
	if (ret < 0) {
		goto cleanup;
	}

	if (curve == GNUTLS_ECC_CURVE_X25519 ||
	    curve == GNUTLS_ECC_CURVE_X448) {
		datum->size = x.size;
		datum->data = gnutls_malloc(datum->size);
		if (datum->data == NULL) {
			ret = GNUTLS_E_MEMORY_ERROR;
			goto cleanup;
		}

		memcpy(datum->data, x.data, x.size);
		goto cleanup;
	}

	int coord_size = gnutls_ecc_curve_get_size(curve);
	ret = _gnutls_coord_pad_left(&x, coord_size, &x_padded);
	if (ret < 0) {
		goto cleanup;
	}

	ret = _gnutls_coord_pad_left(&y, coord_size, &y_padded);
	if (ret < 0) {
		goto cleanup;
	}

	datum->size = 1 + x_padded.size + y_padded.size;
	datum->data = gnutls_malloc(datum->size);
	if (datum->data == NULL) {
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}

	datum->data[0] = 0x04;
	memcpy(datum->data + 1, x_padded.data, x_padded.size);
	memcpy(datum->data + 1 + x_padded.size, y_padded.data, y_padded.size);

cleanup:
	if (x.data != NULL) {
		gnutls_free(x.data);
	}

	if (y.data != NULL) {
		gnutls_free(y.data);
	}

	if (x_padded.data != NULL) {
		gnutls_free(x_padded.data);
	}

	if (y_padded.data != NULL) {
		gnutls_free(y_padded.data);
	}

	return ret;
}

static void
test_hpke_base_mode_keys_should_not_match_if_different_pkE_is_used_for_decap(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead)
{
	int ret;
	gnutls_privkey_t skR = NULL;
	gnutls_pubkey_t pkR = NULL;
	gnutls_datum_t pkE_datum = { NULL, 0 };

	const gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		report_failure("Invalid curve for the given KEM",
			       GNUTLS_E_INVALID_REQUEST);
		return;
	}

	ret = generate_keys(curve, &skR, &pkR);
	if (ret < 0) {
		report_failure("Failed to generate keys", ret);
		return;
	}

	ret = _gnutls_pubkey_to_datum(pkR, &pkE_datum);
	if (ret < 0) {
		report_failure("Failed to convert public key to datum", ret);
		if (pkR != NULL) {
			gnutls_pubkey_deinit(pkR);
		}

		if (skR != NULL) {
			gnutls_privkey_deinit(skR);
		}

		return;
	}

	const bool succes =
		!test_hpke_base(kem, kdf, aead, NULL, NULL, &pkE_datum);

	gnutls_free(pkE_datum.data);

	if (pkR != NULL) {
		gnutls_pubkey_deinit(pkR);
	}

	if (skR != NULL) {
		gnutls_privkey_deinit(skR);
	}

	if (!succes) {
		fail("HPKE base mode keys should not match if different pkE is used for decap; params: %s, %s, %s\n",
		     kem_to_string(kem), kdf_to_string(kdf),
		     aead_to_string(aead));
	}
}

static void suite_hpke_base_mode(const gnutls_hpke_kem_t kem,
				 const gnutls_hpke_kdf_t kdf,
				 const gnutls_hpke_aead_t aead)
{
	test_hpke_base_mode_keys_should_match(kem, kdf, aead);
	test_hpke_base_mode_keys_should_not_match_if_different_pkE_is_used_for_decap(
		kem, kdf, aead);
}

static void test_hpke_psk_mode_keys_should_match(const gnutls_hpke_kem_t kem,
						 const gnutls_hpke_kdf_t kdf,
						 const gnutls_hpke_aead_t aead,
						 const uint8_t *psk)
{
	gnutls_datum_t psk_datum = { (uint8_t *)psk, 32 };

	if (!test_hpke_psk(kem, kdf, aead, NULL, NULL, &psk_datum, &psk_datum,
			   NULL)) {
		fail("HPKE PSK keys do not match\n");
	}
}

static void
test_hpke_psk_mode_keys_should_not_match_if_different_psk_is_used_for_decap(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead, const uint8_t *psk, const uint8_t *psk2)
{
	gnutls_datum_t psk_datum = { (uint8_t *)psk, 32 };
	gnutls_datum_t psk2_datum = { (uint8_t *)psk2, 32 };

	if (test_hpke_psk(kem, kdf, aead, NULL, NULL, &psk_datum, &psk2_datum,
			  NULL)) {
		fail("HPKE PSK keys should not match if different PSK is used for decap\n");
	}
}

static void test_hpke_psk_mode_keys_should_match_if_same_info_is_used(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead, const uint8_t *psk)
{
	gnutls_datum_t psk_datum = { (uint8_t *)psk, 32 };
	gnutls_datum_t info = { (uint8_t *)"test info", 9 };

	if (!test_hpke_psk(kem, kdf, aead, &info, &info, &psk_datum, &psk_datum,
			   NULL)) {
		fail("HPKE PSK keys do not match when same info is used\n");
	}
}

static void test_hpke_psk_mode_keys_should_not_match_if_different_info_is_used(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead, const uint8_t *psk)
{
	gnutls_datum_t psk_datum = { (uint8_t *)psk, 32 };
	const gnutls_datum_t info1 = { (uint8_t *)"test info 1", 11 };
	const gnutls_datum_t info2 = { (uint8_t *)"test info 2", 11 };

	if (test_hpke_psk(kem, kdf, aead, &info1, &info2, &psk_datum,
			  &psk_datum, NULL)) {
		fail("HPKE PSK keys should not match when different info is used\n");
	}
}

static void suite_hpke_psk_mode(const gnutls_hpke_kem_t kem,
				const gnutls_hpke_kdf_t kdf,
				const gnutls_hpke_aead_t aead)
{
	const uint8_t psk[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				  0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
				  0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
				  0x1d, 0x1e, 0x1f, 0x20 };

	const uint8_t psk2[32] = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
				   0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
				   0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
				   0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
				   0x3d, 0x3e, 0x3f, 0x40 };

	test_hpke_psk_mode_keys_should_match(kem, kdf, aead, psk);
	test_hpke_psk_mode_keys_should_not_match_if_different_psk_is_used_for_decap(
		kem, kdf, aead, psk, psk2);

	test_hpke_psk_mode_keys_should_match_if_same_info_is_used(kem, kdf,
								  aead, psk);
	test_hpke_psk_mode_keys_should_not_match_if_different_info_is_used(
		kem, kdf, aead, psk);
}

static void test_hpke_auth_mode_keys_should_match(const gnutls_hpke_kem_t kem,
						  const gnutls_hpke_kdf_t kdf,
						  const gnutls_hpke_aead_t aead)
{
	int ret;
	gnutls_privkey_t skS = NULL;
	gnutls_pubkey_t pkS = NULL;

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		fail("Invalid curve for the given KEM\n");
	}

	ret = generate_keys(curve, &skS, &pkS);
	if (ret < 0) {
		fail("Failed to generate keys: %s\n", gnutls_strerror(ret));
	}

	const bool pass =
		test_hpke_auth(kem, kdf, aead, skS, pkS, NULL, NULL, NULL);

	if (pkS != NULL) {
		gnutls_pubkey_deinit(pkS);
	}

	if (skS != NULL) {
		gnutls_privkey_deinit(skS);
	}

	if (!pass) {
		fail("HPKE Auth keys do not match; params: %s, %s, %s\n",
		     kem_to_string(kem), kdf_to_string(kdf),
		     aead_to_string(aead));
	}
}

static void test_hpke_auth_mode_keys_should_not_match_if_wrong_pkS_is_used(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead)
{
	int ret;
	gnutls_privkey_t skS = NULL;
	gnutls_pubkey_t pkS = NULL;
	gnutls_privkey_t skS_wrong = NULL;
	gnutls_pubkey_t pkS_wrong = NULL;

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		fail("Invalid curve for the given KEM\n");
	}

	ret = generate_keys(curve, &skS, &pkS);
	if (ret < 0) {
		fail("Failed to generate keys: %s\n", gnutls_strerror(ret));
	}

	ret = generate_keys(curve, &skS_wrong, &pkS_wrong);
	if (ret < 0) {
		fail("Failed to generate wrong keys: %s\n",
		     gnutls_strerror(ret));
	}

	bool pass = !test_hpke_auth(kem, kdf, aead, skS, pkS_wrong, NULL, NULL,
				    NULL);

	if (pkS != NULL) {
		gnutls_pubkey_deinit(pkS);
	}

	if (skS != NULL) {
		gnutls_privkey_deinit(skS);
	}

	if (pkS_wrong != NULL) {
		gnutls_pubkey_deinit(pkS_wrong);
	}

	if (skS_wrong != NULL) {
		gnutls_privkey_deinit(skS_wrong);
	}

	if (!pass) {
		fail("HPKE Auth keys should not match when wrong pkS is used; params: %s, %s, %s\n",
		     kem_to_string(kem), kdf_to_string(kdf),
		     aead_to_string(aead));
	}
}

static void suite_hpke_auth_mode(const gnutls_hpke_kem_t kem,
				 const gnutls_hpke_kdf_t kdf,
				 const gnutls_hpke_aead_t aead)
{
	test_hpke_auth_mode_keys_should_match(kem, kdf, aead);
	test_hpke_auth_mode_keys_should_not_match_if_wrong_pkS_is_used(kem, kdf,
								       aead);
}

static void test_hpke_auth_psk_mode_keys_should_match(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead, const uint8_t *psk)
{
	int ret;
	gnutls_privkey_t skS = NULL;
	gnutls_pubkey_t pkS = NULL;

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		fail("Invalid curve for the given KEM\n");
	}

	ret = generate_keys(curve, &skS, &pkS);
	if (ret < 0) {
		fail("Failed to generate keys: %s\n", gnutls_strerror(ret));
	}

	gnutls_datum_t psk_datum = { (uint8_t *)psk, 32 };

	const bool pass = test_hpke_psk_auth(kem, kdf, aead, skS, pkS, NULL,
					     NULL, &psk_datum, &psk_datum,
					     NULL);

	if (pkS != NULL) {
		gnutls_pubkey_deinit(pkS);
	}

	if (skS != NULL) {
		gnutls_privkey_deinit(skS);
	}

	if (!pass) {
		fail("HPKE AuthPSK keys do not match; params: %s, %s, %s\n",
		     kem_to_string(kem), kdf_to_string(kdf),
		     aead_to_string(aead));
	}
}

static void test_hpke_auth_psk_mode_keys_should_not_match_if_wrong_pkS_is_used(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead, const uint8_t *psk)
{
	int ret;
	gnutls_privkey_t skS = NULL;
	gnutls_pubkey_t pkS = NULL;
	gnutls_privkey_t skS_wrong = NULL;
	gnutls_pubkey_t pkS_wrong = NULL;

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		fail("Invalid curve for the given KEM\n");
	}

	ret = generate_keys(curve, &skS, &pkS);
	if (ret < 0) {
		fail("Failed to generate keys: %s\n", gnutls_strerror(ret));
	}

	ret = generate_keys(curve, &skS_wrong, &pkS_wrong);
	if (ret < 0) {
		fail("Failed to generate wrong keys: %s\n",
		     gnutls_strerror(ret));
	}

	gnutls_datum_t psk_datum = { (uint8_t *)psk, 32 };

	bool pass = !test_hpke_psk_auth(kem, kdf, aead, skS, pkS_wrong, NULL,
					NULL, &psk_datum, &psk_datum, NULL);

	if (pkS != NULL) {
		gnutls_pubkey_deinit(pkS);
	}

	if (skS != NULL) {
		gnutls_privkey_deinit(skS);
	}

	if (pkS_wrong != NULL) {
		gnutls_pubkey_deinit(pkS_wrong);
	}

	if (skS_wrong != NULL) {
		gnutls_privkey_deinit(skS_wrong);
	}

	if (!pass) {
		fail("HPKE AuthPSK keys should not match when wrong pkS is used; params: %s, %s, %s\n",
		     kem_to_string(kem), kdf_to_string(kdf),
		     aead_to_string(aead));
	}
}

static void
test_hpke_auth_psk_mode_keys_should_not_match_if_different_psk_is_used_for_decap(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead, const uint8_t *psk, const uint8_t *psk2)
{
	int ret;
	gnutls_privkey_t skS = NULL;
	gnutls_pubkey_t pkS = NULL;

	gnutls_ecc_curve_t curve = get_curve_from_kem(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		fail("Invalid curve for the given KEM\n");
	}

	ret = generate_keys(curve, &skS, &pkS);
	if (ret < 0) {
		fail("Failed to generate keys: %s\n", gnutls_strerror(ret));
	}

	gnutls_datum_t psk_datum = { (uint8_t *)psk, 32 };
	gnutls_datum_t psk2_datum = { (uint8_t *)psk2, 32 };

	bool pass = !test_hpke_psk_auth(kem, kdf, aead, skS, pkS, NULL, NULL,
					&psk_datum, &psk2_datum, NULL);

	if (pkS != NULL) {
		gnutls_pubkey_deinit(pkS);
	}

	if (skS != NULL) {
		gnutls_privkey_deinit(skS);
	}

	if (!pass) {
		fail("HPKE AuthPSK keys should not match if different PSK is used for decap\n");
	}
}

static void suite_hpke_auth_psk_mode(const gnutls_hpke_kem_t kem,
				     const gnutls_hpke_kdf_t kdf,
				     const gnutls_hpke_aead_t aead)
{
	const uint8_t psk[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				  0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
				  0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
				  0x1d, 0x1e, 0x1f, 0x20 };

	const uint8_t psk2[32] = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
				   0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
				   0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
				   0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
				   0x3d, 0x3e, 0x3f, 0x40 };

	test_hpke_auth_psk_mode_keys_should_match(kem, kdf, aead, psk);
	test_hpke_auth_psk_mode_keys_should_not_match_if_wrong_pkS_is_used(
		kem, kdf, aead, psk);
	test_hpke_auth_psk_mode_keys_should_not_match_if_different_psk_is_used_for_decap(
		kem, kdf, aead, psk, psk2);
}

void doit(void)
{
	gnutls_global_init();

	const gnutls_hpke_kem_t kems[] = { GNUTLS_HPKE_KEM_DHKEM_X25519,
					   GNUTLS_HPKE_KEM_DHKEM_X448,
					   GNUTLS_HPKE_KEM_DHKEM_P256,
					   GNUTLS_HPKE_KEM_DHKEM_P384,
					   GNUTLS_HPKE_KEM_DHKEM_P521 };
	const size_t num_kems = sizeof(kems) / sizeof(kems[0]);

	const gnutls_hpke_kdf_t kdfs[] = { GNUTLS_HPKE_KDF_HKDF_SHA256,
					   GNUTLS_HPKE_KDF_HKDF_SHA384,
					   GNUTLS_HPKE_KDF_HKDF_SHA512 };
	const size_t num_kdfs = sizeof(kdfs) / sizeof(kdfs[0]);

	const gnutls_hpke_aead_t aeads[] = {
		GNUTLS_HPKE_AEAD_AES_128_GCM, GNUTLS_HPKE_AEAD_AES_256_GCM,
		GNUTLS_HPKE_AEAD_CHACHA20_POLY1305
	};
	const size_t num_aeads = sizeof(aeads) / sizeof(aeads[0]);

	for (size_t i = 0; i < num_kems; i++) {
		for (size_t j = 0; j < num_kdfs; j++) {
			for (size_t k = 0; k < num_aeads; k++) {
				suite_hpke_base_mode(kems[i], kdfs[j],
						     aeads[k]);
				suite_hpke_psk_mode(kems[i], kdfs[j], aeads[k]);
				suite_hpke_auth_mode(kems[i], kdfs[j],
						     aeads[k]);
				suite_hpke_auth_psk_mode(kems[i], kdfs[j],
							 aeads[k]);
			}
		}
	}

	gnutls_global_deinit();
}
