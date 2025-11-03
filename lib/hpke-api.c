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
#endif /* HAVE_CONFIG_H */

#include <lib/errors.h>

static const gnutls_datum_t empty_datum = { (unsigned char *)"", 0 };

typedef enum hpke_mode_t {
	GNUTLS_HPKE_MODE_BASE = 0x00,
	GNUTLS_HPKE_MODE_PSK = 0x01,
	GNUTLS_HPKE_MODE_AUTH = 0x02,
	GNUTLS_HPKE_MODE_AUTH_PSK = 0x03
} gnutls_hpke_mode_t;

static int is_dhkem(const gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
	case GNUTLS_HPKE_KEM_DHKEM_P384:
	case GNUTLS_HPKE_KEM_DHKEM_P521:
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return 1;
	default:
		return 0;
	}
}

static int _gnutls_hpke_is_auth_mode(const gnutls_hpke_mode_t mode)
{
	return mode == GNUTLS_HPKE_MODE_AUTH ||
	       mode == GNUTLS_HPKE_MODE_AUTH_PSK;
}

static int _gnutls_is_key_curve_type_compatible_with_param_dhkem(
	const gnutls_hpke_kem_t kem, const gnutls_ecc_curve_t curve)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
		return curve == GNUTLS_ECC_CURVE_SECP256R1;
	case GNUTLS_HPKE_KEM_DHKEM_P384:
		return curve == GNUTLS_ECC_CURVE_SECP384R1;
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		return curve == GNUTLS_ECC_CURVE_SECP521R1;
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		return curve == GNUTLS_ECC_CURVE_X25519;
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return curve == GNUTLS_ECC_CURVE_X448;
	default:
		return 0;
	}
}

static gnutls_pk_algorithm_t
_gnutls_hpke_get_kem_associated_pk_algorithm(const gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
	case GNUTLS_HPKE_KEM_DHKEM_P384:
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		return GNUTLS_PK_EC;
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		return GNUTLS_PK_ECDH_X25519;
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return GNUTLS_PK_ECDH_X448;
	default:
		return GNUTLS_PK_UNKNOWN;
	}
}

static gnutls_mac_algorithm_t _gnutls_kdf_to_mac(const gnutls_hpke_kdf_t kdf)
{
	switch (kdf) {
	case GNUTLS_HPKE_KDF_HKDF_SHA256:
		return GNUTLS_MAC_SHA256;
	case GNUTLS_HPKE_KDF_HKDF_SHA384:
		return GNUTLS_MAC_SHA384;
	case GNUTLS_HPKE_KDF_HKDF_SHA512:
		return GNUTLS_MAC_SHA512;
	default:
		return GNUTLS_MAC_UNKNOWN;
	}
}

static gnutls_cipher_algorithm_t
_gnutls_hpke_aead_to_cipher(const gnutls_hpke_aead_t aead)
{
	switch (aead) {
	case GNUTLS_HPKE_AEAD_AES_128_GCM:
		return GNUTLS_CIPHER_AES_128_GCM;
	case GNUTLS_HPKE_AEAD_AES_256_GCM:
		return GNUTLS_CIPHER_AES_256_GCM;
	case GNUTLS_HPKE_AEAD_CHACHA20_POLY1305:
		return GNUTLS_CIPHER_CHACHA20_POLY1305;
	default:
		return GNUTLS_CIPHER_UNKNOWN;
	}
}

static int _gnutls_coord_pad_left(const gnutls_datum_t *in, const int out_size,
				  gnutls_datum_t *out)
{
	if ((int)in->size > out_size) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	out->size = out_size;
	out->data = gnutls_malloc(out->size);
	if (out->data == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
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
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	if (curve == GNUTLS_ECC_CURVE_X25519 ||
	    curve == GNUTLS_ECC_CURVE_X448) {
		datum->size = x.size;
		datum->data = gnutls_malloc(datum->size);
		if (datum->data == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			goto cleanup;
		}

		memcpy(datum->data, x.data, x.size);
		goto cleanup;
	}

	const int coord_size = gnutls_ecc_curve_get_size(curve);
	ret = _gnutls_coord_pad_left(&x, coord_size, &x_padded);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_coord_pad_left(&y, coord_size, &y_padded);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	datum->size = 1 + x_padded.size + y_padded.size;
	datum->data = gnutls_malloc(datum->size);
	if (datum->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
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

static int _gnutls_extract_coordinates_from_pubkey_datum(
	const gnutls_datum_t *datum, const gnutls_ecc_curve_t curve,
	gnutls_datum_t *x, gnutls_datum_t *y)
{
	const size_t coord_size = gnutls_ecc_curve_get_size(curve);

	if (curve == GNUTLS_ECC_CURVE_X25519 ||
	    curve == GNUTLS_ECC_CURVE_X448) {
		if (datum->size != coord_size) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}

		x->size = coord_size;
		x->data = gnutls_malloc(coord_size);
		if (x->data == NULL) {
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		}

		memcpy(x->data, datum->data, coord_size);
		y->size = 0;
		y->data = NULL;

		return GNUTLS_E_SUCCESS;
	}

	if (datum->size != 1 + 2 * coord_size || datum->data[0] != 0x04) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	x->size = coord_size;
	x->data = gnutls_malloc(coord_size);
	if (x->data == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	memcpy(x->data, datum->data + 1, coord_size);

	y->size = coord_size;
	y->data = gnutls_malloc(coord_size);
	if (y->data == NULL) {
		gnutls_free(x->data);
		x->data = NULL;
		x->size = 0;
		y->size = 0;
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	memcpy(y->data, datum->data + 1 + coord_size, coord_size);

	return GNUTLS_E_SUCCESS;
}

static int gnutls_datum_to_pubkey(const gnutls_ecc_curve_t curve,
				  const gnutls_datum_t *datum,
				  gnutls_pubkey_t *pk)
{
	int ret;

	gnutls_datum_t x = { NULL, 0 };
	gnutls_datum_t y = { NULL, 0 };

	ret = _gnutls_extract_coordinates_from_pubkey_datum(datum, curve, &x,
							    &y);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = gnutls_pubkey_init(pk);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = gnutls_pubkey_import_ecc_raw(*pk, curve, &x, &y);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

cleanup:
	if (x.data != NULL) {
		gnutls_free(x.data);
	}

	if (y.data != NULL) {
		gnutls_free(y.data);
	}

	return ret;
}

static gnutls_datum_t _gnutls_compute_suite_id(const uint16_t kem_id)
{
	gnutls_datum_t suite_id = { NULL, 5 };
	suite_id.data = gnutls_malloc(suite_id.size);
	if (suite_id.data == NULL) {
		suite_id.size = 0;
		return suite_id;
	}

	suite_id.data[0] = 'K';
	suite_id.data[1] = 'E';
	suite_id.data[2] = 'M';
	suite_id.data[3] = (kem_id >> 8) & 0xff;
	suite_id.data[4] = kem_id & 0xff;
	return suite_id;
}

static gnutls_datum_t _gnutls_hpke_get_ikm_label(const gnutls_datum_t *suite_id,
						 const gnutls_datum_t *dh)
{
	const char *label_prefix = "HPKE-v1";
	const size_t label_prefix_len = strlen(label_prefix);
	const char *label_suffix = "eae_prk";
	const size_t label_suffix_len = strlen(label_suffix);

	gnutls_datum_t ikm_label = { NULL, 0 };

	ikm_label.size =
		label_prefix_len + suite_id->size + label_suffix_len + dh->size;
	ikm_label.data = gnutls_malloc(ikm_label.size);
	if (ikm_label.data == NULL) {
		ikm_label.size = 0;
		return ikm_label;
	}

	size_t offset = 0;
	memcpy(ikm_label.data + offset, label_prefix, label_prefix_len);
	offset += label_prefix_len;
	memcpy(ikm_label.data + offset, suite_id->data, suite_id->size);
	offset += suite_id->size;
	memcpy(ikm_label.data + offset, label_suffix, label_suffix_len);
	offset += label_suffix_len;
	memcpy(ikm_label.data + offset, dh->data, dh->size);

	return ikm_label;
}

static int _gnutls_hpke_get_kem_context(const gnutls_hpke_mode_t mode,
					const gnutls_pubkey_t receiver_pubkey,
					const gnutls_pubkey_t sender_pubkey,
					const gnutls_pubkey_t ephemeral_pubkey,
					gnutls_datum_t *kem_context)
{
	int ret;
	gnutls_datum_t pkR_raw = { NULL, 0 };
	gnutls_datum_t pkS_raw = { NULL, 0 };
	gnutls_datum_t pkE_raw = { NULL, 0 };

	ret = _gnutls_pubkey_to_datum(ephemeral_pubkey, &pkE_raw);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_pubkey_to_datum(receiver_pubkey, &pkR_raw);
	if (ret != 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	if (_gnutls_hpke_is_auth_mode(mode)) {
		ret = _gnutls_pubkey_to_datum(sender_pubkey, &pkS_raw);
		if (ret != 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	kem_context->size = pkE_raw.size + pkR_raw.size + pkS_raw.size;
	kem_context->data = gnutls_malloc(kem_context->size);
	if (kem_context->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	size_t offset = 0;
	memcpy(kem_context->data + offset, pkE_raw.data, pkE_raw.size);
	offset += pkE_raw.size;
	memcpy(kem_context->data + offset, pkR_raw.data, pkR_raw.size);
	offset += pkR_raw.size;

	if (_gnutls_hpke_is_auth_mode(mode)) {
		if (pkS_raw.data == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
			goto cleanup;
		}
		memcpy(kem_context->data + offset, pkS_raw.data, pkS_raw.size);
	}

cleanup:
	if (pkE_raw.data) {
		gnutls_free(pkE_raw.data);
	}

	if (pkR_raw.data) {
		gnutls_free(pkR_raw.data);
	}

	if (pkS_raw.data) {
		gnutls_free(pkS_raw.data);
	}

	return ret;
}

static int _gnutls_hpke_get_info_label(const gnutls_hpke_mode_t mode,
				       const gnutls_pubkey_t receiver_pubkey,
				       const gnutls_pubkey_t sender_pubkey,
				       const gnutls_pubkey_t ephemeral_pubkey,
				       const gnutls_datum_t suite_id,
				       const uint16_t Nsecret,
				       gnutls_datum_t *info_label)
{
	int ret;
	gnutls_datum_t kem_context = { NULL, 0 };
	ret = _gnutls_hpke_get_kem_context(mode, receiver_pubkey, sender_pubkey,
					   ephemeral_pubkey, &kem_context);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	if (kem_context.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	const char Nsecret_bytes[2] = { (char)(Nsecret >> 8),
					(char)(Nsecret & 0xff) };
	const char *label_prefix = "HPKE-v1";
	const size_t label_prefix_len = strlen(label_prefix);
	const char *label_suffix = "shared_secret";
	const size_t label_suffix_len = strlen(label_suffix);

	size_t info_label_len = 2 + label_prefix_len + suite_id.size +
				label_suffix_len + kem_context.size;
	info_label->size = info_label_len;
	info_label->data = gnutls_malloc(info_label->size);
	if (info_label->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	size_t offset = 0;
	memcpy(info_label->data + offset, Nsecret_bytes, 2);
	offset += 2;
	memcpy(info_label->data + offset, label_prefix, label_prefix_len);
	offset += label_prefix_len;
	memcpy(info_label->data + offset, suite_id.data, suite_id.size);
	offset += suite_id.size;
	memcpy(info_label->data + offset, label_suffix, label_suffix_len);
	offset += label_suffix_len;
	memcpy(info_label->data + offset, kem_context.data, kem_context.size);

cleanup:
	if (kem_context.data != NULL) {
		gnutls_free(kem_context.data);
	}

	return ret;
}

static int _gnutls_hpke_get_shared_secret(
	const gnutls_hpke_kem_t kem, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_mode_t mode, const gnutls_pubkey_t receiver_pubkey,
	const gnutls_pubkey_t sender_pubkey,
	const gnutls_pubkey_t ephemeral_pubkey, const gnutls_datum_t dh,
	gnutls_datum_t *shared_secret)
{
	int ret = 0;
	gnutls_datum_t ikm_label = { NULL, 0 };
	gnutls_datum_t salt = { NULL, 0 };
	gnutls_datum_t eae_prk = { NULL, 0 };
	gnutls_datum_t info_label = { NULL, 0 };
	gnutls_datum_t suite_id = _gnutls_compute_suite_id(kem);
	if (suite_id.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	const gnutls_mac_algorithm_t mac = _gnutls_kdf_to_mac(kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		ret = gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
		goto cleanup;
	}

	const uint8_t Nh = gnutls_hmac_get_len(mac);
	if (Nh == 0) {
		ret = gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
		goto cleanup;
	}

	salt.size = Nh;
	salt.data = gnutls_malloc(salt.size);
	if (salt.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	gnutls_memset(salt.data, 0, Nh);

	ikm_label = _gnutls_hpke_get_ikm_label(&suite_id, &dh);
	if (ikm_label.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	eae_prk.size = Nh;
	eae_prk.data = gnutls_malloc(eae_prk.size);
	if (eae_prk.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	ret = gnutls_hkdf_extract(mac, &ikm_label, &salt, eae_prk.data);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_get_info_label(mode, receiver_pubkey, sender_pubkey,
					  ephemeral_pubkey, suite_id, Nh,
					  &info_label);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	shared_secret->size = Nh;
	shared_secret->data = gnutls_malloc(shared_secret->size);
	if (shared_secret->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}

	ret = gnutls_hkdf_expand(mac, &eae_prk, &info_label,
				 shared_secret->data, Nh);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	goto cleanup;

error:
	if (shared_secret->data != NULL) {
		gnutls_free(shared_secret->data);
		shared_secret->data = NULL;
		shared_secret->size = 0;
	}

cleanup:
	if (salt.data != NULL) {
		gnutls_free(salt.data);
	}

	if (ikm_label.data != NULL) {
		gnutls_free(ikm_label.data);
	}

	if (suite_id.data != NULL) {
		gnutls_free(suite_id.data);
	}

	if (eae_prk.data != NULL) {
		gnutls_memset(eae_prk.data, 0, eae_prk.size);
		gnutls_free(eae_prk.data);
	}

	if (info_label.data != NULL) {
		gnutls_free(info_label.data);
	}

	return ret;
}

static int _gnutls_hpke_encap_get_dh(const gnutls_hpke_mode_t mode,
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

	if (_gnutls_hpke_is_auth_mode(mode)) {
		ret = gnutls_privkey_derive_secret(
			sender_privkey, receiver_pubkey, NULL, &dhS, 0);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	dh->size = dhS.size + dhE.size;
	dh->data = gnutls_malloc(dh->size);
	if (dh->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	memcpy(dh->data, dhE.data, dhE.size);

	if (_gnutls_hpke_is_auth_mode(mode)) {
		memcpy(dh->data + dhE.size, dhS.data, dhS.size);
	}

cleanup:

	if (dhS.data != NULL) {
		gnutls_free(dhS.data);
	}

	if (dhE.data != NULL) {
		gnutls_free(dhE.data);
	}

	return ret;
}

static int _gnutls_hpke_dhkem_encap(const gnutls_hpke_kem_t kem,
				    const gnutls_hpke_kdf_t kdf,
				    const gnutls_hpke_mode_t mode,
				    const gnutls_pubkey_t receiver_pubkey,
				    const gnutls_privkey_t sender_privkey,
				    gnutls_datum_t *enc,
				    gnutls_datum_t *shared_secret)
{
	int ret = 0;
	gnutls_ecc_curve_t curve;
	gnutls_privkey_t ephemeral_privkey = NULL;
	gnutls_pubkey_t ephemeral_pubkey = NULL;
	gnutls_pubkey_t sender_pubkey = NULL;
	gnutls_datum_t dh = { NULL, 0 };

	ret = gnutls_pubkey_export_ecc_raw(receiver_pubkey, &curve, NULL, NULL);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	if (!_gnutls_is_key_curve_type_compatible_with_param_dhkem(kem,
								   curve)) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	ret = gnutls_privkey_init(&ephemeral_privkey);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	const gnutls_pk_algorithm_t pk_algo =
		_gnutls_hpke_get_kem_associated_pk_algorithm(kem);
	if (pk_algo == GNUTLS_PK_UNKNOWN) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	ret = gnutls_privkey_generate(ephemeral_privkey, pk_algo,
				      GNUTLS_CURVE_TO_BITS(curve), 0);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = gnutls_pubkey_init(&ephemeral_pubkey);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = gnutls_pubkey_import_privkey(ephemeral_pubkey, ephemeral_privkey,
					   0, 0);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_pubkey_to_datum(ephemeral_pubkey, enc);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto error;
	}

	ret = _gnutls_hpke_encap_get_dh(mode, receiver_pubkey,
					ephemeral_privkey, sender_privkey, &dh);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto error;
	}

	ret = gnutls_pubkey_init(&sender_pubkey);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto error;
	}

	if (_gnutls_hpke_is_auth_mode(mode)) {
		ret = gnutls_pubkey_import_privkey(sender_pubkey,
						   sender_privkey, 0, 0);
		if (ret < 0) {
			ret = gnutls_assert_val(ret);
			goto error;
		}
	}

	ret = _gnutls_hpke_get_shared_secret(kem, kdf, mode, receiver_pubkey,
					     sender_pubkey, ephemeral_pubkey,
					     dh, shared_secret);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto error;
	}

	goto cleanup;

error:
	if (enc != NULL && enc->data != NULL) {
		gnutls_free(enc->data);
		enc->data = NULL;
		enc->size = 0;
	}

	if (shared_secret != NULL && shared_secret->data != NULL) {
		gnutls_free(shared_secret->data);
		shared_secret->data = NULL;
		shared_secret->size = 0;
	}

cleanup:

	if (ephemeral_pubkey != NULL) {
		gnutls_pubkey_deinit(ephemeral_pubkey);
	}

	if (ephemeral_privkey != NULL) {
		gnutls_privkey_deinit(ephemeral_privkey);
	}

	if (sender_pubkey != NULL) {
		gnutls_pubkey_deinit(sender_pubkey);
	}

	if (dh.data != NULL) {
		gnutls_memset(dh.data, 0, dh.size);
		gnutls_free(dh.data);
	}

	return ret;
}

static int _gnutls_hpke_decap_get_dh(const gnutls_hpke_mode_t mode,
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

	if (_gnutls_hpke_is_auth_mode(mode)) {
		ret = gnutls_privkey_derive_secret(
			receiver_privkey, sender_pubkey, NULL, &dhS, 0);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}
	}

	dh->size = dhE.size + dhS.size;
	dh->data = gnutls_malloc(dh->size);
	if (dh->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	memcpy(dh->data, dhE.data, dhE.size);

	if (_gnutls_hpke_is_auth_mode(mode)) {
		memcpy(dh->data + dhE.size, dhS.data, dhS.size);
	}

cleanup:
	if (dhE.data != NULL) {
		gnutls_free(dhE.data);
	}

	if (dhS.data != NULL) {
		gnutls_free(dhS.data);
	}

	return ret;
}

static int _gnutls_hpke_dhkem_decap(const gnutls_hpke_kem_t kem,
				    const gnutls_hpke_kdf_t kdf,
				    const gnutls_hpke_mode_t mode,
				    const gnutls_privkey_t receiver_privkey,
				    const gnutls_pubkey_t sender_pubkey,
				    const gnutls_datum_t *enc,
				    gnutls_datum_t *shared_secret)
{
	int ret;

	gnutls_datum_t dh = { NULL, 0 };
	gnutls_pubkey_t receiver_pubkey = NULL;
	gnutls_pubkey_t ephemeral_pubkey = NULL;
	gnutls_ecc_curve_t curve;

	ret = gnutls_privkey_export_ecc_raw(receiver_privkey, &curve, NULL,
					    NULL, NULL);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto error;
	}

	if (!_gnutls_is_key_curve_type_compatible_with_param_dhkem(kem,
								   curve)) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto error;
	}

	ret = gnutls_datum_to_pubkey(curve, enc, &ephemeral_pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	ret = _gnutls_hpke_decap_get_dh(mode, ephemeral_pubkey, sender_pubkey,
					receiver_privkey, &dh);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	ret = gnutls_pubkey_init(&receiver_pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	ret = gnutls_pubkey_import_privkey(receiver_pubkey, receiver_privkey, 0,
					   0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	ret = _gnutls_hpke_get_shared_secret(kem, kdf, mode, receiver_pubkey,
					     sender_pubkey, ephemeral_pubkey,
					     dh, shared_secret);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	goto cleanup;

error:
	if (shared_secret != NULL && shared_secret->data != NULL) {
		gnutls_free(shared_secret->data);
	}

cleanup:
	if (dh.data != NULL) {
		gnutls_memset(dh.data, 0, dh.size);
		gnutls_free(dh.data);
	}

	if (receiver_pubkey != NULL) {
		gnutls_pubkey_deinit(receiver_pubkey);
	}

	if (ephemeral_pubkey != NULL) {
		gnutls_pubkey_deinit(ephemeral_pubkey);
	}

	return ret;
}

static gnutls_datum_t
_gnutls_get_suite_id_for_scheduling(const uint16_t kdf_id,
				    const uint16_t aead_id)
{
	gnutls_datum_t suite_id = { NULL, 8 };
	suite_id.data = gnutls_malloc(suite_id.size);
	if (suite_id.data == NULL) {
		suite_id.size = 0;
		return suite_id;
	}

	suite_id.data[0] = 'H';
	suite_id.data[1] = 'P';
	suite_id.data[2] = 'K';
	suite_id.data[3] = 'E';
	suite_id.data[4] = (kdf_id >> 8) & 0xff;
	suite_id.data[5] = kdf_id & 0xff;
	suite_id.data[6] = (aead_id >> 8) & 0xff;
	suite_id.data[7] = aead_id & 0xff;

	return suite_id;
}

static gnutls_datum_t
_gnutls_get_labeled_extract_key(const gnutls_datum_t *suite_id,
				const gnutls_datum_t *label,
				const gnutls_datum_t *ikm)
{
	gnutls_datum_t extract_key = { NULL, 0 };

	gnutls_datum_t label_prefix = { (unsigned char *)"HPKE-v1",
					strlen("HPKE-v1") };

	extract_key.size =
		label_prefix.size + suite_id->size + label->size + ikm->size;
	extract_key.data = gnutls_malloc(extract_key.size);
	if (extract_key.data == NULL) {
		extract_key.size = 0;
		return extract_key;
	}

	size_t offset = 0;
	memcpy(extract_key.data + offset, label_prefix.data, label_prefix.size);
	offset += label_prefix.size;
	memcpy(extract_key.data + offset, suite_id->data, suite_id->size);
	offset += suite_id->size;
	memcpy(extract_key.data + offset, label->data, label->size);
	offset += label->size;
	memcpy(extract_key.data + offset, ikm->data, ikm->size);

	return extract_key;
}

static int
_gnutls_labeled_extract(const gnutls_mac_algorithm_t mac,
			const size_t hash_size, const gnutls_datum_t *suite_id,
			const gnutls_datum_t *salt, const gnutls_datum_t *label,
			const gnutls_datum_t *ikm, gnutls_datum_t *out)
{
	int ret;
	gnutls_datum_t extract_key =
		_gnutls_get_labeled_extract_key(suite_id, label, ikm);
	if (extract_key.data == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	out->size = hash_size;
	out->data = gnutls_malloc(out->size);
	if (out->data == NULL) {
		out->size = 0;
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	ret = gnutls_hkdf_extract(mac, &extract_key, salt, out->data);
	if (ret < 0) {
		gnutls_assert_val(ret);
	}

cleanup:

	if (extract_key.data != NULL) {
		gnutls_free(extract_key.data);
	}

	return ret;
}

static gnutls_datum_t
_gnutls_get_key_context_for_scheduling(const uint8_t mode,
				       const gnutls_datum_t psk_id_hash,
				       const gnutls_datum_t info_hash)
{
	const size_t context_size = 1 + psk_id_hash.size + info_hash.size;
	gnutls_datum_t key_schedule_context = { gnutls_malloc(context_size),
						context_size };
	if (key_schedule_context.data == NULL) {
		key_schedule_context.size = 0;
		return key_schedule_context;
	}

	size_t offset = 0;
	key_schedule_context.data[offset] = mode;
	offset += 1;
	memcpy(key_schedule_context.data + offset, psk_id_hash.data,
	       psk_id_hash.size);
	offset += psk_id_hash.size;
	memcpy(key_schedule_context.data + offset, info_hash.data,
	       info_hash.size);

	return key_schedule_context;
}

static int _gnutls_hpke_compute_expand_info(const gnutls_hpke_kdf_t kdf,
					    const gnutls_hpke_aead_t aead,
					    const gnutls_datum_t *label,
					    const gnutls_datum_t *context,
					    const size_t L,
					    gnutls_datum_t *expand_info)
{
	gnutls_datum_t suite_id = { NULL, 0 };

	char cL[2] = { 0 };
	cL[0] = (L >> 8) & 0xff;
	cL[1] = L & 0xff;

	gnutls_datum_t label_prefix = { (unsigned char *)"HPKE-v1",
					strlen("HPKE-v1") };

	suite_id = _gnutls_get_suite_id_for_scheduling(kdf, aead);
	if (suite_id.data == NULL) {
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	expand_info->size = 2 + label_prefix.size + suite_id.size +
			    label->size + context->size;
	expand_info->data = gnutls_malloc(expand_info->size);
	if (expand_info->data == NULL) {
		if (suite_id.data != NULL) {
			gnutls_free(suite_id.data);
		}
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	size_t offset = 0;
	memcpy(expand_info->data + offset, cL, 2);
	offset += 2;
	memcpy(expand_info->data + offset, label_prefix.data,
	       label_prefix.size);
	offset += label_prefix.size;
	memcpy(expand_info->data + offset, suite_id.data, suite_id.size);
	offset += suite_id.size;
	memcpy(expand_info->data + offset, label->data, label->size);
	offset += label->size;
	memcpy(expand_info->data + offset, context->data, context->size);

	if (suite_id.data != NULL) {
		gnutls_free(suite_id.data);
	}

	return GNUTLS_E_SUCCESS;
}

static int _gnutls_labeled_expand(const gnutls_hpke_kdf_t kdf,
				  const gnutls_hpke_aead_t aead,
				  const gnutls_datum_t *secret,
				  const gnutls_datum_t *label,
				  const gnutls_datum_t *context, const size_t L,
				  gnutls_datum_t *out)
{
	int ret = 0;
	gnutls_datum_t expand_info = { NULL, 0 };
	ret = _gnutls_hpke_compute_expand_info(kdf, aead, label, context, L,
					       &expand_info);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	out->size = L;
	out->data = gnutls_malloc(out->size);
	if (out->data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}

	const gnutls_mac_algorithm_t mac = _gnutls_kdf_to_mac(kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		ret = gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
		goto error;
	}

	ret = gnutls_hkdf_expand(mac, secret, &expand_info, out->data, L);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	goto cleanup;

error:
	if (out != NULL && out->data != NULL) {
		gnutls_free(out->data);
		out->data = NULL;
		out->size = 0;
	}

cleanup:
	if (expand_info.data != NULL) {
		gnutls_free(expand_info.data);
	}

	return ret;
}

static int _gnutls_hpke_schedule(
	const gnutls_datum_t shared_secret, const gnutls_hpke_kdf_t kdf,
	const gnutls_hpke_aead_t aead, const gnutls_hpke_mode_t mode,
	const gnutls_datum_t *info, const gnutls_datum_t *psk,
	const gnutls_datum_t *psk_id, gnutls_datum_t *key,
	gnutls_datum_t *base_nonce, gnutls_datum_t *exporter_secret)
{
	int ret = 0;
	gnutls_datum_t salt = { NULL, 0 };
	gnutls_datum_t psk_id_hash = { NULL, 0 };
	gnutls_datum_t info_hash = { NULL, 0 };
	gnutls_datum_t key_schedule_context = { NULL, 0 };
	gnutls_datum_t secret = { NULL, 0 };
	gnutls_datum_t suite_id = { NULL, 0 };

	const gnutls_mac_algorithm_t mac = _gnutls_kdf_to_mac(kdf);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		ret = gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
		goto cleanup;
	}

	const uint8_t Nh = gnutls_hmac_get_len(mac);
	if (Nh == 0) {
		ret = gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
		goto cleanup;
	}

	salt.size = Nh;
	salt.data = gnutls_malloc(salt.size);
	if (salt.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	gnutls_memset(salt.data, 0, Nh);

	suite_id = _gnutls_get_suite_id_for_scheduling(kdf, aead);
	if (suite_id.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	const gnutls_datum_t psk_id_label = { (unsigned char *)"psk_id_hash",
					      strlen("psk_id_hash") };

	ret = _gnutls_labeled_extract(mac, Nh, &suite_id, &salt, &psk_id_label,
				      psk_id, &psk_id_hash);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	const gnutls_datum_t info_label = { (unsigned char *)"info_hash",
					    strlen("info_hash") };

	ret = _gnutls_labeled_extract(mac, Nh, &suite_id, &salt, &info_label,
				      info, &info_hash);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	key_schedule_context = _gnutls_get_key_context_for_scheduling(
		mode, psk_id_hash, info_hash);
	if (key_schedule_context.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	const gnutls_datum_t secret_label = { (unsigned char *)"secret",
					      strlen("secret") };

	ret = _gnutls_labeled_extract(mac, Nh, &suite_id, &shared_secret,
				      &secret_label, psk, &secret);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	const gnutls_cipher_algorithm_t cipher =
		_gnutls_hpke_aead_to_cipher(aead);

	const size_t Nk = gnutls_cipher_get_key_size(cipher);
	if (Nk == 0) {
		ret = gnutls_assert_val(GNUTLS_E_UNKNOWN_CIPHER_TYPE);
		goto cleanup;
	}

	const gnutls_datum_t key_label = { (unsigned char *)"key",
					   strlen("key") };

	ret = _gnutls_labeled_expand(kdf, aead, &secret, &key_label,
				     &key_schedule_context, Nk, key);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	const gnutls_datum_t base_nonce_label = { (unsigned char *)"base_nonce",
						  strlen("base_nonce") };

	const uint8_t Nn = 12;
	ret = _gnutls_labeled_expand(kdf, aead, &secret, &base_nonce_label,
				     &key_schedule_context, Nn, base_nonce);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	const gnutls_datum_t exporter_secret_label = {
		(unsigned char *)"exporter_secret", strlen("exporter_secret")
	};

	ret = _gnutls_labeled_expand(kdf, aead, &secret, &exporter_secret_label,
				     &key_schedule_context, Nh,
				     exporter_secret);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

cleanup:
	if (salt.data != NULL) {
		gnutls_free(salt.data);
	}

	if (psk_id_hash.data != NULL) {
		gnutls_free(psk_id_hash.data);
	}

	if (info_hash.data != NULL) {
		gnutls_free(info_hash.data);
	}

	if (key_schedule_context.data != NULL) {
		gnutls_free(key_schedule_context.data);
	}

	if (secret.data != NULL) {
		gnutls_memset(secret.data, 0, secret.size);
		gnutls_free(secret.data);
	}

	if (suite_id.data != NULL) {
		gnutls_free(suite_id.data);
	}

	return ret;
}

static int get_mode_from_encap_ctx(const gnutls_hpke_encap_context_t *ctx,
				   gnutls_hpke_mode_t *mode)
{
	*mode = GNUTLS_HPKE_MODE_BASE;

	if (ctx->psk != NULL || ctx->psk_id != NULL) {
		if (ctx->psk == NULL || ctx->psk_id == NULL) {
			_gnutls_debug_log(
				"HPKE: both psk and psk_id must be set for PSK modes\n");
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
		*mode = GNUTLS_HPKE_MODE_PSK;
	}

	if (ctx->sender_privkey != NULL) {
		if (*mode == GNUTLS_HPKE_MODE_PSK) {
			*mode = GNUTLS_HPKE_MODE_AUTH_PSK;
		} else {
			*mode = GNUTLS_HPKE_MODE_AUTH;
		}
	}

	return GNUTLS_E_SUCCESS;
}

/**
 * gnutls_hpke_encap:
 * @ctx: The encapsulation context
 * @enc: Output encapsulated key
 * @key: Output key
 * @base_nonce: Output base nonce
 * @exporter_secret: Output exporter secret
 *
 * This function performs the HPKE encapsulation operation, deriving the
 * encapsulated key, key, base nonce and exporter secret.
 *
 * The HPKE mode is determined from the context parameters as follows:
 * - If bot psk and psk_id are set, then PSK mode is used.
 * - If sender_privkey is set, and both psk and psk_id are NULL, then Auth mode
 *   is used.
 * - If sender_privkey is set, and both psk and psk_id are set, then AuthPSK mode
 *   is used.
 * - Otherwise, Base mode is used.
 *
 * Returns: On success, GNUTLS_E_SUCCESS (0) is returned. On error, a
 * negative error value is returned.
 **/
int gnutls_hpke_encap(const gnutls_hpke_encap_context_t *ctx,
		      gnutls_datum_t *enc, gnutls_datum_t *key,
		      gnutls_datum_t *base_nonce,
		      gnutls_datum_t *exporter_secret)
{
	int ret = 0;
	gnutls_datum_t shared_secret = { 0 };
	const gnutls_datum_t *local_info = ctx->info ? ctx->info : &empty_datum;
	const gnutls_datum_t *local_psk_id = ctx->psk_id ? ctx->psk_id :
							   &empty_datum;
	const gnutls_datum_t *local_psk = ctx->psk ? ctx->psk : &empty_datum;
	gnutls_hpke_mode_t mode;
	ret = get_mode_from_encap_ctx(ctx, &mode);
	if (ret < 0) {
		gnutls_assert_val(ret);
		return ret;
	}

	if (is_dhkem(ctx->kem)) {
		ret = _gnutls_hpke_dhkem_encap(ctx->kem, ctx->kdf, mode,
					       ctx->receiver_pubkey,
					       ctx->sender_privkey, enc,
					       &shared_secret);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}
	} // TODO: else if(is_mlkem(ctx->kem)) {}
	else {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = _gnutls_hpke_schedule(shared_secret, ctx->kdf, ctx->aead, mode,
				    local_info, local_psk, local_psk_id, key,
				    base_nonce, exporter_secret);
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

	if (key->data != NULL) {
		gnutls_free(key->data);
		key->data = NULL;
		key->size = 0;
	}

	if (base_nonce->data != NULL) {
		gnutls_free(base_nonce->data);
		base_nonce->data = NULL;
		base_nonce->size = 0;
	}

	if (exporter_secret->data != NULL) {
		gnutls_free(exporter_secret->data);
		exporter_secret->data = NULL;
		exporter_secret->size = 0;
	}

cleanup:
	if (shared_secret.data != NULL) {
		gnutls_free(shared_secret.data);
		shared_secret.data = NULL;
		shared_secret.size = 0;
	}

	return ret;
}

static int get_mode_from_decap_ctx(const gnutls_hpke_decap_context_t *ctx,
				   gnutls_hpke_mode_t *mode)
{
	*mode = GNUTLS_HPKE_MODE_BASE;

	if (ctx->psk != NULL || ctx->psk_id != NULL) {
		if (ctx->psk == NULL || ctx->psk_id == NULL) {
			_gnutls_debug_log(
				"HPKE: both psk and psk_id must be set for PSK modes\n");
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}
		*mode = GNUTLS_HPKE_MODE_PSK;
	}

	if (ctx->sender_pubkey != NULL) {
		if (*mode == GNUTLS_HPKE_MODE_PSK) {
			*mode = GNUTLS_HPKE_MODE_AUTH_PSK;
		} else {
			*mode = GNUTLS_HPKE_MODE_AUTH;
		}
	}

	return GNUTLS_E_SUCCESS;
}

/**
 * gnutls_hpke_decap:
 * @ctx: The decapsulation context
 * @key: Output key
 * @base_nonce: Output base nonce
 * @exporter_secret: Output exporter secret
 *
 * This function performs the HPKE decapsulation operation, deriving the
 * key, base nonce and exporter secret.
 *
 * The HPKE mode is determined from the context parameters as follows:
 * - If bot psk and psk_id are set, then PSK mode is used.
 * - If sender_privkey is set, and both psk and psk_id are NULL, then Auth mode
 *   is used.
 * - If sender_privkey is set, and both psk and psk_id are set, then AuthPSK mode
 *   is used.
 * - Otherwise, Base mode is used.
 *
 * Returns: On success, GNUTLS_E_SUCCESS (0) is returned. On error, a
 * negative error value is returned.
 **/
int gnutls_hpke_decap(const gnutls_hpke_decap_context_t *ctx,
		      gnutls_datum_t *key, gnutls_datum_t *base_nonce,
		      gnutls_datum_t *exporter_secret)
{
	int ret = 0;
	gnutls_datum_t shared_secret = { NULL, 0 };
	const gnutls_datum_t *local_info = ctx->info ? ctx->info : &empty_datum;
	const gnutls_datum_t *local_psk_id = ctx->psk_id ? ctx->psk_id :
							   &empty_datum;
	const gnutls_datum_t *local_psk = ctx->psk ? ctx->psk : &empty_datum;
	gnutls_hpke_mode_t mode;
	ret = get_mode_from_decap_ctx(ctx, &mode);
	if (ret < 0) {
		gnutls_assert_val(ret);
		return ret;
	}

	if (is_dhkem(ctx->kem)) {
		ret = _gnutls_hpke_dhkem_decap(ctx->kem, ctx->kdf, mode,
					       ctx->receiver_privkey,
					       ctx->sender_pubkey, ctx->enc,
					       &shared_secret);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}
	} // TODO: else if(is_mlkem(ctd->kem)) {}
	else {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	ret = _gnutls_hpke_schedule(shared_secret, ctx->kdf, ctx->aead, mode,
				    local_info, local_psk, local_psk_id, key,
				    base_nonce, exporter_secret);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	goto cleanup;

error:
	if (key->data != NULL) {
		gnutls_free(key->data);
		key->data = NULL;
		key->size = 0;
	}

	if (base_nonce->data != NULL) {
		gnutls_free(base_nonce->data);
		base_nonce->data = NULL;
		base_nonce->size = 0;
	}

	if (exporter_secret->data != NULL) {
		gnutls_free(exporter_secret->data);
		exporter_secret->data = NULL;
		exporter_secret->size = 0;
	}

cleanup:
	if (shared_secret.data != NULL) {
		gnutls_free(shared_secret.data);
	}
	return ret;
}
