/*
 * copyright © 2026 david dudas
 *
 * author: david dudas <david.dudas03@e-uvt.ro>
 *
 * this file is part of gnutls.
 *
 * the gnutls is free software; you can redistribute it and/or
 * modify it under the terms of the gnu lesser general public license
 * as published by the free software foundation; either version 2.1 of
 * the license, or (at your option) any later version.
 *
 * this library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the gnu
 * lesser general public license for more details.

 *
 * you should have received a copy of the gnu lesser general public license
 * along with this program.  if not, see <https://www.gnu.org/licenses/>
 *
 */

#include "hpke-key-management.h"
#include "hpke-params.h"
#include "hpke-builders.h"
#include "hpke-hkdf.h"

#include "errors.h"

#define GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE 66
#define GNUTLS_HPKE_MAX_MONTGOMERY_KEY_SIZE 56

static const unsigned char p256_order[32] = {
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
	0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

static const unsigned char p384_order[48] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
	0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73
};

static const unsigned char p521_order[66] = {
	0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static void coord_pad_left_to_buf(const gnutls_datum_t *in, size_t out_size,
				  unsigned char *out)
{
	gnutls_memset(out, 0, out_size - in->size);
	memcpy(out + (out_size - in->size), in->data, in->size);
}

int _gnutls_hpke_pubkey_to_datum(const gnutls_pubkey_t pk,
				 gnutls_datum_t *pubkey_raw)
{
	int ret;
	gnutls_ecc_curve_t curve;
	gnutls_datum_t x = { NULL, 0 };
	gnutls_datum_t y = { NULL, 0 };

	pubkey_raw->size = 0;

	ret = gnutls_pubkey_export_ecc_raw2(pk, &curve, &x, &y,
					    GNUTLS_EXPORT_FLAG_NO_LZ);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	if (curve == GNUTLS_ECC_CURVE_X25519 ||
	    curve == GNUTLS_ECC_CURVE_X448) {
		if (x.data == NULL || x.size > HPKE_MAX_DHKEM_PUBKEY_SIZE) {
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
			goto cleanup;
		}

		memcpy(pubkey_raw->data, x.data, x.size);
		pubkey_raw->size = x.size;
		goto cleanup;
	}

	size_t coord_size = gnutls_ecc_curve_get_size(curve);
	size_t total_size = 1 + 2 * coord_size;

	if (coord_size == 0 || total_size > HPKE_MAX_DHKEM_PUBKEY_SIZE) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	coord_pad_left_to_buf(&x, coord_size, pubkey_raw->data + 1);
	coord_pad_left_to_buf(&y, coord_size,
			      pubkey_raw->data + 1 + coord_size);

	pubkey_raw->data[0] = 0x04;
	pubkey_raw->size = total_size;

cleanup:
	_gnutls_free_datum(&x);
	_gnutls_free_datum(&y);

	return ret;
}

static int extract_coordinates_from_pubkey_datum(const gnutls_ecc_curve_t curve,
						 const gnutls_datum_t *datum,
						 gnutls_datum_t *x,
						 gnutls_datum_t *y)
{
	const size_t coord_size = gnutls_ecc_curve_get_size(curve);

	if (coord_size == 0 ||
	    coord_size > GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE) {
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	if (curve == GNUTLS_ECC_CURVE_X25519 ||
	    curve == GNUTLS_ECC_CURVE_X448) {
		if (datum->size != coord_size) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}

		memcpy(x->data, datum->data, coord_size);
		x->size = coord_size;
	} else {
		if (datum->size != 1 + 2 * coord_size ||
		    datum->data[0] != 0x04) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}

		memcpy(x->data, datum->data + 1, coord_size);
		x->size = coord_size;
		memcpy(y->data, datum->data + 1 + coord_size, coord_size);
		y->size = coord_size;
	}

	return 0;
}

int _gnutls_hpke_datum_to_pubkey(const gnutls_ecc_curve_t curve,
				 const gnutls_datum_t *datum,
				 gnutls_pubkey_t pubkey)
{
	int ret;

	unsigned char x_buf[GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE];
	unsigned char y_buf[GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE];

	gnutls_datum_t x = { x_buf, 0 };
	gnutls_datum_t y = { y_buf, 0 };

	ret = extract_coordinates_from_pubkey_datum(curve, datum, &x, &y);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	ret = gnutls_pubkey_import_ecc_raw(pubkey, curve, &x, &y);
	if (ret < 0) {
		gnutls_assert_val(ret);
		return ret;
	}

	return ret;
}

static void clamp_sk(const gnutls_hpke_kem_t kem, unsigned char *sk_buf)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_X25519: {
		sk_buf[0] &= 248;
		sk_buf[31] &= 127;
		sk_buf[31] |= 64;
		break;
	}
	case GNUTLS_HPKE_KEM_DHKEM_X448: {
		sk_buf[0] &= 252;
		sk_buf[55] |= 128;
		break;
	}
	default:
		break;
	}
}

static int montgomery_curve_keypair_from_raw_privkey(
	const gnutls_mac_algorithm_t mac, const gnutls_hpke_kem_t kem,
	const gnutls_datum_t *dkp_prk, const gnutls_ecc_curve_t curve,
	const gnutls_datum_t *suite_id, gnutls_privkey_t privkey,
	gnutls_pubkey_t pubkey)
{
	int ret;
	unsigned char
		labeled_expand_info_buf[HPKE_MAX_LABELED_EXPAND_INFO_SIZE] = {
			0
		};
	unsigned char sk_buf[GNUTLS_HPKE_MAX_MONTGOMERY_KEY_SIZE] = { 0 };

	gnutls_datum_t labeled_expand_info = { labeled_expand_info_buf, 0 };
	gnutls_datum_t sk = { sk_buf, 0 };

	sk.size = gnutls_ecc_curve_get_size(curve);
	if (sk.size == 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	const gnutls_datum_t sk_label = { (void *)"sk", sizeof("sk") - 1 };

	_gnutls_hpke_build_expand_info(suite_id, &sk_label, NULL, sk.size,
				       &labeled_expand_info);
	ret = gnutls_hkdf_expand(mac, dkp_prk, &labeled_expand_info, sk.data,
				 sk.size);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	clamp_sk(kem, sk.data);

	ret = gnutls_privkey_import_ecc_raw(privkey, curve, NULL, NULL, &sk);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

cleanup:

	zeroize_key(sk.data, sk.size);
	zeroize_key(labeled_expand_info.data, labeled_expand_info.size);

	return ret;
}

static int is_all_zero(const unsigned char *buf, size_t len)
{
	size_t i;
	unsigned char acc = 0;

	for (i = 0; i < len; i++)
		acc |= buf[i];

	return acc == 0;
}

static const unsigned char *get_kem_order(const gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
		return p256_order;
	case GNUTLS_HPKE_KEM_DHKEM_P384:
		return p384_order;
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		return p521_order;
	default:
		return NULL;
	}
}

static int be_lt(const unsigned char *a, const unsigned char *b, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (a[i] < b[i])
			return 1;
		if (a[i] > b[i])
			return 0;
	}

	return 0;
}

static int prime_curve_keypair_from_raw_privkey(
	const gnutls_mac_algorithm_t mac, const gnutls_hpke_kem_t kem,
	const gnutls_datum_t *dkp_prk, const gnutls_ecc_curve_t curve,
	const gnutls_datum_t *suite_id, gnutls_privkey_t privkey,
	gnutls_pubkey_t pubkey)
{
	int ret;
	unsigned char
		labeled_expand_info_buf[HPKE_MAX_LABELED_EXPAND_INFO_SIZE] = {
			0
		};
	unsigned char sk_buf[GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE] = { 0 };

	gnutls_datum_t labeled_expand_info = { labeled_expand_info_buf, 0 };
	gnutls_datum_t sk = { sk_buf, 0 };

	sk.size = gnutls_ecc_curve_get_size(curve);
	if (sk.size == 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	const gnutls_datum_t candidate_label = { (void *)"candidate",
						 sizeof("candidate") - 1 };

	for (size_t counter = 0; counter < 256; counter++) {
		gnutls_datum_t context = { (void *)&counter, 1 };
		_gnutls_hpke_build_expand_info(suite_id, &candidate_label,
					       &context, sk.size,
					       &labeled_expand_info);

		ret = gnutls_hkdf_expand(mac, dkp_prk, &labeled_expand_info,
					 sk.data, sk.size);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}

		if (kem == GNUTLS_HPKE_KEM_DHKEM_P521) {
			sk_buf[0] &= 0x01;
		}

		if (is_all_zero(sk.data, sk.size)) {
			continue;
		}

		const unsigned char *order = get_kem_order(kem);
		if (order == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
			goto cleanup;
		}

		ret = be_lt(sk.data, order, sk.size);
		if (!ret) {
			continue;
		}

		ret = gnutls_privkey_import_ecc_raw(privkey, curve, NULL, NULL,
						    &sk);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}

		ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}

		break;
	}

cleanup:
	zeroize_key(sk.data, sk.size);
	zeroize_key(labeled_expand_info.data, labeled_expand_info.size);

	return ret;
}

int _gnutls_hpke_keypair_from_ikm(const gnutls_hpke_kem_t kem,
				  const gnutls_datum_t *ikme,
				  gnutls_privkey_t privkey,
				  gnutls_pubkey_t pubkey)
{
	int ret;
	unsigned char dkp_prk_buf[HPKE_MAX_HASH_SIZE] = { 0 };
	gnutls_datum_t dkp_prk = { dkp_prk_buf, 0 };

	const gnutls_mac_algorithm_t mac = _gnutls_hpke_kem_to_mac(kem);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		ret = gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
		goto cleanup;
	}

	gnutls_ecc_curve_t curve = _gnutls_hpke_kem_to_curve(kem);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	unsigned char suite_id_buf[HPKE_SUITE_ID_SIZE] = { 0 };
	_gnutls_hpke_build_kem_suite_id(kem, suite_id_buf);

	gnutls_datum_t suite_id = { suite_id_buf, HPKE_SUITE_ID_SIZE };
	gnutls_datum_t dkp_prk_label = { (void *)"dkp_prk",
					 sizeof("dkp_prk") - 1 };

	ret = _gnutls_hpke_labeled_extract(mac, &suite_id, NULL, &dkp_prk_label,
					   ikme, &dkp_prk);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_X448:
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		ret = montgomery_curve_keypair_from_raw_privkey(
			mac, kem, &dkp_prk, curve, &suite_id, privkey, pubkey);
		break;
	case GNUTLS_HPKE_KEM_DHKEM_P256:
	case GNUTLS_HPKE_KEM_DHKEM_P384:
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		ret = prime_curve_keypair_from_raw_privkey(
			mac, kem, &dkp_prk, curve, &suite_id, privkey, pubkey);
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

cleanup:
	zeroize_key(dkp_prk.data, dkp_prk.size);

	return ret;
}

static int generate_new_keypair(const gnutls_ecc_curve_t curve,
				const gnutls_hpke_kem_t kem,
				const gnutls_pk_algorithm_t pk_algo,
				gnutls_privkey_t ephemeral_privkey,
				gnutls_pubkey_t ephemeral_pubkey)
{
	int ret;

	const gnutls_ecc_curve_t kem_associated_curve =
		_gnutls_hpke_kem_to_curve(kem);
	if (curve != kem_associated_curve) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		return ret;
	}

	ret = gnutls_privkey_generate(ephemeral_privkey, pk_algo,
				      GNUTLS_CURVE_TO_BITS(curve), 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		return ret;
	}

	ret = gnutls_pubkey_import_privkey(ephemeral_pubkey, ephemeral_privkey,
					   0, 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		return ret;
	}

	return ret;
}

int _gnutls_hpke_generate_keypair(const gnutls_datum_t *ikme,
				  const gnutls_hpke_kem_t kem,
				  const gnutls_pubkey_t receiver_pubkey,
				  gnutls_privkey_t ephemeral_privkey,
				  gnutls_pubkey_t ephemeral_pubkey)
{
	int ret;
	if (ikme == NULL) {
		gnutls_ecc_curve_t curve;

		const gnutls_pk_algorithm_t pk_algo =
			_gnutls_hpke_get_kem_associated_pk_algorithm(kem);
		if (pk_algo == GNUTLS_PK_UNKNOWN) {
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
			return ret;
		}

		ret = gnutls_pubkey_export_ecc_raw(receiver_pubkey, &curve,
						   NULL, NULL);
		if (ret < 0) {
			gnutls_assert_val(ret);
			return ret;
		}

		ret = generate_new_keypair(curve, kem, pk_algo,
					   ephemeral_privkey, ephemeral_pubkey);
		if (ret < 0) {
			gnutls_assert_val(ret);
			return ret;
		}

	} else {
		ret = _gnutls_hpke_keypair_from_ikm(
			kem, ikme, ephemeral_privkey, ephemeral_pubkey);
		if (ret < 0) {
			gnutls_assert_val(ret);
			return ret;
		}
	}

	return ret;
}

int _gnutls_hpke_privkey_clone(gnutls_privkey_t src, gnutls_privkey_t *dst)
{
	int ret;
	gnutls_x509_privkey_t xkey = NULL;

	ret = gnutls_privkey_export_x509(src, &xkey);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = gnutls_privkey_init(dst);
	if (ret < 0) {
		gnutls_x509_privkey_deinit(xkey);
		return gnutls_assert_val(ret);
	}

	ret = gnutls_privkey_import_x509(*dst, xkey,
					 GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
	if (ret < 0) {
		gnutls_privkey_deinit(*dst);
		*dst = NULL;
		gnutls_x509_privkey_deinit(xkey);
		return gnutls_assert_val(ret);
	}

	return 0;
}

int _gnutls_hpke_pubkey_clone(gnutls_pubkey_t src, gnutls_pubkey_t *dst)
{
	int ret;
	gnutls_datum_t der = { NULL, 0 };

	ret = gnutls_pubkey_export2(src, GNUTLS_X509_FMT_DER, &der);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	ret = gnutls_pubkey_init(dst);
	if (ret < 0) {
		gnutls_free(der.data);
		return gnutls_assert_val(ret);
	}

	ret = gnutls_pubkey_import(*dst, &der, GNUTLS_X509_FMT_DER);
	gnutls_free(der.data);

	if (ret < 0) {
		gnutls_pubkey_deinit(*dst);
		*dst = NULL;
		return gnutls_assert_val(ret);
	}

	return 0;
}
