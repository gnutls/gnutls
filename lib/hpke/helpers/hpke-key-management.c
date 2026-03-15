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

#include <nettle/curve25519.h>
#include <nettle/curve448.h>
#include <nettle/ecc.h>
#include <nettle/ecc-curve.h>

#define GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE 66
#define GNUTLS_HPKE_MAX_MONTGOMERY_KEY_SIZE 56

static const unsigned char dkp_prk_label[] = "dkp_prk";
static const unsigned char sk_label[] = "sk";
static const unsigned char candidate_label[] = "candidate";

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

static void _gnutls_hpke_coord_pad_left_to_buf(const gnutls_datum_t *in,
					       size_t out_size,
					       unsigned char *out)
{
	gnutls_memset(out, 0, out_size - in->size);
	memcpy(out + (out_size - in->size), in->data, in->size);
}

int _gnutls_hpke_pubkey_to_datum(const gnutls_pubkey_t pk,
				 unsigned char *pubkey_raw,
				 size_t *pubkey_raw_size)
{
	int ret;
	gnutls_ecc_curve_t curve;
	gnutls_datum_t x = { NULL, 0 };
	gnutls_datum_t y = { NULL, 0 };

	*pubkey_raw_size = 0;

	ret = gnutls_pubkey_export_ecc_raw2(pk, &curve, &x, &y,
					    GNUTLS_EXPORT_FLAG_NO_LZ);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	if (curve == GNUTLS_ECC_CURVE_X25519 ||
	    curve == GNUTLS_ECC_CURVE_X448) {
		if (x.data == NULL ||
		    x.size > GNUTLS_HPKE_MAX_DHKEM_PUBKEY_SIZE) {
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
			goto cleanup;
		}

		memcpy(pubkey_raw, x.data, x.size);
		*pubkey_raw_size = x.size;
		goto cleanup;
	}

	size_t coord_size = gnutls_ecc_curve_get_size(curve);
	size_t total_size = 1 + 2 * coord_size;

	if (coord_size == 0 || total_size > GNUTLS_HPKE_MAX_DHKEM_PUBKEY_SIZE) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	_gnutls_hpke_coord_pad_left_to_buf(&x, coord_size, pubkey_raw + 1);
	_gnutls_hpke_coord_pad_left_to_buf(&y, coord_size,
					   pubkey_raw + 1 + coord_size);

	pubkey_raw[0] = 0x04;
	*pubkey_raw_size = total_size;
	ret = 0;

cleanup:
	if (x.data != NULL) {
		gnutls_free(x.data);
	}

	if (y.data != NULL) {
		gnutls_free(y.data);
	}

	return ret;
}

static int _gnutls_hpke_extract_coordinates_from_pubkey_datum(
	const gnutls_ecc_curve_t curve, const gnutls_datum_t *datum,
	unsigned char *x, size_t *x_size, unsigned char *y, size_t *y_size)
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

		memcpy(x, datum->data, coord_size);
		*x_size = coord_size;
	} else {
		if (datum->size != 1 + 2 * coord_size ||
		    datum->data[0] != 0x04) {
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		}

		memcpy(x, datum->data + 1, coord_size);
		*x_size = coord_size;
		memcpy(y, datum->data + 1 + coord_size, coord_size);
		*y_size = coord_size;
	}

	return 0;
}

int _gnutls_hpke_datum_to_pubkey(const gnutls_ecc_curve_t curve,
				 const gnutls_datum_t *datum,
				 gnutls_pubkey_t *pk)
{
	int ret;
	unsigned char x[GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE];
	size_t x_size = 0;
	unsigned char y[GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE];
	size_t y_size = 0;

	ret = _gnutls_hpke_extract_coordinates_from_pubkey_datum(
		curve, datum, x, &x_size, y, &y_size);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	ret = gnutls_pubkey_init(pk);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	gnutls_datum_t x_datum = { x, x_size };
	gnutls_datum_t y_datum = { y, y_size };
	ret = gnutls_pubkey_import_ecc_raw(*pk, curve, &x_datum, &y_datum);
	if (ret < 0) {
		gnutls_assert_val(ret);
		gnutls_pubkey_deinit(*pk);
		*pk = NULL;
		return ret;
	}

	return ret;
}

static void _gnutls_hpke_clamp_sk(const gnutls_hpke_kem_t kem,
				  unsigned char *sk_buf)
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

static int
_gnutls_hpke_derive_montgomery_curve_public_key(const gnutls_hpke_kem_t kem,
						const gnutls_datum_t *priv_raw,
						unsigned char *pub_raw)
{
	uint8_t k[GNUTLS_HPKE_MAX_MONTGOMERY_KEY_SIZE];

	memcpy(k, priv_raw->data, priv_raw->size);
	_gnutls_hpke_clamp_sk(kem, k);

	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_X25519: {
		static const uint8_t basepoint[32] = { 9 };
		curve25519_mul(pub_raw, k, basepoint);
	} break;
	case GNUTLS_HPKE_KEM_DHKEM_X448: {
		static const uint8_t basepoint[56] = { 5 };
		curve448_mul(pub_raw, k, basepoint);
	} break;
	default:
		break;
	}

	gnutls_memset(k, 0, sizeof(k));
	return 0;
}

static int _gnutls_hpke_montgomery_curve_keypair_from_raw_privkey(
	const gnutls_mac_algorithm_t mac, const gnutls_hpke_kem_t kem,
	const gnutls_datum_t *dkp_prk, const gnutls_ecc_curve_t curve,
	const unsigned char *suite_id, size_t suite_id_size,
	gnutls_privkey_t *privkey, gnutls_pubkey_t *pubkey)
{
	int ret;
	unsigned char
		labeled_expand_info[GNUTLS_HPKE_MAX_LABELED_EXPAND_INFO_SIZE] = {
			0
		};
	size_t labeled_expand_info_size = 0;
	unsigned char sk_buf[GNUTLS_HPKE_MAX_MONTGOMERY_KEY_SIZE] = { 0 };
	size_t sk_size = 0;

	sk_size = gnutls_ecc_curve_get_size(curve);
	if (sk_size == 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	_gnutls_hpke_build_expand_info(suite_id, suite_id_size, sk_label,
				       sizeof(sk_label) - 1, NULL, 0, sk_size,
				       labeled_expand_info,
				       &labeled_expand_info_size);
	gnutls_datum_t labeled_expand_info_datum = { labeled_expand_info,
						     labeled_expand_info_size };
	ret = gnutls_hkdf_expand(mac, dkp_prk, &labeled_expand_info_datum,
				 sk_buf, sk_size);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	_gnutls_hpke_clamp_sk(kem, sk_buf);
	ret = gnutls_privkey_init(privkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	gnutls_datum_t k = { sk_buf, sk_size };
	unsigned char pk_buf[32];

	_gnutls_hpke_derive_montgomery_curve_public_key(kem, &k, pk_buf);

	gnutls_datum_t x = { pk_buf, 32 };
	ret = gnutls_privkey_import_ecc_raw(*privkey, curve, &x, NULL, &k);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	ret = gnutls_pubkey_init(pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	ret = gnutls_pubkey_import_ecc_raw(*pubkey, curve, &x, NULL);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto error;
	}

	goto cleanup;

error:
	if (privkey != NULL && *privkey != NULL) {
		gnutls_privkey_deinit(*privkey);
		*privkey = NULL;
	}

	if (pubkey != NULL && *pubkey != NULL) {
		gnutls_pubkey_deinit(*pubkey);
		*pubkey = NULL;
	}

cleanup:

	gnutls_memset(sk_buf, 0, sizeof(sk_buf));
	gnutls_memset(labeled_expand_info, 0, sizeof(labeled_expand_info));

	return ret;
}

static int _gnutls_hpke_is_all_zero(const unsigned char *buf, size_t len)
{
	size_t i;
	unsigned char acc = 0;

	for (i = 0; i < len; i++)
		acc |= buf[i];

	return acc == 0;
}

static const unsigned char *
_gnutls_hpke_get_kem_order(const gnutls_hpke_kem_t kem)
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

static int _gnutls_hpke_be_lt(const unsigned char *a, const unsigned char *b,
			      size_t len)
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

static int
_gnutls_hpke_get_ecc_and_curve_len_for_curve(const gnutls_ecc_curve_t curve,
					     const struct ecc_curve **ecc,
					     size_t *coord_size)
{
	switch (curve) {
	case GNUTLS_ECC_CURVE_SECP256R1:
		*ecc = nettle_get_secp_256r1();
		*coord_size = 32;
		break;
	case GNUTLS_ECC_CURVE_SECP384R1:
		*ecc = nettle_get_secp_384r1();
		*coord_size = 48;
		break;
	case GNUTLS_ECC_CURVE_SECP521R1:
		*ecc = nettle_get_secp_521r1();
		*coord_size = 66;
		break;
	default:
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

	return 0;
}

static int _gnutls_hpke_export_pubkey_coordinate(const size_t coord_size,
						 mpz_t p, unsigned char *p_raw,
						 size_t *p_raw_size)
{
	unsigned char tmp[66];
	size_t count = 0;

	memset(tmp, 0, sizeof(tmp));
	memset(p_raw, 0, coord_size);

	mpz_export(tmp, &count, 1, 1, 1, 0, p);
	if (count > coord_size) {
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	memcpy(p_raw + (coord_size - count), tmp, count);
	*p_raw_size = coord_size;

	gnutls_memset(tmp, 0, sizeof(tmp));

	return 0;
}

static int _gnutls_hpke_derive_raw_public_key_for_prime_curve(
	const gnutls_ecc_curve_t curve, const gnutls_datum_t *priv_raw,
	unsigned char *x, size_t *x_len, unsigned char *y, size_t *y_len)
{
	int ret = 0;
	const struct ecc_curve *ecc = NULL;
	struct ecc_scalar s;
	struct ecc_point p;
	mpz_t k, px, py;
	size_t coord_len = 0;
	int scalar_inited = 0;
	int point_inited = 0;
	int mpz_inited = 0;

	ret = _gnutls_hpke_get_ecc_and_curve_len_for_curve(curve, &ecc,
							   &coord_len);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	*x_len = 0;
	*y_len = 0;

	mpz_init(k);
	mpz_init(px);
	mpz_init(py);
	mpz_inited = 1;

	mpz_import(k, priv_raw->size, 1, 1, 1, 0, priv_raw->data);

	ecc_scalar_init(&s, ecc);
	scalar_inited = 1;

	if (!ecc_scalar_set(&s, k)) {
		ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
		goto cleanup;
	}

	ecc_point_init(&p, ecc);
	point_inited = 1;

	ecc_point_mul_g(&p, &s);
	ecc_point_get(&p, px, py);

	ret = _gnutls_hpke_export_pubkey_coordinate(coord_len, px, x, x_len);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = _gnutls_hpke_export_pubkey_coordinate(coord_len, py, y, y_len);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (point_inited)
		ecc_point_clear(&p);
	if (scalar_inited)
		ecc_scalar_clear(&s);
	if (mpz_inited) {
		mpz_clear(k);
		mpz_clear(px);
		mpz_clear(py);
	}

	return ret;
}

static int _gnutls_hpke_prime_curve_keypair_from_raw_privkey(
	const gnutls_mac_algorithm_t mac, const gnutls_hpke_kem_t kem,
	const gnutls_datum_t *dkp_prk, const gnutls_ecc_curve_t curve,
	const unsigned char *suite_id, size_t suite_id_size,
	gnutls_privkey_t *privkey, gnutls_pubkey_t *pubkey)
{
	int ret;
	unsigned char
		labeled_expand_info[GNUTLS_HPKE_MAX_LABELED_EXPAND_INFO_SIZE] = {
			0
		};
	size_t labeled_expand_info_size = 0;
	unsigned char sk_buf[GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE] = { 0 };
	size_t sk_size = 0;

	sk_size = gnutls_ecc_curve_get_size(curve);
	if (sk_size == 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}

	for (size_t counter = 0; counter < 256; counter++) {
		_gnutls_hpke_build_expand_info(suite_id, suite_id_size,
					       candidate_label,
					       sizeof(candidate_label) - 1,
					       (unsigned char *)&counter, 1,
					       sk_size, labeled_expand_info,
					       &labeled_expand_info_size);
		gnutls_datum_t labeled_expand_info_datum = {
			labeled_expand_info, labeled_expand_info_size
		};

		ret = gnutls_hkdf_expand(mac, dkp_prk,
					 &labeled_expand_info_datum, sk_buf,
					 sk_size);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto cleanup;
		}

		if (kem == GNUTLS_HPKE_KEM_DHKEM_P521) {
			sk_buf[0] &= 0x01;
		}

		if (_gnutls_hpke_is_all_zero(sk_buf, sk_size)) {
			continue;
		}

		const unsigned char *order = _gnutls_hpke_get_kem_order(kem);
		if (order == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
			goto cleanup;
		}

		ret = _gnutls_hpke_be_lt(sk_buf, order, sk_size);
		if (!ret) {
			continue;
		}

		ret = gnutls_privkey_init(privkey);
		if (ret < 0) {
			ret = gnutls_assert_val(ret);
			goto cleanup;
		}

		gnutls_datum_t k = { sk_buf, sk_size };
		unsigned char x_buf[GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE];
		size_t x_buf_len = 0;
		unsigned char y_buf[GNUTLS_HPKE_MAX_RAW_KEY_COORDINATE_SIZE];
		size_t y_buf_len = 0;
		ret = _gnutls_hpke_derive_raw_public_key_for_prime_curve(
			curve, &k, x_buf, &x_buf_len, y_buf, &y_buf_len);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}

		gnutls_datum_t x = { x_buf, x_buf_len };
		gnutls_datum_t y = { y_buf, y_buf_len };
		ret = gnutls_privkey_import_ecc_raw(*privkey, curve, &x, &y,
						    &k);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}

		ret = gnutls_pubkey_init(pubkey);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}

		ret = gnutls_pubkey_import_ecc_raw(*pubkey, curve, &x, &y);
		if (ret < 0) {
			gnutls_assert_val(ret);
			goto error;
		}

		break;
	}

	goto cleanup;

error:
	if (privkey != NULL && *privkey != NULL) {
		gnutls_privkey_deinit(*privkey);
		*privkey = NULL;
	}

	if (pubkey != NULL && *pubkey != NULL) {
		gnutls_pubkey_deinit(*pubkey);
		*pubkey = NULL;
	}

cleanup:

	gnutls_memset(sk_buf, 0, sizeof(sk_buf));
	gnutls_memset(labeled_expand_info, 0, sizeof(labeled_expand_info));

	return ret;
}

int _gnutls_hpke_keypair_from_ikm(const gnutls_hpke_kem_t kem,
				  const gnutls_datum_t *ikme,
				  gnutls_privkey_t *privkey,
				  gnutls_pubkey_t *pubkey)
{
	int ret;
	unsigned char dkp_prk_buf[GNUTLS_HPKE_MAX_HASH_SIZE] = { 0 };
	size_t dkp_prk_len = 0;

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

	unsigned char suite_id_buf[GNUTLS_HPKE_SUITE_ID_SIZE] = { 0 };
	_gnutls_hpke_build_kem_suite_id(kem, suite_id_buf);

	ret = _gnutls_hpke_labeled_extract(mac, suite_id_buf,
					   GNUTLS_HPKE_SUITE_ID_SIZE, NULL, 0,
					   dkp_prk_label,
					   sizeof(dkp_prk_label) - 1, ikme,
					   dkp_prk_buf, &dkp_prk_len);
	if (ret < 0) {
		ret = gnutls_assert_val(ret);
		goto cleanup;
	}

	gnutls_datum_t dkp_prk = { dkp_prk_buf, dkp_prk_len };

	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_X448:
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		ret = _gnutls_hpke_montgomery_curve_keypair_from_raw_privkey(
			mac, kem, &dkp_prk, curve, suite_id_buf,
			GNUTLS_HPKE_SUITE_ID_SIZE, privkey, pubkey);
		break;
	case GNUTLS_HPKE_KEM_DHKEM_P256:
	case GNUTLS_HPKE_KEM_DHKEM_P384:
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		ret = _gnutls_hpke_prime_curve_keypair_from_raw_privkey(
			mac, kem, &dkp_prk, curve, suite_id_buf,
			GNUTLS_HPKE_SUITE_ID_SIZE, privkey, pubkey);
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
	}

cleanup:

	gnutls_memset(dkp_prk_buf, 0, dkp_prk_len);

	return ret;
}

static int _gnutls_hpke_generate_new_keypair(
	const gnutls_ecc_curve_t curve, const gnutls_hpke_kem_t kem,
	const gnutls_pk_algorithm_t pk_algo,
	gnutls_privkey_t *ephemeral_privkey, gnutls_pubkey_t *ephemeral_pubkey)
{
	int ret;

	const gnutls_ecc_curve_t kem_associated_curve =
		_gnutls_hpke_kem_to_curve(kem);
	if (curve != kem_associated_curve) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		return ret;
	}

	ret = gnutls_privkey_generate(*ephemeral_privkey, pk_algo,
				      GNUTLS_CURVE_TO_BITS(curve), 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		return ret;
	}

	ret = gnutls_pubkey_init(ephemeral_pubkey);
	if (ret < 0) {
		gnutls_assert_val(ret);
		return ret;
	}

	ret = gnutls_pubkey_import_privkey(*ephemeral_pubkey,
					   *ephemeral_privkey, 0, 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		return ret;
	}

	return ret;
}

int _gnutls_hpke_generate_keypair(const gnutls_datum_t *ikme,
				  const gnutls_hpke_kem_t kem,
				  const gnutls_pubkey_t receiver_pubkey,
				  gnutls_privkey_t *ephemeral_privkey,
				  gnutls_pubkey_t *ephemeral_pubkey)
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

		ret = _gnutls_hpke_generate_new_keypair(curve, kem, pk_algo,
							ephemeral_privkey,
							ephemeral_pubkey);
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
