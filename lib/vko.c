/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
 * Copyright (C) 2016 Dmitry Eremin-Solenikov
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/*
 * This is split from main TLS key exchange, because it might be useful in
 * future for S/MIME support. For the definition of the algorithm see RFC 4357,
 * section 5.2.
 */
#include "gnutls_int.h"
#include "vko.h"
#include "pk.h"
#include "common.h"

#define UKM_LEN 8

static int
_gnutls_gost_vko_key(gnutls_pk_params_st *pub,
		     gnutls_pk_params_st *priv,
		     gnutls_datum_t *ukm,
		     gnutls_datum_t *kek)
{
	gnutls_digest_algorithm_t digalg;
	gnutls_datum_t tmp_vko_key;
	gnutls_hash_hd_t dig;
	int ret;

	if (pub->algo == GNUTLS_PK_GOST_01)
		digalg = GNUTLS_DIG_GOSTR_94;
	else
		digalg = GNUTLS_DIG_STREEBOG_256;

	ret = _gnutls_pk_derive(pub->algo, &tmp_vko_key,
				priv, pub, ukm);
	if (ret < 0)
		return gnutls_assert_val(ret);

	kek->size = gnutls_hash_get_len(digalg);
	kek->data = gnutls_malloc(kek->size);
	if (kek->data == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}

	ret = gnutls_hash_init(&dig, digalg);
	if (ret < 0) {
		gnutls_assert();
		_gnutls_free_datum(kek);
		goto cleanup;
	}

	gnutls_hash(dig, tmp_vko_key.data, tmp_vko_key.size);
	gnutls_hash_deinit(dig, kek->data);

	ret = 0;

cleanup:
	_gnutls_free_temp_key_datum(&tmp_vko_key);

	return ret;
}

static const gnutls_datum_t zero_data = { NULL, 0 };

int
_gnutls_gost_keytrans_encrypt(gnutls_pk_params_st *pub,
			      gnutls_pk_params_st *priv,
			      int is_ephemeral,
			      gnutls_datum_t *cek,
			      gnutls_datum_t *ukm,
			      gnutls_datum_t *out)
{
	int ret;
	gnutls_datum_t kek;
	gnutls_datum_t enc, imit;
	ASN1_TYPE kx;

	ret = _gnutls_gost_vko_key(pub, priv, ukm, &kek);
	if (ret < 0) {
		gnutls_assert();

		return ret;
	}

	ret = _gnutls_gost_key_wrap(pub->gost_params, &kek, ukm, cek,
				    &enc, &imit);
	_gnutls_free_key_datum(&kek);
	if (ret < 0) {
		gnutls_assert();

		return ret;
	}

	if ((ret = asn1_create_element(_gnutls_get_gnutls_asn(),
				       "GNUTLS.GostR3410-KeyTransport",
				       &kx)) != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		_gnutls_free_datum(&enc);
		_gnutls_free_datum(&imit);

		return ret;
	}

	if ((ret = _gnutls_x509_write_value(kx, "transportParameters.ukm",
					    ukm)) != ASN1_SUCCESS) {
		gnutls_assert();
		goto cleanup;
	}

	if (is_ephemeral) {
		ret = _gnutls_x509_encode_and_copy_PKI_params(kx,
				"transportParameters.ephemeralPublicKey",
				priv);
	} else {
		ret = _gnutls_x509_write_value(kx,
				"transportParameters.ephemeralPublicKey",
				&zero_data);
	}
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	if ((ret = asn1_write_value(kx, "transportParameters.encryptionParamSet",
				    gnutls_gost_paramset_get_oid(pub->gost_params),
				    1)) != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		goto cleanup;
	}

	ret = _gnutls_x509_write_value(kx, "sessionEncryptedKey.encryptedKey", &enc);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_x509_write_value(kx, "sessionEncryptedKey.maskKey", &zero_data);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		goto cleanup;
	}
	ret = _gnutls_x509_write_value(kx, "sessionEncryptedKey.macKey", &imit);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		goto cleanup;
	}

	ret = _gnutls_x509_der_encode(kx, "", out, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

cleanup:
	asn1_delete_structure(&kx);
	_gnutls_free_datum(&enc);
	_gnutls_free_datum(&imit);

	return ret;
}

/* Returns 1 if decode used ephemeral key */
int
_gnutls_gost_keytrans_decrypt(gnutls_pk_params_st *pub,
			      gnutls_pk_params_st *priv,
			      gnutls_datum_t *cek,
			      gnutls_datum_t *ukm,
			      gnutls_datum_t *out)
{
	int ret;
	ASN1_TYPE kx;
	gnutls_pk_params_st pub2;
	int has_pub2 = 0;
	gnutls_datum_t kek;
	gnutls_datum_t ukm2, enc, imit;
	char oid[MAX_OID_SIZE];
	int oid_size;

	if ((ret = asn1_create_element(_gnutls_get_gnutls_asn(),
				       "GNUTLS.GostR3410-KeyTransport",
				       &kx)) != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);

		return ret;
	}

	ret = _asn1_strict_der_decode(&kx, cek->data, cek->size, NULL);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		goto cleanup;
	}

	ret = _gnutls_get_asn_mpis(kx,
				   "transportParameters.ephemeralPublicKey",
				   &pub2);
	if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND) {
		if (pub == NULL) {
			gnutls_assert();
			goto cleanup;
		}
	} else if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	} else {
		pub = &pub2;
		has_pub2 = 1;
	}

	if (pub->algo != priv->algo ||
	    pub->gost_params != priv->gost_params ||
	    pub->curve != priv->curve) {
		gnutls_assert();
		ret = GNUTLS_E_ILLEGAL_PARAMETER;
		goto cleanup;
	}

	oid_size = sizeof(oid);
	ret = asn1_read_value(kx, "transportParameters.encryptionParamSet", oid, &oid_size);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		goto cleanup;
	}

	if (gnutls_oid_to_gost_paramset(oid) != priv->gost_params) {
		gnutls_assert();
		ret = GNUTLS_E_ASN1_DER_ERROR;
		goto cleanup;
	}

	ret = _gnutls_x509_read_value(kx, "transportParameters.ukm", &ukm2);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	if (ukm2.size != UKM_LEN || memcmp(ukm2.data, ukm->data, UKM_LEN) != 0) {
		gnutls_assert();
		_gnutls_free_datum(&ukm2);
		ret = GNUTLS_E_ASN1_DER_ERROR;
		goto cleanup;
	}
	_gnutls_free_datum(&ukm2);

	/* FIXME: no maskKey support */

	ret = _gnutls_x509_read_value(kx, "sessionEncryptedKey.encryptedKey",
				      &enc);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_x509_read_value(kx, "sessionEncryptedKey.macKey",
				      &imit);
	if (ret < 0) {
		gnutls_assert();
		_gnutls_free_datum(&enc);
		goto cleanup;
	}

	ret = _gnutls_gost_vko_key(pub, priv, ukm, &kek);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup2;
	}

	ret = _gnutls_gost_key_unwrap(pub->gost_params, &kek, ukm,
				      &enc, &imit, out);
	_gnutls_free_key_datum(&kek);

	if (ret < 0) {
		gnutls_assert();
		goto cleanup2;
	}

	ret = has_pub2;

cleanup2:
	_gnutls_free_datum(&imit);
	_gnutls_free_datum(&enc);
cleanup:
	if (has_pub2)
		gnutls_pk_params_release(&pub2);
	asn1_delete_structure(&kx);

	return ret;
}
