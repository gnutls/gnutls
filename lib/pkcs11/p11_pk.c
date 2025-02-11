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
#include "p11_provider.h"
#include "x509/x509_int.h"

#include <libtasn1.h>
#include <minmax.h>
#include <p11-kit/pkcs11.h>

static bool mechanism_exists(CK_MECHANISM_TYPE mech)
{
	unsigned i;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SLOT_ID slot = _p11_provider_get_slot();
	CK_MECHANISM_TYPE *mechs = NULL;
	CK_ULONG mech_count = 0;

	if (module->C_GetMechanismList(slot, NULL, &mech_count) != CKR_OK ||
	    mech_count == 0)
		return false;

	mechs = _gnutls_reallocarray(NULL, mech_count,
				     sizeof(CK_MECHANISM_TYPE));
	if (mechs == NULL)
		return false;

	if (module->C_GetMechanismList(slot, mechs, &mech_count) != CKR_OK) {
		gnutls_free(mechs);
		return false;
	}

	for (i = 0; i < mech_count; ++i) {
		if (mechs[i] == mech) {
			gnutls_free(mechs);
			return true;
		}
	}

	gnutls_free(mechs);
	return false;
}

static CK_OBJECT_HANDLE import_rsa_pubkey(CK_SESSION_HANDLE session,
					  const gnutls_pk_params_st *pk_params)
{
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_RSA;
	CK_BBOOL tval = CK_TRUE;
	gnutls_datum_t mod = { NULL, 0 };
	gnutls_datum_t exp = { NULL, 0 };
	CK_ATTRIBUTE attrs[] = { { CKA_CLASS, &klass, sizeof(klass) },
				 { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
				 { CKA_ENCRYPT, &tval, sizeof(tval) },
				 { CKA_VERIFY, &tval, sizeof(tval) },
				 { CKA_MODULUS, NULL, 0 },
				 { CKA_PUBLIC_EXPONENT, NULL, 0 } };
	CK_ULONG attrs_len = sizeof(attrs) / sizeof(attrs[0]);

	if (_gnutls_mpi_dprint(pk_params->params[RSA_MODULUS], &mod) < 0 ||
	    _gnutls_mpi_dprint(pk_params->params[RSA_PUB], &exp) < 0)
		goto cleanup;

	attrs[4].pValue = mod.data;
	attrs[4].ulValueLen = mod.size;
	attrs[5].pValue = exp.data;
	attrs[5].ulValueLen = exp.size;

	module->C_CreateObject(session, attrs, attrs_len, &object);

cleanup:
	_gnutls_free_datum(&mod);
	_gnutls_free_datum(&exp);
	return object;
}

static CK_OBJECT_HANDLE import_rsa_privkey(CK_SESSION_HANDLE session,
					   const gnutls_pk_params_st *pk_params)
{
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_RSA;
	CK_BBOOL tval = CK_TRUE;
	gnutls_datum_t rsa_params[8];
	size_t rsa_params_len = sizeof(rsa_params) / sizeof(rsa_params[0]);
	unsigned i;
	CK_ATTRIBUTE attrs[] = { { CKA_MODULUS, NULL, 0 },
				 { CKA_PUBLIC_EXPONENT, NULL, 0 },
				 { CKA_PRIVATE_EXPONENT, NULL, 0 },
				 { CKA_PRIME_1, NULL, 0 },
				 { CKA_PRIME_2, NULL, 0 },
				 { CKA_COEFFICIENT, NULL, 0 },
				 { CKA_EXPONENT_1, NULL, 0 },
				 { CKA_EXPONENT_2, NULL, 0 },
				 { CKA_CLASS, &klass, sizeof(klass) },
				 { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
				 { CKA_SENSITIVE, &tval, sizeof(tval) },
				 { CKA_DECRYPT, &tval, sizeof(tval) },
				 { CKA_SIGN, &tval, sizeof(tval) } };
	CK_ULONG attrs_len = sizeof(attrs) / sizeof(attrs[0]);

	gnutls_memset(rsa_params, 0, sizeof(rsa_params));
	for (i = 0; i < rsa_params_len; ++i) {
		if (_gnutls_mpi_dprint(pk_params->params[i], rsa_params + i) <
		    0)
			goto cleanup;
		attrs[i].pValue = rsa_params[i].data;
		attrs[i].ulValueLen = rsa_params[i].size;
	}

	module->C_CreateObject(session, attrs, attrs_len, &object);

cleanup:
	for (i = 0; i < rsa_params_len; ++i)
		_gnutls_free_datum(rsa_params + i);

	return object;
}

static CK_OBJECT_HANDLE import_ec_pubkey(CK_SESSION_HANDLE session,
					 const gnutls_pk_params_st *pk_params)
{
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BBOOL tval = CK_TRUE;
	gnutls_datum_t ec_curve = { NULL, 0 };
	gnutls_datum_t ec_point = { NULL, 0 };
	unsigned int tl_size = ASN1_MAX_TL_SIZE;
	uint8_t *ec_point_der = NULL;
	CK_ATTRIBUTE attrs[] = { { CKA_CLASS, &klass, sizeof(klass) },
				 { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
				 { CKA_VERIFY, &tval, sizeof(tval) },
				 { CKA_EC_PARAMS, NULL, 0 },
				 { CKA_EC_POINT, NULL, 0 } };
	CK_ULONG attrs_len = sizeof(attrs) / sizeof(attrs[0]);

	if (_gnutls_x509_write_ecc_params(pk_params->curve, &ec_curve) < 0 ||
	    _gnutls_ecc_ansi_x962_export(
		    pk_params->curve, pk_params->params[ECC_X],
		    pk_params->params[ECC_Y], &ec_point) < 0)
		goto cleanup;

	ec_point_der = gnutls_malloc(ASN1_MAX_TL_SIZE + ec_point.size);
	if (ec_point_der == NULL)
		goto cleanup;

	if (asn1_encode_simple_der(ASN1_ETYPE_OCTET_STRING, ec_point.data,
				   ec_point.size, ec_point_der,
				   &tl_size) != ASN1_SUCCESS)
		goto cleanup;
	memcpy(ec_point_der + tl_size, ec_point.data, ec_point.size);

	attrs[3].pValue = ec_curve.data;
	attrs[3].ulValueLen = ec_curve.size;
	attrs[4].pValue = ec_point_der;
	attrs[4].ulValueLen = tl_size + ec_point.size;

	module->C_CreateObject(session, attrs, attrs_len, &object);

cleanup:
	_gnutls_free_datum(&ec_curve);
	_gnutls_free_datum(&ec_point);
	gnutls_free(ec_point_der);
	return object;
}

static CK_OBJECT_HANDLE import_ec_privkey(CK_SESSION_HANDLE session,
					  const gnutls_pk_params_st *pk_params)
{
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BBOOL tval = CK_TRUE;
	gnutls_datum_t ec_curve = { NULL, 0 };
	gnutls_datum_t ecc_k = { NULL, 0 };
	CK_ATTRIBUTE attrs[] = { { CKA_CLASS, &klass, sizeof(klass) },
				 { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
				 { CKA_SENSITIVE, &tval, sizeof(tval) },
				 { CKA_SIGN, &tval, sizeof(tval) },
				 { CKA_EC_PARAMS, NULL, 0 },
				 { CKA_VALUE, NULL, 0 } };
	CK_ULONG attrs_len = sizeof(attrs) / sizeof(attrs[0]);

	if (_gnutls_x509_write_ecc_params(pk_params->curve, &ec_curve) < 0 ||
	    _gnutls_mpi_dprint(pk_params->params[ECC_K], &ecc_k) < 0)
		goto cleanup;

	attrs[4].pValue = ec_curve.data;
	attrs[4].ulValueLen = ec_curve.size;
	attrs[5].pValue = ecc_k.data;
	attrs[5].ulValueLen = ecc_k.size;

	module->C_CreateObject(session, attrs, attrs_len, &object);

cleanup:
	_gnutls_free_datum(&ec_curve);
	_gnutls_free_datum(&ecc_k);
	return object;
}

static bool init_rsa_oaep_param(CK_RSA_PKCS_OAEP_PARAMS *param,
				const gnutls_x509_spki_st *encrypt_params)
{
	switch (encrypt_params->rsa_oaep_dig) {
	case GNUTLS_DIG_SHA256:
		param->hashAlg = CKM_SHA256;
		param->mgf = CKG_MGF1_SHA256;
		break;
	case GNUTLS_DIG_SHA384:
		param->hashAlg = CKM_SHA384;
		param->mgf = CKG_MGF1_SHA384;
		break;
	case GNUTLS_DIG_SHA512:
		param->hashAlg = CKM_SHA512;
		param->mgf = CKG_MGF1_SHA512;
		break;
	default:
		return false;
	}
	param->source = CKZ_DATA_SPECIFIED;
	param->pSourceData = encrypt_params->rsa_oaep_label.data;
	param->ulSourceDataLen = encrypt_params->rsa_oaep_label.size;
	return true;
}

static bool init_rsa_pss_param(CK_RSA_PKCS_PSS_PARAMS *param,
			       const gnutls_x509_spki_st *sign_params)
{
	switch (sign_params->rsa_pss_dig) {
	case GNUTLS_DIG_SHA256:
		param->hashAlg = CKM_SHA256;
		param->mgf = CKG_MGF1_SHA256;
		break;
	case GNUTLS_DIG_SHA384:
		param->hashAlg = CKM_SHA384;
		param->mgf = CKG_MGF1_SHA384;
		break;
	case GNUTLS_DIG_SHA512:
		param->hashAlg = CKM_SHA512;
		param->mgf = CKG_MGF1_SHA512;
		break;
	default:
		return false;
	}
	param->sLen = sign_params->salt_size;
	return true;
}

static int generate_dh_params(CK_SESSION_HANDLE session,
			      gnutls_pk_params_st *params, CK_ULONG bits)
{
	int ret = 0;
	unsigned i;
	CK_RV rv;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { CKM_DH_PKCS_PARAMETER_GEN, NULL, 0 };
	CK_ATTRIBUTE attrs[] = {
		{ CKA_PRIME_BITS, &bits, sizeof(bits) },
	};
	CK_ATTRIBUTE param[] = {
		{ CKA_PRIME, NULL, CK_UNAVAILABLE_INFORMATION },
		{ CKA_BASE, NULL, CK_UNAVAILABLE_INFORMATION },
	};
	CK_ULONG attrs_len = sizeof(attrs) / sizeof(attrs[0]);
	CK_ULONG param_len = sizeof(param) / sizeof(param[0]);

	rv = module->C_GenerateKey(session, &mech, attrs, attrs_len, &obj);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	rv = module->C_GetAttributeValue(session, obj, param, param_len);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	for (i = 0; i < param_len; ++i) {
		if (param[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
			ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
			goto cleanup;
		}
		param[i].pValue = gnutls_malloc(param[i].ulValueLen);
		if (param[i].pValue == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			goto cleanup;
		}
	}

	rv = module->C_GetAttributeValue(session, obj, param, param_len);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	if (_gnutls_mpi_init_scan(&params->params[DH_P], param[0].pValue,
				  param[0].ulValueLen) < 0 ||
	    _gnutls_mpi_init_scan(&params->params[DH_G], param[1].pValue,
				  param[1].ulValueLen) < 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}
	params->params_nr = 2;

cleanup:
	for (i = 0; i < param_len; ++i)
		gnutls_free(param[i].pValue);

	return ret;
}

static int generate_rsa_keys(CK_SESSION_HANDLE session,
			     gnutls_pk_params_st *params, CK_ULONG bits)
{
	int ret = 0;
	unsigned i;
	CK_RV rv;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE pubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE privkey = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
	CK_BBOOL tval = CK_TRUE;
	CK_BBOOL fval = CK_FALSE;
	CK_ATTRIBUTE pub_attrs[] = {
		{ CKA_ENCRYPT, &tval, sizeof(tval) },
		{ CKA_VERIFY, &tval, sizeof(tval) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
	};
	CK_ATTRIBUTE priv_attrs[] = {
		{ CKA_SENSITIVE, &fval, sizeof(fval) },
		{ CKA_EXTRACTABLE, &tval, sizeof(tval) },
		{ CKA_DECRYPT, &tval, sizeof(tval) },
		{ CKA_SIGN, &tval, sizeof(tval) },
	};
	CK_ATTRIBUTE priv[] = {
		{ CKA_MODULUS, NULL, CK_UNAVAILABLE_INFORMATION },
		{ CKA_PUBLIC_EXPONENT, NULL, CK_UNAVAILABLE_INFORMATION },
		{ CKA_PRIVATE_EXPONENT, NULL, CK_UNAVAILABLE_INFORMATION },
		{ CKA_PRIME_1, NULL, CK_UNAVAILABLE_INFORMATION },
		{ CKA_PRIME_2, NULL, CK_UNAVAILABLE_INFORMATION },
		{ CKA_COEFFICIENT, NULL, CK_UNAVAILABLE_INFORMATION },
		{ CKA_EXPONENT_1, NULL, CK_UNAVAILABLE_INFORMATION },
		{ CKA_EXPONENT_2, NULL, CK_UNAVAILABLE_INFORMATION },
	};
	CK_ULONG pub_attrs_len = sizeof(pub_attrs) / sizeof(pub_attrs[0]);
	CK_ULONG priv_attrs_len = sizeof(priv_attrs) / sizeof(priv_attrs[0]);
	CK_ULONG priv_len = sizeof(priv) / sizeof(priv[0]);

	rv = module->C_GenerateKeyPair(session, &mech, pub_attrs, pub_attrs_len,
				       priv_attrs, priv_attrs_len, &pubkey,
				       &privkey);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	rv = module->C_GetAttributeValue(session, privkey, priv, priv_len);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	for (i = 0; i < priv_len; ++i) {
		if (priv[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
			ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
			goto cleanup;
		}
		priv[i].pValue = gnutls_malloc(priv[i].ulValueLen);
		if (priv[i].pValue == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			goto cleanup;
		}
	}

	rv = module->C_GetAttributeValue(session, privkey, priv, priv_len);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	params->params_nr = 0;
	for (i = 0; i < priv_len; ++i) {
		if (_gnutls_mpi_init_scan(&params->params[i], priv[i].pValue,
					  priv[i].ulValueLen) < 0) {
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
			goto cleanup;
		}
		params->params_nr++;
	}

cleanup:
	for (i = 0; i < priv_len; ++i)
		gnutls_free(priv[i].pValue);

	return ret;
}

static int generate_dh_keys(CK_SESSION_HANDLE session,
			    gnutls_pk_params_st *params)
{
	int ret = 0;
	CK_RV rv;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE pubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE privkey = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL, 0 };
	CK_BBOOL tval = CK_TRUE;
	CK_BBOOL fval = CK_FALSE;
	gnutls_datum_t p = { NULL, 0 };
	gnutls_datum_t g = { NULL, 0 };
	CK_ATTRIBUTE pub_attrs[] = {
		{ CKA_PRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
	};
	CK_ATTRIBUTE priv_attrs[] = {
		{ CKA_SENSITIVE, &fval, sizeof(fval) },
		{ CKA_EXTRACTABLE, &tval, sizeof(tval) },
	};
	CK_ATTRIBUTE pub[] = {
		{ CKA_VALUE, NULL, CK_UNAVAILABLE_INFORMATION },
	};
	CK_ATTRIBUTE priv[] = {
		{ CKA_VALUE, NULL, CK_UNAVAILABLE_INFORMATION },
	};
	CK_ULONG pub_attrs_len = sizeof(pub_attrs) / sizeof(pub_attrs[0]);
	CK_ULONG priv_attrs_len = sizeof(priv_attrs) / sizeof(priv_attrs[0]);
	CK_ULONG pub_len = sizeof(pub) / sizeof(pub[0]);
	CK_ULONG priv_len = sizeof(priv) / sizeof(priv[0]);

	/* Set attributes for key generation
	 */
	if (_gnutls_mpi_dprint(params->params[DH_P], &p) < 0 ||
	    _gnutls_mpi_dprint(params->params[DH_G], &g) < 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}
	pub_attrs[0].pValue = p.data;
	pub_attrs[0].ulValueLen = p.size;
	pub_attrs[1].pValue = g.data;
	pub_attrs[1].ulValueLen = g.size;

	rv = module->C_GenerateKeyPair(session, &mech, pub_attrs, pub_attrs_len,
				       priv_attrs, priv_attrs_len, &pubkey,
				       &privkey);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	/* Retrieve public key
	 */
	rv = module->C_GetAttributeValue(session, pubkey, pub, pub_len);
	if (rv != CKR_OK || pub[0].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}
	pub[0].pValue = gnutls_malloc(pub[0].ulValueLen);
	if (pub[0].pValue == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}
	rv = module->C_GetAttributeValue(session, pubkey, pub, pub_len);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	/* Retrieve private key
	 */
	rv = module->C_GetAttributeValue(session, privkey, priv, priv_len);
	if (rv != CKR_OK || priv[0].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}
	priv[0].pValue = gnutls_malloc(priv[0].ulValueLen);
	if (priv[0].pValue == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}
	rv = module->C_GetAttributeValue(session, privkey, priv, priv_len);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	/* Set result
	 */
	if (_gnutls_mpi_init_scan(&params->params[DH_Y], pub[0].pValue,
				  pub[0].ulValueLen) < 0 ||
	    _gnutls_mpi_init_scan(&params->params[DH_X], priv[0].pValue,
				  priv[0].ulValueLen) < 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}
	params->params_nr += 2;

cleanup:
	_gnutls_free_datum(&p);
	_gnutls_free_datum(&g);
	gnutls_free(pub[0].pValue);
	gnutls_free(priv[0].pValue);
	return ret;
}

static int generate_ec_keys(CK_SESSION_HANDLE session,
			    gnutls_pk_params_st *params,
			    gnutls_ecc_curve_t curve)
{
	int ret = 0;
	uint8_t *pub_x962;
	size_t pub_x962_len;
	CK_RV rv;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE pubkey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE privkey = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
	CK_BBOOL tval = CK_TRUE;
	CK_BBOOL fval = CK_FALSE;
	gnutls_datum_t ec_curve = { NULL, 0 };
	CK_ATTRIBUTE pub_attrs[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
	};
	CK_ATTRIBUTE priv_attrs[] = {
		{ CKA_SENSITIVE, &fval, sizeof(fval) },
		{ CKA_EXTRACTABLE, &tval, sizeof(tval) },
	};
	CK_ATTRIBUTE pub[] = {
		{ CKA_EC_POINT, NULL, CK_UNAVAILABLE_INFORMATION },
	};
	CK_ATTRIBUTE priv[] = {
		{ CKA_VALUE, NULL, CK_UNAVAILABLE_INFORMATION },
	};
	CK_ULONG pub_attrs_len = sizeof(pub_attrs) / sizeof(pub_attrs[0]);
	CK_ULONG priv_attrs_len = sizeof(priv_attrs) / sizeof(priv_attrs[0]);
	CK_ULONG pub_len = sizeof(pub) / sizeof(pub[0]);
	CK_ULONG priv_len = sizeof(priv) / sizeof(priv[0]);

	/* Set attributes for key generation
	 */
	if (_gnutls_x509_write_ecc_params(curve, &ec_curve) < 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	pub_attrs[0].pValue = ec_curve.data;
	pub_attrs[0].ulValueLen = ec_curve.size;

	rv = module->C_GenerateKeyPair(session, &mech, pub_attrs, pub_attrs_len,
				       priv_attrs, priv_attrs_len, &pubkey,
				       &privkey);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	/* Retrieve public key
	 */
	rv = module->C_GetAttributeValue(session, pubkey, pub, pub_len);
	if (rv != CKR_OK || pub[0].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}
	pub[0].pValue = gnutls_malloc(pub[0].ulValueLen);
	if (pub[0].pValue == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}
	rv = module->C_GetAttributeValue(session, pubkey, pub, pub_len);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	/* Retrieve private key
	 */
	rv = module->C_GetAttributeValue(session, privkey, priv, priv_len);
	if (rv != CKR_OK || priv[0].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}
	priv[0].pValue = gnutls_malloc(priv[0].ulValueLen);
	if (priv[0].pValue == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}
	rv = module->C_GetAttributeValue(session, privkey, priv, priv_len);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	pub_x962 = (uint8_t *)pub[0].pValue + 2;
	pub_x962_len = ((uint8_t *)pub[0].pValue)[1];

	/* Set result
	 */
	if (_gnutls_ecc_ansi_x962_import(pub_x962, pub_x962_len,
					 &params->params[ECC_X],
					 &params->params[ECC_Y]) < 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}
	if (_gnutls_mpi_init_scan(&params->params[ECC_K], priv[0].pValue,
				  priv[0].ulValueLen) < 0) {
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto cleanup;
	}
	params->curve = curve;
	params->params_nr = ECC_PRIVATE_PARAMS;

cleanup:
	_gnutls_free_datum(&ec_curve);
	gnutls_free(pub[0].pValue);
	gnutls_free(priv[0].pValue);
	return ret;
}

static int derive_ecdh_secret(CK_SESSION_HANDLE session,
			      const gnutls_pk_params_st *priv,
			      const gnutls_pk_params_st *pub,
			      gnutls_datum_t *out)
{
	CK_RV rv;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_OBJECT_HANDLE priv_obj = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE secret_obj = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS klass = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_EC;
	CK_BBOOL tval = CK_TRUE, fval = CK_FALSE;
	CK_ATTRIBUTE secret[] = {
		{ CKA_VALUE, NULL, CK_UNAVAILABLE_INFORMATION },
	};
	CK_ULONG secret_len = sizeof(secret) / sizeof(secret[0]);
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof(klass) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_SENSITIVE, &fval, sizeof(fval) },
		{ CKA_EXTRACTABLE, &tval, sizeof(tval) },
		{ CKA_ENCRYPT, &tval, sizeof(tval) },
		{ CKA_DECRYPT, &tval, sizeof(tval) },
	};
	CK_ULONG attrs_len = sizeof(attrs) / sizeof(attrs[0]);
	gnutls_datum_t ec_point = { 0 };
	CK_ECDH1_DERIVE_PARAMS param = { 0 };
	CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &param, sizeof(param) };

	if (_gnutls_ecc_ansi_x962_export(pub->curve, pub->params[ECC_X],
					 pub->params[ECC_Y], &ec_point) < 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	param.kdf = CKD_NULL;
	param.ulPublicDataLen = ec_point.size;
	param.pPublicData = ec_point.data;

	priv_obj = import_ec_privkey(session, priv);
	if (priv_obj == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	rv = module->C_DeriveKey(session, &mech, priv_obj, attrs, attrs_len,
				 &secret_obj);
	if (rv != CKR_OK)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	rv = module->C_GetAttributeValue(session, secret_obj, secret,
					 secret_len);
	if (rv != CKR_OK || secret[0].ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	secret[0].pValue = gnutls_malloc(secret[0].ulValueLen);
	if (secret[0].pValue == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	rv = module->C_GetAttributeValue(session, secret_obj, secret,
					 secret_len);
	if (rv != CKR_OK) {
		gnutls_free(secret[0].pValue);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	out->data = secret[0].pValue;
	out->size = secret[0].ulValueLen;
	return 0;
}

static int _wrap_p11_pk_encrypt(gnutls_pk_algorithm_t algo,
				gnutls_datum_t *ciphertext,
				const gnutls_datum_t *plaintext,
				const gnutls_pk_params_st *pk_params,
				const gnutls_x509_spki_st *encrypt_params)
{
	int ret = 0;
	CK_RV rv;
	CK_BYTE *c_data = NULL;
	CK_ULONG c_size = 0;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { 0 };
	CK_RSA_PKCS_OAEP_PARAMS param_rsa_oaep;

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	if (algo == GNUTLS_PK_RSA && pk_params->spki.pk == GNUTLS_PK_RSA_OAEP)
		algo = GNUTLS_PK_RSA_OAEP;

	switch (algo) {
	case GNUTLS_PK_RSA:
		mech.mechanism = CKM_RSA_PKCS;

		if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
			ret = gnutls_assert_val(
				GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM);
			goto cleanup;
		}

		key = import_rsa_pubkey(session, pk_params);
		break;
	case GNUTLS_PK_RSA_OAEP: {
		mech.mechanism = CKM_RSA_PKCS_OAEP;
		mech.pParameter = &param_rsa_oaep;
		mech.ulParameterLen = sizeof(param_rsa_oaep);

		if (!init_rsa_oaep_param(&param_rsa_oaep, encrypt_params)) {
			ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
			goto cleanup;
		}

		key = import_rsa_pubkey(session, pk_params);
		break;
	}
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	if (key == CK_INVALID_HANDLE) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_EncryptInit(session, &mech, key);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_Encrypt(session, (CK_BYTE_PTR)plaintext->data,
			       plaintext->size, NULL, &c_size);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	c_data = gnutls_malloc(c_size);
	if (c_data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	rv = module->C_Encrypt(session, (CK_BYTE_PTR)plaintext->data,
			       plaintext->size, c_data, &c_size);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		gnutls_free(c_data);
		goto cleanup;
	}

	ciphertext->data = c_data;
	ciphertext->size = c_size;

cleanup:
	_p11_provider_close_session(session);
	return ret;
}

static int _wrap_p11_pk_decrypt(gnutls_pk_algorithm_t algo,
				gnutls_datum_t *plaintext,
				const gnutls_datum_t *ciphertext,
				const gnutls_pk_params_st *pk_params,
				const gnutls_x509_spki_st *encrypt_params)
{
	int ret = 0;
	CK_RV rv;
	CK_BYTE *p_data = NULL;
	CK_ULONG p_size = 0;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { 0 };
	CK_RSA_PKCS_OAEP_PARAMS param_rsa_oaep;

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	if (algo == GNUTLS_PK_RSA && pk_params->spki.pk == GNUTLS_PK_RSA_OAEP)
		algo = GNUTLS_PK_RSA_OAEP;

	switch (algo) {
	case GNUTLS_PK_RSA:
		mech.mechanism = CKM_RSA_PKCS;

		if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
			ret = gnutls_assert_val(
				GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM);
			goto cleanup;
		}

		key = import_rsa_privkey(session, pk_params);
		break;
	case GNUTLS_PK_RSA_OAEP:
		mech.mechanism = CKM_RSA_PKCS_OAEP;
		mech.pParameter = &param_rsa_oaep;
		mech.ulParameterLen = sizeof(param_rsa_oaep);

		if (!init_rsa_oaep_param(&param_rsa_oaep, encrypt_params)) {
			ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
			goto cleanup;
		}

		key = import_rsa_privkey(session, pk_params);
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	if (key == CK_INVALID_HANDLE) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_DecryptInit(session, &mech, key);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_Decrypt(session, (CK_BYTE_PTR)ciphertext->data,
			       ciphertext->size, NULL, &p_size);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	p_data = gnutls_malloc(p_size);
	if (p_data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	rv = module->C_Decrypt(session, (CK_BYTE_PTR)ciphertext->data,
			       ciphertext->size, p_data, &p_size);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		gnutls_free(p_data);
		goto cleanup;
	}

	plaintext->data = p_data;
	plaintext->size = p_size;

cleanup:
	_p11_provider_close_session(session);
	return ret;
}

static int _wrap_p11_pk_decrypt2(gnutls_pk_algorithm_t algo,
				 const gnutls_datum_t *ciphertext,
				 unsigned char *plaintext,
				 size_t plaintext_size,
				 const gnutls_pk_params_st *pk_params,
				 const gnutls_x509_spki_st *encrypt_params)
{
	int ret = 0;
	uint32_t is_err;
	size_t copy_size = 0;
	CK_RV rv;
	CK_BYTE *p_data = NULL;
	CK_ULONG p_size = 0;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { 0 };
	CK_RSA_PKCS_OAEP_PARAMS param_rsa_oaep;

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	if (algo == GNUTLS_PK_RSA && pk_params->spki.pk == GNUTLS_PK_RSA_OAEP)
		algo = GNUTLS_PK_RSA_OAEP;

	switch (algo) {
	case GNUTLS_PK_RSA:
		mech.mechanism = CKM_RSA_PKCS;

		if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
			ret = gnutls_assert_val(
				GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM);
			goto cleanup;
		}

		key = import_rsa_privkey(session, pk_params);
		break;
	case GNUTLS_PK_RSA_OAEP:
		mech.mechanism = CKM_RSA_PKCS_OAEP;
		mech.pParameter = &param_rsa_oaep;
		mech.ulParameterLen = sizeof(param_rsa_oaep);

		if (!init_rsa_oaep_param(&param_rsa_oaep, encrypt_params)) {
			ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
			goto cleanup;
		}

		key = import_rsa_privkey(session, pk_params);
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	if (key == CK_INVALID_HANDLE) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_DecryptInit(session, &mech, key);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_Decrypt(session, (CK_BYTE_PTR)ciphertext->data,
			       ciphertext->size, NULL, &p_size);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	p_data = gnutls_malloc(p_size);
	if (p_data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	copy_size = MIN(plaintext_size, p_size);

	rv = module->C_Decrypt(session, (CK_BYTE_PTR)ciphertext->data,
			       ciphertext->size, p_data, &p_size);
	memcpy(plaintext, p_data, copy_size);
	gnutls_free(p_data);

	is_err = rv != CKR_OK;
	ret = (int)((is_err * UINT_MAX) & GNUTLS_E_PKCS11_ERROR);

cleanup:
	_p11_provider_close_session(session);
	return ret;
}

static int _wrap_p11_pk_sign(gnutls_pk_algorithm_t algo,
			     gnutls_datum_t *signature,
			     const gnutls_datum_t *vdata,
			     const gnutls_pk_params_st *pk_params,
			     const gnutls_x509_spki_st *sign_params)
{
	int ret = 0;
	CK_RV rv;
	CK_BYTE *s_data = NULL;
	CK_ULONG s_size = 0;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { 0 };
	CK_RSA_PKCS_PSS_PARAMS param_rsa_pss;

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	switch (algo) {
	case GNUTLS_PK_RSA:
		mech.mechanism = CKM_RSA_PKCS;

		key = import_rsa_privkey(session, pk_params);
		break;
	case GNUTLS_PK_RSA_PSS:
		mech.mechanism = CKM_RSA_PKCS_PSS;
		mech.pParameter = &param_rsa_pss;
		mech.ulParameterLen = sizeof(param_rsa_pss);

		if (!init_rsa_pss_param(&param_rsa_pss, sign_params)) {
			ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
			goto cleanup;
		}

		key = import_rsa_privkey(session, pk_params);
		break;
	case GNUTLS_PK_ECDSA:
		switch (DIG_TO_MAC(sign_params->dsa_dig)) {
		case GNUTLS_MAC_SHA224:
			mech.mechanism = CKM_ECDSA_SHA224;
			break;
		case GNUTLS_MAC_SHA256:
			mech.mechanism = CKM_ECDSA_SHA256;
			break;
		case GNUTLS_MAC_SHA384:
			mech.mechanism = CKM_ECDSA_SHA384;
			break;
		case GNUTLS_MAC_SHA512:
			mech.mechanism = CKM_ECDSA_SHA512;
			break;
		default:
			ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
			goto cleanup;
		}

		key = import_ec_privkey(session, pk_params);
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	if (key == CK_INVALID_HANDLE) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_SignInit(session, &mech, key);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_Sign(session, (CK_BYTE_PTR)vdata->data, vdata->size,
			    NULL, &s_size);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	s_data = gnutls_malloc(s_size);
	if (s_data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	rv = module->C_Sign(session, (CK_BYTE_PTR)vdata->data, vdata->size,
			    s_data, &s_size);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		gnutls_free(s_data);
		goto cleanup;
	}

	signature->data = s_data;
	signature->size = s_size;

cleanup:
	_p11_provider_close_session(session);
	return ret;
}

static int _wrap_p11_pk_verify(gnutls_pk_algorithm_t algo,
			       const gnutls_datum_t *vdata,
			       const gnutls_datum_t *signature,
			       const gnutls_pk_params_st *pk_params,
			       const gnutls_x509_spki_st *sign_params)
{
	int ret;
	CK_RV rv;
	CK_FUNCTION_LIST *module = _p11_provider_get_module();
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_MECHANISM mech = { 0 };
	CK_RSA_PKCS_PSS_PARAMS param_rsa_pss;

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	switch (algo) {
	case GNUTLS_PK_RSA:
		mech.mechanism = CKM_RSA_PKCS;

		key = import_rsa_pubkey(session, pk_params);
		break;
	case GNUTLS_PK_RSA_PSS:
		mech.mechanism = CKM_RSA_PKCS_PSS;
		mech.pParameter = &param_rsa_pss;
		mech.ulParameterLen = sizeof(param_rsa_pss);

		if (!init_rsa_pss_param(&param_rsa_pss, sign_params)) {
			ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
			goto cleanup;
		}

		key = import_rsa_pubkey(session, pk_params);
		break;
	case GNUTLS_PK_ECDSA:
		switch (DIG_TO_MAC(sign_params->dsa_dig)) {
		case GNUTLS_MAC_SHA1:
			mech.mechanism = CKM_ECDSA_SHA1;
			break;
		case GNUTLS_MAC_SHA224:
			mech.mechanism = CKM_ECDSA_SHA224;
			break;
		case GNUTLS_MAC_SHA256:
			mech.mechanism = CKM_ECDSA_SHA256;
			break;
		case GNUTLS_MAC_SHA384:
			mech.mechanism = CKM_ECDSA_SHA384;
			break;
		case GNUTLS_MAC_SHA512:
			mech.mechanism = CKM_ECDSA_SHA512;
			break;
		default:
			ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
			goto cleanup;
		}

		key = import_ec_pubkey(session, pk_params);
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	if (key == CK_INVALID_HANDLE) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_VerifyInit(session, &mech, key);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto cleanup;
	}

	rv = module->C_Verify(session, (CK_BYTE_PTR)vdata->data, vdata->size,
			      (CK_BYTE_PTR)signature->data, signature->size);
	if (rv == CKR_OK)
		ret = 0;
	else if (rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE)
		ret = gnutls_assert_val(GNUTLS_E_PK_SIG_VERIFY_FAILED);
	else
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

cleanup:
	_p11_provider_close_session(session);
	return ret;
}

static int wrap_p11_pk_verify_priv_params(gnutls_pk_algorithm_t algo,
					  const gnutls_pk_params_st *params)
{
	return 0;
}

static int wrap_p11_pk_verify_pub_params(gnutls_pk_algorithm_t algo,
					 const gnutls_pk_params_st *params)
{
	return 0;
}

static int wrap_p11_pk_generate_params(gnutls_pk_algorithm_t algo,
				       unsigned int level /*bits or curve */,
				       gnutls_pk_params_st *params)
{
	int ret = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	switch (algo) {
	case GNUTLS_PK_DH:
		ret = generate_dh_params(session, params, (CK_ULONG)level);
		break;
	case GNUTLS_PK_RSA:
	case GNUTLS_PK_RSA_PSS:
	case GNUTLS_PK_RSA_OAEP:
	case GNUTLS_PK_ECDSA:
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

cleanup:
	_p11_provider_close_session(session);
	return ret;
}

static int wrap_p11_pk_generate_keys(gnutls_pk_algorithm_t algo,
				     unsigned int level /*bits or curve */,
				     gnutls_pk_params_st *params,
				     unsigned ephemeral /*non-zero if true */)
{
	int ret;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	if (IS_EC(algo) && gnutls_ecc_curve_get_pk(level) != algo)
		return gnutls_assert_val(GNUTLS_E_ECC_UNSUPPORTED_CURVE);

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	switch (algo) {
	case GNUTLS_PK_RSA:
	case GNUTLS_PK_RSA_PSS:
	case GNUTLS_PK_RSA_OAEP:
		ret = generate_rsa_keys(session, params, (CK_ULONG)level);
		break;
	case GNUTLS_PK_DH:
		ret = generate_dh_keys(session, params);
		break;
	case GNUTLS_PK_ECDSA:
		ret = generate_ec_keys(session, params,
				       GNUTLS_BITS_TO_CURVE(level));
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

cleanup:
	_p11_provider_close_session(session);
	return ret;
}

static int _wrap_p11_pk_derive(gnutls_pk_algorithm_t algo, gnutls_datum_t *out,
			       const gnutls_pk_params_st *priv,
			       const gnutls_pk_params_st *pub,
			       const gnutls_datum_t *nonce, unsigned int flags)
{
	int ret;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	session = _p11_provider_open_session();
	if (session == CK_INVALID_HANDLE)
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);

	switch (algo) {
	case GNUTLS_PK_EC:
		ret = derive_ecdh_secret(session, priv, pub, out);
		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

cleanup:
	_p11_provider_close_session(session);
	return ret;
}

static int _wrap_p11_pk_encaps(gnutls_pk_algorithm_t algo,
			       gnutls_datum_t *ciphertext,
			       gnutls_datum_t *shared_secret,
			       const gnutls_datum_t *pub)
{
	return 0;
}

static int _wrap_p11_pk_decaps(gnutls_pk_algorithm_t algo,
			       gnutls_datum_t *shared_secret,
			       const gnutls_datum_t *ciphertext,
			       const gnutls_datum_t *priv)
{
	return 0;
}

static int wrap_p11_pk_fixup(gnutls_pk_algorithm_t algo,
			     gnutls_direction_t direction,
			     gnutls_pk_params_st *params)
{
	return 0;
}

static int _wrap_p11_pk_curve_exists(gnutls_ecc_curve_t curve)
{
	switch (curve) {
	case GNUTLS_ECC_CURVE_SECP256R1:
	case GNUTLS_ECC_CURVE_SECP384R1:
	case GNUTLS_ECC_CURVE_SECP521R1:
		return 1;
	default:
		return 0;
	}
}

static int _wrap_p11_pk_exists(gnutls_pk_algorithm_t pk)
{
	switch (pk) {
	case GNUTLS_PK_RSA:
		return mechanism_exists(CKM_RSA_PKCS);
	case GNUTLS_PK_RSA_PSS:
		return mechanism_exists(CKM_RSA_PKCS_PSS);
	case GNUTLS_PK_RSA_OAEP:
		return mechanism_exists(CKM_RSA_PKCS_OAEP);
	case GNUTLS_PK_ECDSA:
		return mechanism_exists(CKM_ECDSA);
	case GNUTLS_PK_DH:
		return mechanism_exists(CKM_DH_PKCS_PARAMETER_GEN);
	default:
		return 0;
	}
}

static int _wrap_p11_pk_sign_exists(gnutls_sign_algorithm_t sign)
{
	switch (sign) {
	case GNUTLS_SIGN_RSA_SHA1:
	case GNUTLS_SIGN_RSA_SHA256:
	case GNUTLS_SIGN_RSA_SHA384:
	case GNUTLS_SIGN_RSA_SHA512:
	case GNUTLS_SIGN_RSA_SHA224:
	case GNUTLS_SIGN_RSA_SHA3_224:
	case GNUTLS_SIGN_RSA_SHA3_256:
	case GNUTLS_SIGN_RSA_SHA3_384:
	case GNUTLS_SIGN_RSA_SHA3_512:
	case GNUTLS_SIGN_RSA_RAW:
		return mechanism_exists(CKM_RSA_PKCS);
	case GNUTLS_SIGN_RSA_PSS_SHA256:
	case GNUTLS_SIGN_RSA_PSS_SHA384:
	case GNUTLS_SIGN_RSA_PSS_SHA512:
		return mechanism_exists(CKM_RSA_PKCS_PSS);
	case GNUTLS_SIGN_ECDSA_SHA224:
	case GNUTLS_SIGN_ECDSA_SHA256:
	case GNUTLS_SIGN_ECDSA_SHA384:
	case GNUTLS_SIGN_ECDSA_SHA512:
	case GNUTLS_SIGN_ECDSA_SECP256R1_SHA256:
	case GNUTLS_SIGN_ECDSA_SECP384R1_SHA384:
	case GNUTLS_SIGN_ECDSA_SECP521R1_SHA512:
		return mechanism_exists(CKM_ECDSA);
	default:
		return 0;
	}
}

gnutls_crypto_pk_st _gnutls_p11_pk_ops = {
	.encrypt = _wrap_p11_pk_encrypt,
	.decrypt = _wrap_p11_pk_decrypt,
	.decrypt2 = _wrap_p11_pk_decrypt2,
	.sign = _wrap_p11_pk_sign,
	.verify = _wrap_p11_pk_verify,
	.verify_priv_params = wrap_p11_pk_verify_priv_params,
	.verify_pub_params = wrap_p11_pk_verify_pub_params,
	.generate_params = wrap_p11_pk_generate_params,
	.generate_keys = wrap_p11_pk_generate_keys,
	.pk_fixup_private_params = wrap_p11_pk_fixup,
	.derive = _wrap_p11_pk_derive,
	.encaps = _wrap_p11_pk_encaps,
	.decaps = _wrap_p11_pk_decaps,
	.curve_exists = _wrap_p11_pk_curve_exists,
	.pk_exists = _wrap_p11_pk_exists,
	.sign_exists = _wrap_p11_pk_sign_exists
};
