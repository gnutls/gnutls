/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "auth_anon.h"
#include "gnutls_num.h"
#include "cert_asn1.h"
#include "cert_der.h"
#include "gnutls_datum.h"
#include "auth_x509.h"

int gen_rsa_server_kx(GNUTLS_KEY, opaque **);

MOD_AUTH_STRUCT rsa_auth_struct = {
	"RSA",
	gen_rsa_server_kx,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

typedef struct {
	gnutls_datum rsa_modulus;
	gnutls_datum rsa_exponent;
} RSA_Params;

/* This function will calculate the SHA/MD5 signature in server kx.
 * This is needed by the protocol.
 */
int _gnutls_calc_rsa_signature( GNUTLS_KEY key, const opaque* data, int data_size, opaque* dst) {
	void* md5;
	void* sha;
	int ret = 0;
	GNUTLS_MAC_HANDLE td;
	
	td = gnutls_hash_init(GNUTLS_MAC_MD5);
	if (td==GNUTLS_HASH_FAILED) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	gnutls_hash( td, key->client_random, 32);
	gnutls_hash( td, key->server_random, 32);
	gnutls_hash( td, data, data_size);
	
	md5 = gnutls_hash_deinit(td);
	if (md5==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memcpy( dst, md5, 16);
	gnutls_free(md5);


	td = gnutls_hash_init(GNUTLS_MAC_SHA);
	if (td==GNUTLS_HASH_FAILED) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	gnutls_hash( td, key->client_random, 32);
	gnutls_hash( td, key->server_random, 32);
	gnutls_hash( td, data, data_size);
	
	sha = gnutls_hash_deinit(td);
	if (sha==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	memcpy( &dst[16], sha, 20);
	gnutls_free(sha);
	
	return ret;
}


#define dat_set( d,s,len) d.data=gnutls_malloc(len); \
		if (d.data==NULL) return GNUTLS_E_MEMORY_ERROR; \
		memcpy(d.data, s, len); d.size = len;

/* This function reads the RSA parameters from the given(?) certificate.
 */
static int _gnutls_get_rsa_params( GNUTLS_KEY key, RSA_Params * params, gnutls_datum cert)
{
	int ret = 0, result;
	opaque str[5*1024];
	int len = sizeof(str);

	create_structure("certificate2", "PKIX1Explicit88.Certificate");

	result = get_der("certificate2", cert.data, cert.size);
	if (result != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	/* Verify sign */
	result =
	    read_value("certificate2.tbsCertificate.subjectPublicKeyInfo.algorithm", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		delete_structure("certificate2");
		return GNUTLS_E_PARSING_ERROR;
	}

	if (!strcmp(str, "111")) {	/* pkix-1 1 - RSA */
		len = sizeof(str);
		result =
		    read_value("certificate2.tbsCertificate.subjectPublicKeyInfo.parameters", str, &len);
		delete_structure("certificate2");

		if (result != ASN_OK) {
			gnutls_assert();
			delete_structure("certificate2");
			return GNUTLS_E_PARSING_ERROR;
		}

		create_structure("rsapublickey", "PKIX1Explicit88.RSAPublicKey");
		result = get_der("rsapublickey", str, len);
		if (result != ASN_OK) {
			gnutls_assert();
			delete_structure("rsapublickey");
			return GNUTLS_E_PARSING_ERROR;
		}	

		result =
		    read_value("rsapublickey.modulus", str, &len);
		if (result != ASN_OK) {
			gnutls_assert();
			delete_structure("rsapublickey");
			return GNUTLS_E_PARSING_ERROR;
		}

		if (gcry_mpi_scan(&key->A,
			  GCRYMPI_FMT_USG, str, &len) != 0) {
			gnutls_assert();
			delete_structure("rsapublickey");
			return GNUTLS_E_MPI_SCAN_FAILED;
		}
		dat_set(params->rsa_modulus, str, len);

		len = sizeof(str);
		result =
		    read_value("rsapublickey.publicExponent", str, &len);
		if (result != ASN_OK) {
			gnutls_assert();
			delete_structure("rsapublickey");
			gnutls_free(params->rsa_modulus.data);
			gcry_mpi_release(key->A);
			return GNUTLS_E_PARSING_ERROR;
		}

		if (gcry_mpi_scan(&key->B,
			  GCRYMPI_FMT_USG, str, &len) != 0) {
			gnutls_assert();
			gcry_mpi_release(key->A);
			gnutls_free(params->rsa_modulus.data);
			delete_structure("rsapublickey");
			return GNUTLS_E_MPI_SCAN_FAILED;
		}
		dat_set(params->rsa_exponent, str, len);

		delete_structure("rsapublickey");

	}

	delete_structure("certificate2");

	return ret;
}

int gen_rsa_server_kx(GNUTLS_KEY key, opaque ** data)
{
	RSA_Params params;
	const X509PKI_SERVER_CREDENTIALS *cred;
	int ret;
	opaque* pdata;

	cred = _gnutls_get_cred(key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	ret =
	    _gnutls_get_rsa_params(key, &params, cred->cert_list[0]);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = params.rsa_modulus.size +
		        params.rsa_modulus.size + 16 + 20 + 4;
	(*data) = gnutls_malloc( ret);
	
	pdata = (*data);
	if (pdata == NULL) return GNUTLS_E_MEMORY_ERROR;
	
	WRITEdatum16(pdata, params.rsa_modulus);
	pdata += params.rsa_modulus.size;

	WRITEdatum16(pdata, params.rsa_exponent);
	pdata += params.rsa_exponent.size;

	ret = _gnutls_calc_rsa_signature( key, (*data), ret-20-16, pdata);
	if (ret< 0) {
		gnutls_free((*data));
		gnutls_assert();
		return ret;
	}

	return ret;	
}

