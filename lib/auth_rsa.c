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

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "x509_asn1.h"
#include "x509_der.h"
#include "gnutls_datum.h"
#include "auth_x509.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <x509_verify.h>
#include "debug.h"

int gen_rsa_certificate(GNUTLS_KEY, opaque **);
int gen_rsa_client_kx(GNUTLS_KEY, opaque **);
int proc_rsa_client_kx(GNUTLS_KEY, opaque *, int);
int proc_rsa_certificate(GNUTLS_KEY, opaque *, int);

MOD_AUTH_STRUCT rsa_auth_struct = {
	"RSA",
	gen_rsa_certificate,
	NULL,			/* gen server kx */
	NULL,			/* gen server kx2 */
	NULL,			/* gen client kx0 */
	gen_rsa_client_kx,
	NULL,			/* gen client cert vrfy */
	NULL,			/* gen server cert vrfy */
	proc_rsa_certificate,
	NULL,			/* proc server kx */
	NULL,			/* proc server kx2 */
	NULL,			/* proc client kx0 */
	proc_rsa_client_kx,	/* proc client kx */
	NULL,			/* proc client cert vrfy */
	NULL			/* proc server cert vrfy */
};

typedef struct {
	gnutls_datum rsa_modulus;
	gnutls_datum rsa_exponent;
} RSA_Params;


/* This function extracts the RSA parameters from the given(?) certificate.
 */
static int _gnutls_get_rsa_params(GNUTLS_KEY key, RSA_Params * params,
				  MPI * mod, MPI * exp, gnutls_datum cert)
{
	int ret = 0, result;
	opaque str[5 * 1024];
	int len = sizeof(str);
	node_asn *srsa, *spk;
	
	if (asn1_create_structure( _gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &srsa, "rsa_params")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der( srsa, cert.data, cert.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}


	len = sizeof(str) - 1;
	result =
	    asn1_read_value
	    (srsa, "rsa_params.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
	     str, &len);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(srsa);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (!strcmp(str, "1 2 840 113549 1 1 1")) {	/* pkix-1 1 - RSA */
		len = sizeof(str) - 1;
		result =
		    asn1_read_value
		    (srsa, "rsa_params.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
		     str, &len);
		asn1_delete_structure(srsa);

		if (result != ASN_OK) {
			gnutls_assert();
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		if (asn1_create_structure
		    ( _gnutls_get_pkcs(),
		     "PKCS-1.RSAPublicKey", &spk, "rsa_public_key") != ASN_OK) {
			gnutls_assert();
			return GNUTLS_E_ASN1_ERROR;
		}

		if (len % 8 != 0) {
			gnutls_assert();
			asn1_delete_structure(spk);
			return GNUTLS_E_UNIMPLEMENTED_FEATURE;
		}
		
		result = asn1_get_der(spk, str, len / 8);

		if (result != ASN_OK) {
			gnutls_assert();
			asn1_delete_structure(spk);
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		len = sizeof(str) - 1;
		result = asn1_read_value(spk, "rsa_public_key.modulus", str, &len);
		if (result != ASN_OK) {
			gnutls_assert();
			asn1_delete_structure(spk);
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		if (gcry_mpi_scan(mod, GCRYMPI_FMT_USG, str, &len) != 0) {
			gnutls_assert();
			asn1_delete_structure(spk);
			return GNUTLS_E_MPI_SCAN_FAILED;
		}

		if (params != NULL)
			if (gnutls_set_datum
			    (&params->rsa_modulus, str, len) < 0) {
				gnutls_assert();
				asn1_delete_structure(spk);
				return GNUTLS_E_MEMORY_ERROR;
			}

		len = sizeof(str) - 1;
		result =
		    asn1_read_value(spk, "rsa_public_key.publicExponent", str, &len);
		if (result != ASN_OK) {
			gnutls_assert();
			asn1_delete_structure(spk);
			if (params != NULL)
				gnutls_free_datum(&params->rsa_modulus);
			_gnutls_mpi_release(mod);
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		if (gcry_mpi_scan(exp, GCRYMPI_FMT_USG, str, &len) != 0) {
			gnutls_assert();
			_gnutls_mpi_release(mod);
			if (params != NULL)
				gnutls_free_datum(&params->rsa_modulus);
			asn1_delete_structure(spk);
			return GNUTLS_E_MPI_SCAN_FAILED;
		}
		if (params != NULL)
			if (gnutls_set_datum
			    (&params->rsa_exponent, str, len) < 0) {
				_gnutls_mpi_release(mod);
				_gnutls_mpi_release(exp);
				if (params != NULL)
					gnutls_free_datum(&params->
							  rsa_modulus);
				asn1_delete_structure(spk);
				return GNUTLS_E_MEMORY_ERROR;
			}

		asn1_delete_structure(spk);

		ret = 0;

	} else {
		/* The certificate that was sent was not
		 * supported by the ciphersuite
		 */
		gnutls_assert();
		ret = GNUTLS_E_X509_CERTIFICATE_ERROR;

		asn1_delete_structure(srsa);
	}


	return ret;
}

/* This function reads the RSA parameters from the given private key
 * cert is not a certificate but a der structure containing the private
 * key(s).
 * Ok this is no longer the case. We now precompile the pkcs1 key
 * to the gnutls_private_key structure.
 */
static int _gnutls_get_private_rsa_params(GNUTLS_KEY key,
					  gnutls_private_key pkey)
{

	key->u = gcry_mpi_copy(pkey.params[0]);
	key->A = gcry_mpi_copy(pkey.params[1]);

	return 0;
}


int gen_rsa_certificate(GNUTLS_KEY key, opaque ** data)
{
	const X509PKI_CREDENTIALS cred;
	int ret, i, pdatasize;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_private_key apr_pkey;
	int apr_cert_list_length;

	/* FIXME: This does not work for clients - yet
	 */
	cred = _gnutls_get_cred(key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (cred->ncerts == 0) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	/* FIXME: FIND APPROPRIATE CERTIFICATE - depending on hostname 
	 */
	apr_cert_list = cred->cert_list[0];
	apr_cert_list_length = cred->cert_list_length[0];
	apr_pkey = cred->pkey[0];

	ret = 3;
	for (i = 0; i < apr_cert_list_length; i++) {
		ret += apr_cert_list[i].raw.size + 3;
		/* hold size
		 * for uint24 */
	}

	(*data) = gnutls_malloc(ret);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	WRITEuint24(ret - 3, pdata);
	pdata += 3;
	for (i = 0; i < apr_cert_list_length; i++) {
		WRITEdatum24(pdata, apr_cert_list[i].raw);
		pdata += (3 + apr_cert_list[i].raw.size);
	}
	pdatasize = ret;

	/* read the rsa parameters now, since later we will
	 * now know which certificate we used!
	 */
	ret = _gnutls_get_private_rsa_params(key, apr_pkey);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return pdatasize;
}

#define RANDOMIZE_KEY(x, galloc) x.size=TLS_MASTER_SIZE; x.data=galloc(x.size); \
		if (x.data==NULL) return GNUTLS_E_MEMORY_ERROR; \
		if (_gnutls_get_random( x.data, x.size, GNUTLS_WEAK_RANDOM) < 0) { \
			return GNUTLS_E_MEMORY_ERROR; \
		}

int proc_rsa_client_kx(GNUTLS_KEY key, opaque * data, int data_size)
{
	gnutls_sdatum plaintext;
	gnutls_datum ciphertext;
	int ret, dsize;

	if (_gnutls_version_ssl3
	    (_gnutls_version_get(key->version.major, key->version.minor))
	    == 0) {
		/* SSL 3.0 */
		ciphertext.data = data;
		ciphertext.size = data_size;
	} else {		/* TLS 1 */
		ciphertext.data = &data[2];
		dsize = READuint16(data);
		ciphertext.size = GMIN(dsize, data_size);
	}
	ret =
	    _gnutls_pkcs1_rsa_decrypt(&plaintext, ciphertext, key->u,
				      key->A, 2); /* btype==2 */

	if (ret < 0) {
		/* in case decryption fails then don't inform
		 * the peer. Just use a random key. (in order to avoid
		 * attack against pkcs-1 formating).
		 */
		gnutls_assert();
		RANDOMIZE_KEY(key->key, secure_malloc);
	} else {
		ret = 0;
		if (plaintext.size != TLS_MASTER_SIZE) {	/* WOW */
			RANDOMIZE_KEY(key->key, secure_malloc);
		} else {
			if (key->version.major != plaintext.data[0])
				ret = GNUTLS_E_DECRYPTION_FAILED;
			if (key->version.minor != plaintext.data[1])
				ret = GNUTLS_E_DECRYPTION_FAILED;
			if (ret != 0) {
				_gnutls_mpi_release(&key->B);
				_gnutls_mpi_release(&key->u);
				_gnutls_mpi_release(&key->A);
				gnutls_assert();
				return ret;
			}
			key->key.data = plaintext.data;
			key->key.size = plaintext.size;
		}
	}

	_gnutls_mpi_release(&key->A);
	_gnutls_mpi_release(&key->B);
	_gnutls_mpi_release(&key->u);
	return 0;
}


int proc_rsa_certificate(GNUTLS_KEY key, opaque * data, int data_size)
{
	int size, len, ret;
	opaque *p = data;
	X509PKI_CLIENT_AUTH_INFO *info;
	const X509PKI_CREDENTIALS cred;
	int dsize = data_size;
	int i, j;
	gnutls_cert* peer_certificate_list;
	int peer_certificate_list_size = 0;
	gnutls_datum tmp;
	CertificateStatus verify;
	
	cred = _gnutls_get_cred(key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	key->auth_info = gnutls_calloc(1, sizeof(X509PKI_CLIENT_AUTH_INFO));
	if (key->auth_info == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	key->auth_info_size = sizeof(X509PKI_CLIENT_AUTH_INFO);

	DECR_LEN(dsize, 3);
	size = READuint24(p);
	p += 3;

	if (size == 0) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	info = key->auth_info;
	i = dsize;

	len = READuint24(p);
	p += 3;

	for (; i > 0; len = READuint24(p), p += 3) {
		DECR_LEN(dsize, (len + 3));
		peer_certificate_list_size++;
		p += len;
		i -= len + 3;
	}

	if (peer_certificate_list_size == 0) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}


	dsize = data_size;
	i = dsize;
	peer_certificate_list =
	    gnutls_malloc( sizeof(gnutls_cert) *
			  ( peer_certificate_list_size));

	if ( peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	p = data + 3;
	i = data_size - 3;
	j = 0;

	len = READuint24(p);
	p += 3;
	for (; i > 0; len = READuint24(p), p += 3) {
		if (j >= peer_certificate_list_size)
			break;

		tmp.size = len;
		tmp.data = p;

		if ( (ret=_gnutls_cert2gnutlsCert( &peer_certificate_list[j], tmp)) < 0) {
			gnutls_assert();
			gnutls_free( peer_certificate_list);
			return ret;
		}

		p += len;
		i -= len + 3;
		j++;
	}

	/* store the required parameters for the handshake
	 */
	if ((ret =
	     _gnutls_get_rsa_params(key, NULL, &key->A, &key->u,
				    peer_certificate_list[0].raw)) < 0) {
		gnutls_assert();
		gnutls_free( peer_certificate_list);
		return ret;
	}


	/* Verify certificate 
	 */
	verify = gnutls_verify_certificate( peer_certificate_list, peer_certificate_list_size, 
		cred->ca_list, cred->ncas, NULL, 0);
 
        _gnutls_copy_x509_client_auth_info( info, &peer_certificate_list[0], verify);


	gnutls_free( peer_certificate_list);

	return 0;
}

/* return RSA(random) using the peers public key 
 */
int gen_rsa_client_kx(GNUTLS_KEY key, opaque ** data)
{
	X509PKI_CLIENT_AUTH_INFO *auth = key->auth_info;
	gnutls_datum sdata;	/* data to send */
	MPI pkey, n;
	int ret;

	if (auth == NULL) {
		/* this shouldn't have happened. The proc_certificate
		 * function should have detected that.
		 */
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	RANDOMIZE_KEY(key->key, secure_malloc);
	key->key.data[0] = key->version.major;
	key->key.data[1] = key->version.minor;

	if ((ret =
	     _gnutls_pkcs1_rsa_encrypt(&sdata, key->key, key->u, key->A, 2)) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey);
		_gnutls_mpi_release(&n);
		return ret;
	}

	_gnutls_mpi_release(&key->A);
	_gnutls_mpi_release(&key->u);

	if (_gnutls_version_ssl3
	    (_gnutls_version_get(key->version.major, key->version.minor))
	    == 0) {
		/* SSL 3.0 */
		*data = sdata.data;
		return sdata.size;
	} else {		/* TLS 1 */
		*data = gnutls_malloc(sdata.size + 2);
		if (*data == NULL) {
			gnutls_free_datum(&sdata);
			return GNUTLS_E_MEMORY_ERROR;
		}
		WRITEuint16(sdata.size, *data);
		memcpy(&(*data)[2], sdata.data, sdata.size);
		ret = sdata.size + 2;
		gnutls_free_datum(&sdata);
		return ret;
	}

}
