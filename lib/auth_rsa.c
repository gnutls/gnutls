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
#include <gnutls_sig.h>

int gen_rsa_server_certificate(GNUTLS_STATE, opaque **);
int gen_rsa_client_certificate(GNUTLS_STATE, opaque **);
int gen_rsa_client_cert_vrfy(GNUTLS_STATE, opaque **);
int proc_rsa_cert_req(GNUTLS_STATE, opaque *, int);
int gen_rsa_client_kx(GNUTLS_STATE, opaque **);
int gen_rsa_server_cert_req(GNUTLS_STATE, opaque **);
int proc_rsa_client_kx(GNUTLS_STATE, opaque *, int);
int proc_rsa_client_cert_vrfy(GNUTLS_STATE, opaque *, int);

int proc_rsa_server_certificate(GNUTLS_STATE, opaque *, int);
#define proc_rsa_client_certificate proc_rsa_server_certificate

MOD_AUTH_STRUCT rsa_auth_struct =
{
	"RSA",
	gen_rsa_server_certificate,
	gen_rsa_client_certificate,
	NULL,			/* gen server kx */
	NULL,			/* gen server kx2 */
	NULL,			/* gen client kx0 */
	gen_rsa_client_kx,
	gen_rsa_client_cert_vrfy, /* gen client cert vrfy */
	gen_rsa_server_cert_req, /* server cert request */

	proc_rsa_server_certificate,
	proc_rsa_client_certificate,
	NULL,			/* proc server kx */
	NULL,			/* proc server kx2 */
	NULL,			/* proc client kx0 */
	proc_rsa_client_kx,	/* proc client kx */
	proc_rsa_client_cert_vrfy, /* proc client cert vrfy */
	proc_rsa_cert_req	/* proc server cert request */
};

typedef struct {
	gnutls_datum rsa_modulus;
	gnutls_datum rsa_exponent;
} RSA_Params;


/* This function extracts the RSA parameters from the given(?) certificate.
 */
static int _gnutls_get_rsa_params(RSA_Params * params,
				  MPI * mod, MPI * exp, gnutls_datum cert)
{
	int ret = 0, result;
	opaque str[5 * 1024];
	int len = sizeof(str);
	node_asn *srsa, *spk;

	if (asn1_create_structure(_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &srsa, "rsa_params")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}
	result = asn1_get_der(srsa, cert.data, cert.size);
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
		    (_gnutls_get_pkcs(),
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
					  gnutls_private_key * pkey)
{

	key->u = gcry_mpi_copy(pkey->params[0]);
	key->A = gcry_mpi_copy(pkey->params[1]);

	return 0;
}


int gen_rsa_client_certificate(GNUTLS_STATE state, opaque ** data)
{
	const X509PKI_CREDENTIALS cred;
	int ret, i, ind, pdatasize;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	if (cred->ncerts == 0) {
		apr_cert_list = NULL;
		apr_cert_list_length = 0;
		apr_pkey = NULL;
	} else {
		ind = state->gnutls_internals.client_certificate_index;

		if (ind < 0) {
			apr_cert_list = NULL;
			apr_cert_list_length = 0;
			apr_pkey = NULL;
		} else {
			apr_cert_list = cred->cert_list[ind];
			apr_cert_list_length = cred->cert_list_length[ind];
			apr_pkey = &cred->pkey[ind];
		}
	}

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
	 * not know which certificate we used!
	 */
	if (i != 0)		/* if we parsed at least one certificate */
		ret = _gnutls_get_private_rsa_params(state->gnutls_key, apr_pkey);
	else
		ret = 0;

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	return pdatasize;
}

int gen_rsa_server_certificate(GNUTLS_STATE state, opaque ** data)
{
	const X509PKI_CREDENTIALS cred;
	int ret, i, ind, pdatasize;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	if (cred->ncerts == 0) {
		apr_cert_list = NULL;
		apr_cert_list_length = 0;
		apr_pkey = NULL;
	} else {
		ind = _gnutls_find_cert_list_index(cred->cert_list, cred->ncerts, state->security_parameters.extensions.dnsname);

		if (ind < 0) {
			apr_cert_list = NULL;
			apr_cert_list_length = 0;
			apr_pkey = NULL;
		} else {
			apr_cert_list = cred->cert_list[ind];
			apr_cert_list_length = cred->cert_list_length[ind];
			apr_pkey = &cred->pkey[ind];
		}
	}

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
	 * not know which certificate we used!
	 */
	if (i != 0)		/* if we parsed at least one certificate */
		ret = _gnutls_get_private_rsa_params(state->gnutls_key, apr_pkey);
	else
		ret = 0;

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

int proc_rsa_client_kx(GNUTLS_STATE state, opaque * data, int data_size)
{
	gnutls_sdatum plaintext;
	gnutls_datum ciphertext;
	int ret, dsize;

	if ( gnutls_get_current_version(state) == GNUTLS_SSL3) {
		/* SSL 3.0 */
		ciphertext.data = data;
		ciphertext.size = data_size;
	} else {		/* TLS 1 */
		ciphertext.data = &data[2];
		dsize = READuint16(data);
		
		if (dsize != data_size - 2) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		ciphertext.size = dsize;
	}

	ret =
	    _gnutls_pkcs1_rsa_decrypt(&plaintext, ciphertext, state->gnutls_key->u,
				      state->gnutls_key->A, 2);		/* btype==2 */

	if (ret < 0) {
		/* in case decryption fails then don't inform
		 * the peer. Just use a random key. (in order to avoid
		 * attack against pkcs-1 formating).
		 */
return ret;
		gnutls_assert();
#ifdef DEBUG
		_gnutls_log( "Possible PKCS-1 format attack\n");
#endif
		RANDOMIZE_KEY(state->gnutls_key->key, secure_malloc);
	} else {
		ret = 0;
		if (plaintext.size != TLS_MASTER_SIZE) {	/* WOW */
			RANDOMIZE_KEY(state->gnutls_key->key, secure_malloc);
		} else {
			if (_gnutls_get_adv_version_major( state) != plaintext.data[0] || _gnutls_get_adv_version_minor( state) != plaintext.data[1]) {
				gnutls_assert();
				ret = GNUTLS_E_DECRYPTION_FAILED;
			}
			if (ret != 0) {
				_gnutls_mpi_release(&state->gnutls_key->B);
				_gnutls_mpi_release(&state->gnutls_key->u);
				_gnutls_mpi_release(&state->gnutls_key->A);
				gnutls_assert();
				return ret;
			}
			state->gnutls_key->key.data = plaintext.data;
			state->gnutls_key->key.size = plaintext.size;
		}
	}

	_gnutls_mpi_release(&state->gnutls_key->A);
	_gnutls_mpi_release(&state->gnutls_key->B);
	_gnutls_mpi_release(&state->gnutls_key->u);
	return 0;
}


int proc_rsa_server_certificate(GNUTLS_STATE state, opaque * data, int data_size)
{
	int size, len, ret;
	opaque *p = data;
	X509PKI_CLIENT_AUTH_INFO info;
	const X509PKI_CREDENTIALS cred;
	int dsize = data_size;
	int i, j;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size = 0;
	gnutls_datum tmp;
	CertificateStatus verify;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	if (state->gnutls_key->auth_info == NULL)
		state->gnutls_key->auth_info = gnutls_calloc(1, sizeof(X509PKI_CLIENT_AUTH_INFO_INT));
	if (state->gnutls_key->auth_info == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	state->gnutls_key->auth_info_size = sizeof(X509PKI_CLIENT_AUTH_INFO_INT);

	DECR_LEN(dsize, 3);
	size = READuint24(p);
	p += 3;

	if (size == 0) {
		gnutls_assert();
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	info = state->gnutls_key->auth_info;
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
	    gnutls_malloc(sizeof(gnutls_cert) *
			  (peer_certificate_list_size));

	if (peer_certificate_list == NULL) {
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

		if ((ret = _gnutls_cert2gnutlsCert(&peer_certificate_list[j], tmp)) < 0) {
			gnutls_assert();
			gnutls_free(peer_certificate_list);
			return ret;
		}
		p += len;
		i -= len + 3;
		j++;
	}

	/* store the required parameters for the handshake
	 */
	if ((ret =
	     _gnutls_get_rsa_params(NULL, &state->gnutls_key->a, &state->gnutls_key->x,
				    peer_certificate_list[0].raw)) < 0) {
		gnutls_assert();
		gnutls_free(peer_certificate_list);
		return ret;
	}
	/* Verify certificate 
	 */
	verify = gnutls_verify_certificate(peer_certificate_list, peer_certificate_list_size,
				     cred->ca_list, cred->ncas, NULL, 0);

	/* keep the PK algorithm */
	state->gnutls_internals.peer_pk_algorithm = peer_certificate_list[0].subject_pk_algorithm;

	_gnutls_copy_x509_client_auth_info(info, &peer_certificate_list[0], verify);

	/* This works for the client
	 */
	if ( peer_certificate_list[0].keyUsage != 0)
		if ( !(peer_certificate_list[0].keyUsage & X509KEY_KEY_ENCIPHERMENT)) {
			gnutls_assert();
			gnutls_free(peer_certificate_list);
			return GNUTLS_E_X509_KEY_USAGE_VIOLATION;
		}

	gnutls_free(peer_certificate_list);

	return 0;
}


/* return RSA(random) using the peers public key 
 */
int gen_rsa_client_kx(GNUTLS_STATE state, opaque ** data)
{
	X509PKI_CLIENT_AUTH_INFO auth = state->gnutls_key->auth_info;
	gnutls_datum sdata;	/* data to send */
	MPI pkey, n;
	int ret;
	GNUTLS_Version ver;

	if (auth == NULL) {
		/* this shouldn't have happened. The proc_certificate
		 * function should have detected that.
		 */
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	RANDOMIZE_KEY(state->gnutls_key->key, secure_malloc);

	ver = _gnutls_version_max(state);

	state->gnutls_key->key.data[0] = _gnutls_version_get_major(ver);
	state->gnutls_key->key.data[1] = _gnutls_version_get_minor(ver);

	if ((ret =
	     _gnutls_pkcs1_rsa_encrypt(&sdata, state->gnutls_key->key, state->gnutls_key->x, state->gnutls_key->a, 2)) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey);
		_gnutls_mpi_release(&n);
		return ret;
	}
	_gnutls_mpi_release(&state->gnutls_key->a);
	_gnutls_mpi_release(&state->gnutls_key->x);

	if ( ver == GNUTLS_SSL3) {
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

int _gnutls_find_dn( gnutls_datum* odn, gnutls_cert* cert) {
node_asn* dn;
int len, result;
int start, end;

	if (asn1_create_structure(_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &dn, "dn") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der( dn, cert->raw.data, cert->raw.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure( dn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
				
	result = asn1_get_start_end_der( dn, cert->raw.data, cert->raw.size,
		"dn.tbsCertificate.issuer", &start, &end);
						
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure( dn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	asn1_delete_structure( dn);

	len = end - start + 1;

	odn->size = len;
	odn->data = &cert->raw.data[start];

	return 0;
}

/* Finds the appropriate certificate depending on the cA Distinguished name
 * advertized by the server. If none matches then returns -1 as index.
 */
static int _gnutls_find_acceptable_client_cert( const X509PKI_CREDENTIALS cred, const opaque* data, 
	int data_size, int *ind) {
int result, size;
int indx = -1;
int i, j, try=0;
gnutls_datum odn;

	if (cred->client_cert_callback!=NULL) {
		/* if try>=0 then the client wants automatic
		 * choose of certificate, otherwise (-1), he
		 * will be prompted to choose one.
		 */
		try = cred->client_cert_callback( NULL, NULL, 0);
	}
	
	if (try>=0)
	do {

		DECR_LEN(data_size, 2);
		size = READuint16(data);
		data += 2;

		for(i=0;i<cred->ncerts;i++) {
			
			for (j=0;j<cred->cert_list_length[i];j++) {
				if ( (result=_gnutls_find_dn( &odn, &cred->cert_list[i][j])) < 0) {
					gnutls_assert();
					return result;
				}
				
				if ( odn.size != size) continue;
			
				if (memcmp( 
					odn.data,
					data, size) == 0 ) {
					indx = i;
					break;
				}
			}
			if (indx != -1)
				break;
		}

		if (indx != -1)
			break;

		/* move to next record */
		data_size -= size;
		if (data_size <= 0)
			break;

		data += size;

	} while (1);

	if (indx==-1 && cred->client_cert_callback!=NULL && cred->ncerts > 0) {/* use a callback to get certificate */
		gnutls_DN *cdn=NULL;
		gnutls_DN *idn=NULL;
		
		cdn = gnutls_malloc( cred->ncerts* sizeof(gnutls_DN));
		if (cdn==NULL) goto clear;
		
		idn = gnutls_malloc( cred->ncerts* sizeof(gnutls_DN));
		if (idn==NULL) goto clear;

		for(i=0;i<cred->ncerts;i++) {
			memcpy( &cdn[i], &cred->cert_list[i][0].cert_info, sizeof(gnutls_DN));
			memcpy( &idn[i], &cred->cert_list[i][0].issuer_info, sizeof(gnutls_DN));
		}
		indx = cred->client_cert_callback( cdn, idn, cred->ncerts);
	
		clear:
			gnutls_free(cdn);
			gnutls_free(idn);
	}
	*ind = indx;
	return 0;
}

#define RSA_SIGN 1
int proc_rsa_cert_req(GNUTLS_STATE state, opaque * data, int data_size)
{
	int size, ret;
	opaque *p = data;
	const X509PKI_CREDENTIALS cred;
	int dsize = data_size;
	int i;
	int found;
	int ind;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	state->gnutls_key->certificate_requested = 1;

	if (state->gnutls_key->auth_info == NULL)
		state->gnutls_key->auth_info = gnutls_calloc(1, sizeof(X509PKI_CLIENT_AUTH_INFO_INT));
	if (state->gnutls_key->auth_info == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	state->gnutls_key->auth_info_size = sizeof(X509PKI_CLIENT_AUTH_INFO_INT);

	DECR_LEN(dsize, 1);
	size = p[0];
	p += 1;

	found = 0;
	for (i = 0; i < size; i++, p++) {
		DECR_LEN(dsize, 1);
		if (*p == RSA_SIGN)
			found = 1;
	}

	if (found == 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_KX_ALGORITHM;
	}
	DECR_LEN(dsize, 2);
	size = READuint16(p);
	p += 2;

	if (size == 0) {
		return 0;
	}

	if ( (ret = _gnutls_find_acceptable_client_cert( cred, p, size, &ind)) < 0) {
		gnutls_assert();
		return ret;
	}

	/* put the index of the client certificate to use
	 */
	state->gnutls_internals.client_certificate_index = ind;

	return 0;
}

int gen_rsa_client_cert_vrfy(GNUTLS_STATE state, opaque ** data)
{
	const X509PKI_CREDENTIALS cred;
	int ret, ind;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length, size;
	gnutls_datum signature;

	*data = NULL;
	
	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	if (cred->ncerts == 0) {
		apr_cert_list = NULL;
		apr_cert_list_length = 0;
		apr_pkey = NULL;
	} else {
		ind = state->gnutls_internals.client_certificate_index;
		if (ind < 0) {
			apr_cert_list = NULL;
			apr_cert_list_length = 0;
			apr_pkey = NULL;
		} else {
			apr_cert_list = cred->cert_list[ind];
			apr_cert_list_length = cred->cert_list_length[ind];
			apr_pkey = &cred->pkey[ind];
		}
	}

	/* If our certificate supports signing
	 */
	if ( apr_cert_list != NULL)
	   if ( apr_cert_list[0].keyUsage != 0)
		if ( !(apr_cert_list[0].keyUsage & X509KEY_DIGITAL_SIGNATURE)) {
			gnutls_assert();
			return GNUTLS_E_X509_KEY_USAGE_VIOLATION;
		}
	
	if (apr_pkey != NULL) {
		if ( (ret=_gnutls_generate_sig( state, apr_pkey, &signature)) < 0) {
			gnutls_assert();
			return ret;
		}
	} else {
		gnutls_assert();
		return 0;
	}

	*data = gnutls_malloc(signature.size+2);
	if (*data==NULL) {
		gnutls_free_datum( &signature);
		return GNUTLS_E_MEMORY_ERROR;
	}
	size = signature.size;
	WRITEuint16( size, *data);

	memcpy( &(*data)[2], signature.data, size);

	gnutls_free_datum( &signature);

	return size+2;
}

int proc_rsa_client_cert_vrfy(GNUTLS_STATE state, opaque * data, int data_size)
{
int size, ret;
int dsize = data_size;
opaque* pdata = data;
gnutls_cert cert;
gnutls_datum sig;

	DECR_LEN(dsize, 2);
	size = READuint16( pdata);
	pdata += 2;

	if ( size < data_size - 2) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	sig.data = pdata;
	sig.size = size;
	
	cert.params = gnutls_malloc( 2*sizeof(MPI));
	if (cert.params==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	cert.params[0] = state->gnutls_key->x;
	cert.params[1] = state->gnutls_key->a;
	cert.subject_pk_algorithm = state->gnutls_internals.peer_pk_algorithm;

	if ( (ret=_gnutls_verify_sig( state, &cert, &sig, data_size+HANDSHAKE_HEADER_SIZE))<0) {
		gnutls_assert();
		gnutls_free( cert.params);
		return ret;
	}

	gnutls_free( cert.params);

	return 0;
}

#define CERTTYPE_SIZE 2
int gen_rsa_server_cert_req(GNUTLS_STATE state, opaque ** data)
{
	const X509PKI_CREDENTIALS cred;
	int ret, i, size;
	opaque *pdata;
	gnutls_datum dn;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	
	size = CERTTYPE_SIZE+2; /* 2 for CertType + 2 for size */
	
	for (i = 0; i < cred->ncas; i++) {
		size += cred->ca_list[i].raw.size + 2;
		/* hold size
		 * for uint16 */
	}

	(*data) = gnutls_malloc(size);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	pdata[0] = CERTTYPE_SIZE - 1;
	pdata[1] = RSA_SIGN; /* only this for now */
	pdata += CERTTYPE_SIZE;
	size = CERTTYPE_SIZE;

	/* leave space to write the actual size */
	pdata += 2;
	size += 2;

	for (i = 0; i < cred->ncas; i++) {
		if ( (ret=_gnutls_find_dn( &dn, &cred->ca_list[i])) < 0) {
			gnutls_free( (*data));
			gnutls_assert();
			return ret;
		}
		WRITEdatum16(pdata, dn);
		pdata += (2 + dn.size);
		size += (2 + dn.size);
	}

	/* write the recalculated size */
	WRITEuint16( size-CERTTYPE_SIZE-2, &(*data)[CERTTYPE_SIZE]);
	
	return size;
}
