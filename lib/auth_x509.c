/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

#include <gnutls_int.h>
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include <gnutls_cert.h>
#include <auth_x509.h>
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "x509_asn1.h"
#include "x509_der.h"
#include "gnutls_datum.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <gnutls_record.h>
#include <x509_verify.h>
#include <gnutls_sig.h>
#include <ext_dnsname.h>

/* Copies data from a internal certificate struct (gnutls_cert) to 
 * exported certificate struct (X509PKI_AUTH_INFO)
 */
void _gnutls_copy_x509_client_auth_info( X509PKI_AUTH_INFO info, gnutls_cert* cert, CertificateStatus verify) {
 /* Copy peer's information to AUTH_INFO
  */
  	memcpy( &info->peer_dn, &cert->cert_info, sizeof(gnutls_DN));
  	memcpy( &info->issuer_dn, &cert->issuer_info, sizeof(gnutls_DN));
  	

	info->peer_certificate_status = verify;

	info->peer_certificate_version = cert->version;
	
	if ( cert->subjectAltDNSName[0]!=0)
		strcpy( info->subjectAltDNSName, cert->subjectAltDNSName);

	info->keyUsage = cert->keyUsage;

	info->peer_certificate_expiration_time = cert->expiration_time;
	info->peer_certificate_activation_time = cert->activation_time;

	return;
}

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

/* Returns the issuer's Distinguished name in odn, of the certificate specified in cert.
 */
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

/* Gets the Distinguished name in idn, and returns a gnutls_DN structure.
 */
int _gnutls_dn2gnutlsdn( gnutls_DN* rdn, gnutls_datum* idn) {
node_asn* dn;
int result;

	if ((result=asn1_create_structure(_gnutls_get_pkix(), "PKIX1Implicit88.Name", &dn, "dn")) != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der( dn, idn->data, idn->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure( dn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = _gnutls_get_name_type( dn, "dn", rdn);
	asn1_delete_structure( dn);

	if (result < 0) {
		/* couldn't decode DER */
		gnutls_assert();
		return result;
	}

	return 0;
}




/* Finds the appropriate certificate depending on the cA Distinguished name
 * advertized by the server. If none matches then returns -1 as index.
 */
static int _gnutls_find_acceptable_client_cert( const X509PKI_CREDENTIALS cred, opaque* _data, 
	int _data_size, int *ind) {
int result, size;
int indx = -1;
int i, j, try=0;
gnutls_datum odn;
opaque* data = _data;
int data_size = _data_size;

	if (cred->client_cert_callback!=NULL) {
		/* if try>=0 then the client wants automatic
		 * choose of certificate, otherwise (-1), he
		 * will be prompted to choose one.
		 */
		try = cred->client_cert_callback( NULL, NULL, 0, NULL, 0);
	}
	
	if (try>=0)
	do {

		DECR_LEN(data_size, 2);
		size = READuint16(data);
		DECR_LEN(data_size, size);
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
		gnutls_DN *req_dn=NULL;
		gnutls_datum tmp;
		int count;
		
		cdn = gnutls_malloc( cred->ncerts* sizeof(gnutls_DN));
		if (cdn==NULL) goto clear;
		
		idn = gnutls_malloc( cred->ncerts* sizeof(gnutls_DN));
		if (idn==NULL) goto clear;

		/* put the requested DNs to req_dn
		 */		
		data = _data;
		data_size = _data_size;
		count = 0; /* holds the number of given CA's DN */
		do {
			data_size-=2;
			if (data_size<=0) goto clear;
			size = READuint16(data);
			data_size-=size;
			if (data_size<0) goto clear;
			
			
			data += 2;
			
			req_dn = gnutls_realloc_fast( req_dn, (count+1)*sizeof(gnutls_DN));
			if (req_dn==NULL) goto clear;
			
			tmp.data = data;
			tmp.size = size;
			if (_gnutls_dn2gnutlsdn( &req_dn[count], &tmp)==0)
				count++; /* otherwise we have failed */
			data+=size;

			if (data_size==0) break;

		} while(1);

		/* put our certificate's issuer and dn into cdn, idn
		 */
		for(i=0;i<cred->ncerts;i++) {
			memcpy( &cdn[i], &cred->cert_list[i][0].cert_info, sizeof(gnutls_DN));
			memcpy( &idn[i], &cred->cert_list[i][0].issuer_info, sizeof(gnutls_DN));
		}
		indx = cred->client_cert_callback( cdn, idn, cred->ncerts, req_dn, count);

		clear:
			gnutls_free(cdn);
			gnutls_free(req_dn);
			gnutls_free(idn);
	}
	*ind = indx;
	return 0;
}



int _gnutls_gen_x509_client_certificate(GNUTLS_STATE state, opaque ** data)
{
	int ret, i, pdatasize;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length;


	/* find the appropriate certificate */
	if ((ret=_gnutls_find_apr_cert( state, &apr_cert_list, &apr_cert_list_length, &apr_pkey))<0) {
		gnutls_assert();
		return ret;
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

int _gnutls_gen_x509_server_certificate(GNUTLS_STATE state, opaque ** data)
{
	int ret, i, pdatasize;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length;

	if ((ret=_gnutls_find_apr_cert( state, &apr_cert_list, &apr_cert_list_length, &apr_pkey))<0) {
		gnutls_assert();
		return ret;
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


#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) gnutls_free_cert(peer_certificate_list[x])
int _gnutls_proc_x509_server_certificate(GNUTLS_STATE state, opaque * data, int data_size)
{
	int size, len, ret;
	opaque *p = data;
	X509PKI_AUTH_INFO info;
	const X509PKI_CREDENTIALS cred;
	int dsize = data_size;
	int i, j, x;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size = 0;
	gnutls_datum tmp;
	CertificateStatus verify;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	if (state->gnutls_key->auth_info == NULL) {
		state->gnutls_key->auth_info = gnutls_calloc(1, sizeof(X509PKI_AUTH_INFO_INT));
		if (state->gnutls_key->auth_info == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		state->gnutls_key->auth_info_size = sizeof(X509PKI_AUTH_INFO_INT);

		info = state->gnutls_key->auth_info;
		info->peer_certificate_status = GNUTLS_CERT_NONE;
	}
	info = state->gnutls_key->auth_info;

	DECR_LEN(dsize, 3);
	size = READuint24(p);
	p += 3;


	if (size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		info->peer_certificate_status = GNUTLS_CERT_NONE;
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
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
	    gnutls_calloc(1, sizeof(gnutls_cert) *
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
			CLEAR_CERTS;
			gnutls_free(peer_certificate_list);
			return ret;
		}
		if (j==0) { /* Copy the first certificate in the chain - peer's certificate 
			     * into the peer_cert. This is needed in order to access these
			     * parameters later.
			     */
			if ((ret = _gnutls_cert2gnutlsCert(&state->gnutls_internals.peer_cert, tmp)) < 0) {
				gnutls_assert();
				CLEAR_CERTS;
				gnutls_free(peer_certificate_list);
				return ret;
			}
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
		CLEAR_CERTS;
		gnutls_free(peer_certificate_list);
		return ret;
	}
	/* Verify certificate 
	 */
	verify = gnutls_verify_certificate(peer_certificate_list, peer_certificate_list_size,
				     cred->ca_list, cred->ncas, NULL, 0);
	if (verify < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_free(peer_certificate_list);
		return verify;
	}

	/* keep the PK algorithm */
	state->gnutls_internals.peer_pk_algorithm = peer_certificate_list[0].subject_pk_algorithm;

	_gnutls_copy_x509_client_auth_info(info, &peer_certificate_list[0], verify);

	if ( (ret=_gnutls_check_x509_key_usage( &peer_certificate_list[0], gnutls_get_current_kx( state))) < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_free(peer_certificate_list);
		return ret;
	}

	CLEAR_CERTS;
	gnutls_free(peer_certificate_list);

	return 0;
}


#ifdef DEBUG
# warning CHECK FOR DSS
#endif

#define RSA_SIGN 1
int _gnutls_check_supported_sign_algo( uint8 algo) {
	switch(algo) {
		case RSA_SIGN:
			return 0;
	}
	
	return -1;
}

int _gnutls_proc_x509_cert_req(GNUTLS_STATE state, opaque * data, int data_size)
{
	int size, ret;
	opaque *p = data;
	const X509PKI_CREDENTIALS cred;
	X509PKI_AUTH_INFO info;
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

	if (state->gnutls_key->auth_info == NULL) {
		state->gnutls_key->auth_info = gnutls_calloc(1, sizeof(X509PKI_AUTH_INFO_INT));
		if (state->gnutls_key->auth_info == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		state->gnutls_key->auth_info_size = sizeof(X509PKI_AUTH_INFO_INT);

		info = state->gnutls_key->auth_info;
		info->peer_certificate_status = GNUTLS_CERT_NONE;
	}
	info = state->gnutls_key->auth_info;
	
	DECR_LEN(dsize, 1);
	size = p[0];
	p += 1;

	/* FIXME: Add support for DSS certificates too
	 */
	found = 0;
	for (i = 0; i < size; i++, p++) {
		DECR_LEN(dsize, 1);
		if ( _gnutls_check_supported_sign_algo(*p)==0)
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

int _gnutls_gen_x509_client_cert_vrfy(GNUTLS_STATE state, opaque ** data)
{
	int ret;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length, size;
	gnutls_datum signature;

	*data = NULL;
	
	/* find the appropriate certificate */
	if ((ret=_gnutls_find_apr_cert( state, &apr_cert_list, &apr_cert_list_length, &apr_pkey))<0) {
		gnutls_assert();
		return ret;
	}
	
	if (apr_pkey != NULL) {
		if ( (ret=_gnutls_generate_sig_from_hdata( state, &apr_cert_list[0], apr_pkey, &signature)) < 0) {
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

int _gnutls_proc_x509_client_cert_vrfy(GNUTLS_STATE state, opaque * data, int data_size)
{
int size, ret;
int dsize = data_size;
opaque* pdata = data;
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

	if ( (ret=_gnutls_verify_sig_hdata( state, &state->gnutls_internals.peer_cert, &sig, data_size+HANDSHAKE_HEADER_SIZE))<0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

#define CERTTYPE_SIZE 2
int _gnutls_gen_x509_server_cert_req(GNUTLS_STATE state, opaque ** data)
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
#ifdef DEBUG
# warning CHECK HERE FOR DSS
#endif
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


/* This function will return the appropriate certificate to use. The return
 * value depends on the side (client or server).
 */
int _gnutls_find_apr_cert( GNUTLS_STATE state, gnutls_cert** apr_cert_list, int *apr_cert_list_length, gnutls_private_key** apr_pkey) 
{
	const X509PKI_CREDENTIALS cred;
	int ind;

	cred =
	    _gnutls_get_kx_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	
	if (cred==NULL) {
		gnutls_assert();
		*apr_cert_list = NULL;
		*apr_pkey= NULL;
		*apr_cert_list_length = 0;
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	
	if (state->security_parameters.entity == GNUTLS_SERVER) {
	
		if (cred->ncerts == 0) {
			*apr_cert_list = NULL;
			*apr_cert_list_length = 0;
			*apr_pkey = NULL;
		} else {
			const char* dnsname = gnutls_ext_get_name_ind( state, GNUTLS_DNSNAME);
			if (dnsname==NULL) dnsname="";
			
			ind =
			    _gnutls_find_cert_list_index(cred->cert_list,
							 cred->ncerts,
							 dnsname);

			if (ind < 0) {
				*apr_cert_list = NULL;
				*apr_cert_list_length = 0;
				*apr_pkey = NULL;
			} else {
				*apr_cert_list = cred->cert_list[ind];
				*apr_cert_list_length = cred->cert_list_length[ind];
				*apr_pkey = &cred->pkey[ind];
			}
		}
	} else { /* CLIENT SIDE */
		if (cred->ncerts == 0) {
			*apr_cert_list = NULL;
			*apr_cert_list_length = 0;
			*apr_pkey = NULL;
		} else {
			ind = state->gnutls_internals.client_certificate_index;

			if (ind < 0) {
				*apr_cert_list = NULL;
				*apr_cert_list_length = 0;
				*apr_pkey = NULL;
			} else {
				*apr_cert_list = cred->cert_list[ind];
				*apr_cert_list_length = cred->cert_list_length[ind];
				*apr_pkey = &cred->pkey[ind];
			}
		}
	
	}
	
	return 0;
}
