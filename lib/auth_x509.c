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
#include <x509_extensions.h>

/* Copies data from a internal certificate struct (gnutls_cert) to 
 * exported certificate struct (X509PKI_AUTH_INFO)
 */
int _gnutls_copy_x509_auth_info(X509PKI_AUTH_INFO info, gnutls_cert * cert,
				int ncerts)
{
	/* Copy peer's information to AUTH_INFO
	 */
	int ret, i, j;

	if (ncerts == 0) {
		info->raw_certificate_list = NULL;
		info->ncerts = 0;
		return 0;
	}

	info->raw_certificate_list =
	    gnutls_calloc(1, sizeof(gnutls_datum) * ncerts);
	if (info->raw_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < ncerts; i++) {
		if (cert->raw.size > 0) {
			ret =
			    gnutls_set_datum(&info->
					     raw_certificate_list[i],
					     cert[i].raw.data,
					     cert[i].raw.size);
			if (ret < 0) {
				gnutls_assert();
				goto clear;
			}
		}
	}
	info->ncerts = ncerts;

	return 0;

      clear:

	for (j = 0; j < i; j++)
		gnutls_free_datum(&info->raw_certificate_list[j]);

	gnutls_free(info->raw_certificate_list);
	info->raw_certificate_list = NULL;

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

/* Returns the issuer's Distinguished name in odn, of the certificate 
 * specified in cert.
 */
int _gnutls_find_dn(gnutls_datum * odn, gnutls_cert * cert)
{
	node_asn *dn;
	int len, result;
	int start, end;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &dn,
	     "dn") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(dn, cert->raw.data, cert->raw.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(dn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = asn1_get_start_end_der(dn, cert->raw.data, cert->raw.size,
					"dn.tbsCertificate.issuer", &start,
					&end);

	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(dn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	asn1_delete_structure(dn);

	len = end - start + 1;

	odn->size = len;
	odn->data = &cert->raw.data[start];

	return 0;
}

/**
  * gnutls_x509pki_extract_dn - This function parses an RDN sequence
  * @idn: should contain a DER encoded RDN sequence
  * @rdn: a pointer to a structure to hold the name
  *
  * This function will return the name of the given RDN sequence.
  * The name will be returned as a gnutls_DN structure.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509pki_extract_dn(const gnutls_datum * idn, gnutls_DN * rdn)
{
	node_asn *dn;
	int result;

	if ((result =
	     asn1_create_structure(_gnutls_get_pkix(),
				   "PKIX1Implicit88.Name", &dn,
				   "dn")) != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(dn, idn->data, idn->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(dn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = _gnutls_get_name_type(dn, "dn", rdn);
	asn1_delete_structure(dn);

	if (result < 0) {
		/* couldn't decode DER */
		gnutls_assert();
		return result;
	}

	return 0;
}




/* Finds the appropriate certificate depending on the cA Distinguished name
 * advertized by the server. If none matches then returns 0 and -1 as index.
 * In case of an error a negative value, is returned.
 */
static int _gnutls_find_acceptable_client_cert(GNUTLS_STATE state,
					       opaque * _data,
					       int _data_size, int *ind)
{
	int result, size;
	int indx = -1;
	int i, j, try = 0;
	gnutls_datum odn;
	opaque *data = _data;
	int data_size = _data_size;
	const GNUTLS_X509PKI_CREDENTIALS cred;


	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}


	if (state->gnutls_internals.client_cert_callback != NULL) {
		/* if try>=0 then the client wants automatic
		 * choose of certificate, otherwise (-1), he
		 * will be prompted to choose one.
		 */
		try =
		    state->gnutls_internals.client_cert_callback( state, NULL, 0,
								 NULL, 0);
	}

	if (try >= 0)
		do {

			DECR_LEN(data_size, 2);
			size = READuint16(data);
			DECR_LEN(data_size, size);
			data += 2;

			for (i = 0; i < cred->ncerts; i++) {

				for (j = 0; j < cred->cert_list_length[i];
				     j++) {
					if ((result =
					     _gnutls_find_dn(&odn,
							     &cred->
							     cert_list[i]
							     [j])) < 0) {
						gnutls_assert();
						return result;
					}

					if (odn.size != size)
						continue;

					if (memcmp(odn.data,
						   data, size) == 0) {
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
			if (data_size <= 0)
				break;

			data += size;

		} while (1);

	if (indx == -1 && state->gnutls_internals.client_cert_callback != NULL && cred->ncerts > 0) {	/* use a callback to get certificate */
		gnutls_datum *my_certs = NULL;
		gnutls_datum *issuers_dn = NULL;
		int count;

		my_certs =
		    gnutls_malloc(cred->ncerts * sizeof(gnutls_datum));
		if (my_certs == NULL)
			goto clear;

		/* put the requested DNs to req_dn
		 */
		data = _data;
		data_size = _data_size;
		count = 0;	/* holds the number of given CA's DN */
		do {
			data_size -= 2;
			if (data_size <= 0)
				goto clear;
			size = READuint16(data);
			data_size -= size;
			if (data_size < 0)
				goto clear;


			data += 2;

			issuers_dn =
			    gnutls_realloc_fast(issuers_dn,
						(count +
						 1) *
						sizeof(gnutls_datum));
			if (issuers_dn == NULL)
				goto clear;

			issuers_dn->data = data;
			issuers_dn->size = size;

			count++;	/* otherwise we have failed */

			data += size;

			if (data_size == 0)
				break;

		} while (1);

		/* put our certificate's issuer and dn into cdn, idn
		 */
		for (i = 0; i < cred->ncerts; i++) {
			my_certs[i] = cred->cert_list[i][0].raw;
		}
		indx =
		    state->gnutls_internals.client_cert_callback(state, my_certs,
								 cred->
								 ncerts,
								 issuers_dn,
								 count);

	      clear:
		gnutls_free(my_certs);
		gnutls_free(issuers_dn);
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
	if ((ret =
	     _gnutls_find_apr_cert(state, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	ret = 3;
	for (i = 0; i < apr_cert_list_length; i++) {
		ret += apr_cert_list[i].raw.size + 3;
		/* hold size
		 * for uint24 */
	}

	/* if no certificates were found then send:
	 * 0B 00 00 03 00 00 00    // Certificate with no certs
	 * instead of:
	 * 0B 00 00 00          // empty certificate handshake
	 *
	 * ( the above is the whole handshake message, not 
	 * the one produced here )
	 */

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
		ret =
		    _gnutls_get_private_rsa_params(state->gnutls_key,
						   apr_pkey);
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

	if ((ret =
	     _gnutls_find_apr_cert(state, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
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
		ret =
		    _gnutls_get_private_rsa_params(state->gnutls_key,
						   apr_pkey);
	else
		ret = 0;

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	return pdatasize;
}


#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) gnutls_free_cert(peer_certificate_list[x])
int _gnutls_proc_x509_server_certificate(GNUTLS_STATE state, opaque * data,
					 int data_size)
{
	int size, len, ret;
	opaque *p = data;
	X509PKI_AUTH_INFO info;
	const GNUTLS_X509PKI_CREDENTIALS cred;
	int dsize = data_size;
	int i, j, x;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size = 0;
	gnutls_datum tmp;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}


	if (state->gnutls_key->auth_info == NULL) {
		state->gnutls_key->auth_info =
		    gnutls_calloc(1, sizeof(X509PKI_AUTH_INFO_INT));
		if (state->gnutls_key->auth_info == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		state->gnutls_key->auth_info_size =
		    sizeof(X509PKI_AUTH_INFO_INT);

		info = state->gnutls_key->auth_info;

		state->gnutls_key->auth_info_type = GNUTLS_X509PKI;
	} else
	    if (gnutls_auth_get_type(state) !=
		state->gnutls_key->auth_info_type) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	info = state->gnutls_key->auth_info;

	DECR_LEN(dsize, 3);
	size = READuint24(p);
	p += 3;


	if (size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	i = dsize;

	DECR_LEN(dsize, 3);
	len = READuint24(p);
	p += 3;

	for (; i > 0; len = READuint24(p), p += 3) {
		DECR_LEN(dsize, len);
		peer_certificate_list_size++;
		p += len;
		i -= len + 3;
		if (i>0) DECR_LEN(dsize, 3);
	}

	if (peer_certificate_list_size == 0) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	/* Now we start parsing the list (again).
	 * We don't use DECR_LEN since the list has
	 * been parsed before.
	 */
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

		if ((ret =
		     _gnutls_cert2gnutlsCert(&peer_certificate_list[j],
					     tmp)) < 0) {
			gnutls_assert();
			CLEAR_CERTS;
			gnutls_free(peer_certificate_list);
			return ret;
		}

		p += len;
		i -= len + 3;
		j++;
	}

	/* move RSA parameters to gnutls_key (state).
	 */
	state->gnutls_key->a =
	    gcry_mpi_copy(peer_certificate_list[0].params[0]);
	state->gnutls_key->x =
	    gcry_mpi_copy(peer_certificate_list[0].params[1]);

	if (state->gnutls_key->a == NULL || state->gnutls_key->x == NULL) {
		_gnutls_mpi_release(&state->gnutls_key->a);
		_gnutls_mpi_release(&state->gnutls_key->x);
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_free(peer_certificate_list);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* keep the PK algorithm */
	state->gnutls_internals.peer_pk_algorithm =
	    peer_certificate_list[0].subject_pk_algorithm;

	if ((ret =
	     _gnutls_copy_x509_auth_info(info, peer_certificate_list,
					 peer_certificate_list_size)) <
	    0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_free(peer_certificate_list);
		return ret;
	}

	if ((ret =
	     _gnutls_check_x509pki_key_usage(&peer_certificate_list[0],
					     gnutls_kx_get_algo(state)))
	    < 0) {
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
int _gnutls_check_supported_sign_algo(uint8 algo)
{
	switch (algo) {
	case RSA_SIGN:
		return 0;
	}

	return -1;
}

int _gnutls_proc_x509_cert_req(GNUTLS_STATE state, opaque * data,
			       int data_size)
{
	int size, ret;
	opaque *p = data;
	const GNUTLS_X509PKI_CREDENTIALS cred;
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
		state->gnutls_key->auth_info =
		    gnutls_calloc(1, sizeof(X509PKI_AUTH_INFO_INT));
		if (state->gnutls_key->auth_info == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		state->gnutls_key->auth_info_size =
		    sizeof(X509PKI_AUTH_INFO_INT);

		info = state->gnutls_key->auth_info;
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
		if (_gnutls_check_supported_sign_algo(*p) == 0)
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

	DECR_LEN(dsize, size);
	if ((ret =
	     _gnutls_find_acceptable_client_cert(state, p, size,
						 &ind)) < 0) {
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
	if ((ret =
	     _gnutls_find_apr_cert(state, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	if (apr_pkey != NULL) {
		if ((ret =
		     _gnutls_generate_sig_from_hdata(state,
						     &apr_cert_list[0],
						     apr_pkey,
						     &signature)) < 0) {
			gnutls_assert();
			return ret;
		}
	} else {
		gnutls_assert();
		return 0;
	}

	*data = gnutls_malloc(signature.size + 2);
	if (*data == NULL) {
		gnutls_free_datum(&signature);
		return GNUTLS_E_MEMORY_ERROR;
	}
	size = signature.size;
	WRITEuint16(size, *data);

	memcpy(&(*data)[2], signature.data, size);

	gnutls_free_datum(&signature);

	return size + 2;
}

int _gnutls_proc_x509_client_cert_vrfy(GNUTLS_STATE state, opaque * data,
				       int data_size)
{
	int size, ret;
	int dsize = data_size;
	opaque *pdata = data;
	gnutls_datum sig;
	X509PKI_AUTH_INFO info = state->gnutls_key->auth_info;
	gnutls_cert peer_cert;

	if (info == NULL || info->ncerts == 0) {
		gnutls_assert();
		/* we need this in order to get peer's certificate */
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	DECR_LEN(dsize, 2);
	size = READuint16(pdata);
	pdata += 2;

	DECR_LEN(dsize, size);

	sig.data = pdata;
	sig.size = size;

	if ((ret =
	     _gnutls_cert2gnutlsCert(&peer_cert,
				     info->raw_certificate_list[0])) < 0) {
		gnutls_assert();
		return ret;
	}

	if ((ret =
	     _gnutls_verify_sig_hdata(state, &peer_cert, &sig,
				      data_size + HANDSHAKE_HEADER_SIZE)) <
	    0) {
		gnutls_assert();
		gnutls_free_cert(peer_cert);
		return ret;
	}
	gnutls_free_cert(peer_cert);

	return 0;
}

#define CERTTYPE_SIZE 2
int _gnutls_gen_x509_server_cert_req(GNUTLS_STATE state, opaque ** data)
{
	const GNUTLS_X509PKI_CREDENTIALS cred;
	int size;
	opaque *pdata;

	/* Now we need to generate the RDN sequence. This is
	 * already in the X509PKI_CRED structure, to improve
	 * performance.
	 */

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	size = CERTTYPE_SIZE + 2;	/* 2 for CertType + 2 for size of rdn_seq 
					 */

	size += cred->rdn_sequence.size;

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
	pdata[1] = RSA_SIGN;	/* only this for now */
	pdata += CERTTYPE_SIZE;

	WRITEdatum16(pdata, cred->rdn_sequence);
	pdata += cred->rdn_sequence.size + 2;

	return size;
}


/* This function will return the appropriate certificate to use. The return
 * value depends on the side (client or server).
 */
int _gnutls_find_apr_cert(GNUTLS_STATE state, gnutls_cert ** apr_cert_list,
			  int *apr_cert_list_length,
			  gnutls_private_key ** apr_pkey)
{
	const GNUTLS_X509PKI_CREDENTIALS cred;
	int ind;

	cred =
	    _gnutls_get_kx_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);

	if (cred == NULL) {
		gnutls_assert();
		*apr_cert_list = NULL;
		*apr_pkey = NULL;
		*apr_cert_list_length = 0;
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (state->security_parameters.entity == GNUTLS_SERVER) {

		if (cred->ncerts == 0) {
			*apr_cert_list = NULL;
			*apr_cert_list_length = 0;
			*apr_pkey = NULL;
			gnutls_assert();	/* this is not allowed */
			return GNUTLS_E_INSUFICIENT_CRED;
		} else {
			/* find_cert_list_index() has been called before.
			 */
			ind = state->gnutls_internals.selected_cert_index;

			if (ind < 0) {
				*apr_cert_list = NULL;
				*apr_cert_list_length = 0;
				*apr_pkey = NULL;
				gnutls_assert();
				return GNUTLS_E_INSUFICIENT_CRED;
			} else {
				*apr_cert_list = cred->cert_list[ind];
				*apr_cert_list_length =
				    cred->cert_list_length[ind];
				*apr_pkey = &cred->pkey[ind];
			}
		}
	} else {		/* CLIENT SIDE */
		if (cred->ncerts == 0) {
			*apr_cert_list = NULL;
			*apr_cert_list_length = 0;
			*apr_pkey = NULL;
			/* it is allowed not to have a certificate 
			 */
		} else {
			ind =
			    state->gnutls_internals.
			    client_certificate_index;

			if (ind < 0) {
				*apr_cert_list = NULL;
				*apr_cert_list_length = 0;
				*apr_pkey = NULL;
			} else {
				*apr_cert_list = cred->cert_list[ind];
				*apr_cert_list_length =
				    cred->cert_list_length[ind];
				*apr_pkey = &cred->pkey[ind];
			}
		}

	}

	return 0;
}

#define CHECK_AUTH(auth, ret) if (gnutls_auth_get_type(state) != auth) { \
	gnutls_assert(); \
	return ret; \
	}

/**
  * gnutls_x509pki_extract_certificate_dn - This function returns the certificate's distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the peer's name
  *
  * This function will return the name of the certificate holder. The name is gnutls_DN structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509pki_extract_certificate_dn(const gnutls_datum * cert,
					  gnutls_DN * ret)
{
	node_asn *c2;
	int result;

	memset(ret, 0, sizeof(gnutls_DN));

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}


	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
#ifdef DEBUG
		_gnutls_log("Decoding error %d\n", result);
#endif
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	if ((result =
	     _gnutls_get_name_type(c2,
				   "certificate2.tbsCertificate.subject",
				   ret)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}

	asn1_delete_structure(c2);

	return 0;
}

/**
  * gnutls_x509pki_extract_certificate_issuer_dn - This function returns the certificate's issuer distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the issuer's name
  *
  * This function will return the name of the issuer stated in the certificate. The name is a gnutls_DN structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509pki_extract_certificate_issuer_dn(const gnutls_datum * cert,
						 gnutls_DN * ret)
{
	node_asn *c2;
	int result;

	memset(ret, 0, sizeof(gnutls_DN));

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
#ifdef DEBUG
		_gnutls_log("Decoding error %d\n", result);
#endif
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	if ((result =
	     _gnutls_get_name_type(c2,
				   "certificate2.tbsCertificate.issuer",
				   ret)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}

	asn1_delete_structure(c2);

	return 0;
}

/**
  * gnutls_x509pki_extract_subject_dns_name - This function returns the peer's dns name, if any
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: is the place where dns name will be copied to
  * @ret_size: holds the size of ret.
  *
  * This function will return the alternative name (the dns part of it), contained in the
  * given certificate.
  * 
  * This is specified in X509v3 Certificate Extensions. 
  * GNUTLS will only return the dnsName of the Alternative name, or a negative
  * error code.
  * Returns GNUTLS_E_MEMORY_ERROR if ret_size is not enough to hold dns name,
  * or the size of dns name if everything was ok.
  *
  * If the certificate does not have a DNS name then returns GNUTLS_E_DATA_NOT_AVAILABLE;
  *
  **/
int gnutls_x509pki_extract_subject_dns_name(const gnutls_datum * cert,
					    char *ret, int *ret_size)
{
	int result;
	gnutls_datum dnsname;

	memset(ret, 0, *ret_size);

	if ((result =
	     _gnutls_get_extension(cert, "2 5 29 17", &dnsname)) < 0) {
		return result;
	}

	if (dnsname.size == 0) {
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if (*ret_size > dnsname.size) {
		*ret_size = dnsname.size;
		strcpy(ret, dnsname.data);
		gnutls_free_datum(&dnsname);
	} else {
		*ret_size = dnsname.size;
		gnutls_free_datum(&dnsname);
		return GNUTLS_E_MEMORY_ERROR;
	}

	return *ret_size;
}

/**
  * gnutls_x509pki_extract_certificate_activation_time - This function returns the peer's certificate activation time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's activation time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  **/
time_t gnutls_x509pki_extract_certificate_activation_time(const
							  gnutls_datum *
							  cert)
{
	node_asn *c2;
	int result;
	time_t ret;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return -1;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
#ifdef DEBUG
		_gnutls_log("Decoding error %d\n", result);
#endif
		gnutls_assert();
		return -1;
	}

	ret = _gnutls_get_time(c2, "certificate2", "notBefore");

	asn1_delete_structure(c2);

	return ret;
}

/**
  * gnutls_x509pki_extract_certificate_expiration_time - This function returns the certificate's expiration time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's expiration time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  **/
time_t gnutls_x509pki_extract_certificate_expiration_time(const
							  gnutls_datum *
							  cert)
{
	node_asn *c2;
	int result;
	time_t ret;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return -1;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
#ifdef DEBUG
		_gnutls_log("Decoding error %d\n", result);
#endif
		gnutls_assert();
		return -1;
	}

	ret = _gnutls_get_time(c2, "certificate2", "notAfter");

	asn1_delete_structure(c2);

	return ret;
}

/**
  * gnutls_x509pki_extract_certificate_version - This function returns the certificate's version
  * @cert: is an X.509 DER encoded certificate
  *
  * This function will return the X.509 certificate's version (1, 2, 3). This is obtained by the X509 Certificate
  * Version field. Returns a negative value in case of an error.
  *
  **/
int gnutls_x509pki_extract_certificate_version(const gnutls_datum * cert)
{
	node_asn *c2;
	int result;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
#ifdef DEBUG
		_gnutls_log("Decoding error %d\n", result);
#endif
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = _gnutls_get_version(c2, "certificate2");

	asn1_delete_structure(c2);

	return result;

}

/**
  * gnutls_x509pki_get_peer_certificate_status - This function returns the peer's certificate status
  * @state: is a gnutls state
  *
  * This function will try to verify the peer's certificate and return it's status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one of the CertificateStatus enumerated elements.
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. Returns a negative error code in case of an error, or GNUTLS_CERT_NONE if no certificate was sent.
  *
  **/
int gnutls_x509pki_get_peer_certificate_status(GNUTLS_STATE state)
{
	X509PKI_AUTH_INFO info;
	const GNUTLS_X509PKI_CREDENTIALS cred;
	CertificateStatus verify;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size, i, x, ret;

	CHECK_AUTH(GNUTLS_X509PKI, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (info->raw_certificate_list == NULL || info->ncerts == 0)
		return GNUTLS_CERT_NONE;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = info->ncerts;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_cert));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < peer_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_cert2gnutlsCert(&peer_certificate_list[i],
					     info->
					     raw_certificate_list[i])) <
		    0) {
			gnutls_assert();
			CLEAR_CERTS;
			gnutls_free(peer_certificate_list);
			return ret;
		}
	}

	/* Verify certificate 
	 */
	verify =
	    gnutls_verify_certificate(peer_certificate_list,
				      peer_certificate_list_size,
				      cred->ca_list, cred->ncas, NULL, 0);

	CLEAR_CERTS;
	gnutls_free(peer_certificate_list);

	if (verify < 0) {
		gnutls_assert();
		return GNUTLS_CERT_INVALID;
	}


	return verify;
}

/* finds the most appropriate certificate in the cert list.
 * The 'appropriate' is defined by the user. 
 * (frontend to _gnutls_server_find_cert_index())
 */
const gnutls_cert *_gnutls_server_find_x509_cert(GNUTLS_STATE state)
{
	int i;
	const GNUTLS_X509PKI_CREDENTIALS x509_cred;

	x509_cred =
            _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
        
        if (x509_cred==NULL)
        	return NULL;

	i = _gnutls_server_find_x509_cert_list_index(state, x509_cred->cert_list,
					 x509_cred->ncerts);

	if (i < 0)
		return NULL;

	return &x509_cred->cert_list[i][0];
}

/* finds the most appropriate certificate in the cert list.
 * The 'appropriate' is defined by the user.
 */
int _gnutls_server_find_x509_cert_list_index(GNUTLS_STATE state,
					gnutls_cert ** cert_list,
					int cert_list_length)
{
	int i, index = -1;
	const GNUTLS_X509PKI_CREDENTIALS cred;

	state->gnutls_internals.selected_cert_index = 0;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (cred->ncerts > 0)
		index = 0;	/* default is use the first certificate */

	if (state->gnutls_internals.client_cert_callback != NULL && cred->ncerts > 0) {	/* use the callback to get certificate */
		gnutls_datum *my_certs = NULL;

		my_certs =
		    gnutls_malloc(cred->ncerts * sizeof(gnutls_datum));
		if (my_certs == NULL)
			goto clear;

		/* put our certificate's issuer and dn into cdn, idn
		 */
		for (i = 0; i < cred->ncerts; i++) {
			my_certs[i] = cred->cert_list[i][0].raw;
		}
		index =
		    state->gnutls_internals.server_cert_callback(state, my_certs,
								 cred->ncerts);

	      clear:
		gnutls_free(my_certs);
	}

	/* store the index for future use, in the handshake.
	 * (This will allow not calling this callback again.)
	 */
	state->gnutls_internals.selected_cert_index = index;
	return index;
}
