/*
 *  Copyright (C) 2001,2002,2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 * 
 */

/* The certificate authentication functions which are needed in the handshake,
 * and are common to RSA and DHE key exchange, are in this file.
 */

#include <gnutls_int.h>
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include <gnutls_cert.h>
#include <auth_cert.h>
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "libtasn1.h"
#include "gnutls_datum.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <gnutls_record.h>
#include <gnutls_sig.h>
#include <gnutls_state.h>
#include <gnutls_pk.h>
#include <gnutls_x509.h>
#include <gnutls_extra.h>
#include "debug.h"

static int _gnutls_server_find_cert_list_index(gnutls_session session,
					       gnutls_pk_algorithm
					       requested_algo);

/* Copies data from a internal certificate struct (gnutls_cert) to 
 * exported certificate struct (CERTIFICATE_AUTH_INFO)
 */
static
int _gnutls_copy_certificate_auth_info(CERTIFICATE_AUTH_INFO info,
				       gnutls_cert * cert, int ncerts)
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
			    _gnutls_set_datum(&info->
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
		_gnutls_free_datum(&info->raw_certificate_list[j]);

	gnutls_free(info->raw_certificate_list);
	info->raw_certificate_list = NULL;

	return ret;
}




/* returns 0 if the algo_to-check exists in the pk_algos list,
 * -1 otherwise.
 */
inline
    static int _gnutls_check_pk_algo_in_list(gnutls_pk_algorithm *
					     pk_algos, int pk_algos_length,
					     gnutls_pk_algorithm
					     algo_to_check)
{
	int i;
	for (i = 0; i < pk_algos_length; i++) {
		if (algo_to_check == pk_algos[i]) {
			return 0;
		}
	}
	return -1;
}



/* Locates the most appropriate x509 certificate using the
 * given DN. If indx == -1 then no certificate was found.
 */
static int _find_x509_cert(const gnutls_certificate_credentials cred,
			   opaque * _data, size_t _data_size,
			   gnutls_pk_algorithm * pk_algos,
			   int pk_algos_length, int *indx)
{
	uint size;
	gnutls_datum odn;
	opaque *data = _data;
	ssize_t data_size = _data_size;
	uint i, j;
	int result, cert_pk;

	*indx = -1;

	do {

		DECR_LENGTH_RET(data_size, 2, 0);
		size = _gnutls_read_uint16(data);
		DECR_LENGTH_RET(data_size, size, 0);
		data += 2;

		for (i = 0; i < cred->ncerts; i++) {
			for (j = 0; j < cred->cert_list_length[i]; j++) {
				if ((result =
				     _gnutls_cert_get_dn( &cred->cert_list[i][j], &odn)) < 0) {
					gnutls_assert();
					return result;
				}

				if (odn.size != size)
					continue;

				/* If the DN matches and
				 * the *_SIGN algorithm matches
				 * the cert is our cert!
				 */
				cert_pk = cred->cert_list[i][0].subject_pk_algorithm;

				if ((memcmp(odn.data, data, size) == 0) &&
				    (_gnutls_check_pk_algo_in_list(pk_algos, pk_algos_length, cert_pk) == 0)) {
					*indx = i;
					break;
				}
			}
			if (*indx != -1)
				break;
		}

		if (*indx != -1)
			break;

		/* move to next record */
		data += size;

	} while (1);

	return 0;

}

/* Locates the most appropriate openpgp cert
 */
static int _find_openpgp_cert(const gnutls_certificate_credentials cred,
			      gnutls_pk_algorithm * pk_algos,
			      int pk_algos_length, int *indx)
{
	uint i, j;

	*indx = -1;

	for (i = 0; i < cred->ncerts; i++) {
		for (j = 0; j < cred->cert_list_length[i]; j++) {

			/* If the *_SIGN algorithm matches
			 * the cert is our cert!
			 */
			if ((_gnutls_check_pk_algo_in_list
			     (pk_algos, pk_algos_length,
			      cred->cert_list[i][0].
			      subject_pk_algorithm) == 0)
			    && (cred->cert_list[i][0].cert_type ==
				GNUTLS_CRT_OPENPGP)) {
				*indx = i;
				break;
			}
		}
		if (*indx != -1)
			break;
	}

	return 0;
}

/* Finds the appropriate certificate depending on the cA Distinguished name
 * advertized by the server. If none matches then returns 0 and -1 as index.
 * In case of an error a negative value, is returned.
 *
 * 20020128: added ability to select a certificate depending on the SIGN
 * algorithm (only in automatic mode).
 */
static int _gnutls_find_acceptable_client_cert(gnutls_session session,
					       opaque * _data,
					       size_t _data_size, int *ind,
					       gnutls_pk_algorithm *
					       pk_algos,
					       int pk_algos_length)
{
	int result, size;
	int indx = -1;
	uint i, j;
	int *ij_map = NULL;
	const gnutls_certificate_credentials cred;
	opaque *data = _data;
	ssize_t data_size = _data_size;
	gnutls_datum *my_certs = NULL;
	gnutls_datum *issuers_dn = NULL;

	cred =
	    _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	/* If we have no callback.
	 */
	if (session->internals.client_cert_callback == NULL) {
		result = 0;

		if (session->security_parameters.cert_type ==
		    GNUTLS_CRT_X509)
			result =
			    _find_x509_cert(cred, _data, _data_size,
					    pk_algos, pk_algos_length,
					    &indx);

		if (session->security_parameters.cert_type ==
		    GNUTLS_CRT_OPENPGP)
			result =
			    _find_openpgp_cert(cred, pk_algos,
					       pk_algos_length, &indx);


		if (result < 0) {
			gnutls_assert();
			return result;
		}
	} else /* If the callback is set, then use it. */
	if (session->internals.client_cert_callback != NULL) {
		/* use a callback to get certificate 
		 */
		uint issuers_dn_len = 0;
		opaque *dataptr = data;
		ssize_t dataptr_size = data_size;

		/* Count the number of the given issuers;
		 * This is used to allocate the issuers_dn without
		 * using realloc().
		 */

		if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509) {

			do {
				/* This works like DECR_LEN() 
				 */
				result = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
				DECR_LENGTH_COM(dataptr_size, 2, goto error);
				size = _gnutls_read_uint16(dataptr);

				result = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
				DECR_LENGTH_COM(dataptr_size, size, goto error);

				dataptr += 2;
		
				if (size > 0) {
					issuers_dn_len++;
					dataptr += size;
				}

				if (dataptr_size == 0)
					break;

			} while (1);


			my_certs =
			    gnutls_alloca(cred->ncerts * sizeof(gnutls_datum));
			if (my_certs == NULL) {
				result = GNUTLS_E_MEMORY_ERROR;
				gnutls_assert();
				goto error;
			}

			/* put the requested DNs to req_dn, only in case
			 * of X509 certificates.
			 */
			if (issuers_dn_len > 0) {
				data = _data;
				data_size = _data_size;

				issuers_dn =
				    gnutls_alloca(issuers_dn_len *
						  sizeof(gnutls_datum));
				if (issuers_dn == NULL) {
					result = GNUTLS_E_MEMORY_ERROR;
					gnutls_assert();
					goto error;
				}

				for (i = 0; i < issuers_dn_len; i++) {
					/* The checks here for the buffer boundaries
					 * are not needed since the buffer has been
					 * parsed above.
					 */
					data_size -= 2;

					size = _gnutls_read_uint16(data);

					data += 2;

					issuers_dn[i].data = data;
					issuers_dn[i].size = size;
	
					data += size;

				}
			}

		} else { /* Other certificate types */
			issuers_dn_len = 0;
			issuers_dn = NULL;
		}

		/* maps j -> i */
		ij_map = gnutls_alloca(sizeof(int) * cred->ncerts);
		if (ij_map == NULL) {
			result = GNUTLS_E_MEMORY_ERROR;
			gnutls_assert();
			goto error;
		}

		/* put our certificate's issuer and dn into cdn, idn
		 * Note that the certificates we provide to the callback
		 * are not all the certificates we have. Only the certificates
		 * that are requested by the server (certificate type - and sign
		 * algorithm matches), are provided.
		 */
		for (j = i = 0; i < cred->ncerts; i++) {
			if ((cred->cert_list[i][0].cert_type ==
			     gnutls_certificate_type_get(session)) &&
			    (_gnutls_check_pk_algo_in_list(pk_algos,
							   pk_algos_length,
							   cred->
							   cert_list[i][0].
							   subject_pk_algorithm)
			     == 0)) {
				/* Add a certificate ONLY if it is allowed
				 * by the peer.
				 */
				ij_map[j] = i;
				my_certs[j++] = cred->cert_list[i][0].raw;
			}
		}

		indx =
		    session->internals.client_cert_callback(session,
							    my_certs,
							    j,
							    issuers_dn,
							    issuers_dn_len);

		/* the indx returned by the user is relative
		 * to the certificates we provided him.
		 * This will make it relative to the certificates
		 * we've got.
		 */
		if (indx != -1)
			indx = ij_map[indx];

		gnutls_afree(my_certs);
		gnutls_afree(ij_map);
		gnutls_afree(issuers_dn);
	}

	*ind = indx;
	return 0;

	error:
		if (my_certs != NULL) { gnutls_afree(my_certs); }
		if (ij_map != NULL) { gnutls_afree(ij_map); }
		if (issuers_dn != NULL) { gnutls_afree(issuers_dn); }
		return result;

}

/* Generate client certificate
 */

int _gnutls_gen_x509_crt(gnutls_session session, opaque ** data)
{
	int ret, i;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_privkey *apr_pkey;
	int apr_cert_list_length;

	/* find the appropriate certificate 
	 */
	if ((ret =
	     _gnutls_find_apr_cert(session, &apr_cert_list,
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
	_gnutls_write_uint24(ret - 3, pdata);
	pdata += 3;
	for (i = 0; i < apr_cert_list_length; i++) {
		_gnutls_write_datum24(pdata, apr_cert_list[i].raw);
		pdata += (3 + apr_cert_list[i].raw.size);
	}

	return ret;
}

enum PGPKeyDescriptorType { PGP_KEY_FINGERPRINT, PGP_KEY };

int _gnutls_gen_openpgp_certificate(gnutls_session session, opaque ** data)
{
	int ret;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_privkey* apr_pkey;
	int apr_cert_list_length;

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(session, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	ret = 3 + 1 + 3;

	if (apr_cert_list_length > 0)
		ret += apr_cert_list[0].raw.size;

	(*data) = gnutls_malloc(ret);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_write_uint24(ret - 3, pdata);
	pdata += 3;

	*pdata = PGP_KEY;	/* whole key */
	pdata++;

	if (apr_cert_list_length > 0) {
		_gnutls_write_datum24(pdata, apr_cert_list[0].raw);
		pdata += (3 + apr_cert_list[0].raw.size);
	} else			/* empty - no certificate */
		_gnutls_write_uint24(0, pdata);

	return ret;
}

OPENPGP_FINGERPRINT _E_gnutls_openpgp_fingerprint = NULL;
OPENPGP_KEY_REQUEST _E_gnutls_openpgp_request_key = NULL;
extern OPENPGP_CERT2GNUTLS_CERT _E_gnutls_openpgp_cert2gnutls_cert;

int _gnutls_gen_openpgp_certificate_fpr(gnutls_session session,
					opaque ** data)
{
	int ret, fpr_size, packet_size;
	opaque *pdata;
	gnutls_cert *apr_cert_list;
	gnutls_privkey* apr_pkey;
	int apr_cert_list_length;

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(session, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	packet_size = 3 + 1;

	/* Only v4 fingerprints are sent 
	 */
	if (apr_cert_list_length > 0 && apr_cert_list[0].version == 4)
		packet_size += 20 + 1;
	else			/* empty certificate case */
		return _gnutls_gen_openpgp_certificate(session, data);

	(*data) = gnutls_malloc(packet_size);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_write_uint24(packet_size - 3, pdata);
	pdata += 3;

	*pdata = PGP_KEY_FINGERPRINT;	/* key fingerprint */
	pdata++;

	*pdata = 20;
	pdata++;

	fpr_size = 20;

	if (_E_gnutls_openpgp_fingerprint == NULL) {
		gnutls_assert();
		return GNUTLS_E_INIT_LIBEXTRA;
	}

	if ((ret =
	     _E_gnutls_openpgp_fingerprint(&apr_cert_list[0].raw, pdata,
					   &fpr_size)) < 0) {
		gnutls_assert();
		return ret;
	}

	return packet_size;
}



int _gnutls_gen_cert_client_certificate(gnutls_session session,
					opaque ** data)
{
	switch (session->security_parameters.cert_type) {
	case GNUTLS_CRT_OPENPGP:
		if (_gnutls_openpgp_send_fingerprint(session) == 0)
			return
			    _gnutls_gen_openpgp_certificate(session, data);
		else
			return
			    _gnutls_gen_openpgp_certificate_fpr
			    (session, data);

	case GNUTLS_CRT_X509:
		return _gnutls_gen_x509_crt(session, data);

	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}
}

int _gnutls_gen_cert_server_certificate(gnutls_session session,
					opaque ** data)
{
	switch (session->security_parameters.cert_type) {
	case GNUTLS_CRT_OPENPGP:
		return _gnutls_gen_openpgp_certificate(session, data);
	case GNUTLS_CRT_X509:
		return _gnutls_gen_x509_crt(session, data);
	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}
}

/* Process server certificate
 */

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) _gnutls_free_cert(&peer_certificate_list[x])
int _gnutls_proc_x509_server_certificate(gnutls_session session,
					 opaque * data, size_t data_size)
{
	int size, len, ret;
	opaque *p = data;
	CERTIFICATE_AUTH_INFO info;
	const gnutls_certificate_credentials cred;
	ssize_t dsize = data_size;
	int i, j, x;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size = 0;
	gnutls_datum tmp;

	cred =
	    _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}


	if ((ret =
	     _gnutls_auth_info_set(session, GNUTLS_CRD_CERTIFICATE,
				   sizeof(CERTIFICATE_AUTH_INFO_INT), 1)) <
	    0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info(session);

	if (data == NULL || data_size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	DECR_LEN(dsize, 3);
	size = _gnutls_read_uint24(p);
	p += 3;

	if (size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	i = dsize;
	while (i > 0) {
		DECR_LEN(dsize, 3);
		len = _gnutls_read_uint24(p);
		p += 3;
		DECR_LEN(dsize, len);
		peer_certificate_list_size++;
		p += len;
		i -= len + 3;
	}

	if (peer_certificate_list_size == 0) {
		gnutls_assert();
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	/* Ok we now allocate the memory to hold the
	 * certificate list 
	 */

	peer_certificate_list =
	    gnutls_alloca(sizeof(gnutls_cert) *
			  (peer_certificate_list_size));

	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memset(peer_certificate_list, 0, sizeof(gnutls_cert) *
	       peer_certificate_list_size);

	p = data + 3;

	/* Now we start parsing the list (again).
	 * We don't use DECR_LEN since the list has
	 * been parsed before.
	 */

	for (j = 0; j < peer_certificate_list_size; j++) {
		len = _gnutls_read_uint24(p);
		p += 3;

		tmp.size = len;
		tmp.data = p;

		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&peer_certificate_list
						   [j], &tmp,
						   CERT_ONLY_EXTENSIONS)) <
		    0) {
			gnutls_assert();
			CLEAR_CERTS;
			gnutls_afree(peer_certificate_list);
			return ret;
		}

		p += len;
	}


	if ((ret =
	     _gnutls_copy_certificate_auth_info(info,
						peer_certificate_list,
						peer_certificate_list_size))
	    < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}

	if ((ret =
	     _gnutls_check_key_usage(&peer_certificate_list[0],
					  gnutls_kx_get(session)))
	    < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}

	CLEAR_CERTS;
	gnutls_afree(peer_certificate_list);

	return 0;
}

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) _gnutls_free_cert(&peer_certificate_list[x])
int _gnutls_proc_openpgp_server_certificate(gnutls_session session,
					    opaque * data,
					    size_t data_size)
{
	int size, ret, len;
	opaque *p = data;
	CERTIFICATE_AUTH_INFO info;
	const gnutls_certificate_credentials cred;
	ssize_t dsize = data_size;
	int i, x;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size = 0;
	gnutls_datum tmp, akey = { NULL, 0 };

	cred =
	    _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	if ((ret =
	     _gnutls_auth_info_set(session, GNUTLS_CRD_CERTIFICATE,
				   sizeof(CERTIFICATE_AUTH_INFO_INT), 1)) <
	    0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info(session);

	if (data == NULL || data_size == 0) {
		gnutls_assert();
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	DECR_LEN(dsize, 3);
	size = _gnutls_read_uint24(p);
	p += 3;

	if (size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	i = dsize;

	/* Read PGPKeyDescriptor */
	DECR_LEN(dsize, 1);
	if (*p == PGP_KEY_FINGERPRINT) {	/* the fingerprint */
		p++;

		DECR_LEN(dsize, 1);
		len = (uint8) * p;
		p++;

		if (len != 20) {
			gnutls_assert();
			return GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED;
		}

		DECR_LEN(dsize, 20);

		/* request the actual key from our database, or
		 * a key server or anything.
		 */
		if (_E_gnutls_openpgp_request_key == NULL) {
			gnutls_assert();
			return GNUTLS_E_INIT_LIBEXTRA;
		}
		if ((ret =
		     _E_gnutls_openpgp_request_key(session, &akey, cred, p,
						   20)) < 0) {
			gnutls_assert();
			return ret;
		}
		tmp = akey;
		peer_certificate_list_size++;

	} else if (*p == PGP_KEY) {	/* the whole key */

		p++;

		/* Read the actual certificate */
		DECR_LEN(dsize, 3);
		len = _gnutls_read_uint24(p);
		p += 3;

		if (len == 0) {
			gnutls_assert();
			/* no certificate was sent */
			return GNUTLS_E_NO_CERTIFICATE_FOUND;
		}

		DECR_LEN(dsize, len);
		peer_certificate_list_size++;

		tmp.size = len;
		tmp.data = p;

	} else {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
	}

	/* ok we now have the peer's key in tmp datum
	 */

	if (peer_certificate_list_size == 0) {
		gnutls_assert();
		_gnutls_free_datum(&akey);
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	peer_certificate_list =
	    gnutls_alloca(sizeof(gnutls_cert) *
			  (peer_certificate_list_size));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memset(peer_certificate_list, 0, sizeof(gnutls_cert) *
	       peer_certificate_list_size);

	if (_E_gnutls_openpgp_cert2gnutls_cert == NULL) {
		gnutls_assert();
		_gnutls_free_datum(&akey);
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return GNUTLS_E_INIT_LIBEXTRA;
	}

	if ((ret =
	     _E_gnutls_openpgp_cert2gnutls_cert(&peer_certificate_list[0],
						&tmp)) < 0) {
		gnutls_assert();
		_gnutls_free_datum(&akey);
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}
	_gnutls_free_datum(&akey);

	if ((ret =
	     _gnutls_copy_certificate_auth_info(info,
						peer_certificate_list,
						peer_certificate_list_size))
	    < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}

	if ((ret =
	     _gnutls_check_key_usage(&peer_certificate_list[0],
					  gnutls_kx_get(session)))
	    < 0) {
		gnutls_assert();
		CLEAR_CERTS;
		gnutls_afree(peer_certificate_list);
		return ret;
	}

	CLEAR_CERTS;
	gnutls_afree(peer_certificate_list);

	return 0;
}

int _gnutls_proc_cert_server_certificate(gnutls_session session,
					 opaque * data, size_t data_size)
{
	switch (session->security_parameters.cert_type) {
	case GNUTLS_CRT_OPENPGP:
		return _gnutls_proc_openpgp_server_certificate(session,
							       data,
							       data_size);
	case GNUTLS_CRT_X509:
		return _gnutls_proc_x509_server_certificate(session, data,
							    data_size);
	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}
}

#define MAX_SIGN_ALGOS 2
typedef enum CertificateSigType { RSA_SIGN = 1, DSA_SIGN
} CertificateSigType;

/* Checks if we support the given signature algorithm 
 * (RSA or DSA). Returns the corresponding gnutls_pk_algorithm
 * if true;
 */
inline static
int _gnutls_check_supported_sign_algo(CertificateSigType algo)
{
	switch (algo) {
	case RSA_SIGN:
		return GNUTLS_PK_RSA;
	case DSA_SIGN:
		return GNUTLS_PK_DSA;
	}

	return -1;
}

int _gnutls_proc_cert_cert_req(gnutls_session session, opaque * data,
			       size_t data_size)
{
	int size, ret;
	opaque *p = data;
	const gnutls_certificate_credentials cred;
	CERTIFICATE_AUTH_INFO info;
	ssize_t dsize = data_size;
	int i, j, ind;
	gnutls_pk_algorithm pk_algos[MAX_SIGN_ALGOS];
	int pk_algos_length;

	cred =
	    _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	if ((ret =
	     _gnutls_auth_info_set(session, GNUTLS_CRD_CERTIFICATE,
				   sizeof(CERTIFICATE_AUTH_INFO_INT), 0)) <
	    0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info(session);

	DECR_LEN(dsize, 1);
	size = p[0];
	p++;
	/* check if the sign algorithm is supported.
	 */
	pk_algos_length = j = 0;
	for (i = 0; i < size; i++, p++) {
		DECR_LEN(dsize, 1);
		if ((ret = _gnutls_check_supported_sign_algo(*p)) > 0) {
			if (j < MAX_SIGN_ALGOS) {
				pk_algos[j++] = ret;
				pk_algos_length++;
			}
		}
	}

	if (pk_algos_length == 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
	}

	if (session->security_parameters.cert_type == GNUTLS_CRT_X509) {
		DECR_LEN(dsize, 2);
		size = _gnutls_read_uint16(p);
		p += 2;
	} else {
		p = NULL;
		size = 0;
	}

	DECR_LEN(dsize, size);

	/* now we ask the user to tell which one
	 * he wants to use.
	 */
	if ((ret =
	     _gnutls_find_acceptable_client_cert(session, p, size,
						 &ind, pk_algos,
						 pk_algos_length)) < 0) {
		gnutls_assert();
		return ret;
	}
	/* put the index of the client certificate to use
	 */
	session->internals.selected_cert_index = ind;

	/* We should reply with a certificate message, 
	 * even if we have no certificate to send.
	 */
	session->key->certificate_requested = 1;

	return 0;
}

int _gnutls_gen_cert_client_cert_vrfy(gnutls_session session,
				      opaque ** data)
{
	int ret;
	gnutls_cert *apr_cert_list;
	gnutls_privkey* apr_pkey;
	int apr_cert_list_length, size;
	gnutls_datum signature;

	*data = NULL;

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(session, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	if (apr_pkey != NULL) {
		if ((ret =
		     _gnutls_tls_sign_hdata(session,
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
		_gnutls_free_datum(&signature);
		return GNUTLS_E_MEMORY_ERROR;
	}
	size = signature.size;
	_gnutls_write_uint16(size, *data);

	memcpy(&(*data)[2], signature.data, size);

	_gnutls_free_datum(&signature);

	return size + 2;
}

int _gnutls_proc_cert_client_cert_vrfy(gnutls_session session,
				       opaque * data, size_t data_size)
{
	int size, ret;
	ssize_t dsize = data_size;
	opaque *pdata = data;
	gnutls_datum sig;
	CERTIFICATE_AUTH_INFO info = _gnutls_get_auth_info(session);
	gnutls_cert peer_cert;

	if (info == NULL || info->ncerts == 0) {
		gnutls_assert();
		/* we need this in order to get peer's certificate */
		return GNUTLS_E_INTERNAL_ERROR;
	}

	DECR_LEN(dsize, 2);
	size = _gnutls_read_uint16(pdata);
	pdata += 2;

	DECR_LEN(dsize, size);

	sig.data = pdata;
	sig.size = size;

	switch (session->security_parameters.cert_type) {
	case GNUTLS_CRT_X509:
		ret =
		    _gnutls_x509_cert2gnutls_cert(&peer_cert,
						  &info->
						  raw_certificate_list[0],
						  CERT_NO_COPY);
		break;
	case GNUTLS_CRT_OPENPGP:
		if (_E_gnutls_openpgp_cert2gnutls_cert == NULL) {
			gnutls_assert();
			return GNUTLS_E_INIT_LIBEXTRA;
		}
		ret =
		    _E_gnutls_openpgp_cert2gnutls_cert(&peer_cert,
						       &info->
						       raw_certificate_list
						       [0]);
		break;
	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if ((ret =
	     _gnutls_verify_sig_hdata(session, &peer_cert, &sig)) < 0) {
		gnutls_assert();
		_gnutls_free_cert(&peer_cert);
		return ret;
	}
	_gnutls_free_cert(&peer_cert);

	return 0;
}

#define CERTTYPE_SIZE 3
int _gnutls_gen_cert_server_cert_req(gnutls_session session,
				     opaque ** data)
{
	const gnutls_certificate_credentials cred;
	int size;
	opaque *pdata;

	/* Now we need to generate the RDN sequence. This is
	 * already in the CERTIFICATE_CRED structure, to improve
	 * performance.
	 */

	cred =
	    _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	size = CERTTYPE_SIZE + 2;	/* 2 for gnutls_certificate_type + 2 for size of rdn_seq 
					 */

	if (session->security_parameters.cert_type == GNUTLS_CRT_X509 &&
		session->internals.ignore_rdn_sequence == 0)
		size += cred->x509_rdn_sequence.size;

	(*data) = gnutls_malloc(size);
	pdata = (*data);

	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	pdata[0] = CERTTYPE_SIZE - 1;

	pdata[1] = RSA_SIGN;
	pdata[2] = DSA_SIGN;	/* only these for now */
	pdata += CERTTYPE_SIZE;

	if (session->security_parameters.cert_type == GNUTLS_CRT_X509 &&
		session->internals.ignore_rdn_sequence == 0) {
		_gnutls_write_datum16(pdata, cred->x509_rdn_sequence);
		pdata += cred->x509_rdn_sequence.size + 2;
	}

	return size;
}


/* This function will return the appropriate certificate to use. The return
 * value depends on the side (client or server).
 */
int _gnutls_find_apr_cert(gnutls_session session,
			  gnutls_cert ** apr_cert_list,
			  int *apr_cert_list_length,
			  gnutls_privkey ** apr_pkey)
{
	const gnutls_certificate_credentials cred;
	int ind;

	cred = _gnutls_get_kx_cred(session, GNUTLS_CRD_CERTIFICATE, NULL);

	if (cred == NULL) {
		gnutls_assert();
		*apr_cert_list = NULL;
		*apr_pkey = NULL;
		*apr_cert_list_length = 0;
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	if (session->security_parameters.entity == GNUTLS_SERVER) {

		if (cred->ncerts == 0) {
			*apr_cert_list = NULL;
			*apr_cert_list_length = 0;
			*apr_pkey = NULL;
			gnutls_assert();	/* this is not allowed */
			return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
		} else {
			/* find_cert_list_index() has been called before.
			 */
			ind = session->internals.selected_cert_index;

			if (ind < 0) {
				*apr_cert_list = NULL;
				*apr_cert_list_length = 0;
				*apr_pkey = NULL;
				gnutls_assert();
				return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
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
			/* we had already decided which certificate
			 * to send.
			 */
			ind = session->internals.selected_cert_index;

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

/* finds the most appropriate certificate in the cert list.
 * The 'appropriate' is defined by the user. 
 * (frontend to _gnutls_server_find_cert_index())
 */
const gnutls_cert *_gnutls_server_find_cert(gnutls_session session,
					    gnutls_pk_algorithm
					    requested_algo)
{
	int i;
	const gnutls_certificate_credentials x509_cred;

	x509_cred =
	    _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);

	if (x509_cred == NULL)
		return NULL;

	i = _gnutls_server_find_cert_list_index(session, requested_algo);

	if (i < 0)
		return NULL;

	return &x509_cred->cert_list[i][0];
}

/* finds the most appropriate certificate in the cert list.
 * The 'appropriate' is defined by the user.
 *
 * requested_algo holds the parameters required by the peer (RSA, DSA
 * or -1 for any).
 */
static int _gnutls_server_find_cert_list_index(gnutls_session session,
					       gnutls_pk_algorithm
					       requested_algo)
{
	uint i, j;
	int index = -1;
	const gnutls_certificate_credentials cred;
	int my_certs_length;
	int *ij_map = NULL;

	cred =
	    _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	index = -1;		/* default is use no certificate */

	for (i = 0; i < cred->ncerts; i++) {
		/* find one compatible certificate */
		if (requested_algo == (gnutls_pk_algorithm) - 1 ||
		    requested_algo ==
		    cred->cert_list[i][0].subject_pk_algorithm) {
			/* if cert type matches */
			if (session->security_parameters.cert_type ==
			    cred->cert_list[i][0].cert_type) {
				index = i;
				break;
			}
		}

	}

	if (session->internals.server_cert_callback != NULL && cred->ncerts > 0) {	
		/* use the callback to get certificate 
		 */
		gnutls_datum *my_certs = NULL;

		my_certs =
		    gnutls_malloc(cred->ncerts * sizeof(gnutls_datum));
		if (my_certs == NULL)
			goto clear;
		my_certs_length = cred->ncerts;

		/* put our certificate's issuer and dn into cdn, idn
		 */
		ij_map = gnutls_malloc(sizeof(int) * cred->ncerts);

		j = 0;
		for (i = 0; i < cred->ncerts; i++) {
			/* Add compatible certificates */
			if (requested_algo == (gnutls_pk_algorithm) - 1 ||
			    requested_algo ==
			    cred->cert_list[i][0].subject_pk_algorithm) {

				/* if cert type matches */
				if (session->security_parameters.
				    cert_type ==
				    cred->cert_list[i][0].cert_type) {

					ij_map[j] = i;
					my_certs[j++] =
					    cred->cert_list[i][0].raw;
				}
			}
		}
		my_certs_length = j;

		index =
		    session->internals.server_cert_callback(session,
							    my_certs,
							    my_certs_length);

		if (index != -1)
			index = ij_map[index];

	      clear:
		gnutls_free(my_certs);
		gnutls_free(ij_map);
	}

	/* store the index for future use, in the handshake.
	 * (This will allow not calling this callback again.)
	 */
	session->internals.selected_cert_index = index;
	return index;
}
