/*
 *  Copyright (C) 2002,2003 Nikos Mavroyanopoulos
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
#include <gnutls_str.h>
#include <debug.h>
#include <x509_b64.h>
#include <gnutls_x509.h>
#include "x509/common.h"
#include "x509/x509.h"
#include "x509/verify.h"
#include "x509/compat.h"
#include "x509/mpi.h"
#include "x509/pkcs7.h"
#include "x509/privkey.h"

/*
 * some x509 certificate parsing functions.
 */

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) { \
	if (peer_certificate_list[x]) \
		gnutls_x509_crt_deinit(peer_certificate_list[x]); \
	} \
	gnutls_free( peer_certificate_list)

/*-
  * _gnutls_x509_cert_verify_peers - This function returns the peer's certificate status
  * @session: is a gnutls session
  *
  * This function will try to verify the peer's certificate and return its status (TRUSTED, REVOKED etc.). 
  * The return value (status) should be one of the gnutls_certificate_status enumerated elements.
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. Returns a negative error code in case of an error, or GNUTLS_E_NO_CERTIFICATE_FOUND if no certificate was sent.
  *
  -*/
int _gnutls_x509_cert_verify_peers(gnutls_session session)
{
	CERTIFICATE_AUTH_INFO info;
	const gnutls_certificate_credentials cred;
	unsigned int verify;
	gnutls_x509_crt *peer_certificate_list;
	int peer_certificate_list_size, i, x, ret;

	CHECK_AUTH(GNUTLS_CRD_CERTIFICATE, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(session);
	if (info == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	cred = _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	if (info->raw_certificate_list == NULL || info->ncerts == 0)
		return GNUTLS_E_NO_CERTIFICATE_FOUND;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = info->ncerts;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_x509_crt));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < peer_certificate_list_size; i++) {
		ret = gnutls_x509_crt_init( &peer_certificate_list[i]);
		if (ret < 0) {
			gnutls_assert();
			CLEAR_CERTS;
			return ret;
		}
		
		ret =
		     gnutls_x509_crt_import(peer_certificate_list[i],
					     &info->
					     raw_certificate_list[i], GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			gnutls_assert();
			CLEAR_CERTS;
			return ret;
		}
	}

	/* Verify certificate 
	 */
	ret =
	    gnutls_x509_crt_list_verify(peer_certificate_list,
				      peer_certificate_list_size,
				      cred->x509_ca_list, cred->x509_ncas, 
				      cred->x509_crl_list, cred->x509_ncrls, 
				      cred->verify_flags, &verify);

	CLEAR_CERTS;

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return verify;
}

/*
 * Read certificates and private keys, from files, memory etc.
 */

/* returns error if the certificate has different algorithm than
 * the given key parameters.
 */
static int _gnutls_check_key_cert_match( gnutls_certificate_credentials res) 
{
gnutls_datum cid;
gnutls_datum kid;
uint pk = res->cert_list[res->ncerts-1][0].subject_pk_algorithm;

	if (res->pkey[res->ncerts-1].pk_algorithm != pk) 
	{
		gnutls_assert();
		return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
	}

	if (pk == GNUTLS_PK_RSA) {
		_gnutls_x509_write_rsa_params( res->pkey[res->ncerts-1].params, 
			res->pkey[res->ncerts-1].params_size, &kid);


		_gnutls_x509_write_rsa_params( res->cert_list[res->ncerts-1][0].params,
			res->cert_list[res->ncerts-1][0].params_size, &cid);
	} else if ( pk == GNUTLS_PK_DSA) {

		_gnutls_x509_write_dsa_params( res->pkey[res->ncerts-1].params, 
			res->pkey[res->ncerts-1].params_size, &kid);

		_gnutls_x509_write_dsa_params( res->cert_list[res->ncerts-1][0].params,
			res->cert_list[res->ncerts-1][0].params_size, &cid);
	}
	
	if (cid.size != kid.size) {
		gnutls_assert();
		_gnutls_free_datum( &kid);
		_gnutls_free_datum( &cid);
		return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
	}
	
	if (memcmp( kid.data, cid.data, kid.size) != 0) {
		gnutls_assert();
		_gnutls_free_datum( &kid);
		_gnutls_free_datum( &cid);
		return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
	}
	
	_gnutls_free_datum( &kid);
	_gnutls_free_datum( &cid);
	return 0;
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a gnutls_cert structure. This is only called if PKCS7 read fails.
 * returns the number of certificates parsed (1)
 */
static int parse_crt_mem( gnutls_cert** cert_list, uint* ncerts, 
	gnutls_x509_crt cert)
{
	int i;
	int ret;

	i = *ncerts + 1;

	*cert_list =
	    (gnutls_cert *) gnutls_realloc_fast( *cert_list,
					   i *
					   sizeof(gnutls_cert));

	if ( *cert_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret = _gnutls_x509_crt2gnutls_cert( 
		&cert_list[0][i-1], cert, 0);
	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	*ncerts = i;

	return 1; /* one certificate parsed */
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a gnutls_cert structure. This is only called if PKCS7 read fails.
 * returns the number of certificates parsed (1)
 */
static int parse_der_cert_mem( gnutls_cert** cert_list, uint* ncerts, 
	const void *input_cert, int input_cert_size)
{
	gnutls_datum tmp;
	gnutls_x509_crt cert;
	int ret;

	ret = gnutls_x509_crt_init( &cert);
	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}

	tmp.data = (opaque*)input_cert;
	tmp.size = input_cert_size;

	ret = gnutls_x509_crt_import( cert, &tmp, GNUTLS_X509_FMT_DER);
	if ( ret < 0) {
		gnutls_assert();
		gnutls_x509_crt_deinit( cert);
		return ret;
	}

	ret = parse_crt_mem( cert_list, ncerts, cert);
	gnutls_x509_crt_deinit( cert);
	
	return ret;
}

#define CERT_PEM 1


/* Reads a PKCS7 base64 encoded certificate list from memory and stores it to
 * a gnutls_cert structure.
 * returns the number of certificate parsed
 */
static int parse_pkcs7_cert_mem( gnutls_cert** cert_list, uint* ncerts, const
	void *input_cert, int input_cert_size, int flags)
{
#ifdef ENABLE_PKI
	int i, j, count;
	gnutls_datum tmp, tmp2;
	int ret;
	opaque *pcert = NULL;
	size_t pcert_size;
	gnutls_pkcs7 pkcs7;
	
	ret = gnutls_pkcs7_init( &pkcs7);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	if (flags & CERT_PEM)
		ret = gnutls_pkcs7_import( pkcs7, &tmp, GNUTLS_X509_FMT_PEM);
	else
		ret = gnutls_pkcs7_import( pkcs7, &tmp, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		/* if we failed to read the structure,
		 * then just try to decode a plain DER
		 * certificate.
		 */
		gnutls_assert();
		gnutls_pkcs7_deinit(pkcs7);
#endif
		return parse_der_cert_mem( cert_list, ncerts,
			input_cert, input_cert_size);
#ifdef ENABLE_PKI
	}

	i = *ncerts + 1;

	/* tmp now contains the decoded certificate list */
	tmp.data = (opaque*)input_cert;
	tmp.size = input_cert_size;

	ret = gnutls_pkcs7_get_crt_count( pkcs7);

	if (ret < 0) {
		gnutls_assert();
		gnutls_pkcs7_deinit(pkcs7);
		return ret;
	}
	count = ret;
	
	j = count - 1;
	do {
		pcert_size = 0;
		ret = gnutls_pkcs7_get_crt_raw( pkcs7, j, NULL, &pcert_size);
		if (ret!=GNUTLS_E_MEMORY_ERROR) {
			count--;
			continue;
		}
		
		pcert = gnutls_malloc( pcert_size);
		if (ret==GNUTLS_E_MEMORY_ERROR) {
			gnutls_assert();
			count--;
			continue;
		}

		/* read the certificate
		 */
		ret = gnutls_pkcs7_get_crt_raw( pkcs7, j, pcert, &pcert_size);
		
		j--;
		
		if (ret >= 0) {
			*cert_list =
			    (gnutls_cert *) gnutls_realloc_fast( *cert_list,
					   i * sizeof(gnutls_cert));

			if ( *cert_list == NULL) {
				gnutls_assert();
				gnutls_free( pcert);
				return GNUTLS_E_MEMORY_ERROR;
			}

			tmp2.data = pcert;
			tmp2.size = pcert_size;

			ret = _gnutls_x509_cert2gnutls_cert( 
				&cert_list[0][i - 1], &tmp2, 0);

			if ( ret < 0) {
				gnutls_assert();
				gnutls_pkcs7_deinit(pkcs7);
				gnutls_free( pcert);
				return ret;
			}
	
			i++;
		}
		
		gnutls_free( pcert);

	} while (ret >= 0 && j >= 0);

	*ncerts = i - 1;

	gnutls_pkcs7_deinit(pkcs7);
	return count;
#endif
}

/* Reads a base64 encoded certificate list from memory and stores it to
 * a gnutls_cert structure. Returns the number of certificate parsed.
 */
static int parse_pem_cert_mem( gnutls_cert** cert_list, uint* ncerts, 
	const opaque *input_cert, int input_cert_size)
{
	int size, siz2, i;
	const opaque *ptr;
	opaque *ptr2;
	gnutls_datum tmp;
	int ret, count;

#ifdef ENABLE_PKI
	if ( (ptr = strnstr( input_cert, PEM_PKCS7_SEP, input_cert_size)) != NULL) 
	{
		size = strlen( ptr);

		ret = parse_pkcs7_cert_mem( cert_list, ncerts, ptr,
			size, CERT_PEM);

		return ret;
	}
#endif

	/* move to the certificate
	 */
	ptr = strnstr( input_cert, PEM_CERT_SEP, input_cert_size);
	if (ptr == NULL) ptr = strnstr( input_cert, PEM_CERT_SEP2, input_cert_size);

	if (ptr == NULL) {
		gnutls_assert();
		return GNUTLS_E_BASE64_DECODING_ERROR;
	}
	size = input_cert_size - (ptr - input_cert);

	i = *ncerts + 1;
	count = 0;

	do {

		siz2 = _gnutls_fbase64_decode(NULL, ptr, size, &ptr2);

		if (siz2 < 0) {
			gnutls_assert();
			return GNUTLS_E_BASE64_DECODING_ERROR;
		}

		*cert_list =
		    (gnutls_cert *) gnutls_realloc_fast( *cert_list,
						   i *
						   sizeof(gnutls_cert));

		if ( *cert_list == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		tmp.data = ptr2;
		tmp.size = siz2;

		ret = _gnutls_x509_cert2gnutls_cert( 
			&cert_list[0][i - 1], &tmp, 0);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
		
		/* now we move ptr after the pem header 
		 */
		ptr++;
		/* find the next certificate (if any)
		 */
		size = input_cert_size - (ptr - input_cert);
		
		if (size > 0) {
			char* ptr2;
			
			ptr2 = strnstr(ptr, PEM_CERT_SEP, size);
			if (ptr2 == NULL) ptr2 = strnstr( ptr, PEM_CERT_SEP2, size);
			
			ptr = ptr2;
		} else ptr = NULL;

		i++;
		count++;

	} while ( ptr != NULL);

	*ncerts = i - 1;

	return count;
}



/* Reads a DER or PEM certificate from memory
 */
static 
int read_cert_mem(gnutls_certificate_credentials res, const void *cert, int cert_size, 
	gnutls_x509_crt_fmt type)
{
	int ret;

	/* allocate space for the certificate to add
	 */
	res->cert_list = gnutls_realloc_fast( res->cert_list, 
		(1+ res->ncerts)*sizeof(gnutls_cert*));
	if ( res->cert_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->cert_list_length = gnutls_realloc_fast( res->cert_list_length,
		(1+ res->ncerts)*sizeof(int));
	if (res->cert_list_length==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->cert_list[res->ncerts] = NULL; /* for realloc */
	res->cert_list_length[res->ncerts] = 0;

	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_pkcs7_cert_mem( &res->cert_list[res->ncerts], 
			&res->cert_list_length[res->ncerts], cert, cert_size, 0);
	else
		ret = parse_pem_cert_mem( &res->cert_list[res->ncerts], &res->cert_list_length[res->ncerts],
		cert, cert_size);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}


static int privkey_cpy( gnutls_privkey* dest, gnutls_x509_privkey src)
{
int i, ret;

	memset( dest, 0, sizeof(gnutls_privkey));

	for(i=0;i<src->params_size;i++) {
		dest->params[i] = _gnutls_mpi_copy( src->params[i]);
		if (dest->params[i] == NULL) {
			gnutls_assert();
			ret = GNUTLS_E_MEMORY_ERROR;
			goto cleanup;
		}
	}

	dest->pk_algorithm = src->pk_algorithm;
	dest->params_size = src->params_size;

	return 0;

	cleanup:
	
	for (i=0;i<src->params_size;i++) {
		_gnutls_mpi_release( &dest->params[i]);
	}
	return ret;
}

void _gnutls_privkey_deinit(gnutls_privkey *key)
{
int i;

	for (i = 0; i < key->params_size; i++) {
		_gnutls_mpi_release( &key->params[i]);
	}
}


/* Reads a PEM encoded PKCS-1 RSA private key from memory
 * 2002-01-26: Added ability to read DSA keys.
 * type indicates the certificate format.
 */
static int read_key_mem(gnutls_certificate_credentials res, const void *key, int key_size, 
	gnutls_x509_crt_fmt type)
{
	int ret;
	gnutls_datum tmp;
	gnutls_x509_privkey tmpkey;

	/* allocate space for the pkey list
	 */
	res->pkey = gnutls_realloc_fast( res->pkey, (res->ncerts+1)*sizeof(gnutls_privkey));
	if (res->pkey==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret = gnutls_x509_privkey_init( &tmpkey); //res->pkey[res->ncerts]);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	tmp.data = (opaque*)key;
	tmp.size = key_size;

	ret = gnutls_x509_privkey_import( tmpkey, &tmp, type);
	if (ret < 0) {
		gnutls_assert();
		gnutls_x509_privkey_deinit( tmpkey);

		return ret;
	}

	ret = privkey_cpy( &res->pkey[res->ncerts], tmpkey);
	if (ret < 0) {
		gnutls_assert();
		gnutls_x509_privkey_deinit( tmpkey);

		return ret;
	}

	gnutls_x509_privkey_deinit( tmpkey);

	return 0;
}

/* Opens a file reads its contents and stores it
 * in allocated memory, which is returned.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_MMAP
# include <unistd.h>
# include <sys/mman.h>
#endif

#include <strfile.h>

void _gnutls_strfile_free( strfile *x)
{
#ifdef HAVE_MMAP
	if (x->mmaped) {
		munmap( x->data, x->size);
		return;
	}
#endif

	gnutls_free( x->data);
	x->data = NULL;
}

strfile _gnutls_file_to_str( const char * file)
{
	int fd1 = -1;
	struct stat stat_st;
	size_t tot_size;
	size_t left;
	opaque* tmp;
	ssize_t i = 0;
	strfile null = { NULL, 0, 0 };
	strfile ret = { NULL, 0, 0 };
	
	fd1 = open( file, 0);
	if (fd1==-1) {
		gnutls_assert();
		return null;
	}
	
	if (fstat( fd1, &stat_st) == -1) {
		gnutls_assert();
		goto error;
	}

	tot_size = stat_st.st_size;

#ifdef HAVE_MMAP
	if ((tmp=mmap( NULL, tot_size, PROT_READ, MAP_SHARED, fd1, 0)) != MAP_FAILED) {
		ret.mmaped = 1;
		ret.data = tmp;
		ret.size = tot_size;
		
		close(fd1);
		return ret;
	}
#endif

	ret.data = gnutls_malloc( tot_size);
	if (ret.data == NULL) {
		gnutls_assert();
		goto error;
	}
	
	left = tot_size;
	while (left > 0) {
		i = read( fd1, &ret.data[tot_size - left], left);
		if (i == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			else {
				gnutls_assert();
				goto error;
			}
		} else if (i==0) break;
	
		left -= i;
	}

	ret.size = tot_size - left;

	ret.mmaped = 0;

	close(fd1);

	return ret;
	
	error:
			
		if (!ret.mmaped)
			gnutls_free( ret.data);
		close(fd1);
		return null;
}

/* Reads a certificate file
 */
static int read_cert_file(gnutls_certificate_credentials res, const char *certfile,
	gnutls_x509_crt_fmt type)
{
	int ret;
	strfile x;

	x = _gnutls_file_to_str( certfile);
	if (x.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	ret = read_cert_mem( res, x.data, x.size, type);
	_gnutls_strfile_free(&x);
	
	return ret;

}



/* Reads PKCS-1 RSA private key file or a DSA file (in the format openssl
 * stores it).
 */
static int read_key_file(gnutls_certificate_credentials res, const char *keyfile,
	gnutls_x509_crt_fmt type)
{
	int ret;
	strfile x;

	x = _gnutls_file_to_str( keyfile);
	if (x.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	ret = read_key_mem( res, x.data, x.size, type);
	_gnutls_strfile_free(&x);
	
	return ret;
}

/**
  * gnutls_certificate_set_x509_key_mem - Used to set keys in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @cert: contains a certificate list (path) for the specified private key
  * @key: is the private key
  * @type: is PEM or DER
  *
  * This function sets a certificate/private key pair in the 
  * gnutls_certificate_credentials structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently are supported: RSA PKCS-1 encoded private keys, 
  * DSA private keys.
  *
  * DSA private keys are encoded the OpenSSL way, which is an ASN.1
  * DER sequence of 6 INTEGERs - version, p, q, g, pub, priv.
  *
  * Note that the keyUsage (2.5.29.15) PKIX extension in X.509 certificates 
  * is supported. This means that certificates intended for signing cannot
  * be used for ciphersuites that require encryption.
  *
  * If the certificate and the private key are given in PEM encoding
  * then the strings that hold their values must be null terminated.
  *
  **/
int gnutls_certificate_set_x509_key_mem(gnutls_certificate_credentials res, const gnutls_datum* cert,
			   const gnutls_datum* key, gnutls_x509_crt_fmt type)
{
	int ret;

	/* this should be first 
	 */
	if ((ret = read_key_mem( res, key->data, key->size, type)) < 0)
		return ret;

	if ((ret = read_cert_mem( res, cert->data, cert->size, type)) < 0)
		return ret;

	res->ncerts++;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/**
  * gnutls_certificate_set_x509_key - Used to set keys in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @cert_list: contains a certificate list (path) for the specified private key
  * @cert_list_size: holds the size of the certificate list
  * @key: is a gnutls_x509_privkey key
  *
  * This function sets a certificate/private key pair in the 
  * gnutls_certificate_credentials structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  **/
int gnutls_certificate_set_x509_key(gnutls_certificate_credentials res, 
	gnutls_x509_crt *cert_list, int cert_list_size,
	gnutls_x509_privkey key)
{
	int ret, i;

	/* this should be first 
	 */

	res->pkey = gnutls_realloc_fast( res->pkey, (res->ncerts+1)*sizeof(gnutls_privkey));
	if (res->pkey==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret = privkey_cpy( &res->pkey[res->ncerts], key);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	res->cert_list = gnutls_realloc_fast( res->cert_list, 
		(1+ res->ncerts)*sizeof(gnutls_cert*));
	if ( res->cert_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->cert_list_length = gnutls_realloc_fast( res->cert_list_length,
		(1+ res->ncerts)*sizeof(int));
	if (res->cert_list_length==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->cert_list[res->ncerts] = NULL; /* for realloc */
	res->cert_list_length[res->ncerts] = 0;


	for (i=0;i<cert_list_size;i++) {
		ret = parse_crt_mem( &res->cert_list[res->ncerts], 
			&res->cert_list_length[res->ncerts], cert_list[i]);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
	}
	res->ncerts++;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/**
  * gnutls_certificate_set_x509_key_file - Used to set keys in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @CERTFILE: is a file that containing the certificate list (path) for
  * the specified private key, in PKCS7 format, or a list of certificates
  * @KEYFILE: is a file that contains the private key
  * @type: is PEM or DER
  *
  * This function sets a certificate/private key pair in the 
  * gnutls_certificate_credentials structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently only PKCS-1 encoded RSA and DSA private keys are accepted by
  * this function.
  *
  **/
int gnutls_certificate_set_x509_key_file(gnutls_certificate_credentials res, const char *CERTFILE,
			   const char *KEYFILE, gnutls_x509_crt_fmt type)
{
	int ret;

	/* this should be first 
	 */
	if ((ret = read_key_file(res, KEYFILE, type)) < 0)
		return ret;

	if ((ret = read_cert_file(res, CERTFILE, type)) < 0)
		return ret;

	res->ncerts++;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

static int generate_rdn_seq( gnutls_certificate_credentials res) 
{
gnutls_datum tmp;
gnutls_datum _tmp;
int ret;
uint size, i;
opaque *pdata;

	/* Generate the RDN sequence 
	 * This will be sent to clients when a certificate
	 * request message is sent.
	 */

	/* FIXME: in case of a client it is not needed
	 * to do that. This would save time and memory.
	 * However we don't have that information available
	 * here.
	 */

	size = 0;
	for (i = 0; i < res->x509_ncas; i++) {
		if ((ret = _gnutls_x509_crt_get_raw_issuer_dn( 
			res->x509_ca_list[i], &tmp)) < 0) {
			gnutls_assert();
			return ret;
		}
		size += (2 + tmp.size);
	}

	if (res->x509_rdn_sequence.data != NULL)
		gnutls_free( res->x509_rdn_sequence.data);

	res->x509_rdn_sequence.data = gnutls_malloc(size);
	if (res->x509_rdn_sequence.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	res->x509_rdn_sequence.size = size;

	pdata = res->x509_rdn_sequence.data;

	for (i = 0; i < res->x509_ncas; i++) {
		if ((ret = _gnutls_x509_crt_get_raw_issuer_dn( 
			res->x509_ca_list[i], &tmp)) < 0) {
			gnutls_free(res->x509_rdn_sequence.data);
			res->x509_rdn_sequence.size = 0;
			res->x509_rdn_sequence.data = NULL;
			gnutls_assert();
			return ret;
		}

		_tmp.data = (opaque*) tmp.data;
		_tmp.size = tmp.size;
		_gnutls_write_datum16(pdata, _tmp);
		pdata += (2 + tmp.size);
	}

	return 0;
}




/* Returns 0 if it's ok to use the gnutls_kx_algorithm with this 
 * certificate (uses the KeyUsage field). 
 */
int _gnutls_check_key_usage( const gnutls_cert* cert,
				    gnutls_kx_algorithm alg)
{
	unsigned int keyUsage = 0;
	int encipher_type;

	if ( cert==NULL) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	if (_gnutls_map_kx_get_cred(alg, 1) == GNUTLS_CRD_CERTIFICATE ||
		_gnutls_map_kx_get_cred(alg, 0) == GNUTLS_CRD_CERTIFICATE) 
	{

		keyUsage = cert->keyUsage;

		encipher_type = _gnutls_kx_encipher_type( alg);
		
		if (keyUsage != 0 && encipher_type != CIPHER_IGN) {
			/* If keyUsage has been set in the certificate
			 */

			if ( encipher_type == CIPHER_ENCRYPT) {
				/* If the key exchange method requires an encipher
				 * type algorithm, and key's usage does not permit
				 * encipherment, then fail.
				 */
				if (!(keyUsage & KEY_KEY_ENCIPHERMENT)) {
					gnutls_assert();
					return
					    GNUTLS_E_KEY_USAGE_VIOLATION;
				}
			}

			if ( encipher_type == CIPHER_SIGN) { 
				/* The same as above, but for sign only keys
				 */
				if (!(keyUsage & KEY_DIGITAL_SIGNATURE)) {
					gnutls_assert();
					return
					    GNUTLS_E_KEY_USAGE_VIOLATION;
				}
			}
		}
	}
	return 0;
}



static int parse_pem_ca_mem( gnutls_x509_crt** cert_list, uint* ncerts, 
	const opaque *input_cert, int input_cert_size)
{
	int i, size;
	const opaque *ptr;
	gnutls_datum tmp;
	int ret, count;

	/* move to the certificate
	 */
	ptr = strnstr( input_cert, PEM_CERT_SEP, input_cert_size);
	if (ptr == NULL) ptr = strnstr( input_cert, PEM_CERT_SEP2, input_cert_size);

	if (ptr == NULL) {
		gnutls_assert();
		return GNUTLS_E_BASE64_DECODING_ERROR;
	}
	size = input_cert_size - (ptr - input_cert);

	i = *ncerts + 1;
	count = 0;

	do {

		*cert_list =
		    (gnutls_x509_crt *) gnutls_realloc_fast( *cert_list,
						   i *
						   sizeof(gnutls_x509_crt));

		if ( *cert_list == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		ret = gnutls_x509_crt_init( &cert_list[0][i - 1]);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
		
		tmp.data = (opaque*)ptr;
		tmp.size = size;

		ret =
		     gnutls_x509_crt_import(
				     cert_list[0][i - 1],
				     &tmp, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* now we move ptr after the pem header 
		 */
		ptr++;
		/* find the next certificate (if any)
		 */

		size = input_cert_size - (ptr - input_cert);
		
		if (size > 0) {
			char* ptr2;
			
			ptr2 = strnstr(ptr, PEM_CERT_SEP, size);
			if (ptr2 == NULL) ptr = strnstr( ptr, PEM_CERT_SEP2, size);
			
			ptr = ptr2;
		} else ptr = NULL;

		i++;
		count++;

	} while ( ptr != NULL);

	*ncerts = i - 1;

	return count;
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a gnutls_cert structure. This is only called if PKCS7 read fails.
 * returns the number of certificates parsed (1)
 */
static int parse_der_ca_mem( gnutls_x509_crt** cert_list, uint* ncerts, 
	const void *input_cert, int input_cert_size)
{
	int i;
	gnutls_datum tmp;
	int ret;

	i = *ncerts + 1;

	*cert_list =
	    (gnutls_x509_crt *) gnutls_realloc_fast( *cert_list,
					   i *
					   sizeof(gnutls_x509_crt));

	if ( *cert_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	tmp.data = (opaque*)input_cert;
	tmp.size = input_cert_size;

	ret = gnutls_x509_crt_init( &cert_list[0][i - 1]);
	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}
		
	ret =
	     gnutls_x509_crt_import(
			     cert_list[0][i - 1],
			     &tmp, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	*ncerts = i;

	return 1; /* one certificate parsed */
}

/**
  * gnutls_certificate_set_x509_trust_mem - Used to add trusted CAs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @ca: is a list of trusted CAs or a DER certificate
  * @type: is DER or PEM
  *
  * This function adds the trusted CAs in order to verify client
  * or server certificates. In case of a client this is not required
  * to be called if the certificates are not verified using
  * gnutls_certificate_verify_peers().
  * This function may be called multiple times.
  *
  * In case of a server the CAs set here will be sent to the client
  * if a certificate request is sent. This can be disabled using 
  * gnutls_certificate_send_x509_rdn_sequence().
  *
  * Returns the number of certificates processed or a negative
  * value on error.
  *
  **/
int gnutls_certificate_set_x509_trust_mem(gnutls_certificate_credentials res, 
	const gnutls_datum *ca, gnutls_x509_crt_fmt type)
{
	int ret, ret2;

	if (type==GNUTLS_X509_FMT_DER)
		return parse_der_ca_mem( &res->x509_ca_list, &res->x509_ncas,
			ca->data, ca->size);
	else
		return parse_pem_ca_mem( &res->x509_ca_list, &res->x509_ncas,
			ca->data, ca->size);

	if ((ret2 = generate_rdn_seq(res)) < 0)
		return ret2;

	return ret;
}

/**
  * gnutls_certificate_set_x509_trust - Used to add trusted CAs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @ca_list: is a list of trusted CAs
  * @ca_list_size: holds the size of the CA list
  *
  * This function adds the trusted CAs in order to verify client
  * or server certificates. In case of a client this is not required
  * to be called if the certificates are not verified using
  * gnutls_certificate_verify_peers().
  * This function may be called multiple times.
  *
  * In case of a server the CAs set here will be sent to the client
  * if a certificate request is sent. This can be disabled using 
  * gnutls_certificate_send_x509_rdn_sequence().
  *
  * Returns 0 on success.
  *
  **/
int gnutls_certificate_set_x509_trust(gnutls_certificate_credentials res, 
	gnutls_x509_crt * ca_list, int ca_list_size)
{
	int ret, i, ret2;

	res->x509_ca_list = gnutls_realloc_fast( res->x509_ca_list, 
		(ca_list_size + res->x509_ncas)*sizeof(gnutls_x509_crt));
	if ( res->x509_ca_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i=0;i<ca_list_size;i++) {
		ret = _gnutls_x509_crt_cpy( res->x509_ca_list[i+res->x509_ncas], 
			ca_list[i]);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
		res->x509_ncas++;
	}

	if ((ret2 = generate_rdn_seq(res)) < 0)
		return ret2;

	return 0;
}

/**
  * gnutls_certificate_set_x509_trust_file - Used to add trusted CAs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @cafile: is a file containing the list of trusted CAs (DER or PEM list)
  * @type: is PEM or DER
  *
  * This function adds the trusted CAs in order to verify client
  * or server certificates. In case of a client this is not required
  * to be called if the certificates are not verified using
  * gnutls_certificate_verify_peers().
  * This function may be called multiple times.
  *
  * In case of a server the CAs set here will be sent to the client
  * if a certificate request is sent. This can be disabled using 
  * gnutls_certificate_send_x509_rdn_sequence().
  *
  * Returns the number of certificates processed or a negative
  * value on error.
  *
  **/
int gnutls_certificate_set_x509_trust_file(gnutls_certificate_credentials res, 
		const char *cafile, gnutls_x509_crt_fmt type)
{
	int ret, ret2;
	strfile x;

	x = _gnutls_file_to_str( cafile);
	if (x.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}
	
	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_der_ca_mem( &res->x509_ca_list, &res->x509_ncas,
			x.data, x.size);
	else
		ret = parse_pem_ca_mem( &res->x509_ca_list, &res->x509_ncas,
			x.data, x.size);

	_gnutls_strfile_free(&x);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if ((ret2 = generate_rdn_seq(res)) < 0)
		return ret2;

	return ret;
}

#ifdef ENABLE_PKI

static int parse_pem_crl_mem( gnutls_x509_crl** crl_list, uint* ncrls, 
	const opaque *input_crl, int input_crl_size)
{
	int size, i;
	const opaque *ptr;
	gnutls_datum tmp;
	int ret, count;

	/* move to the certificate
	 */
	ptr = strnstr( input_crl, PEM_CRL_SEP, input_crl_size);
	if (ptr == NULL) {
		gnutls_assert();
		return GNUTLS_E_BASE64_DECODING_ERROR;
	}

	size = input_crl_size - (ptr - input_crl);

	i = *ncrls + 1;
	count = 0;

	do {

		*crl_list =
		    (gnutls_x509_crl *) gnutls_realloc_fast( *crl_list,
						   i *
						   sizeof(gnutls_x509_crl));

		if ( *crl_list == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		ret = gnutls_x509_crl_init( &crl_list[0][i - 1]);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
		
		tmp.data = (char*)ptr;
		tmp.size = size;
	
		ret =
		     gnutls_x509_crl_import(
				     crl_list[0][i - 1],
				     &tmp, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* now we move ptr after the pem header 
		 */
		ptr++;
		/* find the next certificate (if any)
		 */

		size = input_crl_size - (ptr - input_crl);

		if (size > 0)
			ptr = strnstr(ptr, PEM_CRL_SEP, size);
		else ptr = NULL;
		i++;
		count++;

	} while ( ptr != NULL);

	*ncrls = i - 1;

	return count;
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a gnutls_cert structure. This is only called if PKCS7 read fails.
 * returns the number of certificates parsed (1)
 */
static int parse_der_crl_mem( gnutls_x509_crl** crl_list, uint* ncrls, 
	const void *input_crl, int input_crl_size)
{
	int i;
	gnutls_datum tmp;
	int ret;

	i = *ncrls + 1;

	*crl_list =
	    (gnutls_x509_crl *) gnutls_realloc_fast( *crl_list,
					   i *
					   sizeof(gnutls_x509_crl));

	if ( *crl_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	tmp.data = (opaque*)input_crl;
	tmp.size = input_crl_size;

	ret = gnutls_x509_crl_init( &crl_list[0][i - 1]);
	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}
		
	ret =
	     gnutls_x509_crl_import(
			     crl_list[0][i - 1],
			     &tmp, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	*ncrls = i;

	return 1; /* one certificate parsed */
}


/* Reads a DER or PEM CRL from memory
 */
static 
int read_crl_mem(gnutls_certificate_credentials res, const void *crl, int crl_size, 
	gnutls_x509_crt_fmt type)
{
	int ret;

	/* allocate space for the certificate to add
	 */
	res->x509_crl_list = gnutls_realloc_fast( res->x509_crl_list, 
		(1+ res->x509_ncrls)*sizeof(gnutls_x509_crl));
	if ( res->x509_crl_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_der_crl_mem( &res->x509_crl_list, 
			&res->x509_ncrls, crl, crl_size);
	else
		ret = parse_pem_crl_mem( &res->x509_crl_list, 
			&res->x509_ncrls, crl, crl_size);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}

/**
  * gnutls_certificate_set_x509_crl_mem - Used to add CRLs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @CRL: is a list of trusted CRLs. They should have been verified before.
  * @type: is DER or PEM
  *
  * This function adds the trusted CRLs in order to verify client or server
  * certificates.  In case of a client this is not required
  * to be called if the certificates are not verified using
  * gnutls_certificate_verify_peers().
  * This function may be called multiple times.
  *
  * Returns the number of CRLs processed or a negative value
  * on error. 
  *
  **/
int gnutls_certificate_set_x509_crl_mem(gnutls_certificate_credentials res, 
	const gnutls_datum *CRL, gnutls_x509_crt_fmt type)
{
	int ret;

	if ((ret = read_crl_mem(res, CRL->data, CRL->size, type)) < 0)
		return ret;

	return ret;
}

/**
  * gnutls_certificate_set_x509_crl - Used to add CRLs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @crl_list: is a list of trusted CRLs. They should have been verified before.
  * @crl_list_size: holds the size of the crl_list
  *
  * This function adds the trusted CRLs in order to verify client or server
  * certificates.  In case of a client this is not required
  * to be called if the certificates are not verified using
  * gnutls_certificate_verify_peers().
  * This function may be called multiple times.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_certificate_set_x509_crl(gnutls_certificate_credentials res, 
	gnutls_x509_crl* crl_list, int crl_list_size)
{
	int ret, i;

	res->x509_crl_list = gnutls_realloc_fast( res->x509_crl_list, 
		(crl_list_size + res->x509_ncrls)*sizeof(gnutls_x509_crl));
	if ( res->x509_crl_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i=0;i<crl_list_size;i++) {
		ret = _gnutls_x509_crl_cpy( res->x509_crl_list[i+res->x509_ncrls], 
			crl_list[i]);
		if ( ret < 0) {
			gnutls_assert();
			return ret;
		}
		res->x509_ncrls++;
	}

	return 0;
}

/**
  * gnutls_certificate_set_x509_crl_file - Used to add CRLs in a gnutls_certificate_credentials structure
  * @res: is an &gnutls_certificate_credentials structure.
  * @crlfile: is a file containing the list of verified CRLs (DER or PEM list)
  * @type: is PEM or DER
  *
  * This function adds the trusted CRLs in order to verify client or server
  * certificates.  In case of a client this is not required
  * to be called if the certificates are not verified using
  * gnutls_certificate_verify_peers().
  * This function may be called multiple times.
  *
  * Returns the number of CRLs processed or a negative value
  * on error. 
  *
  **/
int gnutls_certificate_set_x509_crl_file(gnutls_certificate_credentials res, 
		const char *crlfile, gnutls_x509_crt_fmt type)
{
	int ret;
	strfile x;

	x = _gnutls_file_to_str( crlfile);
	if (x.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	if (type==GNUTLS_X509_FMT_DER)
		ret = parse_der_crl_mem( &res->x509_crl_list, &res->x509_ncrls,
			x.data, x.size);
	else
		ret = parse_pem_crl_mem( &res->x509_crl_list, &res->x509_ncrls,
			x.data, x.size);
	
	_gnutls_strfile_free(&x);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}


/**
  * gnutls_certificate_free_crls - Used to free all the CRLs from a gnutls_certificate_credentials structure
  * @sc: is an &gnutls_certificate_credentials structure.
  *
  * This function will delete all the CRLs associated
  * with the given credentials.
  *
  **/
void gnutls_certificate_free_crls(gnutls_certificate_credentials sc)
{
	uint j;

        for (j = 0; j < sc->x509_ncrls; j++) {
		gnutls_x509_crl_deinit( sc->x509_crl_list[j]);
        }
        
        sc->x509_ncrls = 0;

	gnutls_free( sc->x509_crl_list);
	sc->x509_crl_list = NULL;
}

#endif
