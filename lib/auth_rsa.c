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
#include "gnutls_num.h"
#include "cert_asn1.h"
#include "cert_der.h"
#include "gnutls_datum.h"
#include "auth_x509.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>

#if 0
int gen_rsa_server_kx(GNUTLS_KEY, opaque **);
#endif
int gen_rsa_certificate(GNUTLS_KEY, opaque **);
int gen_rsa_client_kx(GNUTLS_KEY, opaque **);
int proc_rsa_client_kx( GNUTLS_KEY, opaque*, int);
int proc_rsa_certificate( GNUTLS_KEY, opaque*, int);

MOD_AUTH_STRUCT rsa_auth_struct = {
	"RSA",
	gen_rsa_certificate,
	NULL, /* gen server kx */
	NULL, /* gen server kx2 */
	NULL, /* gen client kx0 */
	gen_rsa_client_kx,
	NULL, /* gen client cert vrfy */
	NULL, /* gen server cert vrfy */
	proc_rsa_certificate,
	NULL, /* proc server kx */
	NULL, /* proc server kx2 */
	NULL, /* proc client kx0 */
	proc_rsa_client_kx, /* proc client kx */
	NULL, /* proc client cert vrfy */
	NULL /* proc server cert vrfy */
};

typedef struct {
	gnutls_datum rsa_modulus;
	gnutls_datum rsa_exponent;
} RSA_Params;

#if 0
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
	gnutls_hash( td, key->client_random, TLS_RANDOM_SIZE);
	gnutls_hash( td, key->server_random, TLS_RANDOM_SIZE);
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
	gnutls_hash( td, key->client_random, TLS_RANDOM_SIZE);
	gnutls_hash( td, key->server_random, TLS_RANDOM_SIZE);
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
#endif

/* This function extracts the RSA parameters from the given(?) certificate.
 */
static int _gnutls_get_rsa_params( GNUTLS_KEY key, RSA_Params * params, MPI* mod, MPI* exp, gnutls_datum cert)
{
	int ret = 0, result;
	opaque str[5*1024];
	int len = sizeof(str);

	if (create_structure("rsa_params", "PKIX1Explicit88.Certificate")!=ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	result = get_der("rsa_params", cert.data, cert.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}


	result =
	    read_value("rsa_params.tbsCertificate.subjectPublicKeyInfo.algorithm", str, &len);
	if (result != ASN_OK) {
fprintf(stderr, "resut: %d\n", result);
		gnutls_assert();
		delete_structure("rsa_params");
		return GNUTLS_E_PARSING_ERROR;
	}

	if (!strcmp(str, "1 2 840 113549 1 1 1")) { /* pkix-1 1 - RSA */
		len = sizeof(str);
		result =
		    read_value("rsa_params.tbsCertificate.subjectPublicKeyInfo.parameters", str, &len);
		delete_structure("rsa_params");

		if (result != ASN_OK) {
			gnutls_assert();
			delete_structure("rsa_params");
			return GNUTLS_E_PARSING_ERROR;
		}

		if (create_structure("rsapublickey", "PKIX1Explicit88.RSAPublicKey")!=ASN_OK) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}
		
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

		if (gcry_mpi_scan(mod,
			  GCRYMPI_FMT_USG, str, &len) != 0) {
			gnutls_assert();
			delete_structure("rsapublickey");
			return GNUTLS_E_MPI_SCAN_FAILED;
		}
		
		if (params!=NULL)
			if (gnutls_set_datum(&params->rsa_modulus, str, len) < 0) {
				gnutls_assert();
				delete_structure("rsapublickey");
				return GNUTLS_E_MEMORY_ERROR;
			}

		len = sizeof(str);
		result =
		    read_value("rsapublickey.publicExponent", str, &len);
		if (result != ASN_OK) {
			gnutls_assert();
			delete_structure("rsapublickey");
			if (params!=NULL) gnutls_free_datum(&params->rsa_modulus);
			_gnutls_mpi_release(mod);
			return GNUTLS_E_PARSING_ERROR;
		}

		if (gcry_mpi_scan(exp,
			  GCRYMPI_FMT_USG, str, &len) != 0) {
			gnutls_assert();
			_gnutls_mpi_release(mod);
			if (params!=NULL) gnutls_free_datum(&params->rsa_modulus);
			delete_structure("rsapublickey");
			return GNUTLS_E_MPI_SCAN_FAILED;
		}
		if (gnutls_set_datum(&params->rsa_exponent, str, len) < 0) {
			_gnutls_mpi_release(mod);
			_gnutls_mpi_release(exp);
			if (params!=NULL) gnutls_free_datum(&params->rsa_modulus);
			delete_structure("rsapublickey");
			return GNUTLS_E_MEMORY_ERROR;	
		}

		delete_structure("rsapublickey");

	}

	delete_structure("rsa_params");

	return ret;
}

/* This function reads the RSA parameters from the given private key
 * cert is not a certificate but a der structure containing the private
 * key(s).
 */
static int _gnutls_get_private_rsa_params( GNUTLS_KEY key, gnutls_datum cert)
{
	int ret = 0, result;
	opaque str[5*1024];
	int len = sizeof(str);

	if (create_structure("rsakey", "PKCS-1.RSAPrivateKey")!=ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	result = get_der("rsakey", cert.data, cert.size);
	if (result != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	result =
	    read_value("rsakey.privateExponent", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		delete_structure("rsakey");
		return GNUTLS_E_PARSING_ERROR;
	}
	if (gcry_mpi_scan(&key->u,
		  GCRYMPI_FMT_USG, str, &len) != 0) {
		gnutls_assert();
		delete_structure("rsakey");
		return GNUTLS_E_MPI_SCAN_FAILED;
	}


	len = sizeof(str);
	result =
	    read_value("rsakey.modulus", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		delete_structure("rsakey");
		_gnutls_mpi_release(&key->u);
		return GNUTLS_E_PARSING_ERROR;
	}

	if (gcry_mpi_scan(&key->A,
		  GCRYMPI_FMT_USG, str, &len) != 0) {
		gnutls_assert();
		delete_structure("rsakey");
		_gnutls_mpi_release(&key->u);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	delete_structure("rsakey");

	return ret;
}

#if 0 /* wow ... this was not needed ! */
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
	    _gnutls_get_rsa_params(key, &params, cred->pkey);

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

	gnutls_free_datum(&params.rsa_modulus);
	gnutls_free_datum(&params.rsa_modulus);

	ret = _gnutls_calc_rsa_signature( key, (*data), ret-20-16, pdata);
	if (ret< 0) {
		gnutls_free((*data));
		gnutls_assert();
		return ret;
	}

	return ret;	
}
#endif

int gen_rsa_certificate(GNUTLS_KEY key, opaque ** data)
{
	const X509PKI_SERVER_CREDENTIALS *cred;
	int ret, i, pdatasize;
	opaque* pdata;
	gnutls_datum* apr_cert_list;
	gnutls_datum apr_pkey;
	int apr_cert_list_length;
	
	cred = _gnutls_get_cred(key, GNUTLS_X509PKI, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (cred->ncerts==0) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	/* FIXME: FIND APPROPRIATE CERTIFICATE - depending on hostname 
	 */
	apr_cert_list = cred->cert_list[0];
	apr_cert_list_length = cred->cert_list_length[0];
	apr_pkey = cred->pkey[0];

	ret = 3;
	for (i=0;i<apr_cert_list_length;i++) {
		ret += apr_cert_list[i].size + 3; 
					/* hold size
					 * for uint24 */
	}

	(*data) = gnutls_malloc(ret);
	pdata = (*data);
	
	if (pdata == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	WRITEuint24( ret-3, pdata);
	pdata+=3;
	for (i=0;i<apr_cert_list_length;i++) {
		WRITEdatum24( pdata, apr_cert_list[i]); 
		pdata += 3 + apr_cert_list[i].size;
	}
	pdatasize = ret;
	
	/* read the rsa parameters now, since later we will
	 * now know which certificate we used!
	 */
	ret =
	    _gnutls_get_private_rsa_params(key, apr_pkey);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return pdatasize;
}

#define RANDOMIZE_X(x) x.size=TLS_MASTER_SIZE; x.data=gnutls_malloc(x.size); \
		if (x.data==NULL) return GNUTLS_E_MEMORY_ERROR; \
		if (_gnutls_get_random( key->key.data, key->key.size, GNUTLS_WEAK_RANDOM) < 0) { \
			return GNUTLS_E_MEMORY_ERROR; \
		} 

int proc_rsa_client_kx( GNUTLS_KEY key, opaque* data, int data_size) {
	gnutls_datum plaintext;
	gnutls_datum ciphertext;
	int ret, dsize;

	if ( _gnutls_version_ssl3(_gnutls_version_get(key->version.major, key->version.minor)) == 0 ) {
		/* SSL 3.0 */
		ciphertext.data = data;
		ciphertext.size = data_size;
	} else { /* TLS 1 */
		ciphertext.data = &data[2];
		dsize = READuint16(data);
		ciphertext.size = GMIN(dsize, data_size);
	}
	ret = _gnutls_pkcs1_rsa_decrypt(&plaintext, ciphertext, key->u, key->A);

	if ( ret < 0) {
		/* in case decryption fails then don't inform
		 * the peer. Just use a random key. (in order to avoid
		 * attack against pkcs-1 formating).
		 */
		gnutls_assert();
		RANDOMIZE_X(key->key);
	} else {
		ret = 0;
		if (plaintext.size != TLS_MASTER_SIZE) { /* WOW */
			RANDOMIZE_X(key->key);
		} else {
			if (key->version.major != plaintext.data[0]) ret = GNUTLS_E_DECRYPTION_FAILED;
			if (key->version.minor != plaintext.data[1]) ret = GNUTLS_E_DECRYPTION_FAILED;
			if (ret != 0) {
				_gnutls_mpi_release( &key->B);
				_gnutls_mpi_release( &key->u);
				_gnutls_mpi_release( &key->A);
				gnutls_assert();
				return ret;
			}
			key->key.data = plaintext.data;
			key->key.size = plaintext.size;
		}
	}

	_gnutls_mpi_release( &key->A);
	_gnutls_mpi_release( &key->B);
	_gnutls_mpi_release( &key->u);
	return 0;
}

int proc_rsa_certificate( GNUTLS_KEY key, opaque* data, int data_size) {
int size, len;
opaque* p = data;
X509PKI_AUTH_INFO* info;
int dsize = data_size;
int i, j;

	key->auth_info = gnutls_calloc(1, sizeof(X509PKI_AUTH_INFO));
	if (key->auth_info==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	key->auth_info_size = sizeof(X509PKI_AUTH_INFO);
	
	DECR_LEN( dsize, 3);
	size = READuint24( p);
	p+=3;

	if (size==0) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	
	info = key->auth_info;
	i = dsize;
	
	len=READuint24(p); p+=3;

	for(; i > 0; len=READuint24(p),p+=3)  {
		DECR_LEN(dsize, (len+3));
		info->peer_certificate_list_size++;
		p+=len;
		i-=len+3;
	}

	if (info->peer_certificate_list_size==0) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	
	dsize = data_size;
	i = dsize;	
	info->peer_certificate_list = gnutls_malloc(sizeof(gnutls_datum)*(info->peer_certificate_list_size));
	if (info->peer_certificate_list==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
			
	p = data+3;
	i = data_size - 3;
	j = 0;
	
	len=READuint24(p); p+=3;
	for(; i > 0; len=READuint24(p), p+=3) {
		if ( j >= info->peer_certificate_list_size) break;

		info->peer_certificate_list[j].size = len;
		info->peer_certificate_list[j].data = gnutls_malloc(len);
		if (info->peer_certificate_list[j].data==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
			
		memcpy( info->peer_certificate_list[j].data, p, len);
		p+=len;
		i-=len+3;
		j++;
	}
	
	
#warning "WE DO NOT VERIFY RSA CERTIFICATES"
	/* FIXME: Verify certificate 
	 */
	info->peer_certificate_status = GNUTLS_NOT_VERIFIED;
	
	return 0;
}

/* return RSA(random) using the peers public key 
 */
int gen_rsa_client_kx(GNUTLS_KEY key, opaque ** data)
{
	X509PKI_AUTH_INFO *auth = key->auth_info;
	svoid *rand;
	gnutls_datum sdata; /* data to send */
	gnutls_datum edata; /* data to encrypt */
	MPI pkey, n;
	int ret;
		
	if (auth == NULL) {
		/* this shouldn't have happened. The proc_certificate
		 * function should have detected that.
		 */
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	rand = secure_malloc( TLS_MASTER_SIZE);
	if (rand==NULL)
		return GNUTLS_E_MEMORY_ERROR;
			
	_gnutls_get_random( rand, TLS_MASTER_SIZE, GNUTLS_STRONG_RANDOM);
	
	key->key.data = rand;
	key->key.size = TLS_MASTER_SIZE;

	edata.data = rand;
	edata.size = TLS_MASTER_SIZE;

	if ( (ret=_gnutls_get_rsa_params( key, NULL, &n, &pkey, auth->peer_certificate_list[0])) < 0 ) {
		gnutls_assert();
		return ret;
	}

	_gnutls_pkcs1_rsa_encrypt( &sdata, edata, pkey, n);

	secure_free(rand);
	_gnutls_mpi_release(&pkey);
	_gnutls_mpi_release(&n);
	
	*data = sdata.data;
	return sdata.size;
}
