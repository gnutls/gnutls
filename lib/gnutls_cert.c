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
#include <gnutls_errors.h>
#include <x509_b64.h>
#include <auth_x509.h>
#include <gnutls_cert.h>
#include <x509_asn1.h>
#include <x509_der.h>
#include <gnutls_datum.h>
#include <gnutls_gcry.h>
#include <gnutls_privkey.h>
#include <gnutls_global.h>
#include <x509_verify.h>
#include <x509_extensions.h>

/* KX mappings to PK algorithms */
typedef struct {
	KXAlgorithm kx_algorithm;
	PKAlgorithm pk_algorithm;
} gnutls_pk_map;

/* This table maps the Key exchange algorithms to
 * the certificate algorithms. Eg. if we have
 * RSA algorithm in the certificate then we can
 * use GNUTLS_KX_RSA or GNUTLS_KX_DHE_RSA.
 */
static const gnutls_pk_map pk_mappings[] = {
	{GNUTLS_KX_RSA, GNUTLS_PK_RSA},
/*	{ GNUTLS_KX_DHE_RSA,     GNUTLS_PK_RSA }, */
	{0}
};

#define GNUTLS_PK_MAP_LOOP(b) \
        const gnutls_pk_map *p; \
                for(p = pk_mappings; p->kx_algorithm != 0; p++) { b ; }

#define GNUTLS_PK_MAP_ALG_LOOP(a) \
                        GNUTLS_PK_MAP_LOOP( if(p->kx_algorithm == kx_algorithm) { a; break; })


/* returns the PKAlgorithm which is compatible with
 * the given KXAlgorithm.
 */
PKAlgorithm _gnutls_map_pk_get_pk(KXAlgorithm kx_algorithm)
{
	PKAlgorithm ret = -1;

	GNUTLS_PK_MAP_ALG_LOOP(ret = p->pk_algorithm);
	return ret;
}

#define GNUTLS_FREE(x) if(x!=NULL) gnutls_free(x)
void gnutls_free_cert( gnutls_cert cert) {
int n,i;

	switch( cert.subject_pk_algorithm) {
	case GNUTLS_PK_RSA:
		n = 2;/* the number of parameters in MPI* */
		break;
	default:
		n=0;
	}
	
	for (i=0;i<n;i++) {
		_gnutls_mpi_release( &cert.params[i]);
	}
	if (cert.params!=NULL) gnutls_free( cert.params);
	
	gnutls_free_datum( &cert.raw);

	return;
}

/**
  * gnutls_free_x509_sc - Used to free an allocated x509 SERVER CREDENTIALS structure
  * @sc: is an &X509PKI_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_free_x509_sc( X509PKI_CREDENTIALS sc) {
int i,j;

	for (i=0;i<sc->ncerts;i++) {
		for (j=0;j<sc->cert_list_length[i];j++) {
			gnutls_free_cert( sc->cert_list[i][j]);
		}
		gnutls_free( sc->cert_list[i]);
	}

	if (sc->cert_list_length!=NULL) gnutls_free( sc->cert_list_length);
	if (sc->cert_list!=NULL) gnutls_free( sc->cert_list );

	for (j=0;j<sc->ncas;j++) {
		gnutls_free_cert( sc->ca_list[j]);
	}
	if (sc->ca_list!=NULL) gnutls_free( sc->ca_list);

	for (i=0;i<sc->ncerts;i++) {
		_gnutls_free_private_key( sc->pkey[i]);
	}
	if(sc->pkey!=NULL) gnutls_free(sc->pkey);

	gnutls_free(sc);
}

#define MAX_FILE_SIZE 100*1024
#define CERT_SEP "-----BEGIN"

/* Reads a base64 encoded certificate file
 */
static int read_cert_file( X509PKI_CREDENTIALS res, char* certfile) {
int siz, i, siz2;
opaque* b64;
char x[MAX_FILE_SIZE];
char* ptr;
FILE* fd1;
gnutls_datum tmp;
int ret;

	fd1 = fopen(certfile, "r");
	if (fd1 == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;

	siz = fread(x, 1, sizeof(x), fd1);
	fclose(fd1);
	
	ptr = x;
	i=1;

	res->cert_list[res->ncerts] = NULL;

	do {
		siz2 = _gnutls_fbase64_decode(ptr, siz, &b64);
		siz-=siz2; /* FIXME: this is not enough
			    */

		if (siz2 < 0) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_PARSING_ERROR;
		}
		ptr = strstr( ptr, CERT_SEP)+1;

		res->cert_list[res->ncerts] =
		    (gnutls_cert *) gnutls_realloc( res->cert_list[res->ncerts], i * sizeof(gnutls_cert));

		if (res->cert_list[res->ncerts] == NULL) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}
		
		tmp.data = b64;
		tmp.size = siz2;
		if ((ret =
		     _gnutls_cert2gnutlsCert(&res->cert_list[res->ncerts][i-1], tmp)) < 0) {
			gnutls_free( b64);
			gnutls_assert();
			return ret;
		}
		gnutls_free( b64);

		i++;
	} while( (ptr=strstr( ptr, CERT_SEP))!=NULL);

	res->cert_list_length[res->ncerts] = i-1;
	
	/* WE DO NOT CATCH OVERRUNS in gnutls_set_x509_key().
	 * This function should be called as many times as specified 
	 * in allocate_x509_sc().
	 */
	res->ncerts++;

	return 0;
}

/* Reads a base64 encoded CA file (file contains multiple certificate
 * authorities). This is to be called once.
 */
static int read_ca_file( X509PKI_CREDENTIALS res, char* cafile) {
int siz, siz2, i;
opaque* b64;
char x[MAX_FILE_SIZE];
char* ptr;
FILE* fd1;
int ret;
gnutls_datum tmp;

	fd1 = fopen(cafile, "r");
	if (fd1 == NULL) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}
	
	siz = fread(x, 1, sizeof(x), fd1);
	fclose(fd1);

	ptr = x;
	res->ncas=0;
	i=1;

	res->ca_list = NULL;

	do {
		siz2 = _gnutls_fbase64_decode(ptr, siz, &b64);
		siz-=siz2; /* FIXME: this is not enough
			    */

		if (siz2 < 0) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_PARSING_ERROR;
		}
		ptr = strstr( ptr, CERT_SEP)+1;

		res->ca_list =
		    (gnutls_cert *) gnutls_realloc( res->ca_list, i * sizeof(gnutls_cert));
		if (res->ca_list == NULL) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}
		
		tmp.data = b64;
		tmp.size = siz2;
		if ((ret =
		     _gnutls_cert2gnutlsCert(&res->ca_list[i-1], tmp)) < 0) {
			gnutls_assert();
			gnutls_free(b64);
			return ret;
		}
		gnutls_free( b64);

		i++;
	} while( (ptr=strstr( ptr, CERT_SEP))!=NULL);

	res->ncas = i-1;
	return 0;
}


/* Reads a PEM encoded PKCS-1 RSA private key file
 */
static int read_key_file( X509PKI_CREDENTIALS res, char* keyfile) {
int siz, ret;
opaque* b64;
gnutls_datum tmp;
char x[MAX_FILE_SIZE];
FILE* fd2;

	fd2 = fopen(keyfile, "r");
	if (fd2 == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;

/* second file - PKCS-1 private key */

	siz = fread(x, 1, sizeof(x), fd2);
	fclose(fd2);

	siz = _gnutls_fbase64_decode(x, siz, &b64);

	if (siz < 0) {
		gnutls_assert();
		gnutls_free(b64);
		return GNUTLS_E_PARSING_ERROR;
	}

	tmp.data = b64;
	tmp.size = siz;
	if ( (ret =_gnutls_pkcs1key2gnutlsKey(&res->pkey[res->ncerts], tmp)) < 0) {
		gnutls_assert();
		gnutls_free(b64);
		return ret;
	} 

	gnutls_free(b64);

	return 0;
}


/**
  * gnutls_allocate_x509_sc - Used to allocate an x509 SERVER CREDENTIALS structure
  * @res: is a pointer to an &X509PKI_CREDENTIALS structure.
  * @ncerts: this is the number of certificate/private key pair you're going to use.
  * This should be 1 in common sites.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_allocate_x509_sc(X509PKI_CREDENTIALS* res, int ncerts)
{
	*res = gnutls_calloc( 1, sizeof( X509PKI_CREDENTIALS_INT));

	if (*res==NULL) return GNUTLS_E_MEMORY_ERROR;

	(*res)->ncerts=0; /* this is right - set_key() increments it */

	if (ncerts > 0) {
		(*res)->cert_list =
		    (gnutls_cert **) gnutls_malloc( ncerts * sizeof(gnutls_cert *));

		if ( (*res)->cert_list == NULL) {
			gnutls_free(*res);
			return GNUTLS_E_MEMORY_ERROR;
		}

		(*res)->cert_list_length = (int *) gnutls_malloc( ncerts * sizeof(int *));
		if ( (*res)->cert_list_length == NULL) {
			gnutls_free( *res);
			gnutls_free( (*res)->cert_list);
			return GNUTLS_E_MEMORY_ERROR;
		}

		(*res)->pkey = gnutls_malloc( ncerts * sizeof(gnutls_private_key));
		if ( (*res)->pkey == NULL) {
			gnutls_free( *res);
			gnutls_free( (*res)->cert_list);
			gnutls_free( (*res)->cert_list_length);
			return GNUTLS_E_MEMORY_ERROR;
		}

	}
	return 0;
}

/**
  * gnutls_set_x509_key - Used to set keys in a X509PKI_CREDENTIALS structure
  * @res: is an &X509PKI_CREDENTIALS structure.
  * @CERTFILE: is a PEM encoded file containing the certificate list (path) for
  * the specified private key
  * @KEYFILE: is a PEM encoded file containing a private key
  *
  * This function sets a certificate/private key pair in the 
  * X509PKI_CREDENTIALS structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server)
  **/
int gnutls_set_x509_key(X509PKI_CREDENTIALS res, char* CERTFILE, char *KEYFILE)
{
int ret;

	/* this should be first 
	 */
	if ( (ret=read_key_file( res, KEYFILE)) < 0)
		return ret;

	if ( (ret=read_cert_file( res, CERTFILE)) < 0)
		return ret;

	return 0;
}

/**
  * gnutls_set_x509_trust - Used to set trusted CAs in a X509PKI_CREDENTIALS structure
  * @res: is an &X509PKI_CREDENTIALS structure.
  * @CAFILE: is a PEM encoded file containing trusted CAs
  * @CRLFILE: is a PEM encoded file containing CRLs (ignored for now)
  *
  * This function sets the trusted CAs in order to verify client
  * certificates.
  **/
int gnutls_set_x509_trust(X509PKI_CREDENTIALS res, char* CAFILE, char* CRLFILE)
{
int ret;

	if ( (ret=read_ca_file( res, CAFILE)) < 0)
		return ret;

	return 0;
}


static int _read_rsa_params(opaque * der, int dersize, MPI ** params)
{
	opaque str[MAX_X509_CERT_SIZE];
	int len, result;
	node_asn *spk;

	if (asn1_create_structure
	    ( _gnutls_get_pkcs(), "PKCS-1.RSAPublicKey", &spk, "rsa_public_key") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der ( spk, der, dersize);

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

	/* allocate size for the parameters (2) */
	*params = gnutls_calloc(1, 2 * sizeof(MPI));

	if (gcry_mpi_scan(&(*params)[0], GCRYMPI_FMT_USG, str, &len) != 0) {
		gnutls_assert();
		gnutls_free((*params));
		asn1_delete_structure(spk);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	len = sizeof(str) - 1;
	result = asn1_read_value(spk, "rsa_public_key.publicExponent", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		_gnutls_mpi_release(&(*params)[0]);
		gnutls_free((*params));
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}


	if (gcry_mpi_scan(&(*params)[1], GCRYMPI_FMT_USG, str, &len) != 0) {
		gnutls_assert();
		_gnutls_mpi_release(&(*params)[0]);
		gnutls_free((*params));
		asn1_delete_structure(spk);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	asn1_delete_structure(spk);

	return 0;

}

/* res is not malloced 
 */
#define _READ( str, OID, ANAME, NAME, res) \
	if(strcmp(str, OID)==0){ \
	  strcpy( str, "PKIX1Implicit88."); \
	  strcat( str, ANAME); \
	  strcpy( name2, "temp-structure-"); \
	  strcat( name2, NAME); \
	  if ( (result = asn1_create_structure( _gnutls_get_pkix(), str, &tmpasn, name2)) != ASN_OK) { \
	  	gnutls_assert(); \
	  	return GNUTLS_E_ASN1_ERROR; \
	  } \
	  len = sizeof(str) - 1; \
	  if ( (result=asn1_read_value( rasn, name3, str,&len)) != ASN_OK) { \
	  	asn1_delete_structure( tmpasn); \
	  	continue; \
	  } \
      	  if ( (result=asn1_get_der( tmpasn, str, len)) != ASN_OK) { \
	  	asn1_delete_structure( tmpasn); \
	  	continue; \
	  } \
	  strcpy( name3,name2); \
	  len = sizeof(str) - 1; \
	  if ( (result=asn1_read_value( tmpasn, name3, str, &len)) != ASN_OK) {  /* CHOICE */ \
	  	asn1_delete_structure( tmpasn); \
	  	continue; \
	  } \
	  str[len] = 0; \
  	  strcat( name3, "."); \
	  strcat( name3, str); \
	  len = sizeof(str) - 1; \
	  if ( (result=asn1_read_value( tmpasn, name3, str,&len)) != ASN_OK) { \
	  	asn1_delete_structure( tmpasn); \
	  	continue; \
	  } \
	  str[len]=0; \
	  if (strlen(str) < sizeof(res)) strcpy( res, str); \
	  asn1_delete_structure( tmpasn); \
	}


/* this function will convert up to 3 digit
 * numbers to characters.
 */
void _gnutls_int2str(int k, char* data) {
    if (k > 999) data[0] = 0;
    else sprintf( data, "%d", k);
}

/* This function will attempt to read a Name
 * ASN.1 structure. (Taken from Fabio's samples!)
 *
 * FIXME: These functions need carefull auditing
 * --nmav
 */
static int _get_Name_type( node_asn *rasn, char *root, gnutls_DN * dn)
{
	int k, k2, result, len;
	char name[128], str[1024], name2[128], counter[MAX_INT_DIGITS], name3[128];

	k = 0;
	do {
		k++;
		
		strcpy(name, root);
		strcat(name, ".rdnSequence.?");
		_gnutls_int2str(k, counter);
		strcat(name, counter);

		len = sizeof(str) - 1;

		result = asn1_read_value( rasn, name, str, &len);
		
		/* move to next
		 */
		if (result==ASN_ELEMENT_NOT_FOUND) break;

		k2 = 0;
		do {
			k2++;

			strcpy(name2, name);
			strcat(name2, ".?");
			_gnutls_int2str(k2, counter);
			strcat(name2, counter);

			len = sizeof(str) - 1;
			result = asn1_read_value( rasn, name2, str, &len);

			if (result==ASN_ELEMENT_NOT_FOUND) break;

			strcpy(name3, name2);
			strcat(name3, ".type");
			
			len = sizeof(str) - 1;
			result = asn1_read_value( rasn, name3, str, &len);

			if (result==ASN_ELEMENT_NOT_FOUND) break;
			else
				if (result != ASN_OK) {
					gnutls_assert();
					return GNUTLS_E_ASN1_PARSING_ERROR;
				}
			strcpy(name3, name2);
			strcat(name3, ".value");

			if (result == ASN_OK) {
				node_asn *tmpasn;
#ifdef DEBUG
# warning " FIX COUNTRY HERE"
#endif
				_READ(str, "2 5 4 6", "X520OrganizationName",
					"countryName", dn->country);
				_READ(str, "2 5 4 10", "X520OrganizationName",
					"OrganizationName", dn->organization);
				_READ(str, "2 5 4 11", "X520OrganizationalUnitName",
				      "OrganizationalUnitName", dn->organizational_unit_name);
				_READ(str, "2 5 4 3", "X520CommonName", 
					"CommonName", dn->common_name);
				_READ(str, "2 5 4 7", "X520LocalityName",
					"LocalityName", dn->locality_name);
				_READ(str, "2 5 4 8", "X520StateOrProvinceName",
				      "StateOrProvinceName", dn->state_or_province_name);
			}
		} while (1);
	} while (1);

	if (result==ASN_ELEMENT_NOT_FOUND)
		return 0;
	else 
		return GNUTLS_E_ASN1_PARSING_ERROR;
}



#define MAX_TIME 1024
static time_t _gnutls_get_time( node_asn* c2, char* root, char* when) {
opaque ttime[MAX_TIME];
char name[1024];
time_t ctime;
int len, result;

	strcpy(name, root);
	strcat(name, ".tbsCertificate.validity.");
	strcat(name, when);
	
	len = sizeof(ttime) - 1;
	if ((result =
	     asn1_read_value(c2, name, ttime, &len)) < 0) {
		gnutls_assert();
		return (time_t) (-1);
	}

	/* CHOICE */
	strcpy(name, root);

	if (strcmp(ttime, "GeneralizedTime") == 0) {

		strcat(name, ".tbsCertificate.validity.");
		strcat(name, when);
		strcat(name, ".generalTime");
		len = sizeof(ttime) - 1;
		result =
		    asn1_read_value(c2, name, ttime, &len);
		if (result == ASN_OK)
			ctime = _gnutls_generalTime2gtime(ttime);
	} else {		/* UTCTIME */

		strcat(name, ".tbsCertificate.validity.");
		strcat(name, when);
		strcat(name, ".utcTime");
		len = sizeof(ttime) - 1;
		result =
		    asn1_read_value(c2, name, ttime, &len);
		if (result == ASN_OK)
			ctime = _gnutls_utcTime2gtime(ttime);
	}

	if (result!=ASN_OK) {
		gnutls_assert();
		return (time_t) (-1);
	}
	return ctime;
}

static int _gnutls_get_version( node_asn* c2, char* root) {
opaque gversion[2];
char name[1024];
int len, result;

	strcpy(name, root);
	strcat(name, ".tbsCertificate.version");
	
	len = sizeof(gversion) - 1;
	if ((result =
	     asn1_read_value(c2, name, gversion, &len)) < 0) {
		gnutls_assert();
		return (-1);
	}

	return (int) gversion[0]+1;
}

int _gnutls_cert2gnutlsCert(gnutls_cert * gCert, gnutls_datum derCert)
{
	int result;
	node_asn *c2;
	opaque str[MAX_X509_CERT_SIZE];
	int len = sizeof(str);

	gCert->valid = 1;
	
	if (asn1_create_structure( _gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2, "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der( c2, derCert.data, derCert.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
#ifdef DEBUG
		_gnutls_log( "Decoding error %d\n", result);
#endif		
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	len = sizeof(str) - 1;
	result =
	    asn1_read_value
	    (c2, "certificate2.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
	     str, &len);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (strcmp(str, "1 2 840 113549 1 1 1") == 0) {	/* pkix-1 1 - RSA */
		/* params[0] is the modulus,
		 * params[1] is the exponent
		 */
		gCert->subject_pk_algorithm = GNUTLS_PK_RSA;

		len = sizeof(str) - 1;
		result =
		    asn1_read_value
		    (c2, "certificate2.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
		     str, &len);

		if (result != ASN_OK) {
			gnutls_assert();
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		if ((result =
		     _read_rsa_params(str, len / 8, &gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}

	} else {
		/* other types like DH, DSA
		 * currently not supported
		 */
		gnutls_assert();
#ifdef DEBUG
_gnutls_log( "ALGORITHM: %s\n", str);
return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
		gCert->subject_pk_algorithm = GNUTLS_PK_UNKNOWN;
		gCert->params = NULL;
		
	}

	len = sizeof( gCert->signature);
	result =
	    asn1_read_value
		    (c2, "certificate2.signature",
		     gCert->signature, &len);

	if ((len % 8) !=0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;		
	}
	len /= 8; /* convert to bytes */
	gCert->signature_size = len;


	memset( &gCert->cert_info, 0, sizeof(gCert->cert_info));
	memset( &gCert->issuer_info, 0, sizeof(gCert->issuer_info));

	if ((result =
	     _get_Name_type( c2, "certificate2.tbsCertificate.subject", &gCert->cert_info)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}

	if ((result =
	     _gnutls_get_ext_type( c2, "certificate2.tbsCertificate.extensions", gCert)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}

	if ((result =
	     _get_Name_type( c2, "certificate2.tbsCertificate.issuer", &gCert->issuer_info)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}


	gCert->expiration_time = _gnutls_get_time( c2, "certificate2", "notAfter");
	gCert->activation_time = _gnutls_get_time( c2, "certificate2", "notBefore");

	gCert->version = _gnutls_get_version( c2, "certificate2");
	
	asn1_delete_structure(c2);

	if (gnutls_set_datum( &gCert->raw, derCert.data, derCert.size) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	gCert->valid = 0; /* if we got until here
	                   * the certificate is valid.
	                   */

	return 0;

}

/* returns the KX algorithms that are supported by a
 * certificate. (Eg a certificate with RSA params, supports
 * GNUTLS_KX_RSA algorithm).
 */
int _gnutls_cert_supported_kx(gnutls_cert * cert, KXAlgorithm ** alg,
			      int *alg_size)
{
	KXAlgorithm kx;
	int i;
	PKAlgorithm pk;
	KXAlgorithm kxlist[255];

	i = 0;
	for (kx = 0; kx < 255; kx++) {
		pk = _gnutls_map_pk_get_pk(kx);
		if (pk == cert->subject_pk_algorithm) {
			kxlist[i] = kx;
			i++;
		}
	}

	*alg = gnutls_calloc(1, sizeof(KXAlgorithm) * i);
	if (*alg == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	*alg_size = i;

	memcpy(*alg, kxlist, i*sizeof(KXAlgorithm));

	return 0;
}

/* finds a certificate in the cert list that contains
 * common_name (or subjectAltName) field similar to name
 */
gnutls_cert *_gnutls_find_cert(gnutls_cert ** cert_list,
			       int cert_list_length, char *name)
{
	gnutls_cert *cert = NULL;
	int i;

	for (i = 0; i < cert_list_length; i++) {
		if (cert_list[i][0].cert_info.common_name[0] != 0) {
			if (strcasecmp(cert_list[i][0].cert_info.common_name, name) == 0 || strcasecmp(cert_list[i][0].subjectAltName, name) == 0) {
				cert = &cert_list[i][0];
				break;
			}
		}
	}
	return cert;
}
