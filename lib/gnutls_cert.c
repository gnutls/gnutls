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
#include <cert_b64.h>
#include <auth_x509.h>
#include <gnutls_cert.h>
#include <cert_asn1.h>
#include <cert_der.h>
#include <gnutls_datum.h>
#include <gnutls_gcry.h>
#include <gnutls_privkey.h>

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
	
	GNUTLS_FREE( cert.common_name);
	GNUTLS_FREE( cert.country);
	GNUTLS_FREE( cert.organization);
	GNUTLS_FREE( cert.organizational_unit_name);
	GNUTLS_FREE( cert.locality_name);
	GNUTLS_FREE( cert.state_or_province_name);

	gnutls_free_datum( &cert.raw);

	return;
}

/**
  * gnutls_free_x509_sc - Used to free an allocated x509 SERVER CREDENTIALS structure
  * @sc: is an &X509PKI_SERVER_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_free_x509_sc( X509PKI_SERVER_CREDENTIALS sc) {
int i,j;

	for (i=0;i<sc.ncerts;i++) {
		for (j=0;j<sc.cert_list_length[i];j++) {
			gnutls_free_cert( sc.cert_list[i][j]);
		}
		gnutls_free( sc.cert_list[i]);
	}
	gnutls_free( sc.cert_list );
	for (i=0;i<sc.ncerts;i++) {
		_gnutls_free_private_key( sc.pkey[i]);
	}
	gnutls_free(sc.pkey);
}

/* FIXME: this function is a mess 
 */
/**
  * gnutls_allocate_x509_sc - Used to allocate an x509 SERVER CREDENTIALS structure
  * @res: is a pointer to an &X509PKI_SERVER_CREDENTIALS structure.
  * @CERTFILE: is the name of a PEM encoded certificate file
  * @KEYFILE: is the name of a PEM encoded key file
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure from the given keys.
  * FIXME: does not support multiple keys yet.
  **/
int gnutls_allocate_x509_sc(X509PKI_SERVER_CREDENTIALS * res, char *CERTFILE,
		      char *KEYFILE)
{
	FILE *fd1, *fd2;
	char x[100 * 1024];
	int siz, ret;
	opaque *b64;
	gnutls_datum tmp;

	fd1 = fopen(CERTFILE, "r");
	if (fd1 == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;

	fd2 = fopen(KEYFILE, "r");
	if (fd2 == NULL) {
		fclose(fd1);
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	siz = fread(x, 1, sizeof(x), fd1);
	siz = _gnutls_fbase64_decode(x, siz, &b64);

	if (siz < 0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	res->cert_list =
	    (gnutls_cert **) gnutls_malloc(1 * sizeof(gnutls_cert *));
	if (res->cert_list == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	res->cert_list[0] =
	    (gnutls_cert *) gnutls_malloc(1 * sizeof(gnutls_cert));
	if (res->cert_list[0] == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	res->cert_list_length = (int *) gnutls_malloc(1 * sizeof(int *));
	if (res->cert_list_length == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	res->ncerts = 1;

	res->cert_list_length[0] = 1;

	fclose(fd1);

	tmp.data = b64;
	tmp.size = siz;
	if ((ret =
	     _gnutls_cert2gnutlsCert(&res->cert_list[0][0], tmp)) < 0) {
		gnutls_assert();
		return ret;
	}

/* second file - PKCS-1 private key */

	siz = fread(x, 1, sizeof(x), fd2);
	fclose(fd2);

	siz = _gnutls_fbase64_decode(x, siz, &b64);

	if (siz < 0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	res->pkey = gnutls_malloc(1 * sizeof(gnutls_private_key));
	if (res->pkey == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	tmp.data = b64;
	tmp.size = siz;
	if ( (ret =_gnutls_pkcs1key2gnutlsKey(&res->pkey[0], tmp)) < 0) {
		gnutls_assert();
		return ret;
	} 


	return 0;
}


static int _read_rsa_params(opaque * der, int dersize, MPI ** params)
{
	opaque str[5 * 1024];
	int len, result;

	if (create_structure
	    ("rsa_public_key", "PKIX1Explicit88.RSAPublicKey") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = get_der("rsa_public_key", der, dersize);

	if (result != ASN_OK) {
		gnutls_assert();
		delete_structure("rsa_public_key");
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	len = sizeof(str);
	result = read_value("rsa_public_key.modulus", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		delete_structure("rsa_public_key");
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	/* allocate size for the parameters (2) */
	*params = gnutls_calloc(1, 2 * sizeof(MPI));

	if (gcry_mpi_scan(&(*params)[0], GCRYMPI_FMT_USG, str, &len) != 0) {
		gnutls_assert();
		gnutls_free((*params));
		delete_structure("rsa_public_key");
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	len = sizeof(str);
	result = read_value("rsa_public_key.publicExponent", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		_gnutls_mpi_release(&(*params)[0]);
		gnutls_free((*params));
		delete_structure("rsa_public_key");
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}


	if (gcry_mpi_scan(&(*params)[1], GCRYMPI_FMT_USG, str, &len) != 0) {
		gnutls_assert();
		_gnutls_mpi_release(&(*params)[0]);
		gnutls_free((*params));
		delete_structure("rsa_public_key");
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	delete_structure("rsa_public_key");

	return 0;

}



#define _READ( str, OID, NAME, res) \
	if(strcmp(str, OID)==0){ \
	  strcpy( str, "PKIX1Explicit88.X520"); \
	  strcat( str, NAME); \
	  strcpy( name2, "temp-structure-"); \
	  strcat( name2, NAME); \
	  if ( (result = create_structure( name2, str)) != ASN_OK) { \
	  	gnutls_assert(); \
	  	return GNUTLS_E_ASN1_ERROR; \
	  } \
	  len = sizeof(str); \
	  if (read_value(name3,str,&len) != ASN_OK) { \
	  	delete_structure( name2); \
	  	continue; \
	  } \
      	  if (get_der( name2, str, len) != ASN_OK) { \
	  	delete_structure( name2); \
	  	continue; \
	  } \
	  strcpy( name3,name2); \
	  len = sizeof(str); \
	  if (read_value( name3, str, &len) != ASN_OK) {  /* CHOICE */ \
	  	delete_structure( name2); \
	  	continue; \
	  } \
  	  strcat( name3, "."); \
	  strcat( name3, str); \
	  len = sizeof(str) - 1; \
	  if (read_value(name3,str,&len) != ASN_OK) { \
	  	delete_structure( name2); \
	  	continue; \
	  } \
	  str[len]=0; \
	  res = strdup(str); \
	  delete_structure(name2); \
	}


/* This function will attempt to read a Name
 * ASN.1 structure. (Taken from Fabio's samples!)
 * --nmav
 */
static int _get_Name_type(char *root, gnutls_cert * gCert)
{
	int k, k2, result, len;
	char name[128], str[1024], name2[128], counter[5], name3[128];

	k = 1;
	do {
		strcpy(name, root);
		strcat(name, ".rdnSequence.?");
		ltostr(k, counter);
		strcat(name, counter);

		len = sizeof(str);
		result = read_value(name, str, &len);
		if (result == ASN_ELEMENT_NOT_FOUND)
			break;
		k2 = 1;
		do {
			strcpy(name2, name);
			strcat(name2, ".?");
			ltostr(k2, counter);
			strcat(name2, counter);

			len = sizeof(str);
			result = read_value(name2, str, &len);
			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			strcpy(name3, name2);
			strcat(name3, ".type");
			
			len = sizeof(str);
			result = read_value(name3, str, &len);

			if (result != ASN_OK) {
				gnutls_assert();
				return GNUTLS_E_ASN1_PARSING_ERROR;
			}
			strcpy(name3, name2);
			strcat(name3, ".value");

			if (result == ASN_OK) {
/*				_READ(str, "2 5 4 6", "countryName",
 *				      gCert->country);
 * This one fails (with SIGSEGV).
 */
				_READ(str, "2 5 4 10", "OrganizationName",
				      gCert->organization);
				_READ(str, "2 5 4 11",
				      "OrganizationalUnitName",
				      gCert->organizational_unit_name);
				_READ(str, "2 5 4 3", "CommonName",
				      gCert->common_name);
				_READ(str, "2 5 4 7", "LocalityName",
				      gCert->locality_name);
				_READ(str, "2 5 4 8",
				      "StateOrProvinceName",
				      gCert->state_or_province_name);
			}
			k2++;
		} while (1);
		k++;
	} while (1);
	return 0;
}


int _gnutls_cert2gnutlsCert(gnutls_cert * gCert, gnutls_datum derCert)
{
	int result;
	opaque str[5 * 1024];
	int len = sizeof(str);

	if (create_structure("certificate3", "PKIX1Explicit88.Certificate")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = get_der("certificate3", derCert.data, derCert.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}


	len = sizeof(str);
	result =
	    read_value
	    ("certificate3.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
	     str, &len);

	if (result != ASN_OK) {
		gnutls_assert();
		delete_structure("certificate3");
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if (strcmp(str, "1 2 840 113549 1 1 1") == 0) {	/* pkix-1 1 - RSA */
		/* params[0] is the modulus,
		 * params[1] is the exponent
		 */
		gCert->subject_pk_algorithm = GNUTLS_PK_RSA;

		len = sizeof(str);
		result =
		    read_value
		    ("certificate3.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
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
		delete_structure("certificate3");

		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	/* Try to read the name 
	 * We need a special function for that ()
	 */
	gCert->country = NULL;
	gCert->common_name = NULL;
	gCert->organization = NULL;
	gCert->organizational_unit_name = NULL;
	gCert->locality_name = NULL;
	gCert->state_or_province_name = NULL;
	if ((result =
	     _get_Name_type("certificate3.tbsCertificate.subject",
			    gCert)) < 0) {
		gnutls_assert();
		delete_structure("certificate3");
		return result;
	}

	delete_structure("certificate3");

	if (gnutls_set_datum(&gCert->raw, derCert.data, derCert.size) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

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
 * common_name field similar to name
 */
gnutls_cert *_gnutls_find_cert(gnutls_cert ** cert_list,
			       int cert_list_length, char *name)
{
	gnutls_cert *cert = NULL;
	int i;

	for (i = 0; i < cert_list_length; i++) {
		if (cert_list[i][0].common_name != NULL) {
			if (strcmp(cert_list[i][0].common_name, name) == 0) {
				cert = &cert_list[i][0];
				break;
			}
		}
	}
	return cert;
}
