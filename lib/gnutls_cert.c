/*
 *      Copyright (C) 2001,2002 Nikos Mavroyanopoulos
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
#include <gnutls_algorithms.h>
#include <gnutls_dh.h>
#include <gnutls_str.h>

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
	{GNUTLS_KX_DHE_RSA, GNUTLS_PK_RSA},
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

void gnutls_free_cert(gnutls_cert cert)
{
	int n, i;

	switch (cert.subject_pk_algorithm) {
	case GNUTLS_PK_RSA:
		n = 2;		/* the number of parameters in MPI* */
		break;
	default:
		n = 0;
	}

	for (i = 0; i < n; i++) {
		_gnutls_mpi_release(&cert.params[i]);
	}

	gnutls_free_datum(&cert.raw);

	return;
}

/**
  * gnutls_x509pki_free_sc - Used to free an allocated x509 SERVER CREDENTIALS structure
  * @sc: is an &GNUTLS_X509PKI_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_x509pki_free_sc(GNUTLS_X509PKI_CREDENTIALS sc)
{
	int i, j;

	for (i = 0; i < sc->ncerts; i++) {
		for (j = 0; j < sc->cert_list_length[i]; j++) {
			gnutls_free_cert(sc->cert_list[i][j]);
		}
		gnutls_free(sc->cert_list[i]);
	}

	gnutls_free(sc->cert_list_length);
	gnutls_free(sc->cert_list);

	for (j = 0; j < sc->ncas; j++) {
		gnutls_free_cert(sc->ca_list[j]);
	}

	gnutls_free(sc->ca_list);

	for (i = 0; i < sc->ncerts; i++) {
		_gnutls_free_private_key(sc->pkey[i]);
	}

	gnutls_free(sc->pkey);
	gnutls_free(sc->rdn_sequence.data);

	gnutls_free(sc);
}

#define MAX_FILE_SIZE 100*1024
#define CERT_SEP "-----BEGIN"

/* Reads a base64 encoded certificate from memory
 */
static int read_cert_mem(GNUTLS_X509PKI_CREDENTIALS res, const char *cert, int cert_size)
{
	int siz, i, siz2;
	opaque *b64;
	const char *ptr;
	gnutls_datum tmp;
	int ret;

	ptr = cert;
	siz = cert_size;
	i = 1;

	res->cert_list[res->ncerts] = NULL;

	do {
		siz2 = _gnutls_fbase64_decode(ptr, siz, &b64);
		siz -= siz2;	/* FIXME: this is not enough
				 */

		if (siz2 < 0) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_PARSING_ERROR;
		}
		ptr = strstr(ptr, CERT_SEP) + 1;

		res->cert_list[res->ncerts] =
		    (gnutls_cert *) gnutls_realloc(res->
						   cert_list[res->ncerts],
						   i *
						   sizeof(gnutls_cert));

		if (res->cert_list[res->ncerts] == NULL) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}
		/* set defaults to zero 
		 */
		memset(&res->cert_list[res->ncerts][i - 1], 0,
		       sizeof(gnutls_cert));

		tmp.data = b64;
		tmp.size = siz2;
		if ((ret =
		     _gnutls_cert2gnutlsCert(&res->
					     cert_list[res->ncerts][i - 1],
					     tmp)) < 0) {
			gnutls_free(b64);
			gnutls_assert();
			return ret;
		}
		gnutls_free(b64);

		i++;
	} while ((ptr = strstr(ptr, CERT_SEP)) != NULL);

	res->cert_list_length[res->ncerts] = i - 1;

	/* WE DO NOT CATCH OVERRUNS in gnutls_x509pki_set_key().
	 * This function should be called as many times as specified 
	 * in x509pki_allocate_sc().
	 */
	res->ncerts++;

	return 0;
}

/* Reads a base64 encoded CA list from memory 
 * This is to be called once.
 */
static int read_ca_mem(GNUTLS_X509PKI_CREDENTIALS res, const char *ca, int ca_size)
{
	int siz, siz2, i;
	opaque *b64;
	const char *ptr;
	int ret;
	gnutls_datum tmp;

	siz = ca_size;

	ptr = ca;

	i = res->ncas + 1;

	do {
		siz2 = _gnutls_fbase64_decode(ptr, siz, &b64);
		siz -= siz2;	/* FIXME: this is not enough
				 */

		if (siz2 < 0) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_PARSING_ERROR;
		}
		ptr = strstr(ptr, CERT_SEP) + 1;

		res->ca_list =
		    (gnutls_cert *) gnutls_realloc(res->ca_list,
						   i *
						   sizeof(gnutls_cert));
		if (res->ca_list == NULL) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}
		memset(&res->ca_list[i - 1], 0, sizeof(gnutls_cert));

		tmp.data = b64;
		tmp.size = siz2;
		if ((ret =
		     _gnutls_cert2gnutlsCert(&res->ca_list[i - 1],
					     tmp)) < 0) {
			gnutls_assert();
			gnutls_free(b64);
			return ret;
		}
		gnutls_free(b64);

		i++;
	} while ((ptr = strstr(ptr, CERT_SEP)) != NULL);

	res->ncas = i - 1;



	return 0;
}


/* Reads a PEM encoded PKCS-1 RSA private key from memory
 * 2002-01-26: Added ability to read DSA keys.
 */
static int read_key_mem(GNUTLS_X509PKI_CREDENTIALS res, const char *key, int key_size)
{
	int siz, ret;
	opaque *b64;
	gnutls_datum tmp;
	PKAlgorithm pk;

	/* read PKCS-1 private key */
	siz = key_size;

	
	/* If we find the "DSA PRIVATE" string in the
	 * pem encoded certificate then it's a DSA key.
	 */
	if (strstr( key, "DSA PRIVATE")!=NULL) 
		pk = GNUTLS_PK_DSA;
	else
		pk = GNUTLS_PK_RSA;

	siz = _gnutls_fbase64_decode(key, siz, &b64);

	if (siz < 0) {
		gnutls_assert();
		gnutls_free(b64);
		return GNUTLS_E_PARSING_ERROR;
	}

	tmp.data = b64;
	tmp.size = siz;
	
	switch (pk) { /* decode the key */
		case GNUTLS_PK_RSA:
			if ((ret =
			     _gnutls_PKCS1key2gnutlsKey(&res->pkey[res->ncerts],
							tmp)) < 0) {
				gnutls_assert();
				gnutls_free(b64);
				return ret;
			}
			break;
		case GNUTLS_PK_DSA:
			if ((ret =
			     _gnutls_DSAkey2gnutlsKey(&res->pkey[res->ncerts],
							tmp)) < 0) {
				gnutls_assert();
				gnutls_free(b64);
				return ret;
			}
			break;	
	}
	gnutls_free(b64);

	return 0;
}

/* Reads a base64 encoded certificate file
 */
static int read_cert_file(GNUTLS_X509PKI_CREDENTIALS res, char *certfile)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(certfile, "r");
	if (fd1 == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;

	siz = fread(x, 1, sizeof(x), fd1);
	fclose(fd1);

	return read_cert_mem( res, x, siz);

}

/* Reads a base64 encoded CA file (file contains multiple certificate
 * authorities). This is to be called once.
 */
static int read_ca_file(GNUTLS_X509PKI_CREDENTIALS res, char *cafile)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(cafile, "r");
	if (fd1 == NULL) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	siz = fread(x, 1, sizeof(x), fd1);
	fclose(fd1);

	return read_ca_mem( res, x, siz);
}


/* Reads a PEM encoded PKCS-1 RSA private key file
 */
static int read_key_file(GNUTLS_X509PKI_CREDENTIALS res, char *keyfile)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd2;

	fd2 = fopen(keyfile, "r");
	if (fd2 == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;

	siz = fread(x, 1, sizeof(x), fd2);
	fclose(fd2);

	return read_key_mem( res, x, siz);
}

/**
  * gnutls_x509pki_allocate_sc - Used to allocate an x509 SERVER CREDENTIALS structure
  * @res: is a pointer to an &GNUTLS_X509PKI_CREDENTIALS structure.
  * @ncerts: this is the number of certificate/private key pair you're going to use.
  * This should be 1 in common sites.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_x509pki_allocate_sc(GNUTLS_X509PKI_CREDENTIALS * res, int ncerts)
{
	*res = gnutls_calloc(1, sizeof(X509PKI_CREDENTIALS_INT));

	if (*res == NULL)
		return GNUTLS_E_MEMORY_ERROR;


	(*res)->ncerts = 0;	/* this is right - set_key() increments it */

	if (ncerts > 0) {
		(*res)->cert_list =
		    (gnutls_cert **) gnutls_malloc(ncerts *
						   sizeof(gnutls_cert *));

		if ((*res)->cert_list == NULL) {
			gnutls_free(*res);
			return GNUTLS_E_MEMORY_ERROR;
		}

		(*res)->cert_list_length =
		    (int *) gnutls_malloc(ncerts * sizeof(int *));
		if ((*res)->cert_list_length == NULL) {
			gnutls_free(*res);
			gnutls_free((*res)->cert_list);
			return GNUTLS_E_MEMORY_ERROR;
		}

		(*res)->pkey =
		    gnutls_malloc(ncerts * sizeof(gnutls_private_key));
		if ((*res)->pkey == NULL) {
			gnutls_free(*res);
			gnutls_free((*res)->cert_list);
			gnutls_free((*res)->cert_list_length);
			return GNUTLS_E_MEMORY_ERROR;
		}

	}
	return 0;
}

/* returns error if the certificate has different algorithm than
 * the given key parameters.
 */
static int _gnutls_check_key_cert_match( GNUTLS_X509PKI_CREDENTIALS res) {
	if (res->pkey->pk_algorithm != res->cert_list[0]->subject_pk_algorithm) {
		gnutls_assert();
		return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
	}
	return 0;
}


/**
  * gnutls_x509pki_set_key_file - Used to set keys in a GNUTLS_X509PKI_CREDENTIALS structure
  * @res: is an &GNUTLS_X509PKI_CREDENTIALS structure.
  * @CERTFILE: is a PEM encoded file containing the certificate list (path) for
  * the specified private key
  * @KEYFILE: is a PEM encoded file containing a private key
  *
  * This function sets a certificate/private key pair in the 
  * GNUTLS_X509PKI_CREDENTIALS structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently only PKCS-1 PEM encoded RSA and DSA private keys are accepted by
  * this function.
  *
  **/
int gnutls_x509pki_set_key_file(GNUTLS_X509PKI_CREDENTIALS res, char *CERTFILE,
			   char *KEYFILE)
{
	int ret;

	/* this should be first 
	 */
	if ((ret = read_key_file(res, KEYFILE)) < 0)
		return ret;

	if ((ret = read_cert_file(res, CERTFILE)) < 0)
		return ret;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

static int generate_rdn_seq( GNUTLS_X509PKI_CREDENTIALS res) {
gnutls_datum tmp;
int ret, size, i;
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
	for (i = 0; i < res->ncas; i++) {
		if ((ret = _gnutls_find_dn(&tmp, &res->ca_list[i])) < 0) {
			gnutls_assert();
			return ret;
		}
		size += (2 + tmp.size);
	}

	if (res->rdn_sequence.data != NULL)
		gnutls_free( res->rdn_sequence.data);

	res->rdn_sequence.data = gnutls_malloc(size);
	if (res->rdn_sequence.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	res->rdn_sequence.size = size;

	pdata = res->rdn_sequence.data;

	for (i = 0; i < res->ncas; i++) {
		if ((ret = _gnutls_find_dn(&tmp, &res->ca_list[i])) < 0) {
			gnutls_free(res->rdn_sequence.data);
			res->rdn_sequence.size = 0;
			res->rdn_sequence.data = NULL;
			gnutls_assert();
			return ret;
		}
		WRITEdatum16(pdata, tmp);
		pdata += (2 + tmp.size);
	}

	return 0;
}

/**
  * gnutls_x509pki_set_trust_mem - Used to add trusted CAs in a GNUTLS_X509PKI_CREDENTIALS structure
  * @res: is an &GNUTLS_X509PKI_CREDENTIALS structure.
  * @CA: is a PEM encoded list of trusted CAs
  * @CRL: is a PEM encoded list of CRLs (ignored for now)
  *
  * This function adds the trusted CAs in order to verify client
  * certificates. This function may be called multiple times.
  *
  **/
int gnutls_x509pki_set_trust_mem(GNUTLS_X509PKI_CREDENTIALS res, const gnutls_datum *CA,
			     const gnutls_datum *CRL)
{
	int ret;

	if ((ret = read_ca_mem(res, CA->data, CA->size)) < 0)
		return ret;

	if ((ret = generate_rdn_seq(res)) < 0)
		return ret;

	return 0;
}

/**
  * gnutls_x509pki_set_trust_file - Used to add trusted CAs in a GNUTLS_X509PKI_CREDENTIALS structure
  * @res: is an &GNUTLS_X509PKI_CREDENTIALS structure.
  * @CAFILE: is a PEM encoded file containing trusted CAs
  * @CRLFILE: is a PEM encoded file containing CRLs (ignored for now)
  *
  * This function sets the trusted CAs in order to verify client
  * certificates. This function may be called multiple times.
  *
  **/
int gnutls_x509pki_set_trust_file(GNUTLS_X509PKI_CREDENTIALS res, char *CAFILE,
			     char *CRLFILE)
{
	int ret;

	if ((ret = read_ca_file(res, CAFILE)) < 0)
		return ret;

	if ((ret = generate_rdn_seq(res)) < 0)
		return ret;

	return 0;
}


/**
  * gnutls_x509pki_set_key_mem - Used to set keys in a GNUTLS_X509PKI_CREDENTIALS structure
  * @res: is an &GNUTLS_X509PKI_CREDENTIALS structure.
  * @CERT: contains a PEM encoded certificate list (path) for
  * the specified private key
  * @KEY: is a PEM encoded private key
  *
  * This function sets a certificate/private key pair in the 
  * GNUTLS_X509PKI_CREDENTIALS structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently only PKCS-1 PEM encoded RSA private keys are accepted by
  * this function.
  *
  **/
int gnutls_x509pki_set_key_mem(GNUTLS_X509PKI_CREDENTIALS res, const gnutls_datum* CERT,
			   const gnutls_datum* KEY)
{
	int ret;

	/* this should be first 
	 */
	if ((ret = read_key_mem( res, KEY->data, KEY->size)) < 0)
		return ret;

	if ((ret = read_cert_mem( res, CERT->data, CERT->size)) < 0)
		return ret;

	if ((ret=_gnutls_check_key_cert_match( res)) < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}


static int _read_rsa_params(opaque * der, int dersize, MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	node_asn *spk;

	if (asn1_create_structure
	    (_gnutls_get_gnutls_asn(), "GNUTLS.RSAPublicKey", &spk,
	     "rsa_public_key") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(spk, der, dersize);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}


	if ( (result=_gnutls_x509_read_int( spk, "rsa_public_key.modulus", 
		str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if ( (result=_gnutls_x509_read_int( spk, "rsa_public_key.publicExponent", 
		str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&params[0]);
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	asn1_delete_structure(spk);

	return 0;

}


/* reads p,q and g 
 * from the certificate 
 * params[0-2]
 */
static int _read_dsa_params(opaque * der, int dersize, MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	node_asn *spk;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Dss-Parms", &spk,
	     "dsa_parms") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(spk, der, dersize);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	/* FIXME: If the parameters are not included in the certificate
	 * then the issuer's parameters should be used.
	 */

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.p", str, sizeof(str)-1, &params[0])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	/* Read q */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.q", str, sizeof(str)-1, &params[1])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		_gnutls_mpi_release(&params[0]);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	/* Read g */
	
	if ( (result=_gnutls_x509_read_int( spk, "dsa_parms.g", str, sizeof(str)-1, &params[2])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		_gnutls_mpi_release(&params[0]);
		_gnutls_mpi_release(&params[1]);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	asn1_delete_structure(spk);

	return 0;

}

/* reads DSA's Y
 * from the certificate 
 * params[3]
 */
static int _read_dsa_pubkey(opaque * der, int dersize, MPI * params)
{
	opaque str[MAX_PARAMETER_SIZE];
	int result;
	node_asn *spk;

	if ( (result=asn1_create_structure
	    (_gnutls_get_gnutls_asn(), "GNUTLS.DSAPublicKey", &spk,
	     "dsa_public_key")) != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(spk, der, dersize);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	/* Read p */

	if ( (result=_gnutls_x509_read_int( spk, "dsa_public_key", str, sizeof(str)-1, &params[3])) < 0) {
		gnutls_assert();
		asn1_delete_structure(spk);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	asn1_delete_structure(spk);

	return 0;

}


#define _READ(a, aa, b, c, d, e, res, f) \
	result = _IREAD(a, aa, sizeof(aa), b, c, d, e, res, sizeof(res)-1, f); \
	if (result<0) return result; \
	if (result==1) continue


int _IREAD(node_asn * rasn, char *name3, int name3_size, char *rstr, char *OID,
	   char *ANAME, char *TYPE, char *res, int res_size, int CHOICE)
{
	char name2[256];
	int result, len;
	char str[1024];
	node_asn *tmpasn;

	if (strcmp(rstr, OID) == 0) {

		_gnutls_str_cpy(str, sizeof(str), "PKIX1Implicit88."); 
		_gnutls_str_cat(str, sizeof(str), ANAME); 
		_gnutls_str_cpy(name2, sizeof(name2), "temp-structure-"); 
		_gnutls_str_cat(name2, sizeof(name2), TYPE); 

		if ((result =
		     asn1_create_structure(_gnutls_get_pkix(), str,
					   &tmpasn, name2)) != ASN_OK) {
			gnutls_assert();
			return GNUTLS_E_ASN1_ERROR;
		}

		len = sizeof(str) -1;
		if ((result =
		     asn1_read_value(rasn, name3, str, &len)) != ASN_OK) {
			asn1_delete_structure(tmpasn);
			return 1;
		}

		if ((result = asn1_get_der(tmpasn, str, len)) != ASN_OK) {
			asn1_delete_structure(tmpasn);
			return 1;
		}
		_gnutls_str_cpy(name3, name3_size, name2);

		len = sizeof(str) - 1;
		if ((result = asn1_read_value(tmpasn, name3, str, &len)) != ASN_OK) {	/* CHOICE */
			asn1_delete_structure(tmpasn);
			return 1;
		}

		if (CHOICE == 0) {
			str[len] = 0;
			/* strlen(str) < res_size, checked above */
			_gnutls_str_cpy(res, res_size, str); 
			
		} else {	/* CHOICE */
			str[len] = 0;
			_gnutls_str_cat(name3, name3_size, "."); 
			_gnutls_str_cat(name3, name3_size, str); 
			len = sizeof(str) - 1;

			if ((result =
			     asn1_read_value(tmpasn, name3, str,
					     &len)) != ASN_OK) {
				asn1_delete_structure(tmpasn);
				return 1;
			}
			str[len] = 0;
			if ( len < res_size)
				_gnutls_str_cpy(res, res_size, str); 
		}
		asn1_delete_structure(tmpasn);

	}
	return 0;
}

/* this function will convert up to 3 digit
 * numbers to characters.
 */
void _gnutls_int2str(int k, char *data)
{
	if (k > 999)
		data[0] = 0;
	else
		sprintf(data, "%d", k); 
}

/* This function will attempt to read a Name
 * ASN.1 structure. (Taken from Fabio's samples!)
 *
 * FIXME: These functions need carefull auditing
 * (they're complex enough)
 * --nmav
 */
int _gnutls_get_name_type(node_asn * rasn, char *root, gnutls_DN * dn)
{
	int k, k2, result, len;
	char name[128], str[1024], name2[128], counter[MAX_INT_DIGITS],
	    name3[128];

	k = 0;
	do {
		k++;

		_gnutls_str_cpy(name, sizeof(name), root); 
		_gnutls_str_cat(name, sizeof(name), ".rdnSequence.?"); 
		_gnutls_int2str(k, counter);
		_gnutls_str_cat(name, sizeof(name), counter); 

		len = sizeof(str) - 1;

		result = asn1_read_value(rasn, name, str, &len);

		/* move to next
		 */
		if (result == ASN_ELEMENT_NOT_FOUND)
			break;
		if (result != ASN_VALUE_NOT_FOUND) {
			gnutls_assert();
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		k2 = 0;
		do {
			k2++;

			_gnutls_str_cpy(name2, sizeof(name2), name); 
			_gnutls_str_cat(name2, sizeof(name2), ".?"); 
			_gnutls_int2str(k2, counter);
			_gnutls_str_cat(name2, sizeof(name2), counter); 

			len = sizeof(str) - 1;
			result = asn1_read_value(rasn, name2, str, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			if (result != ASN_VALUE_NOT_FOUND) {
				gnutls_assert();
				return GNUTLS_E_ASN1_PARSING_ERROR;
			}

			_gnutls_str_cpy(name3, sizeof(name3), name2);
			_gnutls_str_cat(name3, sizeof(name3), ".type"); 

			len = sizeof(str) - 1;
			result = asn1_read_value(rasn, name3, str, &len);

			if (result == ASN_ELEMENT_NOT_FOUND)
				break;
			else if (result != ASN_OK) {
				gnutls_assert();
				return GNUTLS_E_ASN1_PARSING_ERROR;
			}

			_gnutls_str_cpy(name3, sizeof(name3), name2);
			_gnutls_str_cat(name3, sizeof(name3), ".value"); 

			if (result == ASN_OK) {
#ifdef DEBUG
# warning " FIX COUNTRY HERE"
#endif
				_READ(rasn, name3, str, "2 5 4 6",
				      "X520OrganizationName",
				      "countryName", dn->country, 1);
				_READ(rasn, name3, str, "2 5 4 10",
				      "X520OrganizationName",
				      "OrganizationName", dn->organization,
				      1);
				_READ(rasn, name3, str, "2 5 4 11",
				      "X520OrganizationalUnitName",
				      "OrganizationalUnitName",
				      dn->organizational_unit_name, 1);
				_READ(rasn, name3, str, "2 5 4 3",
				      "X520CommonName", "CommonName",
				      dn->common_name, 1);
				_READ(rasn, name3, str, "2 5 4 7",
				      "X520LocalityName", "LocalityName",
				      dn->locality_name, 1);
				_READ(rasn, name3, str, "2 5 4 8",
				      "X520StateOrProvinceName",
				      "StateOrProvinceName",
				      dn->state_or_province_name, 1);
				_READ(rasn, name3, str,
				      "1 2 840 113549 1 9 1", "Pkcs9email",
				      "emailAddress", dn->email, 0);
			}
		} while (1);
	} while (1);

	if (result == ASN_ELEMENT_NOT_FOUND)
		return 0;
	else
		return GNUTLS_E_ASN1_PARSING_ERROR;
}



#define MAX_TIME 1024
time_t _gnutls_get_time(node_asn * c2, char *root, char *when)
{
	opaque ttime[MAX_TIME];
	char name[1024];
	time_t ctime;
	int len, result;

	_gnutls_str_cpy(name, sizeof(name), root);
	_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.validity."); 
	_gnutls_str_cat(name, sizeof(name), when);

	len = sizeof(ttime) - 1;
	if ((result = asn1_read_value(c2, name, ttime, &len)) < 0) {
		gnutls_assert();
		return (time_t) (-1);
	}

	/* CHOICE */
	_gnutls_str_cpy(name, sizeof(name), root);

	if (strcmp(ttime, "GeneralizedTime") == 0) {

		_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.validity."); 
		_gnutls_str_cat(name, sizeof(name), when);
		_gnutls_str_cat(name, sizeof(name), ".generalTime"); 
		len = sizeof(ttime) - 1;
		result = asn1_read_value(c2, name, ttime, &len);
		if (result == ASN_OK)
			ctime = _gnutls_generalTime2gtime(ttime);
	} else {		/* UTCTIME */

		_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.validity."); 
		_gnutls_str_cat(name, sizeof(name), when);
		_gnutls_str_cat(name, sizeof(name), ".utcTime"); 
		len = sizeof(ttime) - 1;
		result = asn1_read_value(c2, name, ttime, &len);
		if (result == ASN_OK)
			ctime = _gnutls_utcTime2gtime(ttime);
	}

	if (result != ASN_OK) {
		gnutls_assert();
		return (time_t) (-1);
	}
	return ctime;
}

int _gnutls_get_version(node_asn * c2, char *root)
{
	opaque gversion[5];
	char name[1024];
	int len, result;

	_gnutls_str_cpy(name, sizeof(name), root);
	_gnutls_str_cat(name, sizeof(name), ".tbsCertificate.version"); 

	len = sizeof(gversion) - 1;
	if ((result = asn1_read_value(c2, name, gversion, &len)) < 0) {
		gnutls_assert();
		return (-1);
	}
	return (int) gversion[0] + 1;
}


/* Extracts DSA and RSA parameters from a certificate.
 */
static 
int _gnutls_extract_cert_mpi_params( const char* ALGO_OID, gnutls_cert * gCert,
	node_asn* c2, char* tmpstr, int tmpstr_size) {
int len, result;
	
	if (strcmp( ALGO_OID, "1 2 840 113549 1 1 1") == 0) {	/* pkix-1 1 - RSA */
		/* params[0] is the modulus,
		 * params[1] is the exponent
		 */
		gCert->subject_pk_algorithm = GNUTLS_PK_RSA;

		len = tmpstr_size - 1;
		result =
		    asn1_read_value
		    (c2, "certificate2.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
		     tmpstr, &len);

		if (result != ASN_OK) {
			gnutls_assert();
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		if ((sizeof(gCert->params) / sizeof(MPI)) < RSA_PARAMS) {
			gnutls_assert();
			/* internal error. Increase the MPIs in params */
			return GNUTLS_E_INTERNAL;
		}

		if ((result =
		     _read_rsa_params(tmpstr, len / 8, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}
		
		return 0;
	}

	if (strcmp( ALGO_OID, "1 2 840 10040 4 1") == 0) {	/* pkix-1 1 - DSA */
		/* params[0] is p,
		 * params[1] is q,
		 * params[2] is q,
		 * params[3] is pub.
		 */
		gCert->subject_pk_algorithm = GNUTLS_PK_DSA;

		len = tmpstr_size - 1;
		result =
		    asn1_read_value
		    (c2, "certificate2.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
		     tmpstr, &len);

		if (result != ASN_OK) {
			gnutls_assert();
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		if ((sizeof(gCert->params) / sizeof(MPI)) < DSA_PARAMS) {
			gnutls_assert();
			/* internal error. Increase the MPIs in params */
			return GNUTLS_E_INTERNAL;
		}

		if ((result =
		     _read_dsa_pubkey(tmpstr, len / 8, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}

		/* Now read the parameters
		 */
		len = tmpstr_size - 1;
		result =
		    asn1_read_value
		    (c2, "certificate2.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters",
		     tmpstr, &len);

		if (result != ASN_OK) {
			gnutls_assert();
			return GNUTLS_E_ASN1_PARSING_ERROR;
		}

		if ((result =
		     _read_dsa_params(tmpstr, len, gCert->params)) < 0) {
			gnutls_assert();
			return result;
		}
		
		return 0;
	}



	/* other types like DH
	 * currently not supported
	 */
	gnutls_assert();

	_gnutls_log("CERT: ALGORITHM: %s\n", ALGO_OID);

	gCert->subject_pk_algorithm = GNUTLS_PK_UNKNOWN;

	return GNUTLS_E_INVALID_PARAMETERS;
}


/* This function will convert a der certificate, to a format
 * (structure) that gnutls can understand and use. Actually the
 * important thing on this function is that it extracts the 
 * certificate's (public key) parameters.
 */
int _gnutls_cert2gnutlsCert(gnutls_cert * gCert, gnutls_datum derCert)
{
	int result;
	node_asn *c2;
	opaque str[MAX_X509_CERT_SIZE];
	int len = sizeof(str);

	memset(gCert, 0, sizeof(gnutls_cert));

	gCert->valid = 1;

	if (gnutls_set_datum(&gCert->raw, derCert.data, derCert.size) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		gnutls_free_datum( &gCert->raw);
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(c2, derCert.data, derCert.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("CERT: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	len = sizeof(str) - 1;
	result =
	    asn1_read_value
	    (c2,
	     "certificate2.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",
	     str, &len);

	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if ( (result=_gnutls_extract_cert_mpi_params( str, gCert, c2, str, sizeof(str))) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return result;
	}

	len = sizeof(gCert->signature);
	result =
	    asn1_read_value
	    (c2, "certificate2.signature", gCert->signature, &len);

	if ((len % 8) != 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	len /= 8;		/* convert to bytes */
	gCert->signature_size = len;


	gCert->expiration_time =
	    _gnutls_get_time(c2, "certificate2", "notAfter");
	gCert->activation_time =
	    _gnutls_get_time(c2, "certificate2", "notBefore");
	gCert->version = _gnutls_get_version(c2, "certificate2");

	if ((result =
	     _gnutls_get_ext_type(c2,
				  "certificate2.tbsCertificate.extensions",
				  gCert)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		gnutls_free_datum( &gCert->raw);
		return result;
	}

	asn1_delete_structure(c2);


	gCert->valid = 0;	/* if we got until here
				 * the certificate is valid.
				 */

	return 0;

}

/* Returns 0 if it's ok to use the KXAlgorithm with this cert
 * (using KeyUsage field). 
 */
int _gnutls_check_x509pki_key_usage(const gnutls_cert * cert,
				    KXAlgorithm alg)
{
	if (_gnutls_map_kx_get_cred(alg) == GNUTLS_X509PKI) {
		switch (alg) {
		case GNUTLS_KX_RSA:
			if (cert->keyUsage != 0) {
				if (!
				    (cert->
				     keyUsage & GNUTLS_X509KEY_KEY_ENCIPHERMENT))
					return
					    GNUTLS_E_X509_KEY_USAGE_VIOLATION;
				else
					return 0;
			}
			return 0;
		case GNUTLS_KX_DHE_RSA:
		case GNUTLS_KX_DHE_DSS:
			if (cert->keyUsage != 0) {
				if (!
				    (cert->
				     keyUsage & GNUTLS_X509KEY_DIGITAL_SIGNATURE))
					return
					    GNUTLS_E_X509_KEY_USAGE_VIOLATION;
				else
					return 0;
			}
			return 0;
		default:
			gnutls_assert();
			return GNUTLS_E_X509_KEY_USAGE_VIOLATION;
		}
	}
	return 0;
}

/* returns the KX algorithms that are supported by a
 * certificate. (Eg a certificate with RSA params, supports
 * GNUTLS_KX_RSA algorithm).
 * This function also uses the KeyUsage field of the certificate
 * extensions in order to disable unneded algorithms.
 */
int _gnutls_cert_supported_kx(const gnutls_cert * cert, KXAlgorithm ** alg,
			      int *alg_size)
{
	KXAlgorithm kx;
	int i;
	PKAlgorithm pk;
	KXAlgorithm kxlist[MAX_KX_ALGOS];

	i = 0;
	for (kx = 0; kx < MAX_KX_ALGOS; kx++) {
		pk = _gnutls_map_pk_get_pk(kx);
		if (pk == cert->subject_pk_algorithm) {
			if (_gnutls_check_x509pki_key_usage(cert, kx) == 0) {
				kxlist[i] = kx;
				i++;
			}
		}
	}

	if (i==0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_PARAMETERS;
	}

	*alg = gnutls_calloc(1, sizeof(KXAlgorithm) * i);
	if (*alg == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	*alg_size = i;

	memcpy(*alg, kxlist, i * sizeof(KXAlgorithm));

	return 0;
}


/**
  * gnutls_x509pki_server_set_cert_request - Used to set whether to request a client certificate
  * @state: is an &GNUTLS_STATE structure.
  * @req: is one of GNUTLS_CERT_REQUEST, GNUTLS_CERT_REQUIRE
  *
  * This function specifies if we (in case of a server) are going
  * to send a certificate request message to the client. If 'req'
  * is GNUTLS_CERT_REQUIRE then the server will return an error if
  * the peer does not provide a certificate. If you do not
  * call this function then the client will not be asked to
  * send a certificate.
  **/
void gnutls_x509pki_server_set_cert_request(GNUTLS_STATE state,
					    CertificateRequest req)
{
	state->gnutls_internals.send_cert_req = req;
}

/**
  * gnutls_x509pki_set_client_cert_callback - Used to set a callback while selecting the proper (client) certificate
  * @state: is a &GNUTLS_STATE structure.
  * @func: is the callback function
  *
  * The callback's function form is:
  * int (*callback)(GNUTLS_STATE, gnutls_datum *client_cert, int ncerts, gnutls_datum* req_ca_cert, int nreqs);
  *
  * 'client_cert' contains 'ncerts' gnutls_datum structures which hold
  * the DER encoded X.509 certificates of the client. 
  *
  * 'req_ca_cert' contains a list with the CA names that the server
  * considers trusted. Normaly we should send a certificate that is signed
  * by one of these CAs. These names are DER encoded. To get a more
  * meaningful value use the function gnutls_x509pki_extract_dn().
  *
  * This function specifies what we, in case of a client, are going
  * to do when we have to send a certificate. If this callback
  * function is not provided then gnutls will automaticaly try to
  * find an appropriate certificate to send.
  *
  * If the callback function is provided then gnutls will call it
  * once with NULL parameters. If the callback function returns
  * a positive or zero number then gnutls will attempt to automaticaly
  * choose the appropriate certificate. If gnutls fails to find an appropriate
  * certificate, then it will call the callback function again with the 
  * appropriate parameters.
  *
  * In case the callback returned a negative number then gnutls will
  * not attempt to choose the appropriate certificate and will call again
  * the callback function with the appropriate parameters, and rely
  * only to the return value of the callback function.
  *
  * The callback function should return the index of the certificate
  * choosen by the user. -1 indicates that the user
  * does not want to use client authentication.
  *
  * This function returns 0 on success.
  **/
void gnutls_x509pki_set_client_cert_callback(GNUTLS_STATE state,
					     x509pki_client_cert_callback_func
					     * func)
{
	state->gnutls_internals.client_cert_callback = func;
}

/**
  * gnutls_x509pki_set_server_cert_callback - Used to set a callback while selecting the proper (server) certificate
  * @state: is a &GNUTLS_STATE structure.
  * @func: is the callback function
  *
  * The callback's function form is:
  * int (*callback)(GNUTLS_STATE, gnutls_datum *server_cert, int ncerts);
  *
  * 'server_cert' contains 'ncerts' gnutls_datum structures which hold
  * the DER encoded X.509 certificates of the server. 
  *
  * This function specifies what we, in case of a server, are going
  * to do when we have to send a certificate. If this callback
  * function is not provided then gnutls will automaticaly try to
  * find an appropriate certificate to send. (actually send the first in the list)
  *
  * In case the callback returned a negative number then gnutls will
  * not attempt to choose the appropriate certificate and the caller function
  * will fail.
  *
  * The callback function will only be called once per handshake.
  * The callback function should return the index of the certificate
  * choosen by the server. -1 indicates an error.
  *
  **/
void gnutls_x509pki_set_server_cert_callback(GNUTLS_STATE state,
					     x509pki_server_cert_callback_func
					     * func)
{
	state->gnutls_internals.server_cert_callback = func;
}
