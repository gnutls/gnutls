/*
 * Copyright (C) 2003, 2004, 2005, 2007, 2008 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#ifndef X509_H
# define X509_H

#include <gnutls/x509.h>

#define HASH_OID_SHA1 "1.3.14.3.2.26"
#define HASH_OID_MD5 "1.2.840.113549.2.5"
#define HASH_OID_MD2 "1.2.840.113549.2.2"
#define HASH_OID_RMD160 "1.3.36.3.2.1"
#define HASH_OID_SHA256 "2.16.840.1.101.3.4.2.1"
#define HASH_OID_SHA384 "2.16.840.1.101.3.4.2.2"
#define HASH_OID_SHA512 "2.16.840.1.101.3.4.2.3"

typedef struct gnutls_x509_crl_int
{
  ASN1_TYPE crl;
} gnutls_x509_crl_int;

typedef struct gnutls_x509_crt_int
{
  ASN1_TYPE cert;
  int use_extensions;
} gnutls_x509_crt_int;

typedef struct gnutls_x509_crq_int
{
  ASN1_TYPE crq;
} gnutls_x509_crq_int;

typedef struct gnutls_pkcs7_int
{
  ASN1_TYPE pkcs7;
} gnutls_pkcs7_int;

#define MAX_PRIV_PARAMS_SIZE 6	/* ok for RSA and DSA */

/* parameters should not be larger than this limit */
#define DSA_PRIVATE_PARAMS 5
#define DSA_PUBLIC_PARAMS 4
#define RSA_PRIVATE_PARAMS 6
#define RSA_PUBLIC_PARAMS 2

#if MAX_PRIV_PARAMS_SIZE - RSA_PRIVATE_PARAMS < 0
# error INCREASE MAX_PRIV_PARAMS
#endif

#if MAX_PRIV_PARAMS_SIZE - DSA_PRIVATE_PARAMS < 0
# error INCREASE MAX_PRIV_PARAMS
#endif

typedef struct gnutls_x509_privkey_int
{
  /* the size of params depends on the public
   * key algorithm
   */
  mpi_t params[MAX_PRIV_PARAMS_SIZE];

  /*
   * RSA: [0] is modulus
   *      [1] is public exponent
   *      [2] is private exponent
   *      [3] is prime1 (p)
   *      [4] is prime2 (q)
   *      [5] is coefficient (u == inverse of p mod q)
   *          note that other packages used inverse of q mod p,
   *          so we need to perform conversions.
   * DSA: [0] is p
   *      [1] is q
   *      [2] is g
   *      [3] is y (public key)
   *      [4] is x (private key)
   */
  int params_size;		/* holds the number of params */

  gnutls_pk_algorithm_t pk_algorithm;

  /* The crippled keys will not use the ASN1_TYPE key.  The encoding
   * will only be performed at the export phase, to optimize copying
   * etc. Cannot be used with the exported API (used internally only).
   */
  int crippled;

  ASN1_TYPE key;
} gnutls_x509_privkey_int;

int _gnutls_x509_crt_cpy (gnutls_x509_crt_t dest, gnutls_x509_crt_t src);


int _gnutls_x509_compare_raw_dn (const gnutls_datum_t * dn1,
				 const gnutls_datum_t * dn2);


int _gnutls_x509_crl_cpy (gnutls_x509_crl_t dest, gnutls_x509_crl_t src);
int _gnutls_x509_crl_get_raw_issuer_dn (gnutls_x509_crl_t crl,
					gnutls_datum_t * dn);

/* sign.c */
int _gnutls_x509_sign (const gnutls_datum_t * tbs,
		       gnutls_digest_algorithm_t hash,
		       gnutls_x509_privkey_t signer,
		       gnutls_datum_t * signature);
int _gnutls_x509_sign_tbs (ASN1_TYPE cert, const char *tbs_name,
			   gnutls_digest_algorithm_t hash,
			   gnutls_x509_privkey_t signer,
			   gnutls_datum_t * signature);
int _gnutls_x509_pkix_sign (ASN1_TYPE src, const char *src_name,
			    gnutls_digest_algorithm_t,
			    gnutls_x509_crt_t issuer,
			    gnutls_x509_privkey_t issuer_key);

/* dn.c */
#define OID_X520_COUNTRY_NAME		"2.5.4.6"
#define OID_X520_ORGANIZATION_NAME	"2.5.4.10"
#define OID_X520_ORGANIZATIONAL_UNIT_NAME "2.5.4.11"
#define OID_X520_COMMON_NAME 		"2.5.4.3"
#define OID_X520_LOCALITY_NAME 		"2.5.4.7"
#define OID_X520_STATE_OR_PROVINCE_NAME 	"2.5.4.8"
#define OID_LDAP_DC			"0.9.2342.19200300.100.1.25"
#define OID_LDAP_UID			"0.9.2342.19200300.100.1.1"
#define OID_PKCS9_EMAIL 			"1.2.840.113549.1.9.1"

int _gnutls_x509_parse_dn (ASN1_TYPE asn1_struct,
			   const char *asn1_rdn_name, char *buf,
			   size_t * sizeof_buf);

int _gnutls_x509_parse_dn_oid (ASN1_TYPE asn1_struct,
			       const char *asn1_rdn_name, const char *oid,
			       int indx, unsigned int raw_flag, void *buf,
			       size_t * sizeof_buf);

int _gnutls_x509_set_dn_oid (ASN1_TYPE asn1_struct,
			     const char *asn1_rdn_name, const char *oid,
			     int raw_flag, const char *name, int sizeof_name);

int _gnutls_x509_get_dn_oid (ASN1_TYPE asn1_struct,
			     const char *asn1_rdn_name,
			     int indx, void *_oid, size_t * sizeof_oid);

/* dsa.c */
int _gnutls_dsa_generate_params (mpi_t * resarr, int *resarr_len, int bits);


/* verify.c */
int gnutls_x509_crt_is_issuer (gnutls_x509_crt_t cert,
			       gnutls_x509_crt_t issuer);
int _gnutls_x509_verify_signature (const gnutls_datum_t * tbs,
				   const gnutls_datum_t * signature,
				   gnutls_x509_crt_t issuer);
int _gnutls_x509_privkey_verify_signature (const gnutls_datum_t * tbs,
					   const gnutls_datum_t * signature,
					   gnutls_x509_privkey_t issuer);

/* privkey.h */
ASN1_TYPE _gnutls_privkey_decode_pkcs1_rsa_key (const gnutls_datum_t *raw_key,
						gnutls_x509_privkey_t pkey);
int _gnutls_asn1_encode_dsa (ASN1_TYPE * c2, mpi_t * params);

#endif
