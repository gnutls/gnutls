/*
 * Copyright (C) 2003, 2004, 2005, 2007 Free Software Foundation
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
  mpi_t params[MAX_PRIV_PARAMS_SIZE];	/* the size of params depends on the public 
					 * key algorithm 
					 */
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

  int crippled;			/* The crippled keys will not use the ASN1_TYPE key.
				 * The encoding will only be performed at the export
				 * phase, to optimize copying etc. Cannot be used with
				 * the exported API (used internally only).
				 */
  ASN1_TYPE key;
} gnutls_x509_privkey_int;

int gnutls_x509_crt_get_issuer_dn_by_oid (gnutls_x509_crt_t cert,
					  const char *oid, int indx,
					  unsigned int raw_flag, void *buf,
					  size_t * sizeof_buf);
int gnutls_x509_crt_get_subject_alt_name (gnutls_x509_crt_t cert,
					  unsigned int seq, void *ret,
					  size_t * ret_size,
					  unsigned int *critical);
int gnutls_x509_crt_get_dn_by_oid (gnutls_x509_crt_t cert, const char *oid,
				   int indx, unsigned int raw_flag, void *buf,
				   size_t * sizeof_buf);
int gnutls_x509_crt_get_ca_status (gnutls_x509_crt_t cert,
				   unsigned int *critical);
int gnutls_x509_crt_get_pk_algorithm (gnutls_x509_crt_t cert,
				      unsigned int *bits);

int _gnutls_x509_crt_cpy (gnutls_x509_crt_t dest, gnutls_x509_crt_t src);

int gnutls_x509_crt_get_serial (gnutls_x509_crt_t cert, void *result,
				size_t * result_size);

int _gnutls_x509_compare_raw_dn (const gnutls_datum_t * dn1,
				 const gnutls_datum_t * dn2);

int gnutls_x509_crt_check_revocation (gnutls_x509_crt_t cert,
				      const gnutls_x509_crl_t * crl_list,
				      int crl_list_length);


int _gnutls_x509_crl_cpy (gnutls_x509_crl_t dest, gnutls_x509_crl_t src);
int _gnutls_x509_crl_get_raw_issuer_dn (gnutls_x509_crl_t crl,
					gnutls_datum_t * dn);
int gnutls_x509_crl_get_crt_count (gnutls_x509_crl_t crl);
int gnutls_x509_crl_get_crt_serial (gnutls_x509_crl_t crl, int indx,
				    unsigned char *serial,
				    size_t * serial_size, time_t * t);

void gnutls_x509_crl_deinit (gnutls_x509_crl_t crl);
int gnutls_x509_crl_init (gnutls_x509_crl_t * crl);
int gnutls_x509_crl_import (gnutls_x509_crl_t crl,
			    const gnutls_datum_t * data,
			    gnutls_x509_crt_fmt_t format);
int gnutls_x509_crl_export (gnutls_x509_crl_t crl,
			    gnutls_x509_crt_fmt_t format, void *output_data,
			    size_t * output_data_size);

int gnutls_x509_crt_init (gnutls_x509_crt_t * cert);
void gnutls_x509_crt_deinit (gnutls_x509_crt_t cert);
int gnutls_x509_crt_import (gnutls_x509_crt_t cert,
			    const gnutls_datum_t * data,
			    gnutls_x509_crt_fmt_t format);
int gnutls_x509_crt_export (gnutls_x509_crt_t cert,
			    gnutls_x509_crt_fmt_t format, void *output_data,
			    size_t * output_data_size);

int gnutls_x509_crt_get_key_usage (gnutls_x509_crt_t cert,
				   unsigned int *key_usage,
				   unsigned int *critical);
int gnutls_x509_crt_get_signature_algorithm (gnutls_x509_crt_t cert);
int gnutls_x509_crt_get_version (gnutls_x509_crt_t cert);

int gnutls_x509_privkey_init (gnutls_x509_privkey_t * key);
void gnutls_x509_privkey_deinit (gnutls_x509_privkey_t key);

int gnutls_x509_privkey_generate (gnutls_x509_privkey_t key,
				  gnutls_pk_algorithm_t algo,
				  unsigned int bits, unsigned int flags);

int gnutls_x509_privkey_import (gnutls_x509_privkey_t key,
				const gnutls_datum_t * data,
				gnutls_x509_crt_fmt_t format);
int gnutls_x509_privkey_get_pk_algorithm (gnutls_x509_privkey_t key);
int gnutls_x509_privkey_import_rsa_raw (gnutls_x509_privkey_t key,
					const gnutls_datum_t * m,
					const gnutls_datum_t * e,
					const gnutls_datum_t * d,
					const gnutls_datum_t * p,
					const gnutls_datum_t * q,
					const gnutls_datum_t * u);
int gnutls_x509_privkey_export_rsa_raw (gnutls_x509_privkey_t key,
					gnutls_datum_t * m,
					gnutls_datum_t * e,
					gnutls_datum_t * d,
					gnutls_datum_t * p,
					gnutls_datum_t * q,
					gnutls_datum_t * u);
int gnutls_x509_privkey_export (gnutls_x509_privkey_t key,
				gnutls_x509_crt_fmt_t format,
				void *output_data, size_t * output_data_size);

#define GNUTLS_CRL_REASON_UNUSED 128
#define GNUTLS_CRL_REASON_KEY_COMPROMISE 64
#define GNUTLS_CRL_REASON_CA_COMPROMISE 32
#define GNUTLS_CRL_REASON_AFFILIATION_CHANGED 16
#define GNUTLS_CRL_REASON_SUPERSEEDED 8
#define GNUTLS_CRL_REASON_CESSATION_OF_OPERATION 4
#define GNUTLS_CRL_REASON_CERTIFICATE_HOLD 2
#define GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN 1
#define GNUTLS_CRL_REASON_AA_COMPROMISE 32768

#endif
