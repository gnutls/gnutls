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

#endif
