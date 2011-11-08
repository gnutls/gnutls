/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <gnutls_int.h>
#include <algorithms.h>
#include <gnutls_errors.h>
#include <x509/common.h>

static int
compare_algo (gnutls_session_t session, const void *i_A1,
                      const void *i_A2);
static void
_gnutls_qsort (gnutls_session_t session, void *_base, size_t nmemb,
               size_t size, int (*compar) (gnutls_session_t, const void *,
                                           const void *));

/* Cipher SUITES */
#define GNUTLS_CIPHER_SUITE_ENTRY( name, block_algorithm, kx_algorithm, mac_algorithm, min_version, max_version, dtls ) \
	{ #name, {name}, block_algorithm, kx_algorithm, mac_algorithm, min_version, max_version, dtls, GNUTLS_MAC_SHA256}
#define GNUTLS_CIPHER_SUITE_ENTRY_PRF( name, block_algorithm, kx_algorithm, mac_algorithm, min_version, max_version, dtls, prf ) \
	{ #name, {name}, block_algorithm, kx_algorithm, mac_algorithm, min_version, max_version, dtls, prf}

typedef struct
{
  const char *name;
  cipher_suite_st id;
  gnutls_cipher_algorithm_t block_algorithm;
  gnutls_kx_algorithm_t kx_algorithm;
  gnutls_mac_algorithm_t mac_algorithm;
  gnutls_protocol_t min_version;        /* this cipher suite is supported
                                         * from 'version' and above;
                                         */
  gnutls_protocol_t max_version;        /* this cipher suite is not supported after that */
  unsigned int dtls:1; /* whether this ciphersuite is valid in DTLS */
  gnutls_mac_algorithm_t prf;
} gnutls_cipher_suite_entry;

/* RSA with NULL cipher and MD5 MAC
 * for test purposes.
 */
#define GNUTLS_RSA_NULL_MD5 { 0x00, 0x01 }
#define GNUTLS_RSA_NULL_SHA1 { 0x00, 0x02 }
#define GNUTLS_RSA_NULL_SHA256 { 0x00, 0x3B }

/* ANONymous cipher suites.
 */

#define GNUTLS_DH_ANON_3DES_EDE_CBC_SHA1 { 0x00, 0x1B }
#define GNUTLS_DH_ANON_ARCFOUR_MD5 { 0x00, 0x18 }

 /* rfc3268: */
#define GNUTLS_DH_ANON_AES_128_CBC_SHA1 { 0x00, 0x34 }
#define GNUTLS_DH_ANON_AES_256_CBC_SHA1 { 0x00, 0x3A }

/* rfc4132 */
#define GNUTLS_DH_ANON_CAMELLIA_128_CBC_SHA1 { 0x00,0x46 }
#define GNUTLS_DH_ANON_CAMELLIA_256_CBC_SHA1 { 0x00,0x89 }

#define GNUTLS_DH_ANON_AES_128_CBC_SHA256 { 0x00, 0x6C }
#define GNUTLS_DH_ANON_AES_256_CBC_SHA256 { 0x00, 0x6D }

/* PSK (not in TLS 1.0)
 * draft-ietf-tls-psk:
 */
#define GNUTLS_PSK_SHA_ARCFOUR_SHA1 { 0x00, 0x8A }
#define GNUTLS_PSK_SHA_3DES_EDE_CBC_SHA1 { 0x00, 0x8B }
#define GNUTLS_PSK_SHA_AES_128_CBC_SHA1 { 0x00, 0x8C }
#define GNUTLS_PSK_SHA_AES_256_CBC_SHA1 { 0x00, 0x8D }

#define GNUTLS_DHE_PSK_SHA_ARCFOUR_SHA1 { 0x00, 0x8E }
#define GNUTLS_DHE_PSK_SHA_3DES_EDE_CBC_SHA1 { 0x00, 0x8F }
#define GNUTLS_DHE_PSK_SHA_AES_128_CBC_SHA1 { 0x00, 0x90 }
#define GNUTLS_DHE_PSK_SHA_AES_256_CBC_SHA1 { 0x00, 0x91 }


/* SRP (rfc5054)
 */
#define GNUTLS_SRP_SHA_3DES_EDE_CBC_SHA1 { 0xC0, 0x1A }
#define GNUTLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1 { 0xC0, 0x1B }
#define GNUTLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1 { 0xC0, 0x1C }

#define GNUTLS_SRP_SHA_AES_128_CBC_SHA1 { 0xC0, 0x1D }
#define GNUTLS_SRP_SHA_RSA_AES_128_CBC_SHA1 { 0xC0, 0x1E }
#define GNUTLS_SRP_SHA_DSS_AES_128_CBC_SHA1 { 0xC0, 0x1F }

#define GNUTLS_SRP_SHA_AES_256_CBC_SHA1 { 0xC0, 0x20 }
#define GNUTLS_SRP_SHA_RSA_AES_256_CBC_SHA1 { 0xC0, 0x21 }
#define GNUTLS_SRP_SHA_DSS_AES_256_CBC_SHA1 { 0xC0, 0x22 }

/* RSA
 */
#define GNUTLS_RSA_ARCFOUR_SHA1 { 0x00, 0x05 }
#define GNUTLS_RSA_ARCFOUR_MD5 { 0x00, 0x04 }
#define GNUTLS_RSA_3DES_EDE_CBC_SHA1 { 0x00, 0x0A }

#define GNUTLS_RSA_EXPORT_ARCFOUR_40_MD5 { 0x00, 0x03 }

/* rfc3268:
 */
#define GNUTLS_RSA_AES_128_CBC_SHA1 { 0x00, 0x2F }
#define GNUTLS_RSA_AES_256_CBC_SHA1 { 0x00, 0x35 }

/* rfc4132 */
#define GNUTLS_RSA_CAMELLIA_128_CBC_SHA1 { 0x00,0x41 }
#define GNUTLS_RSA_CAMELLIA_256_CBC_SHA1 { 0x00,0x84 }

#define GNUTLS_RSA_AES_128_CBC_SHA256 { 0x00, 0x3C }
#define GNUTLS_RSA_AES_256_CBC_SHA256 { 0x00, 0x3D }

/* DHE DSS
 */

#define GNUTLS_DHE_DSS_3DES_EDE_CBC_SHA1 { 0x00, 0x13 }


/* draft-ietf-tls-56-bit-ciphersuites-01:
 */
#define GNUTLS_DHE_DSS_ARCFOUR_SHA1 { 0x00, 0x66 }


/* rfc3268:
 */
#define GNUTLS_DHE_DSS_AES_256_CBC_SHA1 { 0x00, 0x38 }
#define GNUTLS_DHE_DSS_AES_128_CBC_SHA1 { 0x00, 0x32 }

/* rfc4132 */
#define GNUTLS_DHE_DSS_CAMELLIA_128_CBC_SHA1 { 0x00,0x44 }
#define GNUTLS_DHE_DSS_CAMELLIA_256_CBC_SHA1 { 0x00,0x87 }

#define GNUTLS_DHE_DSS_AES_128_CBC_SHA256 { 0x00, 0x40 }
#define GNUTLS_DHE_DSS_AES_256_CBC_SHA256 { 0x00, 0x6A }

/* DHE RSA
 */
#define GNUTLS_DHE_RSA_3DES_EDE_CBC_SHA1 { 0x00, 0x16 }

/* rfc3268:
 */
#define GNUTLS_DHE_RSA_AES_128_CBC_SHA1 { 0x00, 0x33 }
#define GNUTLS_DHE_RSA_AES_256_CBC_SHA1 { 0x00, 0x39 }

/* rfc4132 */
#define GNUTLS_DHE_RSA_CAMELLIA_128_CBC_SHA1 { 0x00,0x45 }
#define GNUTLS_DHE_RSA_CAMELLIA_256_CBC_SHA1 { 0x00,0x88 }

#define GNUTLS_DHE_RSA_AES_128_CBC_SHA256 { 0x00, 0x67 }
#define GNUTLS_DHE_RSA_AES_256_CBC_SHA256 { 0x00, 0x6B }

/* GCM: RFC5288 */
#define GNUTLS_RSA_AES_128_GCM_SHA256 { 0x00, 0x9C }
#define GNUTLS_DHE_RSA_AES_128_GCM_SHA256 {0x00,0x9E}
#define GNUTLS_DHE_DSS_AES_128_GCM_SHA256 {0x00,0xA2}
#define GNUTLS_DH_ANON_AES_128_GCM_SHA256 {0x00,0xA6}

/* RFC 5487 */
/* GCM-PSK */
#define GNUTLS_PSK_AES_128_GCM_SHA256 { 0x00, 0xA8 }
#define GNUTLS_DHE_PSK_AES_128_GCM_SHA256 { 0x00, 0xAA }

/* PSK - SHA256 HMAC */
#define GNUTLS_PSK_AES_128_CBC_SHA256 { 0x00, 0xAE }
#define GNUTLS_DHE_PSK_AES_128_CBC_SHA256 { 0x00, 0xB2 }

#define GNUTLS_PSK_NULL_SHA256 { 0x00, 0xB0 }
#define GNUTLS_DHE_PSK_NULL_SHA256 { 0x00, 0xB4 }

/* ECC */
#define GNUTLS_ECDH_ANON_NULL_SHA { 0xC0, 0x15 }
#define GNUTLS_ECDH_ANON_3DES_EDE_CBC_SHA { 0xC0, 0x17 }
#define GNUTLS_ECDH_ANON_AES_128_CBC_SHA { 0xC0, 0x18 }
#define GNUTLS_ECDH_ANON_AES_256_CBC_SHA { 0xC0, 0x19 }

/* ECC-RSA */
#define GNUTLS_ECDHE_RSA_NULL_SHA { 0xC0, 0x10 }
#define GNUTLS_ECDHE_RSA_3DES_EDE_CBC_SHA { 0xC0, 0x12 }
#define GNUTLS_ECDHE_RSA_AES_128_CBC_SHA { 0xC0, 0x13 }
#define GNUTLS_ECDHE_RSA_AES_256_CBC_SHA { 0xC0, 0x14 }

/* ECC-ECDSA */
#define GNUTLS_ECDHE_ECDSA_NULL_SHA           { 0xC0, 0x06 }
#define GNUTLS_ECDHE_ECDSA_3DES_EDE_CBC_SHA   { 0xC0, 0x08 }
#define GNUTLS_ECDHE_ECDSA_AES_128_CBC_SHA    { 0xC0, 0x09 }
#define GNUTLS_ECDHE_ECDSA_AES_256_CBC_SHA    { 0xC0, 0x0A }

/* ECC with SHA2 */
#define GNUTLS_ECDHE_ECDSA_AES_128_CBC_SHA256     {0xC0,0x23}
#define GNUTLS_ECDHE_RSA_AES_128_CBC_SHA256       {0xC0,0x27}

/* ECC with AES-GCM */
#define GNUTLS_ECDHE_ECDSA_AES_128_GCM_SHA256   {0xC0,0x2B}
#define GNUTLS_ECDHE_RSA_AES_128_GCM_SHA256     {0xC0,0x2F}
#define GNUTLS_ECDHE_RSA_AES_256_GCM_SHA384     {0xC0,0x30}

/* SuiteB */
#define GNUTLS_ECDHE_ECDSA_AES_256_GCM_SHA384   {0xC0,0x2E}
#define GNUTLS_ECDHE_ECDSA_AES_256_CBC_SHA384   {0xC0,0x24}


/* ECC with PSK */
#define GNUTLS_ECDHE_PSK_3DES_EDE_CBC_SHA { 0xC0, 0x34 }
#define GNUTLS_ECDHE_PSK_AES_128_CBC_SHA { 0xC0, 0x35 }
#define GNUTLS_ECDHE_PSK_AES_256_CBC_SHA { 0xC0, 0x36 }
#define GNUTLS_ECDHE_PSK_AES_128_CBC_SHA256 { 0xC0, 0x37 }
#define GNUTLS_ECDHE_PSK_AES_256_CBC_SHA384 { 0xC0, 0x38 }
#define GNUTLS_ECDHE_PSK_NULL_SHA256 { 0xC0, 0x3A }
#define GNUTLS_ECDHE_PSK_NULL_SHA384 { 0xC0, 0x3B }

#define CIPHER_SUITES_COUNT (sizeof(cs_algorithms)/sizeof(gnutls_cipher_suite_entry)-1)

static const gnutls_cipher_suite_entry cs_algorithms[] = {
  /* DH_ANON */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_ARCFOUR_MD5,
                             GNUTLS_CIPHER_ARCFOUR_128,
                             GNUTLS_KX_ANON_DH, GNUTLS_MAC_MD5,
                             GNUTLS_SSL3, GNUTLS_VERSION_MAX, 0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_ANON_DH,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ANON_DH,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_ANON_DH,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_CAMELLIA_128_CBC_SHA1,
                             GNUTLS_CIPHER_CAMELLIA_128_CBC,
                             GNUTLS_KX_ANON_DH,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_CAMELLIA_256_CBC_SHA1,
                             GNUTLS_CIPHER_CAMELLIA_256_CBC,
                             GNUTLS_KX_ANON_DH,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ANON_DH,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_AES_256_CBC_SHA256,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_ANON_DH,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),

  /* PSK */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_PSK_SHA_ARCFOUR_SHA1,
                             GNUTLS_CIPHER_ARCFOUR, GNUTLS_KX_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_PSK_SHA_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_PSK_SHA_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_PSK_SHA_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_PSK_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_PSK,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_PSK_AES_128_GCM_SHA256,
                             GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_PSK,
                             GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_PSK_NULL_SHA256,
                             GNUTLS_CIPHER_NULL, GNUTLS_KX_PSK,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  /* DHE-PSK */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_PSK_SHA_ARCFOUR_SHA1,
                             GNUTLS_CIPHER_ARCFOUR, GNUTLS_KX_DHE_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_PSK_SHA_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_DHE_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_PSK_SHA_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_DHE_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_PSK_SHA_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_DHE_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_PSK_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_DHE_PSK,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_PSK_AES_128_GCM_SHA256,
                             GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_DHE_PSK,
                             GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_PSK_NULL_SHA256,
                             GNUTLS_CIPHER_NULL, GNUTLS_KX_DHE_PSK,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  /* SRP */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_SRP,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_SRP,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_SRP,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_SRP_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_SRP_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_DSS_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_SRP_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_RSA_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_SRP_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_DSS_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_SRP_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_SRP_SHA_RSA_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_SRP_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),

  /* DHE_DSS */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_ARCFOUR_SHA1,
                             GNUTLS_CIPHER_ARCFOUR_128, GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_CAMELLIA_128_CBC_SHA1,
                             GNUTLS_CIPHER_CAMELLIA_128_CBC,
                             GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_CAMELLIA_256_CBC_SHA1,
                             GNUTLS_CIPHER_CAMELLIA_256_CBC,
                             GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_AES_256_CBC_SHA256,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  /* DHE_RSA */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_DHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_DHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_DHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_CAMELLIA_128_CBC_SHA1,
                             GNUTLS_CIPHER_CAMELLIA_128_CBC,
                             GNUTLS_KX_DHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_CAMELLIA_256_CBC_SHA1,
                             GNUTLS_CIPHER_CAMELLIA_256_CBC,
                             GNUTLS_KX_DHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_DHE_RSA,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_AES_256_CBC_SHA256,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_DHE_RSA,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  /* RSA-NULL */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_NULL_MD5,
                             GNUTLS_CIPHER_NULL,
                             GNUTLS_KX_RSA, GNUTLS_MAC_MD5, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_NULL_SHA1,
                             GNUTLS_CIPHER_NULL,
                             GNUTLS_KX_RSA, GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_NULL_SHA256,
                             GNUTLS_CIPHER_NULL,
                             GNUTLS_KX_RSA, GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),

  /* RSA-EXPORT */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_EXPORT_ARCFOUR_40_MD5,
                             GNUTLS_CIPHER_ARCFOUR_40,
                             GNUTLS_KX_RSA_EXPORT, GNUTLS_MAC_MD5,
                             GNUTLS_SSL3, GNUTLS_TLS1_0, 0),

  /* RSA */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_ARCFOUR_SHA1,
                             GNUTLS_CIPHER_ARCFOUR_128,
                             GNUTLS_KX_RSA, GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_ARCFOUR_MD5,
                             GNUTLS_CIPHER_ARCFOUR_128,
                             GNUTLS_KX_RSA, GNUTLS_MAC_MD5, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 0),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_3DES_EDE_CBC_SHA1,
                             GNUTLS_CIPHER_3DES_CBC,
                             GNUTLS_KX_RSA, GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_AES_128_CBC_SHA1,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_AES_256_CBC_SHA1,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_SSL3,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_CAMELLIA_128_CBC_SHA1,
                             GNUTLS_CIPHER_CAMELLIA_128_CBC, GNUTLS_KX_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_CAMELLIA_256_CBC_SHA1,
                             GNUTLS_CIPHER_CAMELLIA_256_CBC, GNUTLS_KX_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_RSA,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_AES_256_CBC_SHA256,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_RSA,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
/* GCM */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_RSA_AES_128_GCM_SHA256,
                             GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_RSA,
                             GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_RSA_AES_128_GCM_SHA256,
                             GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_DHE_RSA,
                             GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DHE_DSS_AES_128_GCM_SHA256,
                             GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_DHE_DSS,
                             GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_DH_ANON_AES_128_GCM_SHA256,
                             GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_ANON_DH,
                             GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
/* ECC-ANON */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDH_ANON_NULL_SHA,
                             GNUTLS_CIPHER_NULL, GNUTLS_KX_ANON_ECDH,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDH_ANON_3DES_EDE_CBC_SHA,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_ANON_ECDH,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDH_ANON_AES_128_CBC_SHA,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ANON_ECDH,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDH_ANON_AES_256_CBC_SHA,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_ANON_ECDH,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
/* ECC-RSA */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_RSA_NULL_SHA,
                             GNUTLS_CIPHER_NULL, GNUTLS_KX_ECDHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_RSA_3DES_EDE_CBC_SHA,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_ECDHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_RSA_AES_128_CBC_SHA,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ECDHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_RSA_AES_256_CBC_SHA,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_ECDHE_RSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  /* ECDHE-ECDSA */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_ECDSA_NULL_SHA,
                             GNUTLS_CIPHER_NULL, GNUTLS_KX_ECDHE_ECDSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_ECDSA_3DES_EDE_CBC_SHA,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_ECDHE_ECDSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_ECDSA_AES_128_CBC_SHA,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ECDHE_ECDSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_ECDSA_AES_256_CBC_SHA,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_ECDHE_ECDSA,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  /* More ECC */

  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_ECDSA_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ECDHE_ECDSA,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_RSA_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ECDHE_RSA,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_ECDSA_AES_128_GCM_SHA256,
                             GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_ECDHE_ECDSA,
                             GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_RSA_AES_128_GCM_SHA256,
                             GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_ECDHE_RSA,
                             GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                             GNUTLS_VERSION_MAX, 1),
  /* ECC - PSK */
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_PSK_3DES_EDE_CBC_SHA,
                             GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_ECDHE_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_PSK_AES_128_CBC_SHA,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ECDHE_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_PSK_AES_256_CBC_SHA,
                             GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_ECDHE_PSK,
                             GNUTLS_MAC_SHA1, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_PSK_AES_128_CBC_SHA256,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ECDHE_PSK,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY_PRF (GNUTLS_ECDHE_PSK_AES_256_CBC_SHA384,
                             GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_ECDHE_PSK,
                             GNUTLS_MAC_SHA384, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1, GNUTLS_MAC_SHA384),
  GNUTLS_CIPHER_SUITE_ENTRY (GNUTLS_ECDHE_PSK_NULL_SHA256,
                             GNUTLS_CIPHER_NULL, GNUTLS_KX_ECDHE_PSK,
                             GNUTLS_MAC_SHA256, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1),
  GNUTLS_CIPHER_SUITE_ENTRY_PRF (GNUTLS_ECDHE_PSK_NULL_SHA384,
                             GNUTLS_CIPHER_NULL, GNUTLS_KX_ECDHE_PSK,
                             GNUTLS_MAC_SHA384, GNUTLS_TLS1_0,
                             GNUTLS_VERSION_MAX, 1, GNUTLS_MAC_SHA384),
  GNUTLS_CIPHER_SUITE_ENTRY_PRF(GNUTLS_ECDHE_ECDSA_AES_256_GCM_SHA384,
                                GNUTLS_CIPHER_AES_256_GCM, GNUTLS_KX_ECDHE_ECDSA,
                                GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                                GNUTLS_VERSION_MAX, 1, GNUTLS_DIG_SHA384),
  GNUTLS_CIPHER_SUITE_ENTRY_PRF(GNUTLS_ECDHE_RSA_AES_256_GCM_SHA384,
                                GNUTLS_CIPHER_AES_256_GCM, GNUTLS_KX_ECDHE_RSA,
                                GNUTLS_MAC_AEAD, GNUTLS_TLS1_2,
                                GNUTLS_VERSION_MAX, 1, GNUTLS_DIG_SHA384),
  GNUTLS_CIPHER_SUITE_ENTRY_PRF(GNUTLS_ECDHE_ECDSA_AES_256_CBC_SHA384,
                                GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_ECDHE_ECDSA,
                                GNUTLS_MAC_SHA384, GNUTLS_TLS1_2,
                                GNUTLS_VERSION_MAX, 1, GNUTLS_DIG_SHA384),

  {0, {{0, 0}}, 0, 0, 0, 0, 0, 0}
};

#define GNUTLS_CIPHER_SUITE_LOOP(b) \
        const gnutls_cipher_suite_entry *p; \
                for(p = cs_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_CIPHER_SUITE_ALG_LOOP(a) \
                        GNUTLS_CIPHER_SUITE_LOOP( if( (p->id.suite[0] == suite->suite[0]) && (p->id.suite[1] == suite->suite[1])) { a; break; } )


/* Cipher Suite's functions */
gnutls_cipher_algorithm_t
_gnutls_cipher_suite_get_cipher_algo (const cipher_suite_st * suite)
{
  int ret = 0;
  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->block_algorithm);
  return ret;
}

static int
_gnutls_cipher_suite_is_version_supported (gnutls_session_t session, const cipher_suite_st * suite)
{
  int ret = 0;
  int version = gnutls_protocol_get_version( session);
  
  GNUTLS_CIPHER_SUITE_ALG_LOOP (if (version >= p->min_version
                                 && version <= p->max_version) ret = 1;
                                 if (IS_DTLS(session) && p->dtls==0) ret = 0;);
  return ret;
}

gnutls_kx_algorithm_t
_gnutls_cipher_suite_get_kx_algo (const cipher_suite_st * suite)
{
  int ret = 0;

  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->kx_algorithm);
  return ret;

}

gnutls_mac_algorithm_t
_gnutls_cipher_suite_get_prf (const cipher_suite_st * suite)
{
  int ret = 0;

  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->prf);
  return ret;

}

gnutls_mac_algorithm_t
_gnutls_cipher_suite_get_mac_algo (const cipher_suite_st * suite)
{                               /* In bytes */
  int ret = 0;
  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->mac_algorithm);
  return ret;

}

const char *
_gnutls_cipher_suite_get_name (cipher_suite_st * suite)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_CIPHER_SUITE_ALG_LOOP (ret = p->name + sizeof ("GNUTLS_") - 1);

  return ret;
}

/**
 * gnutls_cipher_suite_get_name:
 * @kx_algorithm: is a Key exchange algorithm
 * @cipher_algorithm: is a cipher algorithm
 * @mac_algorithm: is a MAC algorithm
 *
 * Note that the full cipher suite name must be prepended by TLS or
 * SSL depending of the protocol in use.
 *
 * Returns: a string that contains the name of a TLS cipher suite,
 * specified by the given algorithms, or %NULL.
 **/
const char *
gnutls_cipher_suite_get_name (gnutls_kx_algorithm_t kx_algorithm,
                              gnutls_cipher_algorithm_t cipher_algorithm,
                              gnutls_mac_algorithm_t mac_algorithm)
{
  const char *ret = NULL;

  GNUTLS_CIPHER_SUITE_LOOP (
      if (kx_algorithm == p->kx_algorithm &&
          cipher_algorithm == p->block_algorithm && mac_algorithm == p->mac_algorithm)
        {
          ret = p->name + sizeof ("GNUTLS_") - 1;
          break;
        }
  );

  return ret;
}

/**
 * gnutls_cipher_suite_info:
 * @idx: index of cipher suite to get information about, starts on 0.
 * @cs_id: output buffer with room for 2 bytes, indicating cipher suite value
 * @kx: output variable indicating key exchange algorithm, or %NULL.
 * @cipher: output variable indicating cipher, or %NULL.
 * @mac: output variable indicating MAC algorithm, or %NULL.
 * @min_version: output variable indicating TLS protocol version, or %NULL.
 *
 * Get information about supported cipher suites.  Use the function
 * iteratively to get information about all supported cipher suites.
 * Call with idx=0 to get information about first cipher suite, then
 * idx=1 and so on until the function returns NULL.
 *
 * Returns: the name of @idx cipher suite, and set the information
 * about the cipher suite in the output variables.  If @idx is out of
 * bounds, %NULL is returned.
 **/
const char *
gnutls_cipher_suite_info (size_t idx,
                          char *cs_id,
                          gnutls_kx_algorithm_t * kx,
                          gnutls_cipher_algorithm_t * cipher,
                          gnutls_mac_algorithm_t * mac,
                          gnutls_protocol_t * min_version)
{
  if (idx >= CIPHER_SUITES_COUNT)
    return NULL;

  if (cs_id)
    memcpy (cs_id, cs_algorithms[idx].id.suite, 2);
  if (kx)
    *kx = cs_algorithms[idx].kx_algorithm;
  if (cipher)
    *cipher = cs_algorithms[idx].block_algorithm;
  if (mac)
    *mac = cs_algorithms[idx].mac_algorithm;
  if (min_version)
    *min_version = cs_algorithms[idx].min_version;

  return cs_algorithms[idx].name + sizeof ("GNU") - 1;
}


static inline int
_gnutls_cipher_suite_is_ok (cipher_suite_st * suite)
{
  size_t ret;
  const char *name = NULL;

  GNUTLS_CIPHER_SUITE_ALG_LOOP (name = p->name);
  if (name != NULL)
    ret = 0;
  else
    ret = 1;
  return ret;

}

int
_gnutls_supported_ciphersuites_sorted (gnutls_session_t session,
                                       uint8_t* cipher_suites, int max_cipher_suites_size)
{

  int count;

  count = _gnutls_supported_ciphersuites (session, cipher_suites, max_cipher_suites_size);
  if (count < 0)
    return gnutls_assert_val(count);

  _gnutls_qsort (session, cipher_suites, count/2,
                 2, compare_algo);

  return count;
}

int
_gnutls_supported_ciphersuites (gnutls_session_t session,
                                uint8_t *cipher_suites, int max_cipher_suite_size)
{

  unsigned int i, ret_count, j;

  if (max_cipher_suite_size < (CIPHER_SUITES_COUNT)*2)
    return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

  for (i = j = 0; i < CIPHER_SUITES_COUNT; i++)
    {
      /* remove private cipher suites, if requested.
       */
      if (cs_algorithms[i].id.suite[0] == 0xFF &&
          session->internals.enable_private == 0)
        continue;

      /* remove cipher suites which do not support the
       * protocol version used.
       */
      if (_gnutls_cipher_suite_is_version_supported (session, &cs_algorithms[i].id)
          == 0)
        continue;

      if (_gnutls_kx_priority
          (session, _gnutls_cipher_suite_get_kx_algo (&cs_algorithms[i].id)) < 0)
        continue;

      if (_gnutls_mac_priority
          (session, _gnutls_cipher_suite_get_mac_algo (&cs_algorithms[i].id)) < 0)
        continue;

      if (_gnutls_cipher_priority
          (session,
           _gnutls_cipher_suite_get_cipher_algo (&cs_algorithms[i].id)) < 0)
        continue;

      memcpy (&cipher_suites[j], &cs_algorithms[i].id.suite, 2);
      j+=2;
    }

  ret_count = j;

  /* This function can no longer return 0 cipher suites.
   * It returns an error code instead.
   */
  if (ret_count == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_CIPHER_SUITES;
    }
  return ret_count;
}

#define SWAP(x, y) memcpy(tmp,x,size); \
		   memcpy(x,y,size); \
		   memcpy(y,tmp,size);

#define MAX_ELEM_SIZE 4
static inline int
_gnutls_partition (gnutls_session_t session, void *_base,
                   size_t nmemb, size_t size,
                   int (*compar) (gnutls_session_t,
                                  const void *, const void *))
{
  uint8_t *base = _base;
  uint8_t tmp[MAX_ELEM_SIZE];
  uint8_t ptmp[MAX_ELEM_SIZE];
  unsigned int pivot;
  unsigned int i, j;
  unsigned int full;

  i = pivot = 0;
  j = full = (nmemb - 1) * size;

  memcpy (ptmp, &base[0], size);        /* set pivot item */

  while (i < j)
    {
      while ((compar (session, &base[i], ptmp) <= 0) && (i < full))
        {
          i += size;
        }
      while ((compar (session, &base[j], ptmp) >= 0) && (j > 0))
        j -= size;

      if (i < j)
        {
          SWAP (&base[j], &base[i]);
        }
    }

  if (j > pivot)
    {
      SWAP (&base[pivot], &base[j]);
      pivot = j;
    }
  else if (i < pivot)
    {
      SWAP (&base[pivot], &base[i]);
      pivot = i;
    }
  return pivot / size;
}

static void
_gnutls_qsort (gnutls_session_t session, void *_base, size_t nmemb,
               size_t size, int (*compar) (gnutls_session_t, const void *,
                                           const void *))
{
  unsigned int pivot;
  char *base = _base;
  size_t snmemb = nmemb;

#ifdef DEBUG
  if (size > MAX_ELEM_SIZE)
    {
      gnutls_assert ();
      _gnutls_debug_log ("QSORT BUG\n");
      exit (1);
    }
#endif

  if (snmemb <= 1)
    return;
  pivot = _gnutls_partition (session, _base, nmemb, size, compar);

  _gnutls_qsort (session, base, pivot < nmemb ? pivot + 1 : pivot, size,
                 compar);
  _gnutls_qsort (session, &base[(pivot + 1) * size], nmemb - pivot - 1,
                 size, compar);
}


/* a compare function for KX algorithms (using priorities). 
 * For use with qsort 
 */
static int
compare_algo (gnutls_session_t session, const void *i_A1,
                      const void *i_A2)
{
  cipher_suite_st A1, A2;
  gnutls_kx_algorithm_t kA1, kA2;
  gnutls_cipher_algorithm_t cA1, cA2;
  gnutls_mac_algorithm_t mA1, mA2;
  int p1, p2;
  
  memcpy(A1.suite, i_A1, 2);
  memcpy(A2.suite, i_A2, 2);

  kA1 = _gnutls_cipher_suite_get_kx_algo (&A1);
  kA2 = _gnutls_cipher_suite_get_kx_algo (&A2);
  
  cA1 = _gnutls_cipher_suite_get_cipher_algo (&A1);
  cA2 = _gnutls_cipher_suite_get_cipher_algo (&A2);
  
  mA1 = _gnutls_cipher_suite_get_mac_algo (&A1);
  mA2 = _gnutls_cipher_suite_get_mac_algo (&A2);

  p1 = (_gnutls_kx_priority (session, kA1) + 1) * 256;
  p2 = (_gnutls_kx_priority (session, kA2) + 1) * 256;
  p1 += (_gnutls_cipher_priority (session, cA1) + 1) * 16;
  p2 += (_gnutls_cipher_priority (session, cA2) + 1) * 16;
  p1 += _gnutls_mac_priority (session, mA1);
  p2 += _gnutls_mac_priority (session, mA2);

  if (p1 > p2)
    {
      return 1;
    }
  else
    {
      if (p1 == p2)
        {
          return 0;
        }
      return -1;
    }
}
