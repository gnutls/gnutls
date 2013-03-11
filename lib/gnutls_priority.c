/*
 * Copyright (C) 2004-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
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

/* Here lies the code of the gnutls_*_set_priority() functions.
 */

#include "gnutls_int.h"
#include "algorithms.h"
#include "gnutls_errors.h"
#include <gnutls_num.h>

static void
break_comma_list (char *etag,
                  char **broken_etag, int *elements, int max_elements,
                  char sep);

/**
 * gnutls_cipher_set_priority:
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_cipher_algorithm_t elements.
 *
 * Sets the priority on the ciphers supported by gnutls.  Priority is
 * higher for elements specified before others.  After specifying the
 * ciphers you want, you must append a 0.  Note that the priority is
 * set on the client. The server does not use the algorithm's
 * priority except for disabling algorithms that were not specified.
 *
 * Returns: %GNUTLS_E_SUCCESS (0) on success, or a negative error code.
 **/
int
gnutls_cipher_set_priority (gnutls_session_t session, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  session->internals.priorities.cipher.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.priorities.cipher.priority[i] = list[i];
    }

  return 0;
}

typedef void (bulk_rmadd_func) (priority_st * priority_list, const int *);

inline static void
_set_priority (priority_st * st, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  st->algorithms = num;

  for (i = 0; i < num; i++)
    {
      st->priority[i] = list[i];
    }

  return;
}

inline static void
_add_priority (priority_st * st, const int *list)
{
  int num, i, j, init;

  init = i = st->algorithms;

  for (num=0;list[num]!=0;++num)
    {
      if (i+1 > MAX_ALGOS)
        {
          return;
        }
      
      for (j=0;j<init;j++)
        {
          if (st->priority[j] == (unsigned)list[num])
            {
              break;
            }
        }

      if (j == init)
        {
          st->priority[i++] = list[num];
          st->algorithms++;
        }
    }
    
  return;
}

static void
_clear_priorities (priority_st * st, const int *list)
{
  memset(st, 0, sizeof(*st));  
}

/**
 * gnutls_kx_set_priority:
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_kx_algorithm_t elements.
 *
 * Sets the priority on the key exchange algorithms supported by
 * gnutls.  Priority is higher for elements specified before others.
 * After specifying the algorithms you want, you must append a 0.
 * Note that the priority is set on the client. The server does not
 * use the algorithm's priority except for disabling algorithms that
 * were not specified.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_kx_set_priority (gnutls_session_t session, const int *list)
{
  _set_priority (&session->internals.priorities.kx, list);
  return 0;
}

/**
 * gnutls_mac_set_priority:
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_mac_algorithm_t elements.
 *
 * Sets the priority on the mac algorithms supported by gnutls.
 * Priority is higher for elements specified before others.  After
 * specifying the algorithms you want, you must append a 0.  Note
 * that the priority is set on the client. The server does not use
 * the algorithm's priority except for disabling algorithms that were
 * not specified.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_mac_set_priority (gnutls_session_t session, const int *list)
{
  _set_priority (&session->internals.priorities.mac, list);
  return 0;
}

/**
 * gnutls_compression_set_priority:
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_compression_method_t elements.
 *
 * Sets the priority on the compression algorithms supported by
 * gnutls.  Priority is higher for elements specified before others.
 * After specifying the algorithms you want, you must append a 0.
 * Note that the priority is set on the client. The server does not
 * use the algorithm's priority except for disabling algorithms that
 * were not specified.
 *
 * TLS 1.0 does not define any compression algorithms except
 * NULL. Other compression algorithms are to be considered as gnutls
 * extensions.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_compression_set_priority (gnutls_session_t session, const int *list)
{
  _set_priority (&session->internals.priorities.compression, list);
  return 0;
}

/**
 * gnutls_protocol_set_priority:
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_protocol_t elements.
 *
 * Sets the priority on the protocol versions supported by gnutls.
 * This function actually enables or disables protocols. Newer protocol
 * versions always have highest priority.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_protocol_set_priority (gnutls_session_t session, const int *list)
{
  _set_priority (&session->internals.priorities.protocol, list);

  /* set the current version to the first in the chain.
   * This will be overridden later.
   */
  if (list)
    _gnutls_set_current_version (session, list[0]);

  return 0;
}

/**
 * gnutls_certificate_type_set_priority:
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_certificate_type_t elements.
 *
 * Sets the priority on the certificate types supported by gnutls.
 * Priority is higher for elements specified before others.
 * After specifying the types you want, you must append a 0.
 * Note that the certificate type priority is set on the client.
 * The server does not use the cert type priority except for disabling
 * types that were not specified.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_certificate_type_set_priority (gnutls_session_t session,
                                      const int *list)
{
#ifdef ENABLE_OPENPGP
  _set_priority (&session->internals.priorities.cert_type, list);
  return 0;
#else

  return GNUTLS_E_UNIMPLEMENTED_FEATURE;

#endif
}

static const int supported_ecc_normal[] = {
  GNUTLS_ECC_CURVE_SECP192R1,
  GNUTLS_ECC_CURVE_SECP224R1,
  GNUTLS_ECC_CURVE_SECP256R1,
  GNUTLS_ECC_CURVE_SECP384R1,
  GNUTLS_ECC_CURVE_SECP521R1,
  0
};

static const int supported_ecc_secure128[] = {
  GNUTLS_ECC_CURVE_SECP256R1,
  GNUTLS_ECC_CURVE_SECP384R1,
  GNUTLS_ECC_CURVE_SECP521R1,
  0
};

static const int supported_ecc_suiteb128[] = {
  GNUTLS_ECC_CURVE_SECP256R1,
  GNUTLS_ECC_CURVE_SECP384R1,
  0
};

static const int supported_ecc_suiteb192[] = {
  GNUTLS_ECC_CURVE_SECP384R1,
  0
};

static const int supported_ecc_secure192[] = {
  GNUTLS_ECC_CURVE_SECP384R1,
  GNUTLS_ECC_CURVE_SECP521R1,
  0
};

static const int protocol_priority[] = {
  GNUTLS_TLS1_2,
  GNUTLS_TLS1_1,
  GNUTLS_TLS1_0,
  GNUTLS_SSL3,
  GNUTLS_DTLS1_0,
  0
};

static const int protocol_priority_suiteb[] = {
  GNUTLS_TLS1_2,
  0
};

static const int kx_priority_performance[] = {
  GNUTLS_KX_RSA,
#ifdef ENABLE_ECDHE
  GNUTLS_KX_ECDHE_ECDSA,
  GNUTLS_KX_ECDHE_RSA,
#endif
#ifdef ENABLE_DHE
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_DHE_DSS,
#endif
  0
};

static const int kx_priority_suiteb[] = {
  GNUTLS_KX_ECDHE_ECDSA,
  0
};

static const int kx_priority_export[] = {
  GNUTLS_KX_RSA,
#ifdef ENABLE_ECDHE
  GNUTLS_KX_ECDHE_ECDSA,
  GNUTLS_KX_ECDHE_RSA,
#endif
#ifdef ENABLE_DHE
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_DHE_DSS,
#endif
#ifdef ENABLE_RSA_EXPORT
  GNUTLS_KX_RSA_EXPORT,
#endif
  0
};

static const int kx_priority_secure[] = {
  /* The ciphersuites that offer forward secrecy take
   * precedence
   */
#ifdef ENABLE_ECDHE
  GNUTLS_KX_ECDHE_ECDSA,
  GNUTLS_KX_ECDHE_RSA,
#endif
  GNUTLS_KX_RSA,
  /* KX-RSA is now ahead of DHE-RSA and DHE-DSS due to the compatibility
   * issues the DHE ciphersuites have. That is, one cannot enforce a specific
   * security level without dropping the connection. 
   */
#ifdef ENABLE_DHE
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_DHE_DSS,
#endif
  /* GNUTLS_KX_ANON_DH: Man-in-the-middle prone, don't add!
   * GNUTLS_KX_RSA_EXPORT: Deprecated, don't add!
   */
  0
};

static const int cipher_priority_performance_sw[] = {
  GNUTLS_CIPHER_ARCFOUR_128,
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_AES_128_GCM,
  GNUTLS_CIPHER_AES_256_GCM,
  0
};

/* If GCM and AES acceleration is available then prefer
 * them over anything else.
 */
static const int cipher_priority_performance_hw_aes[] = {
  GNUTLS_CIPHER_AES_128_GCM,
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_AES_256_GCM,
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
  GNUTLS_CIPHER_3DES_CBC,
  0
};

static const int cipher_priority_normal_sw[] = {
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
  GNUTLS_CIPHER_AES_128_GCM,
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
  GNUTLS_CIPHER_AES_256_GCM,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  0
};

static const int cipher_priority_normal_hw_aes[] = {
  GNUTLS_CIPHER_AES_128_GCM,
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_AES_256_GCM,
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  0
};

static const int *cipher_priority_performance = cipher_priority_performance_sw;
static const int *cipher_priority_normal = cipher_priority_normal_sw;


static const int cipher_priority_suiteb128[] = {
  GNUTLS_CIPHER_AES_128_GCM,
  GNUTLS_CIPHER_AES_256_GCM,
  0
};

static const int cipher_priority_suiteb192[] = {
  GNUTLS_CIPHER_AES_256_GCM,
  0
};


static const int cipher_priority_secure128[] = {
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
  GNUTLS_CIPHER_AES_128_GCM,
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
  GNUTLS_CIPHER_AES_256_GCM,
  0
};


static const int cipher_priority_secure192[] = {
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
  GNUTLS_CIPHER_AES_256_GCM,
  0
};

/* The same as cipher_priority_security_normal + arcfour-40. */
static const int cipher_priority_export[] = {
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_AES_256_CBC,
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
  GNUTLS_CIPHER_AES_128_GCM,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  GNUTLS_CIPHER_ARCFOUR_40,
  0
};

static const int comp_priority[] = {
  /* compression should be explicitly requested to be enabled */
  GNUTLS_COMP_NULL,
  0
};

static const int sign_priority_default[] = {
  GNUTLS_SIGN_RSA_SHA256,
  GNUTLS_SIGN_DSA_SHA256,
  GNUTLS_SIGN_ECDSA_SHA256,

  GNUTLS_SIGN_RSA_SHA384,
  GNUTLS_SIGN_ECDSA_SHA384,

  GNUTLS_SIGN_RSA_SHA512,
  GNUTLS_SIGN_ECDSA_SHA512,

  GNUTLS_SIGN_RSA_SHA224,
  GNUTLS_SIGN_DSA_SHA224,
  GNUTLS_SIGN_ECDSA_SHA224,

  GNUTLS_SIGN_RSA_SHA1,
  GNUTLS_SIGN_DSA_SHA1,
  GNUTLS_SIGN_ECDSA_SHA1,
  0
};

static const int sign_priority_suiteb128[] = {
  GNUTLS_SIGN_ECDSA_SHA256,
  GNUTLS_SIGN_ECDSA_SHA384,
  0
};

static const int sign_priority_suiteb192[] = {
  GNUTLS_SIGN_ECDSA_SHA384,
  0
};

static const int sign_priority_secure128[] = {
  GNUTLS_SIGN_RSA_SHA256,
  GNUTLS_SIGN_DSA_SHA256,
  GNUTLS_SIGN_ECDSA_SHA256,
  GNUTLS_SIGN_RSA_SHA384,
  GNUTLS_SIGN_ECDSA_SHA384,
  GNUTLS_SIGN_RSA_SHA512,
  GNUTLS_SIGN_ECDSA_SHA512,
  0
};

static const int sign_priority_secure192[] = {
  GNUTLS_SIGN_RSA_SHA384,
  GNUTLS_SIGN_ECDSA_SHA384,
  GNUTLS_SIGN_RSA_SHA512,
  GNUTLS_SIGN_ECDSA_SHA512,
  0
};

static const int mac_priority_normal[] = {
  GNUTLS_MAC_SHA1,
  GNUTLS_MAC_SHA256,
  GNUTLS_MAC_SHA384,
  GNUTLS_MAC_AEAD,
  GNUTLS_MAC_MD5,
  0
};

static const int mac_priority_suiteb128[] = {
  GNUTLS_MAC_AEAD,
  0
};

static const int mac_priority_suiteb192[] = {
  GNUTLS_MAC_AEAD,
  0
};

static const int mac_priority_secure128[] = {
  GNUTLS_MAC_SHA1,
  GNUTLS_MAC_SHA256,
  GNUTLS_MAC_SHA384,
  GNUTLS_MAC_AEAD,
  0
};

static const int mac_priority_secure192[] = {
  GNUTLS_MAC_SHA256,
  GNUTLS_MAC_SHA384,
  GNUTLS_MAC_AEAD,
  0
};

static const int cert_type_priority_default[] = {
  GNUTLS_CRT_X509,
  0
};

static const int cert_type_priority_all[] = {
  GNUTLS_CRT_X509,
  GNUTLS_CRT_OPENPGP,
  0
};

typedef void (rmadd_func) (priority_st * priority_list, unsigned int alg);

static void
prio_remove (priority_st * priority_list, unsigned int algo)
{
  int i = 0;
  int pos = -1;                 /* the position of the cipher to remove */

  while (priority_list->priority[i] != 0)
    {
      if (priority_list->priority[i] == algo)
        pos = i;
      i++;
    }

  if (pos >= 0)
    {
      priority_list->priority[pos] = priority_list->priority[i - 1];
      priority_list->priority[i - 1] = 0;
      priority_list->algorithms--;
    }

  return;
}

static void
prio_add (priority_st * priority_list, unsigned int algo)
{
  register int i = 0;
  while (priority_list->priority[i] != 0)
    {
      if (algo == priority_list->priority[i])
        return;                 /* if it exists */
      i++;
    }

  if (i < MAX_ALGOS)
    {
      priority_list->priority[i] = algo;
      priority_list->algorithms++;
    }

  return;
}


/**
 * gnutls_priority_set:
 * @session: is a #gnutls_session_t structure.
 * @priority: is a #gnutls_priority_t structure.
 *
 * Sets the priorities to use on the ciphers, key exchange methods,
 * macs and compression methods.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_priority_set (gnutls_session_t session, gnutls_priority_t priority)
{
  if (priority == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_CIPHER_SUITES;
    }

  memcpy (&session->internals.priorities, priority,
          sizeof (struct gnutls_priority_st));

  /* set the current version to the first in the chain.
   * This will be overridden later.
   */
  if (session->internals.priorities.protocol.algorithms > 0)
    _gnutls_set_current_version (session,
                                 session->internals.priorities.protocol.
                                 priority[0]);

  if (session->internals.priorities.protocol.algorithms == 0 ||
      session->internals.priorities.cipher.algorithms == 0 ||
      session->internals.priorities.mac.algorithms == 0 ||
      session->internals.priorities.kx.algorithms == 0 ||
      session->internals.priorities.compression.algorithms == 0)
    return gnutls_assert_val(GNUTLS_E_NO_PRIORITIES_WERE_SET);

  return 0;
}


#define MAX_ELEMENTS 48

#define LEVEL_NONE "NONE"
#define LEVEL_NORMAL "NORMAL"
#define LEVEL_PERFORMANCE "PERFORMANCE"
#define LEVEL_SECURE128 "SECURE128"
#define LEVEL_SECURE192 "SECURE192"
#define LEVEL_SECURE256 "SECURE256"
#define LEVEL_SUITEB128 "SUITEB128"
#define LEVEL_SUITEB192 "SUITEB192"
#define LEVEL_EXPORT "EXPORT"

static
int check_level(const char* level, gnutls_priority_t priority_cache, int add)
{
bulk_rmadd_func *func;

  if (add) func = _add_priority;
  else func = _set_priority;

  if (strcasecmp (level, LEVEL_PERFORMANCE) == 0)
    {
      func (&priority_cache->cipher,
                     cipher_priority_performance);
      func (&priority_cache->kx, kx_priority_performance);
      func (&priority_cache->mac, mac_priority_normal);
      func (&priority_cache->sign_algo,
                     sign_priority_default);
      func (&priority_cache->supported_ecc, supported_ecc_normal);

      if (priority_cache->level == 0)
        priority_cache->level = GNUTLS_SEC_PARAM_VERY_WEAK;
      return 1;
    }
  else if (strcasecmp (level, LEVEL_NORMAL) == 0)
    {
      func (&priority_cache->cipher, cipher_priority_normal);
      func (&priority_cache->kx, kx_priority_secure);
      func (&priority_cache->mac, mac_priority_normal);
      func (&priority_cache->sign_algo,
                     sign_priority_default);
      func (&priority_cache->supported_ecc, supported_ecc_normal);

      if (priority_cache->level == 0)
        priority_cache->level = GNUTLS_SEC_PARAM_VERY_WEAK;
      return 1;
    }
  else if (strcasecmp (level, LEVEL_SECURE256) == 0
           || strcasecmp (level, LEVEL_SECURE192) == 0)
    {
      func (&priority_cache->cipher,
                     cipher_priority_secure192);
      func (&priority_cache->kx, kx_priority_secure);
      func (&priority_cache->mac, mac_priority_secure192);
      func (&priority_cache->sign_algo,
                     sign_priority_secure192);
      func (&priority_cache->supported_ecc, supported_ecc_secure192);
      
      /* be conservative for now. Set the bits to correspond to 96-bit level */
      if (priority_cache->level == 0)
        priority_cache->level = GNUTLS_SEC_PARAM_LEGACY;
      return 1;
    }
  else if (strcasecmp (level, LEVEL_SECURE128) == 0
           || strcasecmp (level, "SECURE") == 0)
    {
      func (&priority_cache->cipher,
                     cipher_priority_secure128);
      func (&priority_cache->kx, kx_priority_secure);
      func (&priority_cache->mac, mac_priority_secure128);
      func (&priority_cache->sign_algo,
                     sign_priority_secure128);
      func (&priority_cache->supported_ecc, supported_ecc_secure128);

      /* be conservative for now. Set the bits to correspond to an 72-bit level */
      if (priority_cache->level == 0)
        priority_cache->level = GNUTLS_SEC_PARAM_WEAK;
      return 1;
    }
  else if (strcasecmp (level, LEVEL_SUITEB128) == 0)
    {
      func (&priority_cache->protocol, protocol_priority_suiteb);
      func (&priority_cache->cipher,
                     cipher_priority_suiteb128);
      func (&priority_cache->kx, kx_priority_suiteb);
      func (&priority_cache->mac, mac_priority_suiteb128);
      func (&priority_cache->sign_algo,
                     sign_priority_suiteb128);
      func (&priority_cache->supported_ecc, supported_ecc_suiteb128);

      if (priority_cache->level == 0)
        priority_cache->level = GNUTLS_SEC_PARAM_HIGH;
      return 1;
    }
  else if (strcasecmp (level, LEVEL_SUITEB192) == 0)
    {
      func (&priority_cache->protocol, protocol_priority_suiteb);
      func (&priority_cache->cipher,
                     cipher_priority_suiteb192);
      func (&priority_cache->kx, kx_priority_suiteb);
      func (&priority_cache->mac, mac_priority_suiteb192);
      func (&priority_cache->sign_algo,
                     sign_priority_suiteb192);
      func (&priority_cache->supported_ecc, supported_ecc_suiteb192);

      if (priority_cache->level == 0)
        priority_cache->level = GNUTLS_SEC_PARAM_ULTRA;
      return 1;
    }
  else if (strcasecmp (level, LEVEL_EXPORT) == 0)
    {
      func (&priority_cache->cipher, cipher_priority_export);
      func (&priority_cache->kx, kx_priority_export);
      func (&priority_cache->mac, mac_priority_secure128);
      func (&priority_cache->sign_algo,
                     sign_priority_default);
      func (&priority_cache->supported_ecc, supported_ecc_normal);

      if (priority_cache->level == 0)
        priority_cache->level = GNUTLS_SEC_PARAM_EXPORT;
      return 1;
    }
  return 0;
}

/**
 * gnutls_priority_init:
 * @priority_cache: is a #gnutls_prioritity_t structure.
 * @priorities: is a string describing priorities
 * @err_pos: In case of an error this will have the position in the string the error occured
 *
 * Sets priorities for the ciphers, key exchange methods, macs and
 * compression methods.
 *
 * The #priorities option allows you to specify a colon
 * separated list of the cipher priorities to enable.
 * Some keywords are defined to provide quick access
 * to common preferences.
 *
 * "PERFORMANCE" means all the "secure" ciphersuites are enabled,
 * limited to 128 bit ciphers and sorted by terms of speed
 * performance.
 *
 * "NORMAL" means all "secure" ciphersuites. The 256-bit ciphers are
 * included as a fallback only.  The ciphers are sorted by security
 * margin.
 *
 * "SECURE128" means all "secure" ciphersuites of security level 128-bit
 * or more.
 *
 * "SECURE192" means all "secure" ciphersuites of security level 192-bit
 * or more.
 *
 * "SUITEB128" means all the NSA SuiteB ciphersuites with security level
 * of 128.
 *
 * "SUITEB192" means all the NSA SuiteB ciphersuites with security level
 * of 192.
 *
 * "EXPORT" means all ciphersuites are enabled, including the
 * low-security 40 bit ciphers.
 *
 * "NONE" means nothing is enabled.  This disables even protocols and
 * compression methods.
 *
 * Special keywords are "!", "-" and "+".
 * "!" or "-" appended with an algorithm will remove this algorithm.
 * "+" appended with an algorithm will add this algorithm.
 *
 * Check the GnuTLS manual section "Priority strings" for detailed
 * information.
 *
 * Examples:
 *
 * "NONE:+VERS-TLS-ALL:+MAC-ALL:+RSA:+AES-128-CBC:+SIGN-ALL:+COMP-NULL"
 *
 * "NORMAL:-ARCFOUR-128" means normal ciphers except for ARCFOUR-128.
 *
 * "SECURE:-VERS-SSL3.0:+COMP-DEFLATE" means that only secure ciphers are
 * enabled, SSL3.0 is disabled, and libz compression enabled.
 *
 * "NONE:+VERS-TLS-ALL:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL:+SIGN-RSA-SHA1", 
 *
 * "NONE:+VERS-TLS-ALL:+AES-128-CBC:+ECDHE-RSA:+SHA1:+COMP-NULL:+SIGN-RSA-SHA1:+CURVE-SECP256R1", 
 *
 * "SECURE256:+SECURE128",
 *
 * Note that "NORMAL:%COMPAT" is the most compatible mode.
 *
 * Returns: On syntax error %GNUTLS_E_INVALID_REQUEST is returned,
 * %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_priority_init (gnutls_priority_t * priority_cache,
                      const char *priorities, const char **err_pos)
{
  char *broken_list[MAX_ELEMENTS];
  int broken_list_size = 0, i = 0, j;
  char *darg = NULL;
  int algo;
  rmadd_func *fn;
  bulk_rmadd_func *bulk_fn;

  *priority_cache = gnutls_calloc (1, sizeof (struct gnutls_priority_st));
  if (*priority_cache == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  
  if (err_pos)
    *err_pos = priorities;

  /* for now unsafe renegotiation is default on everyone. To be removed
   * when we make it the default.
   */
  (*priority_cache)->sr = SR_PARTIAL;
  (*priority_cache)->ssl3_record_version = 1;
  
  
  (*priority_cache)->max_empty_records = DEFAULT_MAX_EMPTY_RECORDS;

  if (priorities == NULL)
    priorities = LEVEL_NORMAL;

  darg = gnutls_strdup (priorities);
  if (darg == NULL)
    {
      gnutls_assert ();
      goto error;
    }

  break_comma_list (darg, broken_list, &broken_list_size, MAX_ELEMENTS, ':');
  /* This is our default set of protocol version, certificate types and
   * compression methods.
   */
  if (strcasecmp (broken_list[0], LEVEL_NONE) != 0)
    {
      _set_priority (&(*priority_cache)->protocol, protocol_priority);
      _set_priority (&(*priority_cache)->compression, comp_priority);
      _set_priority (&(*priority_cache)->cert_type, cert_type_priority_default);
      _set_priority (&(*priority_cache)->sign_algo, sign_priority_default);
      _set_priority (&(*priority_cache)->supported_ecc, supported_ecc_normal);
      (*priority_cache)->level = GNUTLS_SEC_PARAM_VERY_WEAK;
      i = 0;
    }
  else
    {
      i = 1;
    }

  for (; i < broken_list_size; i++)
    {
      if (check_level(broken_list[i], *priority_cache, 0) != 0)
        {
          continue;
        }
      else if (broken_list[i][0] == '!' || broken_list[i][0] == '+'
               || broken_list[i][0] == '-')
        {
          if (broken_list[i][0] == '+')
            {
              fn = prio_add;
              bulk_fn = _set_priority;
            }
          else
            {
              fn = prio_remove;
              bulk_fn = _clear_priorities;
            }

          if (broken_list[i][0] == '+' && check_level(&broken_list[i][1], *priority_cache, 1) != 0)
            {
              continue;
            }
          else if ((algo =
               gnutls_mac_get_id (&broken_list[i][1])) != GNUTLS_MAC_UNKNOWN)
            fn (&(*priority_cache)->mac, algo);
          else if ((algo = gnutls_cipher_get_id (&broken_list[i][1])) !=
                   GNUTLS_CIPHER_UNKNOWN)
            fn (&(*priority_cache)->cipher, algo);
          else if ((algo = gnutls_kx_get_id (&broken_list[i][1])) !=
                   GNUTLS_KX_UNKNOWN)
            fn (&(*priority_cache)->kx, algo);
          else if (strncasecmp (&broken_list[i][1], "VERS-", 5) == 0)
            {
              if (strncasecmp (&broken_list[i][1], "VERS-TLS-ALL", 12) == 0)
                {
                  bulk_fn (&(*priority_cache)->protocol,
                                 protocol_priority);
                }
              else
                {
                  if ((algo =
                       gnutls_protocol_get_id (&broken_list[i][6])) !=
                      GNUTLS_VERSION_UNKNOWN)
                    fn (&(*priority_cache)->protocol, algo);
                  else
                    goto error;

                }
            }                   /* now check if the element is something like -ALGO */
          else if (strncasecmp (&broken_list[i][1], "COMP-", 5) == 0)
            {
              if (strncasecmp (&broken_list[i][1], "COMP-ALL", 8) == 0)
                {
                  bulk_fn (&(*priority_cache)->compression,
                                 comp_priority);
                }
              else
                {
                  if ((algo =
                       gnutls_compression_get_id (&broken_list[i][6])) !=
                      GNUTLS_COMP_UNKNOWN)
                    fn (&(*priority_cache)->compression, algo);
                  else
                    goto error;
                }
            }                   /* now check if the element is something like -ALGO */
          else if (strncasecmp (&broken_list[i][1], "CURVE-", 6) == 0)
            {
              if (strncasecmp (&broken_list[i][1], "CURVE-ALL", 9) == 0)
                {
                  bulk_fn (&(*priority_cache)->supported_ecc,
                                 supported_ecc_normal);
                }
              else
                {
                  if ((algo =
                       _gnutls_ecc_curve_get_id (&broken_list[i][7])) !=
                      GNUTLS_ECC_CURVE_INVALID)
                    fn (&(*priority_cache)->supported_ecc, algo);
                  else
                    goto error;
                }
            }                   /* now check if the element is something like -ALGO */
          else if (strncasecmp (&broken_list[i][1], "CTYPE-", 6) == 0)
            {
              if (strncasecmp (&broken_list[i][1], "CTYPE-ALL", 9) == 0)
                {
                  bulk_fn (&(*priority_cache)->cert_type,
                                 cert_type_priority_all);
                }
              else
                {
                  if ((algo =
                       gnutls_certificate_type_get_id (&broken_list[i][7])) !=
                      GNUTLS_CRT_UNKNOWN)
                    fn (&(*priority_cache)->cert_type, algo);
                  else
                    goto error;
                }
            }                   /* now check if the element is something like -ALGO */
          else if (strncasecmp (&broken_list[i][1], "SIGN-", 5) == 0)
            {
              if (strncasecmp (&broken_list[i][1], "SIGN-ALL", 8) == 0)
                {
                  bulk_fn (&(*priority_cache)->sign_algo,
                                 sign_priority_default);
                }
              else
                {
                  if ((algo =
                       gnutls_sign_get_id (&broken_list[i][6])) !=
                      GNUTLS_SIGN_UNKNOWN)
                    fn (&(*priority_cache)->sign_algo, algo);
                  else
                    goto error;
                }
            }
          else if (strncasecmp (&broken_list[i][1], "MAC-ALL", 7) == 0)
            {
                  bulk_fn (&(*priority_cache)->mac,
                                mac_priority_normal);
            }
          else if (strncasecmp (&broken_list[i][1], "CIPHER-ALL", 10) == 0)
            {
                  bulk_fn (&(*priority_cache)->cipher,
                                cipher_priority_normal);
            }
          else if (strncasecmp (&broken_list[i][1], "KX-ALL", 6) == 0)
            {
                  bulk_fn (&(*priority_cache)->kx,
                                kx_priority_secure);
            }
          else
            goto error;
        }
      else if (broken_list[i][0] == '%')
        {
          if (strcasecmp (&broken_list[i][1], "COMPAT") == 0)
            {
              ENABLE_COMPAT((*priority_cache));
            }
          else if (strcasecmp (&broken_list[i][1], "NO_EXTENSIONS") == 0)
            {
              (*priority_cache)->no_extensions = 1;
            }
          else if (strcasecmp (&broken_list[i][1], "STATELESS_COMPRESSION") == 0)
            {
              (*priority_cache)->stateless_compression = 1;
            }
          else if (strcasecmp (&broken_list[i][1],
                               "VERIFY_ALLOW_SIGN_RSA_MD5") == 0)
            {
              prio_add (&(*priority_cache)->sign_algo, GNUTLS_SIGN_RSA_MD5);
              (*priority_cache)->additional_verify_flags |=
                GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5;
            }
          else if (strcasecmp (&broken_list[i][1],
                               "VERIFY_DISABLE_CRL_CHECKS") == 0)
            {
              (*priority_cache)->additional_verify_flags |=
                GNUTLS_VERIFY_DISABLE_CRL_CHECKS;
            }
          else if (strcasecmp (&broken_list[i][1],
                               "SSL3_RECORD_VERSION") == 0)
            (*priority_cache)->ssl3_record_version = 1;
          else if (strcasecmp (&broken_list[i][1],
                               "LATEST_RECORD_VERSION") == 0)
            (*priority_cache)->ssl3_record_version = 0;
          else if (strcasecmp (&broken_list[i][1],
                               "VERIFY_ALLOW_X509_V1_CA_CRT") == 0)
            (*priority_cache)->additional_verify_flags |=
              GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT;
          else if (strcasecmp (&broken_list[i][1],
                               "UNSAFE_RENEGOTIATION") == 0)
            {
              (*priority_cache)->sr = SR_UNSAFE;
            }
          else if (strcasecmp (&broken_list[i][1], "SAFE_RENEGOTIATION") == 0)
            {
              (*priority_cache)->sr = SR_SAFE;
            }
          else if (strcasecmp (&broken_list[i][1],
                               "PARTIAL_RENEGOTIATION") == 0)
            {
              (*priority_cache)->sr = SR_PARTIAL;
            }
          else if (strcasecmp (&broken_list[i][1],
                               "DISABLE_SAFE_RENEGOTIATION") == 0)
            {
              (*priority_cache)->sr = SR_DISABLED;
            }
          else if (strcasecmp (&broken_list[i][1],
                               "SERVER_PRECEDENCE") == 0)
            {
              (*priority_cache)->server_precedence = 1;
            }
          else if (strcasecmp (&broken_list[i][1],
                               "NEW_PADDING") == 0)
            {
              (*priority_cache)->new_record_padding = 1;
            }
          else
            goto error;
        }
      else
        goto error;
    }

  gnutls_free (darg);
  return 0;

error:
  if (err_pos != NULL && i < broken_list_size)
    {
      *err_pos = priorities;
      for (j = 0; j < i; j++)
        {
          (*err_pos) += strlen (broken_list[j]) + 1;
        }
    }
  gnutls_free (darg);
  gnutls_free (*priority_cache);

  return GNUTLS_E_INVALID_REQUEST;

}

/**
 * gnutls_priority_deinit:
 * @priority_cache: is a #gnutls_prioritity_t structure.
 *
 * Deinitializes the priority cache.
 **/
void
gnutls_priority_deinit (gnutls_priority_t priority_cache)
{
  gnutls_free (priority_cache);
}


/**
 * gnutls_priority_set_direct:
 * @session: is a #gnutls_session_t structure.
 * @priorities: is a string describing priorities
 * @err_pos: In case of an error this will have the position in the string the error occured
 *
 * Sets the priorities to use on the ciphers, key exchange methods,
 * macs and compression methods.  This function avoids keeping a
 * priority cache and is used to directly set string priorities to a
 * TLS session.  For documentation check the gnutls_priority_init().
 *
 * Returns: On syntax error %GNUTLS_E_INVALID_REQUEST is returned,
 * %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_priority_set_direct (gnutls_session_t session,
                            const char *priorities, const char **err_pos)
{
  gnutls_priority_t prio;
  int ret;

  ret = gnutls_priority_init (&prio, priorities, err_pos);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = gnutls_priority_set (session, prio);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  gnutls_priority_deinit (prio);

  return 0;
}

/* Breaks a list of "xxx", "yyy", to a character array, of
 * MAX_COMMA_SEP_ELEMENTS size; Note that the given string is modified.
  */
static void
break_comma_list (char *etag,
                  char **broken_etag, int *elements, int max_elements,
                  char sep)
{
  char *p = etag;
  if (sep == 0)
    sep = ',';

  *elements = 0;

  do
    {
      broken_etag[*elements] = p;

      (*elements)++;

      p = strchr (p, sep);
      if (p)
        {
          *p = 0;
          p++;                  /* move to next entry and skip white
                                 * space.
                                 */
          while (*p == ' ')
            p++;
        }
    }
  while (p != NULL && *elements < max_elements);
}

/**
 * gnutls_set_default_priority:
 * @session: is a #gnutls_session_t structure.
 *
 * Sets some default priority on the ciphers, key exchange methods,
 * macs and compression methods.
 *
 * This is the same as calling:
 *
 * gnutls_priority_set_direct (session, "NORMAL", NULL);
 *
 * This function is kept around for backwards compatibility, but
 * because of its wide use it is still fully supported.  If you wish
 * to allow users to provide a string that specify which ciphers to
 * use (which is recommended), you should use
 * gnutls_priority_set_direct() or gnutls_priority_set() instead.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_set_default_priority (gnutls_session_t session)
{
  return gnutls_priority_set_direct (session, "NORMAL", NULL);
}

/**
 * gnutls_set_default_export_priority:
 * @session: is a #gnutls_session_t structure.
 *
 * Sets some default priority on the ciphers, key exchange methods, macs
 * and compression methods.  This function also includes weak algorithms.
 *
 * This is the same as calling:
 *
 * gnutls_priority_set_direct (session, "EXPORT", NULL);
 *
 * This function is kept around for backwards compatibility, but
 * because of its wide use it is still fully supported.  If you wish
 * to allow users to provide a string that specify which ciphers to
 * use (which is recommended), you should use
 * gnutls_priority_set_direct() or gnutls_priority_set() instead.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_set_default_export_priority (gnutls_session_t session)
{
  return gnutls_priority_set_direct (session, "EXPORT", NULL);
}

/* Increases the priority of AES-GCM as it is much faster
 * than anything else if hardware support is there.
 */
void _gnutls_priority_prefer_aes_gcm(void)
{
  cipher_priority_performance = cipher_priority_performance_hw_aes;
  cipher_priority_normal = cipher_priority_normal_hw_aes;
}

/**
 * gnutls_priority_ecc_curve_list:
 * @pcache: is a #gnutls_prioritity_t structure.
 * @list: will point to an integer list
 *
 * Get a list of available elliptic curves in the priority
 * structure. 
 *
 * Returns: the number of curves, or an error code.
 * Since: 3.0
 **/
int
gnutls_priority_ecc_curve_list (gnutls_priority_t pcache, const unsigned int** list)
{
  if (pcache->supported_ecc.algorithms == 0)
    return 0;
  
  *list = pcache->supported_ecc.priority;
  return pcache->supported_ecc.algorithms;
}

/**
 * gnutls_priority_compression_list:
 * @pcache: is a #gnutls_prioritity_t structure.
 * @list: will point to an integer list
 *
 * Get a list of available compression method in the priority
 * structure. 
 *
 * Returns: the number of methods, or an error code.
 * Since: 3.0
 **/
int
gnutls_priority_compression_list (gnutls_priority_t pcache, const unsigned int** list)
{
  if (pcache->compression.algorithms == 0)
    return 0;
  
  *list = pcache->compression.priority;
  return pcache->compression.algorithms;
}

/**
 * gnutls_priority_protocol_list:
 * @pcache: is a #gnutls_prioritity_t structure.
 * @list: will point to an integer list
 *
 * Get a list of available TLS version numbers in the priority
 * structure. 
 *
 * Returns: the number of protocols, or an error code.
 * Since: 3.0
 **/
int
gnutls_priority_protocol_list (gnutls_priority_t pcache, const unsigned int** list)
{
  if (pcache->protocol.algorithms == 0)
    return 0;
  
  *list = pcache->protocol.priority;
  return pcache->protocol.algorithms;
}

/**
 * gnutls_priority_sign_list:
 * @pcache: is a #gnutls_prioritity_t structure.
 * @list: will point to an integer list
 *
 * Get a list of available signature algorithms in the priority
 * structure. 
 *
 * Returns: the number of algorithms, or an error code.
 * Since: 3.0
 **/
int
gnutls_priority_sign_list (gnutls_priority_t pcache, const unsigned int** list)
{
  if (pcache->sign_algo.algorithms == 0)
    return 0;
  
  *list = pcache->sign_algo.priority;
  return pcache->sign_algo.algorithms;
}

/**
 * gnutls_priority_certificate_type_list:
 * @pcache: is a #gnutls_prioritity_t structure.
 * @list: will point to an integer list
 *
 * Get a list of available certificate types in the priority
 * structure. 
 *
 * Returns: the number of certificate types, or an error code.
 * Since: 3.0
 **/
int
gnutls_priority_certificate_type_list (gnutls_priority_t pcache, const unsigned int** list)
{
  if (pcache->cert_type.algorithms == 0)
    return 0;
  
  *list = pcache->cert_type.priority;
  return pcache->cert_type.algorithms;
}
