/*
 * Copyright (C) 2004, 2005, 2006, 2007 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
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

/* Here lies the code of the gnutls_*_set_priority() functions.
 */

#include "gnutls_int.h"
#include "gnutls_algorithms.h"
#include "gnutls_errors.h"
#include <gnutls_num.h>

/**
  * gnutls_cipher_set_priority - Sets the priority on the ciphers supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_cipher_algorithm_t elements.
  *
  * Sets the priority on the ciphers supported by gnutls.
  * Priority is higher for ciphers specified before others.
  * After specifying the ciphers you want, you must append a 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_cipher_set_priority (gnutls_session_t session, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  session->internals.cipher_algorithm_priority.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.cipher_algorithm_priority.priority[i] = list[i];
    }

  return 0;
}

/**
  * gnutls_kx_set_priority - Sets the priority on the key exchange algorithms supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_kx_algorithm_t elements.
  *
  * Sets the priority on the key exchange algorithms supported by gnutls.
  * Priority is higher for algorithms specified before others.
  * After specifying the algorithms you want, you must append a 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  *
  * Returns 0 on success.
  *
 **/
int
gnutls_kx_set_priority (gnutls_session_t session, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  session->internals.kx_algorithm_priority.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.kx_algorithm_priority.priority[i] = list[i];
    }

  return 0;
}

/**
  * gnutls_mac_set_priority - Sets the priority on the mac algorithms supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_mac_algorithm_t elements.
  *
  * Sets the priority on the mac algorithms supported by gnutls.
  * Priority is higher for algorithms specified before others.
  * After specifying the algorithms you want, you must append a 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_mac_set_priority (gnutls_session_t session, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  session->internals.mac_algorithm_priority.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.mac_algorithm_priority.priority[i] = list[i];
    }

  return 0;
}

/**
  * gnutls_compression_set_priority - Sets the priority on the compression algorithms supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_compression_method_t elements.
  *
  * Sets the priority on the compression algorithms supported by gnutls.
  * Priority is higher for algorithms specified before others.
  * After specifying the algorithms you want, you must append a 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  *
  * TLS 1.0 does not define any compression algorithms except
  * NULL. Other compression algorithms are to be considered
  * as gnutls extensions.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_compression_set_priority (gnutls_session_t session, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  session->internals.compression_method_priority.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.compression_method_priority.priority[i] = list[i];
    }
  return 0;
}

/**
  * gnutls_protocol_set_priority - Sets the priority on the protocol versions supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_protocol_t elements.
  *
  * Sets the priority on the protocol versions supported by gnutls.
  * This function actually enables or disables protocols. Newer protocol
  * versions always have highest priority.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_protocol_set_priority (gnutls_session_t session, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  session->internals.protocol_priority.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.protocol_priority.priority[i] = list[i];
    }

  /* set the current version to the first in the chain.
   * This will be overridden later.
   */
  if (num > 0)
    _gnutls_set_current_version (session, list[0]);

  return 0;
}

/**
  * gnutls_certificate_type_set_priority - Sets the priority on the certificate types supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_certificate_type_t elements.
  *
  * Sets the priority on the certificate types supported by gnutls.
  * Priority is higher for types specified before others.
  * After specifying the types you want, you must append a 0.
  * Note that the certificate type priority is set on the client. 
  * The server does not use the cert type priority except for disabling
  * types that were not specified.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_certificate_type_set_priority (gnutls_session_t session,
				      const int *list)
{
#ifdef ENABLE_OPENPGP

  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  session->internals.cert_type_priority.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.cert_type_priority.priority[i] = list[i];
    }

  return 0;

#else

  return GNUTLS_E_UNIMPLEMENTED_FEATURE;

#endif
}

/**
  * gnutls_set_default_priority - Sets some default priority on the cipher suites supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  *
  * Sets some default priority on the ciphers, key exchange methods,
  * macs and compression methods. This is to avoid using the
  * gnutls_*_priority() functions, if these defaults are ok.  You may
  * override any of the following priorities by calling the
  * appropriate functions.
  *
  * The default order is:
  * Protocols: TLS 1.2, TLS 1.1, TLS 1.0, and SSL3.
  * Key exchange algorithm: DHE-PSK, PSK, SRP-RSA, SRP-DSS, SRP,
  * DHE-RSA, DHE-DSS, RSA.
  * Cipher: AES_256_CBC, AES_128_CBC, 3DES_CBC, and ARCFOUR_128.
  * MAC algorithm: SHA, and MD5.
  * Certificate types: X.509, OpenPGP
  * Compression: DEFLATE, NULL.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_set_default_priority (gnutls_session_t session)
{
  static const int protocol_priority[] = {
    GNUTLS_TLS1_2,
    GNUTLS_TLS1_1,
    GNUTLS_TLS1_0,
    GNUTLS_SSL3,
    0
  };
  static const int kx_priority[] = {
    GNUTLS_KX_DHE_PSK,
    GNUTLS_KX_PSK,
    GNUTLS_KX_SRP_RSA,
    GNUTLS_KX_SRP_DSS,
    GNUTLS_KX_SRP,
    GNUTLS_KX_DHE_RSA,
    GNUTLS_KX_DHE_DSS,
    GNUTLS_KX_RSA,
    /* GNUTLS_KX_ANON_DH: Man-in-the-middle prone, don't add!
     * GNUTLS_KX_RSA_EXPORT: Deprecated, don't add!
     */
    0
  };
  static const int cipher_priority[] = {
    GNUTLS_CIPHER_AES_256_CBC,
    GNUTLS_CIPHER_AES_128_CBC,
    GNUTLS_CIPHER_3DES_CBC,
    GNUTLS_CIPHER_ARCFOUR_128,
    /* GNUTLS_CIPHER_ARCFOUR_40: Insecure, don't add! */
    0
  };
  static const int comp_priority[] = {
    /* GNUTLS_COMP_LZO: Not standardized, don't add! */
    GNUTLS_COMP_DEFLATE,
    GNUTLS_COMP_NULL,
    0
  };
  static const int mac_priority[] = {
    GNUTLS_MAC_SHA1,
    GNUTLS_MAC_MD5,
    0
  };
  static int cert_type_priority[] = {
    GNUTLS_CRT_X509,
    GNUTLS_CRT_OPENPGP,
    0
  };

  gnutls_cipher_set_priority (session, cipher_priority);
  gnutls_compression_set_priority (session, comp_priority);
  gnutls_kx_set_priority (session, kx_priority);
  gnutls_protocol_set_priority (session, protocol_priority);
  gnutls_mac_set_priority (session, mac_priority);
  gnutls_certificate_type_set_priority (session, cert_type_priority);

  return 0;
}

/**
  * gnutls_set_default_export_priority - Sets some default priority on the cipher suites supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  *
  * Sets some default priority on the ciphers, key exchange methods, macs
  * and compression methods. This is to avoid using the gnutls_*_priority() functions, if
  * these defaults are ok. This function also includes weak algorithms.
  * The order is TLS1, SSL3 for protocols,  RSA, DHE_DSS, 
  * DHE_RSA, RSA_EXPORT for key exchange algorithms.
  * SHA, MD5, RIPEMD160 for MAC algorithms,
  * AES_256_CBC, AES_128_CBC, 
  * and 3DES_CBC, ARCFOUR_128, ARCFOUR_40 for ciphers.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_set_default_export_priority (gnutls_session_t session)
{
  static const int protocol_priority[] = {
    GNUTLS_TLS1, GNUTLS_SSL3, 0
  };
  static const int kx_priority[] = {
    GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA,
    GNUTLS_KX_RSA_EXPORT, 0
  };
  static const int cipher_priority[] = {
    GNUTLS_CIPHER_AES_128_CBC,
    GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR_128,
    GNUTLS_CIPHER_ARCFOUR_40, 0
  };
  static const int comp_priority[] = { GNUTLS_COMP_NULL, 0 };
  static const int mac_priority[] =
    { GNUTLS_MAC_SHA1, GNUTLS_MAC_MD5, 0 };

  gnutls_cipher_set_priority (session, cipher_priority);
  gnutls_compression_set_priority (session, comp_priority);
  gnutls_kx_set_priority (session, kx_priority);
  gnutls_protocol_set_priority (session, protocol_priority);
  gnutls_mac_set_priority (session, mac_priority);

  return 0;
}
