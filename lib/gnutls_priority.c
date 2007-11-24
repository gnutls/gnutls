/*
 * Copyright (C) 2004, 2005, 2006, 2007 Free Software Foundation
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

/* Here lies the code of the gnutls_*_set_priority() functions.
 */

#include "gnutls_int.h"
#include "gnutls_algorithms.h"
#include "gnutls_errors.h"
#include <gnutls_num.h>

static void
break_comma_list (char *etag,
		  char **broken_etag, int *elements, int max_elements,
		  char sep);

/**
  * gnutls_cipher_set_priority - Sets the priority on the ciphers supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_cipher_algorithm_t elements.
  *
  * Sets the priority on the ciphers supported by gnutls.
  * Priority is higher for elements specified before others.
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
  session->internals.priorities.cipher.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.priorities.cipher.priority[i] = list[i];
    }

  return 0;
}

/**
  * gnutls_kx_set_priority - Sets the priority on the key exchange algorithms supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_kx_algorithm_t elements.
  *
  * Sets the priority on the key exchange algorithms supported by gnutls.
  * Priority is higher for elements specified before others.
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
  session->internals.priorities.kx.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.priorities.kx.priority[i] = list[i];
    }

  return 0;
}

/**
  * gnutls_mac_set_priority - Sets the priority on the mac algorithms supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_mac_algorithm_t elements.
  *
  * Sets the priority on the mac algorithms supported by gnutls.
  * Priority is higher for elements specified before others.
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
  session->internals.priorities.mac.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.priorities.mac.priority[i] = list[i];
    }

  return 0;
}

/**
  * gnutls_compression_set_priority - Sets the priority on the compression algorithms supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @list: is a 0 terminated list of gnutls_compression_method_t elements.
  *
  * Sets the priority on the compression algorithms supported by gnutls.
  * Priority is higher for elements specified before others.
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
  session->internals.priorities.compression.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.priorities.compression.priority[i] = list[i];
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
  session->internals.priorities.protocol.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.priorities.protocol.priority[i] = list[i];
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
  * Priority is higher for elements specified before others.
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
  session->internals.priorities.cert_type.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.priorities.cert_type.priority[i] = list[i];
    }

  return 0;

#else

  return GNUTLS_E_UNIMPLEMENTED_FEATURE;

#endif
}

static const int protocol_priority[] = {
  /* GNUTLS_TLS1_2, -- not finalized yet! */
  GNUTLS_TLS1_1,
  GNUTLS_TLS1_0,
  GNUTLS_SSL3,
  0
};

static const int kx_priority_performance[] = {
  GNUTLS_KX_RSA,
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_DHE_DSS,
  GNUTLS_KX_PSK,
  GNUTLS_KX_DHE_PSK,
  GNUTLS_KX_SRP_RSA,
  GNUTLS_KX_SRP_DSS,
  GNUTLS_KX_SRP,
  /* GNUTLS_KX_ANON_DH: Man-in-the-middle prone, don't add!
   * GNUTLS_KX_RSA_EXPORT: Deprecated, don't add!
   */
  0
};

static const int kx_priority_export[] = {
  GNUTLS_KX_RSA,
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_DHE_DSS,
  GNUTLS_KX_PSK,
  GNUTLS_KX_DHE_PSK,
  GNUTLS_KX_SRP_RSA,
  GNUTLS_KX_SRP_DSS,
  GNUTLS_KX_SRP,
  GNUTLS_KX_RSA_EXPORT,
  0
};

static const int kx_priority_security[] = {
  /* The ciphersuites that offer forward secrecy take
   * precendance
   */
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_DHE_DSS,
  GNUTLS_KX_DHE_PSK,
  GNUTLS_KX_SRP_RSA,
  GNUTLS_KX_SRP_DSS,
  GNUTLS_KX_RSA,
  GNUTLS_KX_PSK,
  GNUTLS_KX_SRP,
  /* GNUTLS_KX_ANON_DH: Man-in-the-middle prone, don't add!
   * GNUTLS_KX_RSA_EXPORT: Deprecated, don't add!
   */
  0
};

static const int cipher_priority_performance[] = {
  GNUTLS_CIPHER_ARCFOUR_128,
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
#endif
  GNUTLS_CIPHER_AES_128_CBC,
  GNUTLS_CIPHER_3DES_CBC,
  /* GNUTLS_CIPHER_ARCFOUR_40: Insecure, don't add! */
  0
};

static const int cipher_priority_security_normal[] = {
  GNUTLS_CIPHER_AES_128_CBC,
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
#endif
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  /* GNUTLS_CIPHER_ARCFOUR_40: Insecure, don't add! */
  0
};

static const int cipher_priority_security_high[] = {
  GNUTLS_CIPHER_AES_256_CBC,
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_CAMELLIA_256_CBC,
#endif
  GNUTLS_CIPHER_AES_128_CBC,
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
#endif
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  /* GNUTLS_CIPHER_ARCFOUR_40: Insecure, don't add! */
  0
};

static const int cipher_priority_export[] = {
  GNUTLS_CIPHER_AES_128_CBC,
#ifdef	ENABLE_CAMELLIA
  GNUTLS_CIPHER_CAMELLIA_128_CBC,
#endif
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_ARCFOUR_128,
  GNUTLS_CIPHER_ARCFOUR_40,
  0
};

static const int comp_priority[] = {
  /* compression should be explicitely requested to be enabled */
  GNUTLS_COMP_NULL,
  0
};


static const int mac_priority_performance[] = {
  GNUTLS_MAC_MD5,
  GNUTLS_MAC_SHA1,
  0
};

static const int mac_priority_security[] = {
  GNUTLS_MAC_SHA1,
  GNUTLS_MAC_MD5,
  0
};

#define mac_priority_export mac_priority_security

static int cert_type_priority[] = {
  GNUTLS_CRT_X509,
  GNUTLS_CRT_OPENPGP,
  0
};

typedef void (rmadd_func)(priority_st* priority_list, int alg);

static void
prio_remove (priority_st* priority_list, int algo)
{
  int i = 0;
  int pos = -1;			/* the position of the cipher to remove */

  while (priority_list->priority[i] != 0)
    {
      if (priority_list->priority[i] == algo)
	pos = i;
      i++;
    }

  if (pos >= 0)
    {
      priority_list->priority[pos] =
	priority_list->priority[i - 1];
      priority_list->priority[i - 1] = 0;
      priority_list->algorithms--;
    }

  return;
}

static void
prio_add (priority_st* priority_list, int algo)
{
  register int i = 0;
  while (priority_list->priority[i] != 0) {
    if (algo == priority_list->priority[i]) return; /* if it exists */
    i++;
  }

  if (i < MAX_ALGOS) {
    priority_list->priority[i] = algo;
    priority_list->algorithms++;
  }

  return;
}

#define MAX_ELEMENTS 48

/**
  * gnutls_set_priority - Sets some default priority on the cipher suites supported by gnutls.
  * @session: is a #gnutls_session_t structure.
  * @priority: is a string describing priorities
  * @syntax_error: In case of an error an error string will be copied there.
  * @syntax_error_size: the length of the previous string.
  *
  * Sets some default priority on the ciphers, key exchange methods,
  * macs and compression methods. This is to avoid using the
  * gnutls_*_priority() functions, if these defaults are ok.  You may
  * override any of the following priorities by calling the
  * appropriate functions.
  *
  * The #priority option allows you to specify a semi-colon separated
  * list of the cipher priorities to enable.
  *
  * Unless the first keyword is "NONE" the defaults are:
  * Protocols: TLS1.1, TLS1.0, and SSL3.0.
  * Compression: NULL.
  * Certificate types: X.509.
  *
  * You can also use predefined sets of ciphersuites:
  * "PERFORMANCE" all the "secure" ciphersuites are enabled, 
  * limited to 128 bit ciphers and sorted by terms of speed performance.
  *
  * "NORMAL" option enables all "secure" ciphersuites 
  * limited to 128 bit ciphers and sorted by security margin.
  *
  * "HIGH" flag enables all "secure" ciphersuites 
  * including 256 bit ciphers and sorted by security margin.
  *
  * "EXPORT" all the ciphersuites are enabled, including
  * the low-security 40 bit ciphers.
  *
  * "NONE" nothing is enabled. This disables even protocols and compression
  * methods.
  *
  * Special keywords:
  * '!' or '-' appended with an algorithm will remove this algorithm.
  * '+' appended with an algorithm will add this algorithm.
  * '%COMPAT' will enable compatibility features for a server.
  *
  * To avoid collisions in order to specify a compression algorithm
  * in this string you have to prefix it with "COMP-", protocol versions with
  * "VERS-" and certificate types with "CTYPE-". All other algorithms don't need
  * a prefix.
  *
  * For key exchange algorithms when in NORMAL or HIGH levels
  * the perfect forward secrecy algorithms take precendence of the other protocols.
  * In all cases all the supported key exchange algorithms are enabled (except for the
  * RSA-EXPORT which is only enabled in EXPORT level).
  *
  * Note that although one can select very long key sizes for symmetric algorithms, 
  * to actually increase security the public key algorithms have to use longer key 
  * sizes as well.
  *
  * Examples: "NORMAL:!AES-128-CBC", "EXPORT:!VERS-TLS1.0:+COMP-DEFLATE:+CTYPE-OPENPGP",
  * "+AES-128-CBC:+RSA:+SHA1", "NORMAL".
  *
  * On syntax error GNUTLS_E_INVALID_REQUEST is returned and 0 on success.
  *
  **/
int
gnutls_set_priority(gnutls_session_t session, const char *priority,
			      char *syntax_error, size_t syntax_error_size)
{
  char *broken_list[MAX_ELEMENTS];
  int broken_list_size, i, j;
  char *darg;
  int ret, algo;
  rmadd_func* fn;

  if (priority == NULL)
    priority = "NORMAL";

  darg = gnutls_strdup (priority);
  if (darg == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  break_comma_list (darg, broken_list, &broken_list_size, MAX_ELEMENTS, ':');

  /* This is our default set of protocol version, certificate types and
   * compression methods.
   */
  if (strcasecmp (broken_list[0], "NONE") != 0) 
    {
      gnutls_protocol_set_priority (session, protocol_priority);
      gnutls_compression_set_priority (session, comp_priority);
      gnutls_certificate_type_set_priority (session, cert_type_priority);
    }

  for (i = 0; i < broken_list_size; i++)
    {
      if (strcasecmp (broken_list[i], "PERFORMANCE") == 0)
	{
	  gnutls_cipher_set_priority (session, cipher_priority_performance);
	  gnutls_kx_set_priority (session, kx_priority_performance);
	  gnutls_mac_set_priority (session, mac_priority_performance);
	}
      else if (strcasecmp (broken_list[i], "NORMAL") == 0)
	{
	  gnutls_cipher_set_priority (session,
				      cipher_priority_security_normal);
	  gnutls_kx_set_priority (session, kx_priority_security);
	  gnutls_mac_set_priority (session, mac_priority_security);
	}
      else if (strcasecmp (broken_list[i], "HIGH") == 0)
	{
	  gnutls_cipher_set_priority (session, cipher_priority_security_high);
	  gnutls_kx_set_priority (session, kx_priority_security);
	  gnutls_mac_set_priority (session, mac_priority_security);
	}
      else if (strcasecmp (broken_list[i], "EXPORT") == 0)
	{
	  gnutls_cipher_set_priority (session, cipher_priority_export);
	  gnutls_kx_set_priority (session, kx_priority_export);
	  gnutls_mac_set_priority (session, mac_priority_export);
	}			/* now check if the element is something like -ALGO */
      else if (broken_list[i][0] == '!' || broken_list[i][0] == '+' || broken_list[i][0] == '-')
	{
	  if (broken_list[i][0] == '+') fn = prio_add;
	  else fn = prio_remove;

	  if ((algo =
	       gnutls_mac_get_id (&broken_list[i][1])) != GNUTLS_MAC_UNKNOWN)
	    fn(&session->internals.priorities.mac, algo);
	  else if ((algo = gnutls_cipher_get_id (&broken_list[i][1])) !=
		   GNUTLS_CIPHER_UNKNOWN)
	    fn (&session->internals.priorities.cipher, algo);
	  else if ((algo = gnutls_kx_get_id (&broken_list[i][1])) !=
		   GNUTLS_KX_UNKNOWN)
	    fn(&session->internals.priorities.kx, algo);
	  else if (strncasecmp (&broken_list[i][1], "VERS-", 5) == 0)
	    {
	      if ((algo =
		   gnutls_protocol_get_id (&broken_list[i][6])) !=
		  GNUTLS_VERSION_UNKNOWN)
		fn(&session->internals.priorities.protocol, algo);
	    }			/* now check if the element is something like -ALGO */
	  else if (strncasecmp (&broken_list[i][1], "COMP-", 5) == 0)
	    {
	      if ((algo =
		   gnutls_compression_get_id (&broken_list[i][6])) !=
		  GNUTLS_COMP_UNKNOWN)
		fn(&session->internals.priorities.compression, algo);
	    }			/* now check if the element is something like -ALGO */
	  else if (strncasecmp (&broken_list[i][1], "CTYPE-", 6) == 0)
	    {
	      if ((algo =
		   gnutls_certificate_type_get_id (&broken_list[i][7])) !=
		  GNUTLS_CRT_UNKNOWN)
		fn(&session->internals.priorities.cert_type, algo);
	    }			/* now check if the element is something like -ALGO */
	  else
	    goto error;
	}
      else if (broken_list[i][0] == '%')
	{
	  if (strcasecmp (&broken_list[i][1], "COMPAT") == 0)
	    gnutls_session_enable_compatibility_mode (session);
	  else
	    goto error;
	}
      else
	goto error;
    }

  gnutls_free (darg);
  return 0;

error:
  gnutls_free (darg);
  if (syntax_error != NULL)
    snprintf (syntax_error, syntax_error_size, "Unknown element: %s",
	      broken_list[i]);
  return GNUTLS_E_INVALID_REQUEST;

}

/**
  * gnutls_check_priority - Checks for syntax errors the given priority string
  * @priority: is a string describing priorities
  * @syntax_error: In case of an error an error string will be copied there.
  * @syntax_error_size: the length of the previous string.
  *
  * Checks for syntax errors the given priority string. The rules are
  * described in gnutls_set_priority().
  *
  * On syntax error GNUTLS_E_INVALID_REQUEST is returned and 0 on success.
  *
  **/
int
gnutls_check_priority(const char *priority, char *syntax_error, size_t syntax_error_size)
{
gnutls_session t;
int ret;

  gnutls_init(&t, GNUTLS_SERVER);
  ret = gnutls_set_priority( t, priority, syntax_error, syntax_error_size);
  gnutls_deinit(t);

  return ret;
}


/* New priority API with strings
 */

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
	  p++;			/* move to next entry and skip white
				 * space.
				 */
	  while (*p == ' ')
	    p++;
	}
    }
  while (p != NULL && *elements < max_elements);
}

