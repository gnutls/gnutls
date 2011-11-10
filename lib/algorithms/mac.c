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

struct gnutls_hash_entry
{
  const char *name;
  const char *oid;
  gnutls_mac_algorithm_t id;
  size_t key_size;              /* in case of mac */
};
typedef struct gnutls_hash_entry gnutls_hash_entry;

static const gnutls_hash_entry hash_algorithms[] = {
  {"SHA1", HASH_OID_SHA1, GNUTLS_MAC_SHA1, 20},
  {"MD5", HASH_OID_MD5, GNUTLS_MAC_MD5, 16},
  {"SHA256", HASH_OID_SHA256, GNUTLS_MAC_SHA256, 32},
  {"SHA384", HASH_OID_SHA384, GNUTLS_MAC_SHA384, 48},
  {"SHA512", HASH_OID_SHA512, GNUTLS_MAC_SHA512, 64},
  {"SHA224", HASH_OID_SHA224, GNUTLS_MAC_SHA224, 28},
  {"AEAD", NULL, GNUTLS_MAC_AEAD, 0},
  {"MD2", HASH_OID_MD2, GNUTLS_MAC_MD2, 0},     /* not used as MAC */
  {"RIPEMD160", HASH_OID_RMD160, GNUTLS_MAC_RMD160, 20},
  {"MAC-NULL", NULL, GNUTLS_MAC_NULL, 0},
  {0, 0, 0, 0}
};


#define GNUTLS_HASH_LOOP(b) \
        const gnutls_hash_entry *p; \
                for(p = hash_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_HASH_ALG_LOOP(a) \
                        GNUTLS_HASH_LOOP( if(p->id == algorithm) { a; break; } )

int
_gnutls_mac_priority (gnutls_session_t session,
                      gnutls_mac_algorithm_t algorithm)
{                               /* actually returns the priority */
  unsigned int i;
  for (i = 0; i < session->internals.priorities.mac.algorithms; i++)
    {
      if (session->internals.priorities.mac.priority[i] == algorithm)
        return i;
    }
  return -1;
}

/**
 * gnutls_mac_get_name:
 * @algorithm: is a MAC algorithm
 *
 * Convert a #gnutls_mac_algorithm_t value to a string.
 *
 * Returns: a string that contains the name of the specified MAC
 *   algorithm, or %NULL.
 **/
const char *
gnutls_mac_get_name (gnutls_mac_algorithm_t algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_HASH_ALG_LOOP (ret = p->name);

  return ret;
}

/**
 * gnutls_mac_get_id:
 * @name: is a MAC algorithm name
 *
 * Convert a string to a #gnutls_mac_algorithm_t value.  The names are
 * compared in a case insensitive way.
 *
 * Returns: a #gnutls_mac_algorithm_t id of the specified MAC
 *   algorithm string, or %GNUTLS_MAC_UNKNOWN on failures.
 **/
gnutls_mac_algorithm_t
gnutls_mac_get_id (const char *name)
{
  gnutls_mac_algorithm_t ret = GNUTLS_MAC_UNKNOWN;

  GNUTLS_HASH_LOOP (
    if (strcasecmp (p->name, name) == 0) 
      {
        ret = p->id;
        break;
      }
  );

  return ret;
}

/**
 * gnutls_mac_get_key_size:
 * @algorithm: is an encryption algorithm
 *
 * Get size of MAC key.
 *
 * Returns: length (in bytes) of the given MAC key size, or 0 if the
 *   given MAC algorithm is invalid.
 **/
size_t
gnutls_mac_get_key_size (gnutls_mac_algorithm_t algorithm)
{
  size_t ret = 0;

  /* avoid prefix */
  GNUTLS_HASH_ALG_LOOP (ret = p->key_size);

  return ret;
}

/**
 * gnutls_mac_list:
 *
 * Get a list of hash algorithms for use as MACs.  Note that not
 * necessarily all MACs are supported in TLS cipher suites.  For
 * example, MD2 is not supported as a cipher suite, but is supported
 * for other purposes (e.g., X.509 signature verification or similar).
 *
 * This function is not thread safe.
 *
 * Returns: Return a (0)-terminated list of #gnutls_mac_algorithm_t
 *   integers indicating the available MACs.
 **/
const gnutls_mac_algorithm_t *
gnutls_mac_list (void)
{
static gnutls_mac_algorithm_t supported_macs[MAX_ALGOS] = { 0 };

  if (supported_macs[0] == 0)
    {
      int i = 0;

      GNUTLS_HASH_LOOP ( supported_macs[i++]=p->id);
      supported_macs[i++]=0;
    }

  return supported_macs;
}

const char *
_gnutls_x509_mac_to_oid (gnutls_mac_algorithm_t algorithm)
{
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_HASH_ALG_LOOP (ret = p->oid);

  return ret;
}

gnutls_mac_algorithm_t
_gnutls_x509_oid2mac_algorithm (const char *oid)
{
  gnutls_mac_algorithm_t ret = 0;

  GNUTLS_HASH_LOOP (if (p->oid && strcmp (oid, p->oid) == 0)
                    {
                    ret = p->id; break;}
  );

  if (ret == 0)
    return GNUTLS_MAC_UNKNOWN;
  return ret;
}

const char *
_gnutls_x509_digest_to_oid (gnutls_digest_algorithm_t algorithm)
{
  return _gnutls_x509_mac_to_oid ((gnutls_mac_algorithm_t) algorithm);
}

gnutls_digest_algorithm_t
_gnutls_x509_oid2digest_algorithm (const char *oid)
{
  return (gnutls_digest_algorithm_t) _gnutls_x509_oid2mac_algorithm (oid);
}

const char *
_gnutls_digest_get_name (gnutls_digest_algorithm_t algorithm)
{
  return gnutls_mac_get_name ((gnutls_digest_algorithm_t) algorithm);
}

int
_gnutls_mac_is_ok (gnutls_mac_algorithm_t algorithm)
{
  ssize_t ret = -1;
  GNUTLS_HASH_ALG_LOOP (ret = p->id);
  if (ret >= 0)
    ret = 0;
  else
    ret = 1;
  return ret;
}
