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

/* signature algorithms;
 */
struct gnutls_sign_entry
{
  const char *name;
  const char *oid;
  gnutls_sign_algorithm_t id;
  gnutls_pk_algorithm_t pk;
  gnutls_digest_algorithm_t mac;
  /* See RFC 5246 HashAlgorithm and SignatureAlgorithm
     for values to use in aid struct. */
  const sign_algorithm_st aid;
};
typedef struct gnutls_sign_entry gnutls_sign_entry;

#define TLS_SIGN_AID_UNKNOWN {255, 255}
static const sign_algorithm_st unknown_tls_aid = TLS_SIGN_AID_UNKNOWN;

static const gnutls_sign_entry sign_algorithms[] = {
  {"RSA-SHA1", SIG_RSA_SHA1_OID, GNUTLS_SIGN_RSA_SHA1, GNUTLS_PK_RSA,
   GNUTLS_MAC_SHA1, {2, 1}},
  {"RSA-SHA224", SIG_RSA_SHA224_OID, GNUTLS_SIGN_RSA_SHA224, GNUTLS_PK_RSA,
   GNUTLS_MAC_SHA224, {3, 1}},
  {"RSA-SHA256", SIG_RSA_SHA256_OID, GNUTLS_SIGN_RSA_SHA256, GNUTLS_PK_RSA,
   GNUTLS_MAC_SHA256, {4, 1}},
  {"RSA-SHA384", SIG_RSA_SHA384_OID, GNUTLS_SIGN_RSA_SHA384, GNUTLS_PK_RSA,
   GNUTLS_MAC_SHA384, {5, 1}},
  {"RSA-SHA512", SIG_RSA_SHA512_OID, GNUTLS_SIGN_RSA_SHA512, GNUTLS_PK_RSA,
   GNUTLS_MAC_SHA512, {6, 1}},
  {"RSA-RMD160", SIG_RSA_RMD160_OID, GNUTLS_SIGN_RSA_RMD160, GNUTLS_PK_RSA,
   GNUTLS_MAC_RMD160, TLS_SIGN_AID_UNKNOWN},
  {"DSA-SHA1", SIG_DSA_SHA1_OID, GNUTLS_SIGN_DSA_SHA1, GNUTLS_PK_DSA,
   GNUTLS_MAC_SHA1, {2, 2}},
  {"DSA-SHA224", SIG_DSA_SHA224_OID, GNUTLS_SIGN_DSA_SHA224, GNUTLS_PK_DSA,
   GNUTLS_MAC_SHA224, {3, 2}},
  {"DSA-SHA256", SIG_DSA_SHA256_OID, GNUTLS_SIGN_DSA_SHA256, GNUTLS_PK_DSA,
   GNUTLS_MAC_SHA256, {4, 2}},
  {"RSA-MD5", SIG_RSA_MD5_OID, GNUTLS_SIGN_RSA_MD5, GNUTLS_PK_RSA,
   GNUTLS_MAC_MD5, {1, 1}},
  {"RSA-MD2", SIG_RSA_MD2_OID, GNUTLS_SIGN_RSA_MD2, GNUTLS_PK_RSA,
   GNUTLS_MAC_MD2, TLS_SIGN_AID_UNKNOWN},
  {"ECDSA-SHA1", "1.2.840.10045.4.1", GNUTLS_SIGN_ECDSA_SHA1, GNUTLS_PK_ECC, GNUTLS_MAC_SHA1, {2, 3}},
  {"ECDSA-SHA224", "1.2.840.10045.4.3.1", GNUTLS_SIGN_ECDSA_SHA224, GNUTLS_PK_ECC, GNUTLS_MAC_SHA224, {3, 3}},
  {"ECDSA-SHA256", "1.2.840.10045.4.3.2", GNUTLS_SIGN_ECDSA_SHA256, GNUTLS_PK_ECC, GNUTLS_MAC_SHA256, {4, 3}},
  {"ECDSA-SHA384", "1.2.840.10045.4.3.3", GNUTLS_SIGN_ECDSA_SHA384, GNUTLS_PK_ECC, GNUTLS_MAC_SHA384, {5, 3}},
  {"ECDSA-SHA512", "1.2.840.10045.4.3.4", GNUTLS_SIGN_ECDSA_SHA512, GNUTLS_PK_ECC, GNUTLS_MAC_SHA512, {6, 3}},
  {"GOST R 34.10-2001", SIG_GOST_R3410_2001_OID, 0, 0, 0,
   TLS_SIGN_AID_UNKNOWN},
  {"GOST R 34.10-94", SIG_GOST_R3410_94_OID, 0, 0, 0, TLS_SIGN_AID_UNKNOWN},
  {0, 0, 0, 0, 0, TLS_SIGN_AID_UNKNOWN}
};

#define GNUTLS_SIGN_LOOP(b) \
  do {								       \
    const gnutls_sign_entry *p;					       \
    for(p = sign_algorithms; p->name != NULL; p++) { b ; }	       \
  } while (0)

#define GNUTLS_SIGN_ALG_LOOP(a) \
  GNUTLS_SIGN_LOOP( if(p->id && p->id == sign) { a; break; } )

/**
 * gnutls_sign_get_name:
 * @algorithm: is a sign algorithm
 *
 * Convert a #gnutls_sign_algorithm_t value to a string.
 *
 * Returns: a string that contains the name of the specified sign
 *   algorithm, or %NULL.
 **/
const char *
gnutls_sign_get_name (gnutls_sign_algorithm_t algorithm)
{
  gnutls_sign_algorithm_t sign = algorithm;
  const char *ret = NULL;

  /* avoid prefix */
  GNUTLS_SIGN_ALG_LOOP (ret = p->name);

  return ret;
}

/**
 * gnutls_sign_list:
 *
 * Get a list of supported public key signature algorithms.
 *
 * Returns: a (0)-terminated list of #gnutls_sign_algorithm_t
 *   integers indicating the available ciphers.
 *
 **/
const gnutls_sign_algorithm_t *
gnutls_sign_list (void)
{
static gnutls_sign_algorithm_t supported_sign[MAX_ALGOS] = {0};

  if (supported_sign[0] == 0)
    {
      int i = 0;

      GNUTLS_SIGN_LOOP (supported_sign[i++]=p->id);
      supported_sign[i++]=0;
    }

  return supported_sign;
}

/**
 * gnutls_sign_get_id:
 * @name: is a MAC algorithm name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: return a #gnutls_sign_algorithm_t value corresponding to
 *   the specified cipher, or %GNUTLS_SIGN_UNKNOWN on error.
 **/
gnutls_sign_algorithm_t
gnutls_sign_get_id (const char *name)
{
  gnutls_sign_algorithm_t ret = GNUTLS_SIGN_UNKNOWN;

  GNUTLS_SIGN_LOOP (
    if (strcasecmp (p->name, name) == 0) 
      {
        ret = p->id;
        break;
      }
  );

  return ret;

}

gnutls_sign_algorithm_t
_gnutls_x509_oid2sign_algorithm (const char *oid)
{
  gnutls_sign_algorithm_t ret = 0;

  GNUTLS_SIGN_LOOP (if (p->oid && strcmp (oid, p->oid) == 0)
                    {
                      ret = p->id; 
                      break;
                    }
  );

  if (ret == 0)
    {
      _gnutls_debug_log ("Unknown SIGN OID: '%s'\n", oid);
      return GNUTLS_SIGN_UNKNOWN;
    }
  return ret;
}

gnutls_sign_algorithm_t
_gnutls_x509_pk_to_sign (gnutls_pk_algorithm_t pk, gnutls_digest_algorithm_t mac)
{
  gnutls_sign_algorithm_t ret = 0;

  GNUTLS_SIGN_LOOP (if (pk == p->pk && mac == p->mac)
                    {
                    ret = p->id; break;}
  );

  if (ret == 0)
    return GNUTLS_SIGN_UNKNOWN;
  return ret;
}

const char *
_gnutls_x509_sign_to_oid (gnutls_pk_algorithm_t pk,
                          gnutls_digest_algorithm_t mac)
{
  gnutls_sign_algorithm_t sign;
  const char *ret = NULL;

  sign = _gnutls_x509_pk_to_sign (pk, mac);
  if (sign == GNUTLS_SIGN_UNKNOWN)
    return NULL;

  GNUTLS_SIGN_ALG_LOOP (ret = p->oid);
  return ret;
}

gnutls_digest_algorithm_t
_gnutls_sign_get_hash_algorithm (gnutls_sign_algorithm_t sign)
{
  gnutls_digest_algorithm_t ret = GNUTLS_DIG_UNKNOWN;

  GNUTLS_SIGN_ALG_LOOP (ret = p->mac);

  return ret;
}

gnutls_pk_algorithm_t
_gnutls_sign_get_pk_algorithm (gnutls_sign_algorithm_t sign)
{
  gnutls_pk_algorithm_t ret = GNUTLS_PK_UNKNOWN;

  GNUTLS_SIGN_ALG_LOOP (ret = p->pk);

  return ret;
}

gnutls_sign_algorithm_t
_gnutls_tls_aid_to_sign (const sign_algorithm_st * aid)
{
  gnutls_sign_algorithm_t ret = GNUTLS_SIGN_UNKNOWN;

  if (memcmp(aid, &unknown_tls_aid, sizeof(*aid))==0)
    return ret;

  GNUTLS_SIGN_LOOP (if (p->aid.hash_algorithm == aid->hash_algorithm
                        && p->aid.sign_algorithm == aid->sign_algorithm)
                    {
                      ret = p->id; break;
                    }
  );


  return ret;
}

/* Returns NULL if a valid AID is not found
 */
const sign_algorithm_st*
_gnutls_sign_to_tls_aid (gnutls_sign_algorithm_t sign)
{
  const sign_algorithm_st * ret = NULL;

  GNUTLS_SIGN_ALG_LOOP (ret = &p->aid);

  if (ret != NULL && memcmp(ret, &unknown_tls_aid, sizeof(*ret))==0)
    return NULL;

  return ret;
}

