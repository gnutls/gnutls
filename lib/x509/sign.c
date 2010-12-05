/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2010 Free Software
 * Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* All functions which relate to X.509 certificate signing stuff are
 * included here
 */

#include <gnutls_int.h>

#ifdef ENABLE_PKI

#include <gnutls_errors.h>
#include <gnutls_cert.h>
#include <libtasn1.h>
#include <gnutls_global.h>
#include <gnutls_num.h>		/* MAX */
#include <gnutls_sig.h>
#include <gnutls_str.h>
#include <gnutls_datum.h>
#include <x509_int.h>
#include <common.h>
#include <sign.h>
#include <gnutls/abstract.h>

/* Writes the digest information and the digest in a DER encoded
 * structure. The digest info is allocated and stored into the info structure.
 */
static int
encode_ber_digest_info (gnutls_digest_algorithm_t hash,
			const gnutls_datum_t * digest,
			gnutls_datum_t * output)
{
  ASN1_TYPE dinfo = ASN1_TYPE_EMPTY;
  int result;
  const char *algo;

  algo = _gnutls_x509_mac_to_oid ((gnutls_mac_algorithm_t) hash);
  if (algo == NULL)
    {
      gnutls_assert ();
      _gnutls_x509_log ("Hash algorithm: %d\n", hash);
      return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
    }

  if ((result = asn1_create_element (_gnutls_get_gnutls_asn (),
				     "GNUTLS.DigestInfo",
				     &dinfo)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = asn1_write_value (dinfo, "digestAlgorithm.algorithm", algo, 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  /* Write an ASN.1 NULL in the parameters field.  This matches RFC
     3279 and RFC 4055, although is arguable incorrect from a historic
     perspective (see those documents for more information).
     Regardless of what is correct, this appears to be what most
     implementations do.  */
  result = asn1_write_value (dinfo, "digestAlgorithm.parameters",
			     ASN1_NULL, ASN1_NULL_SIZE);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  result = asn1_write_value (dinfo, "digest", digest->data, digest->size);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  output->size = 0;
  asn1_der_coding (dinfo, "", NULL, &output->size, NULL);

  output->data = gnutls_malloc (output->size);
  if (output->data == NULL)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = asn1_der_coding (dinfo, "", output->data, &output->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  asn1_delete_structure (&dinfo);

  return 0;
}

/* if hash==MD5 then we do RSA-MD5
 * if hash==SHA then we do RSA-SHA
 * params[0] is modulus
 * params[1] is public key
 */
int
pk_pkcs1_rsa_hash (gnutls_digest_algorithm_t hash,
		   const gnutls_datum_t * text, gnutls_datum_t * output)
{
  int ret;
  opaque _digest[MAX_HASH_SIZE];
  digest_hd_st hd;
  gnutls_datum_t digest;

  ret = _gnutls_hash_init (&hd, HASH2MAC (hash));
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_hash (&hd, text->data, text->size);
  _gnutls_hash_deinit (&hd, _digest);

  digest.data = _digest;
  digest.size = _gnutls_hash_get_algo_len (HASH2MAC (hash));

  /* Encode the digest as a DigestInfo
   */
  if ((ret = encode_ber_digest_info (hash, &digest, output)) != 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

int
pk_dsa_hash (gnutls_digest_algorithm_t hash, const gnutls_datum_t * text,
	     gnutls_datum_t * digest)
{
  int ret;
  digest_hd_st hd;

  if (hash != GNUTLS_DIG_SHA1 && hash != GNUTLS_DIG_SHA224 &&
      hash != GNUTLS_DIG_SHA256)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  digest->size = _gnutls_hash_get_algo_len (hash);
  digest->data = gnutls_malloc (digest->size);
  if (digest->data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = _gnutls_hash_init (&hd, hash);
  if (ret < 0)
    {
      gnutls_assert ();
      goto fail;
    }

  _gnutls_hash (&hd, text->data, text->size);

  _gnutls_hash_deinit (&hd, digest->data);

  return 0;

fail:
  gnutls_free (digest->data);

  return ret;
}

/* This is the same as the _gnutls_x509_sign, but this one will decode
 * the ASN1_TYPE given, and sign the DER data. Actually used to get the DER
 * of the TBS and sign it on the fly.
 */
int
_gnutls_x509_get_tbs (ASN1_TYPE cert, const char *tbs_name,
		      gnutls_datum_t * tbs)
{
  int result;
  opaque *buf;
  int buf_size;

  buf_size = 0;
  asn1_der_coding (cert, tbs_name, NULL, &buf_size, NULL);

  buf = gnutls_malloc (buf_size);
  if (buf == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = asn1_der_coding (cert, tbs_name, buf, &buf_size, NULL);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_free (buf);
      return _gnutls_asn2err (result);
    }

  tbs->data = buf;
  tbs->size = buf_size;

  return 0;
}

/*-
 * _gnutls_x509_pkix_sign - This function will sign a CRL or a certificate with a key
 * @src: should contain an ASN1_TYPE
 * @issuer: is the certificate of the certificate issuer
 * @issuer_key: holds the issuer's private key
 *
 * This function will sign a CRL or a certificate with the issuer's private key, and
 * will copy the issuer's information into the CRL or certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 -*/
int
_gnutls_x509_pkix_sign (ASN1_TYPE src, const char *src_name,
			gnutls_digest_algorithm_t dig,
			gnutls_x509_crt_t issuer, gnutls_privkey_t issuer_key)
{
  int result;
  gnutls_datum_t signature;
  gnutls_datum_t tbs;
  char name[128];

  /* Step 1. Copy the issuer's name into the certificate.
   */
  _gnutls_str_cpy (name, sizeof (name), src_name);
  _gnutls_str_cat (name, sizeof (name), ".issuer");

  result = asn1_copy_node (src, name, issuer->cert, "tbsCertificate.subject");
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  /* Step 1.5. Write the signature stuff in the tbsCertificate.
   */
  _gnutls_str_cpy (name, sizeof (name), src_name);
  _gnutls_str_cat (name, sizeof (name), ".signature");

  result = _gnutls_x509_write_sig_params (src, name,
					  gnutls_privkey_get_pk_algorithm
					  (issuer_key, NULL), dig);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  /* Step 2. Sign the certificate.
   */
  result = _gnutls_x509_get_tbs (src, src_name, &tbs);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = gnutls_privkey_sign_data (issuer_key, dig, 0, &tbs, &signature);
  gnutls_free (tbs.data);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  /* write the signature (bits)
   */
  result =
    asn1_write_value (src, "signature", signature.data, signature.size * 8);

  _gnutls_free_datum (&signature);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  /* Step 3. Move up and write the AlgorithmIdentifier, which is also
   * the same. 
   */

  result = _gnutls_x509_write_sig_params (src, "signatureAlgorithm",
					  gnutls_privkey_get_pk_algorithm
					  (issuer_key, NULL), dig);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

#endif
