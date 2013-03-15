/*
 * Copyright (C) 2001-2012 Free Software Foundation, Inc.
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

/* This file contains the functions needed for RSA/DSA public key
 * encryption and signatures. 
 */

#include <gnutls_int.h>
#include <gnutls_mpi.h>
#include <gnutls_pk.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_num.h>
#include "debug.h"
#include <x509/x509_int.h>
#include <x509/common.h>
#include <random.h>

/* encodes the Dss-Sig-Value structure
 */
int
_gnutls_encode_ber_rs_raw (gnutls_datum_t * sig_value, 
                           const gnutls_datum_t *r, 
                           const gnutls_datum_t *s)
{
  ASN1_TYPE sig;
  int result;

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (),
                            "GNUTLS.DSASignatureValue",
                            &sig)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = asn1_write_value( sig, "r", r->data, r->size);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return _gnutls_asn2err(result);
    }

  result = asn1_write_value( sig, "s", s->data, s->size);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return _gnutls_asn2err(result);
    }

  result = _gnutls_x509_der_encode (sig, "", sig_value, 0);
  asn1_delete_structure (&sig);

  if (result < 0)
    return gnutls_assert_val(result);

  return 0;
}

int
_gnutls_encode_ber_rs (gnutls_datum_t * sig_value, bigint_t r, bigint_t s)
{
  ASN1_TYPE sig;
  int result;

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (),
                            "GNUTLS.DSASignatureValue",
                            &sig)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_write_int (sig, "r", r, 1);
  if (result < 0)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return result;
    }

  result = _gnutls_x509_write_int (sig, "s", s, 1);
  if (result < 0)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return result;
    }

  result = _gnutls_x509_der_encode (sig, "", sig_value, 0);
  asn1_delete_structure (&sig);

  if (result < 0)
    return gnutls_assert_val(result);

  return 0;
}


/* decodes the Dss-Sig-Value structure
 */
int
_gnutls_decode_ber_rs (const gnutls_datum_t * sig_value, bigint_t * r,
                       bigint_t * s)
{
  ASN1_TYPE sig;
  int result;

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (),
                            "GNUTLS.DSASignatureValue",
                            &sig)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&sig, sig_value->data, sig_value->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_read_int (sig, "r", r);
  if (result < 0)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return result;
    }

  result = _gnutls_x509_read_int (sig, "s", s);
  if (result < 0)
    {
      gnutls_assert ();
      _gnutls_mpi_release (s);
      asn1_delete_structure (&sig);
      return result;
    }

  asn1_delete_structure (&sig);

  return 0;
}

/* some generic pk functions */

int _gnutls_pk_params_copy (gnutls_pk_params_st * dst, const gnutls_pk_params_st * src)
{
  unsigned int i, j;
  dst->params_nr = 0;

  if (src == NULL || src->params_nr == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  for (i = 0; i < src->params_nr; i++)
    {
      dst->params[i] = _gnutls_mpi_set (NULL, src->params[i]);
      if (dst->params[i] == NULL)
        {
          for (j = 0; j < i; j++)
            _gnutls_mpi_release (&dst->params[j]);
          return GNUTLS_E_MEMORY_ERROR;
        }
      dst->params_nr++;
    }

  return 0;
}

void
gnutls_pk_params_init (gnutls_pk_params_st * p)
{
  memset (p, 0, sizeof (gnutls_pk_params_st));
}

void
gnutls_pk_params_release (gnutls_pk_params_st * p)
{
  unsigned int i;
  for (i = 0; i < p->params_nr; i++)
    {
      _gnutls_mpi_release (&p->params[i]);
    }
  p->params_nr = 0;
}

void
gnutls_pk_params_clear (gnutls_pk_params_st * p)
{
  unsigned int i;
  for (i = 0; i < p->params_nr; i++)
    {
      _gnutls_mpi_clear (p->params[i]);
    }
}

int
_gnutls_pk_get_hash_algorithm (gnutls_pk_algorithm_t pk, 
                               gnutls_pk_params_st* params,
                               gnutls_digest_algorithm_t * dig,
                               unsigned int *mand)
{
  if (mand)
    {
      if (pk == GNUTLS_PK_DSA)
        *mand = 1;
      else
        *mand = 0;
    }

  return _gnutls_x509_verify_algorithm (dig,
                                        NULL, pk, params);

}

/* Writes the digest information and the digest in a DER encoded
 * structure. The digest info is allocated and stored into the info structure.
 */
int
encode_ber_digest_info (gnutls_digest_algorithm_t hash,
                        const gnutls_datum_t * digest,
                        gnutls_datum_t * output)
{
  ASN1_TYPE dinfo = ASN1_TYPE_EMPTY;
  int result;
  const char *algo;
  uint8_t *tmp_output;
  int tmp_output_size;

  algo = _gnutls_x509_mac_to_oid ((gnutls_mac_algorithm_t) hash);
  if (algo == NULL)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Hash algorithm: %d has no OID\n", hash);
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

  tmp_output_size = 0;
  asn1_der_coding (dinfo, "", NULL, &tmp_output_size, NULL);

  tmp_output = gnutls_malloc (tmp_output_size);
  if (tmp_output == NULL)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = asn1_der_coding (dinfo, "", tmp_output, &tmp_output_size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  asn1_delete_structure (&dinfo);

  output->size = tmp_output_size;
  output->data = tmp_output;

  return 0;
}

/* Reads the digest information.
 * we use DER here, although we should use BER. It works fine
 * anyway.
 */
int
decode_ber_digest_info (const gnutls_datum_t * info,
                        gnutls_digest_algorithm_t * hash,
                        uint8_t * digest, unsigned int *digest_size)
{
  ASN1_TYPE dinfo = ASN1_TYPE_EMPTY;
  int result;
  char str[1024];
  int len;

  if ((result = asn1_create_element (_gnutls_get_gnutls_asn (),
                                     "GNUTLS.DigestInfo",
                                     &dinfo)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&dinfo, info->data, info->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  len = sizeof (str) - 1;
  result = asn1_read_value (dinfo, "digestAlgorithm.algorithm", str, &len);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  *hash = _gnutls_x509_oid_to_digest (str);

  if (*hash == GNUTLS_DIG_UNKNOWN)
    {

      _gnutls_debug_log ("verify.c: HASH OID: %s\n", str);

      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return GNUTLS_E_UNKNOWN_ALGORITHM;
    }

  len = sizeof (str) - 1;
  result = asn1_read_value (dinfo, "digestAlgorithm.parameters", str, &len);
  /* To avoid permitting garbage in the parameters field, either the
     parameters field is not present, or it contains 0x05 0x00. */
  if (!(result == ASN1_ELEMENT_NOT_FOUND ||
        (result == ASN1_SUCCESS && len == ASN1_NULL_SIZE &&
         memcmp (str, ASN1_NULL, ASN1_NULL_SIZE) == 0)))
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return GNUTLS_E_ASN1_GENERIC_ERROR;
    }

  len = *digest_size;
  result = asn1_read_value (dinfo, "digest", digest, &len);
  
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      *digest_size = len;
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  *digest_size = len;
  asn1_delete_structure (&dinfo);

  return 0;
}

