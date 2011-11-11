/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2010
 * Free Software Foundation, Inc.
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

/* Do PKCS-1 RSA encryption. 
 * params is modulus, public exp.
 */
int
_gnutls_pkcs1_rsa_encrypt (gnutls_datum_t * ciphertext,
                           const gnutls_datum_t * plaintext,
                           gnutls_pk_params_st * params, 
                           unsigned btype)
{
  unsigned int i, pad;
  int ret;
  opaque *edata, *ps;
  size_t k, psize;
  size_t mod_bits;
  gnutls_datum_t to_encrypt, encrypted;

  mod_bits = _gnutls_mpi_get_nbits (params->params[0]);
  k = mod_bits / 8;
  if (mod_bits % 8 != 0)
    k++;

  if (plaintext->size > k - 11)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_ENCRYPTION_FAILED;
    }

  edata = gnutls_malloc (k);
  if (edata == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* EB = 00||BT||PS||00||D 
   * (use block type 'btype')
   */

  edata[0] = 0;
  edata[1] = btype;
  psize = k - 3 - plaintext->size;

  ps = &edata[2];
  switch (btype)
    {
    case 2:
      /* using public key */
      if (params->params_nr < RSA_PUBLIC_PARAMS)
        {
          gnutls_assert ();
          gnutls_free (edata);
          return GNUTLS_E_INTERNAL_ERROR;
        }

      ret = gnutls_rnd (GNUTLS_RND_RANDOM, ps, psize);
      if (ret < 0)
        {
          gnutls_assert ();
          gnutls_free (edata);
          return ret;
        }
      for (i = 0; i < psize; i++)
        while (ps[i] == 0)
          {
            ret = gnutls_rnd (GNUTLS_RND_RANDOM, &ps[i], 1);
            if (ret < 0)
              {
                gnutls_assert ();
                gnutls_free (edata);
                return ret;
              }
          }
      break;
    case 1:
      /* using private key */

      if (params->params_nr < RSA_PRIVATE_PARAMS)
        {
          gnutls_assert ();
          gnutls_free (edata);
          return GNUTLS_E_INTERNAL_ERROR;
        }

      for (i = 0; i < psize; i++)
        ps[i] = 0xff;
      break;
    default:
      gnutls_assert ();
      gnutls_free (edata);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ps[psize] = 0;
  memcpy (&ps[psize + 1], plaintext->data, plaintext->size);

  to_encrypt.data = edata;
  to_encrypt.size = k;

  if (btype == 2)               /* encrypt */
    ret =
      _gnutls_pk_encrypt (GNUTLS_PK_RSA, &encrypted, &to_encrypt, params);
  else                          /* sign */
    ret =
      _gnutls_pk_sign (GNUTLS_PK_RSA, &encrypted, &to_encrypt, params);

  gnutls_free (edata);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  psize = encrypted.size;
  if (psize < k)
    {
      /* padding psize */
      pad = k - psize;
      psize = k;
    }
  else if (psize == k)
    {
      /* pad = 0; 
       * no need to do anything else
       */
      ciphertext->data = encrypted.data;
      ciphertext->size = encrypted.size;
      return 0;
    }
  else
    {                           /* psize > k !!! */
      /* This is an impossible situation */
      gnutls_assert ();
      _gnutls_free_datum (&encrypted);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ciphertext->data = gnutls_malloc (psize);
  if (ciphertext->data == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  memcpy (&ciphertext->data[pad], encrypted.data, encrypted.size);
  for (i = 0; i < pad; i++)
    ciphertext->data[i] = 0;

  ciphertext->size = k;

  ret = 0;

cleanup:
  _gnutls_free_datum (&encrypted);

  return ret;
}


/* Do PKCS-1 RSA decryption. 
 * params is modulus, public exp., private key
 * Can decrypt block type 1 and type 2 packets.
 */
int
_gnutls_pkcs1_rsa_decrypt (gnutls_datum_t * plaintext,
                           const gnutls_datum_t * ciphertext,
                           gnutls_pk_params_st* params,
                           unsigned btype)
{
  unsigned int k, i;
  int ret;
  size_t esize, mod_bits;

  mod_bits = _gnutls_mpi_get_nbits (params->params[0]);
  k = mod_bits / 8;
  if (mod_bits % 8 != 0)
    k++;

  esize = ciphertext->size;

  if (esize != k)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_DECRYPTION_FAILED;
    }

  /* we can use btype to see if the private key is
   * available.
   */
  if (btype == 2)
    {
      ret =
        _gnutls_pk_decrypt (GNUTLS_PK_RSA, plaintext, ciphertext, params);
    }
  else
    {
      ret =
        _gnutls_pk_encrypt (GNUTLS_PK_RSA, plaintext, ciphertext, params);
    }

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* EB = 00||BT||PS||00||D
   * (use block type 'btype')
   *
   * From now on, return GNUTLS_E_DECRYPTION_FAILED on errors, to
   * avoid attacks similar to the one described by Bleichenbacher in:
   * "Chosen Ciphertext Attacks against Protocols Based on RSA
   * Encryption Standard PKCS #1".
   */
  if (plaintext->data[0] != 0 || plaintext->data[1] != btype)
    {
      gnutls_assert ();
      return GNUTLS_E_DECRYPTION_FAILED;
    }

  ret = GNUTLS_E_DECRYPTION_FAILED;
  switch (btype)
    {
    case 2:
      for (i = 2; i < plaintext->size; i++)
        {
          if (plaintext->data[i] == 0)
            {
              ret = 0;
              break;
            }
        }
      break;
    case 1:
      for (i = 2; i < plaintext->size; i++)
        {
          if (plaintext->data[i] == 0 && i > 2)
            {
              ret = 0;
              break;
            }
          if (plaintext->data[i] != 0xff)
            {
              _gnutls_handshake_log ("PKCS #1 padding error");
              _gnutls_free_datum (plaintext);
              /* PKCS #1 padding error.  Don't use
                 GNUTLS_E_PKCS1_WRONG_PAD here.  */
              break;
            }
        }
      break;
    default:
      gnutls_assert ();
      _gnutls_free_datum (plaintext);
      break;
    }

  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (plaintext);
      return GNUTLS_E_DECRYPTION_FAILED;
    }

  i++;
  memmove (plaintext->data, &plaintext->data[i], esize - i);
  plaintext->size = esize - i;

  return 0;
}


int
_gnutls_rsa_verify (const gnutls_datum_t * vdata,
                    const gnutls_datum_t * ciphertext, 
                    gnutls_pk_params_st * params,
                    int btype)
{

  gnutls_datum_t plain;
  int ret;

  /* decrypt signature */
  if ((ret =
       _gnutls_pkcs1_rsa_decrypt (&plain, ciphertext, params,
                                  btype)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (plain.size != vdata->size)
    {
      gnutls_assert ();
      _gnutls_free_datum (&plain);
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  if (memcmp (plain.data, vdata->data, plain.size) != 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (&plain);
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  _gnutls_free_datum (&plain);

  return 0;                     /* ok */
}

/* encodes the Dss-Sig-Value structure
 */
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
    {
      gnutls_assert ();
      return result;
    }

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
  int i, j;
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

  return _gnutls_x509_verify_algorithm ((gnutls_mac_algorithm_t *) dig,
                                        NULL, pk, params);

}
