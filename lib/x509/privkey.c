/*
 * Copyright (C) 2003, 2004, 2005, 2007, 2008, 2009, 2010, 2011 Free Software
 * Foundation, Inc.
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
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <gnutls_rsa_export.h>
#include <gnutls_sig.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509_int.h>
#include <gnutls_pk.h>
#include <gnutls_mpi.h>
#include <gnutls_ecc.h>

/**
 * gnutls_x509_privkey_init:
 * @key: The structure to be initialized
 *
 * This function will initialize an private key structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_init (gnutls_x509_privkey_t * key)
{
  *key = gnutls_calloc (1, sizeof (gnutls_x509_privkey_int));

  if (*key)
    {
      (*key)->key = ASN1_TYPE_EMPTY;
      (*key)->pk_algorithm = GNUTLS_PK_UNKNOWN;
      return 0;                 /* success */
    }

  return GNUTLS_E_MEMORY_ERROR;
}

/**
 * gnutls_x509_privkey_deinit:
 * @key: The structure to be deinitialized
 *
 * This function will deinitialize a private key structure.
 **/
void
gnutls_x509_privkey_deinit (gnutls_x509_privkey_t key)
{
  if (!key)
    return;

  gnutls_pk_params_release(&key->params);
  asn1_delete_structure (&key->key);
  gnutls_free (key);
}

/**
 * gnutls_x509_privkey_cpy:
 * @dst: The destination key, which should be initialized.
 * @src: The source key
 *
 * This function will copy a private key from source to destination
 * key. Destination has to be initialized.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_cpy (gnutls_x509_privkey_t dst, gnutls_x509_privkey_t src)
{
  int i, ret;

  if (!src || !dst)
    return GNUTLS_E_INVALID_REQUEST;

  for (i = 0; i < src->params.params_nr; i++)
    {
      dst->params.params[i] = _gnutls_mpi_copy (src->params.params[i]);
      if (dst->params.params[i] == NULL)
        return GNUTLS_E_MEMORY_ERROR;
    }

  dst->params.params_nr = src->params.params_nr;
  dst->params.flags = src->params.flags;

  dst->pk_algorithm = src->pk_algorithm;

  ret = _gnutls_asn1_encode_privkey (dst->pk_algorithm, &dst->key, &dst->params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

/* Converts an RSA PKCS#1 key to
 * an internal structure (gnutls_private_key)
 */
ASN1_TYPE
_gnutls_privkey_decode_pkcs1_rsa_key (const gnutls_datum_t * raw_key,
                                      gnutls_x509_privkey_t pkey)
{
  int result;
  ASN1_TYPE pkey_asn;

  gnutls_pk_params_init(&pkey->params);

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (),
                            "GNUTLS.RSAPrivateKey",
                            &pkey_asn)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return NULL;
    }

  result = asn1_der_decoding (&pkey_asn, raw_key->data, raw_key->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (pkey_asn, "modulus",
                                       &pkey->params.params[0])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result =
       _gnutls_x509_read_int (pkey_asn, "publicExponent",
                              &pkey->params.params[1])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result =
       _gnutls_x509_read_int (pkey_asn, "privateExponent",
                              &pkey->params.params[2])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (pkey_asn, "prime1",
                                       &pkey->params.params[3])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (pkey_asn, "prime2",
                                       &pkey->params.params[4])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (pkey_asn, "coefficient",
                                       &pkey->params.params[5])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (pkey_asn, "exponent1",
                                       &pkey->params.params[6])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (pkey_asn, "exponent2",
                                       &pkey->params.params[7])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  result = _gnutls_pk_fixup (GNUTLS_PK_RSA, GNUTLS_IMPORT, &pkey->params);
  if (result < 0)
    {
      gnutls_assert ();
      goto error;
    }

  pkey->params.params_nr = RSA_PRIVATE_PARAMS;

  return pkey_asn;

error:
  asn1_delete_structure (&pkey_asn);
  gnutls_pk_params_release (&pkey->params);
  return NULL;

}

/* Converts an ECC key to
 * an internal structure (gnutls_private_key)
 */
ASN1_TYPE
_gnutls_privkey_decode_ecc_key (const gnutls_datum_t * raw_key,
                                      gnutls_x509_privkey_t pkey)
{
  int ret;
  ASN1_TYPE pkey_asn;
  unsigned int version;
  char oid[MAX_OID_SIZE];
  int oid_size;
  gnutls_datum out;

  gnutls_pk_params_init(&pkey->params);

  if ((ret =
       asn1_create_element (_gnutls_get_gnutls_asn (),
                            "GNUTLS.ECPrivateKey",
                            &pkey_asn)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return NULL;
    }

  ret = asn1_der_decoding (&pkey_asn, raw_key->data, raw_key->size, NULL);
  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      goto error;
    }

  ret = _gnutls_x509_read_uint (pkey_asn, "Version", &version);
  if (ret < 0)
    {
      gnutls_assert();
      goto error;
    }

  if (version != 1)
    {
      _gnutls_debug_log("ECC private key version %u is not supported\n", version);
      gnutls_assert();
      goto error;
    }

  /* read the curve */
  oid_size = sizeof(oid);
  ret = asn1_read_value(pkey_asn, "parameters.namedCurve", oid, &oid_size);
  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      goto error;
    }
    
  pkey->params.flags = _gnutls_oid_to_ecc_curve(oid);
  if (pkey->params.flags == GNUTLS_ECC_CURVE_INVALID)
    {
      _gnutls_debug_log("Curve %s is not supported\n", oid);
      gnutls_assert();
      goto error;
    }
    
  ret = _gnutls_ecc_curve_fill_params(pkey->params.flags, &pkey->params);
  if (ret < 0)
    {
      gnutls_assert();
      goto error;
    }

  /* read the public key */
  ret = _gnutls_x509_read_value(pkey_asn, "publicKey", &out, 2);
  if (ret < 0)
    {
      gnutls_assert();
      goto error;
    }

  ret = _gnutls_ecc_ansi_x963_import (out.data, out.size, &pkey->params.params[ECC_X],
                                         &pkey->params.params[ECC_Y]);
  
  _gnutls_free_datum(&out);
  if (ret < 0)
    {
      gnutls_assert();
      goto error;
    }
  pkey->params.params_nr += 2;

  /* read the private key */
  ret = _gnutls_x509_read_int (pkey_asn, "privateKey", &pkey->params.params[ECC_K]);
  if (ret < 0)
    {
      gnutls_assert();
      goto error;
    }
  pkey->params.params_nr ++;

  return pkey_asn;

error:
  asn1_delete_structure (&pkey_asn);
  gnutls_pk_params_release (&pkey->params);
  return NULL;

}


static ASN1_TYPE
decode_dsa_key (const gnutls_datum_t * raw_key, gnutls_x509_privkey_t pkey)
{
  int result;
  ASN1_TYPE dsa_asn;

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (),
                            "GNUTLS.DSAPrivateKey",
                            &dsa_asn)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return NULL;
    }

  pkey->params.params_nr = 0;

  result = asn1_der_decoding (&dsa_asn, raw_key->data, raw_key->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (dsa_asn, "p", &pkey->params.params[0])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (dsa_asn, "q", &pkey->params.params[1])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (dsa_asn, "g", &pkey->params.params[2])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (dsa_asn, "Y", &pkey->params.params[3])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  if ((result = _gnutls_x509_read_int (dsa_asn, "priv",
                                       &pkey->params.params[4])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params.params_nr++;

  return dsa_asn;

error:
  asn1_delete_structure (&dsa_asn);
  gnutls_pk_params_release(&pkey->params);
  return NULL;

}


#define PEM_KEY_DSA "DSA PRIVATE KEY"
#define PEM_KEY_RSA "RSA PRIVATE KEY"
#define PEM_KEY_ECC "EC PRIVATE KEY"

/**
 * gnutls_x509_privkey_import:
 * @key: The structure to store the parsed key
 * @data: The DER or PEM encoded certificate.
 * @format: One of DER or PEM
 *
 * This function will convert the given DER or PEM encoded key to the
 * native #gnutls_x509_privkey_t format. The output will be stored in
 * @key .
 *
 * If the key is PEM encoded it should have a header of "RSA PRIVATE
 * KEY", or "DSA PRIVATE KEY".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_import (gnutls_x509_privkey_t key,
                            const gnutls_datum_t * data,
                            gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  gnutls_datum_t _data;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _data.data = data->data;
  _data.size = data->size;

  key->pk_algorithm = GNUTLS_PK_UNKNOWN;

  /* If the Certificate is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      /* Try the first header */
      result =
        _gnutls_fbase64_decode (PEM_KEY_RSA, data->data, data->size, &out);

      if (result >= 0)
        key->pk_algorithm = GNUTLS_PK_RSA;

      if (result == GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR)
        {
          /* try for the second header */
          result =
            _gnutls_fbase64_decode (PEM_KEY_DSA, data->data, data->size,
                                    &out);

          if (result >= 0)
            key->pk_algorithm = GNUTLS_PK_DSA;

          if (result == GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR)
            {
              /* try for the second header */
              result =
                _gnutls_fbase64_decode (PEM_KEY_ECC, data->data, data->size,
                                    &out);
              if (result >= 0)
                key->pk_algorithm = GNUTLS_PK_ECC;
             }
        }

      if (result < 0)
        {
          gnutls_assert ();
          goto failover;
        }

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  if (key->pk_algorithm == GNUTLS_PK_RSA)
    {
      key->key = _gnutls_privkey_decode_pkcs1_rsa_key (&_data, key);
      if (key->key == NULL)
        gnutls_assert ();
    }
  else if (key->pk_algorithm == GNUTLS_PK_DSA)
    {
      key->key = decode_dsa_key (&_data, key);
      if (key->key == NULL)
        gnutls_assert ();
    }
  else if (key->pk_algorithm == GNUTLS_PK_ECC)
    {
      key->key = _gnutls_privkey_decode_ecc_key (&_data, key);
      if (key->key == NULL)
        gnutls_assert ();
    }
  else
    {
      /* Try decoding with both, and accept the one that
       * succeeds.
       */
      key->pk_algorithm = GNUTLS_PK_RSA;
      key->key = _gnutls_privkey_decode_pkcs1_rsa_key (&_data, key);

      if (key->key == NULL)
        {
          key->pk_algorithm = GNUTLS_PK_DSA;
          key->key = decode_dsa_key (&_data, key);
          if (key->key == NULL)
            gnutls_assert ();
        }
    }

  if (key->key == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_ASN1_DER_ERROR;
      goto failover;
    }

  if (need_free)
    _gnutls_free_datum (&_data);

  /* The key has now been decoded.
   */

  return 0;

failover:
  /* Try PKCS #8 */
#ifdef ENABLE_PKI
  if (result == GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR)
    {
      _gnutls_debug_log ("Falling back to PKCS #8 key decoding\n");
      result = gnutls_x509_privkey_import_pkcs8 (key, data, format,
                                                 NULL, GNUTLS_PKCS_PLAIN);
    }
#endif

  if (need_free)
    _gnutls_free_datum (&_data);

  return result;
}

/**
 * gnutls_x509_privkey_import_rsa_raw:
 * @key: The structure to store the parsed key
 * @m: holds the modulus
 * @e: holds the public exponent
 * @d: holds the private exponent
 * @p: holds the first prime (p)
 * @q: holds the second prime (q)
 * @u: holds the coefficient
 *
 * This function will convert the given RSA raw parameters to the
 * native #gnutls_x509_privkey_t format.  The output will be stored in
 * @key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_import_rsa_raw (gnutls_x509_privkey_t key,
                                    const gnutls_datum_t * m,
                                    const gnutls_datum_t * e,
                                    const gnutls_datum_t * d,
                                    const gnutls_datum_t * p,
                                    const gnutls_datum_t * q,
                                    const gnutls_datum_t * u)
{
  return gnutls_x509_privkey_import_rsa_raw2 (key, m, e, d, p, q, u, NULL,
                                              NULL);
}

/**
 * gnutls_x509_privkey_import_rsa_raw2:
 * @key: The structure to store the parsed key
 * @m: holds the modulus
 * @e: holds the public exponent
 * @d: holds the private exponent
 * @p: holds the first prime (p)
 * @q: holds the second prime (q)
 * @u: holds the coefficient
 * @e1: holds e1 = d mod (p-1)
 * @e2: holds e2 = d mod (q-1)
 *
 * This function will convert the given RSA raw parameters to the
 * native #gnutls_x509_privkey_t format.  The output will be stored in
 * @key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_import_rsa_raw2 (gnutls_x509_privkey_t key,
                                     const gnutls_datum_t * m,
                                     const gnutls_datum_t * e,
                                     const gnutls_datum_t * d,
                                     const gnutls_datum_t * p,
                                     const gnutls_datum_t * q,
                                     const gnutls_datum_t * u,
                                     const gnutls_datum_t * e1,
                                     const gnutls_datum_t * e2)
{
  int ret;
  size_t siz = 0;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  gnutls_pk_params_init(&key->params);

  siz = m->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[0], m->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  siz = e->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[1], e->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  siz = d->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[2], d->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  siz = p->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[3], p->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  siz = q->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[4], q->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  siz = u->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[5], u->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  if (e1 && e2)
    {
      siz = e1->size;
      if (_gnutls_mpi_scan_nz (&key->params.params[6], e1->data, siz))
        {
          gnutls_assert ();
          ret = GNUTLS_E_MPI_SCAN_FAILED;
          goto cleanup;
        }
      key->params.params_nr++;

      siz = e2->size;
      if (_gnutls_mpi_scan_nz (&key->params.params[7], e2->data, siz))
        {
          gnutls_assert ();
          ret = GNUTLS_E_MPI_SCAN_FAILED;
          goto cleanup;
        }
      key->params.params_nr++;
    }

  ret = _gnutls_pk_fixup (GNUTLS_PK_RSA, GNUTLS_IMPORT, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_asn1_encode_privkey (GNUTLS_PK_RSA, &key->key, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  key->params.params_nr = RSA_PRIVATE_PARAMS;
  key->pk_algorithm = GNUTLS_PK_RSA;

  return 0;

cleanup:
  gnutls_pk_params_release(&key->params);
  return ret;

}

/**
 * gnutls_x509_privkey_import_dsa_raw:
 * @key: The structure to store the parsed key
 * @p: holds the p
 * @q: holds the q
 * @g: holds the g
 * @y: holds the y
 * @x: holds the x
 *
 * This function will convert the given DSA raw parameters to the
 * native #gnutls_x509_privkey_t format.  The output will be stored
 * in @key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_import_dsa_raw (gnutls_x509_privkey_t key,
                                    const gnutls_datum_t * p,
                                    const gnutls_datum_t * q,
                                    const gnutls_datum_t * g,
                                    const gnutls_datum_t * y,
                                    const gnutls_datum_t * x)
{
  int ret;
  size_t siz = 0;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  siz = p->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[0], p->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }

  siz = q->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[1], q->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }

  siz = g->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[2], g->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }

  siz = y->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[3], y->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }

  siz = x->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[4], x->data, siz))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }

  ret = _gnutls_asn1_encode_privkey (GNUTLS_PK_DSA, &key->key, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  key->params.params_nr = DSA_PRIVATE_PARAMS;
  key->pk_algorithm = GNUTLS_PK_DSA;

  return 0;

cleanup:
  gnutls_pk_params_release(&key->params);
  return ret;

}

/**
 * gnutls_x509_privkey_import_ecc_raw:
 * @key: The structure to store the parsed key
 * @curve: holds the curve
 * @x: holds the x
 * @y: holds the y
 * @k: holds the k
 *
 * This function will convert the given elliptic curve parameters to the
 * native #gnutls_x509_privkey_t format.  The output will be stored
 * in @key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_x509_privkey_import_ecc_raw (gnutls_x509_privkey_t key,
                                    gnutls_ecc_curve_t curve,
                                    const gnutls_datum_t * x,
                                    const gnutls_datum_t * y,
                                    const gnutls_datum_t * k)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  key->params.flags = curve;

  ret = _gnutls_ecc_curve_fill_params(curve, &key->params);
  if (ret < 0)
    return gnutls_assert_val(ret);

  if (_gnutls_mpi_scan_nz (&key->params.params[ECC_X], x->data, x->size))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  if (_gnutls_mpi_scan_nz (&key->params.params[ECC_Y], y->data, y->size))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  if (_gnutls_mpi_scan_nz (&key->params.params[ECC_K], k->data, k->size))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MPI_SCAN_FAILED;
      goto cleanup;
    }
  key->params.params_nr++;

  key->pk_algorithm = GNUTLS_PK_ECC;

  return 0;

cleanup:
  gnutls_pk_params_release(&key->params);
  return ret;

}


/**
 * gnutls_x509_privkey_get_pk_algorithm:
 * @key: should contain a #gnutls_x509_privkey_t structure
 *
 * This function will return the public key algorithm of a private
 * key.
 *
 * Returns: a member of the #gnutls_pk_algorithm_t enumeration on
 *   success, or a negative error code on error.
 **/
int
gnutls_x509_privkey_get_pk_algorithm (gnutls_x509_privkey_t key)
{
  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return key->pk_algorithm;
}

/**
 * gnutls_x509_privkey_export:
 * @key: Holds the key
 * @format: the format of output params. One of PEM or DER.
 * @output_data: will contain a private key PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the private key to a PKCS1 structure for
 * RSA keys, or an integer sequence for DSA keys.  The DSA keys are in
 * the same format with the parameters used by openssl.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@output_data_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER
 * will be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN RSA PRIVATE KEY".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_export (gnutls_x509_privkey_t key,
                            gnutls_x509_crt_fmt_t format, void *output_data,
                            size_t * output_data_size)
{
  const char *msg;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (key->pk_algorithm == GNUTLS_PK_RSA)
    msg = PEM_KEY_RSA;
  else if (key->pk_algorithm == GNUTLS_PK_DSA)
    msg = PEM_KEY_DSA;
  else if (key->pk_algorithm == GNUTLS_PK_ECC)
    msg = PEM_KEY_ECC;
  else
    msg = "UNKNOWN";

  return _gnutls_x509_export_int (key->key, format, msg,
                                  output_data, output_data_size);
}

/**
 * gnutls_x509_privkey_sec_param:
 * @key: a key structure
 *
 * This function will return the security parameter appropriate with
 * this private key.
 *
 * Returns: On success, a valid security parameter is returned otherwise
 * %GNUTLS_SEC_PARAM_UNKNOWN is returned.
 *
 * Since: 2.12.0
 **/
gnutls_sec_param_t
gnutls_x509_privkey_sec_param (gnutls_x509_privkey_t key)
{
  int bits;

  bits = pubkey_to_bits(key->pk_algorithm, &key->params);
  if (bits <= 0)
    return GNUTLS_SEC_PARAM_UNKNOWN;
  
  return gnutls_pk_bits_to_sec_param(key->pk_algorithm, bits);
}

/**
 * gnutls_x509_privkey_export_ecc_raw:
 * @key: a structure that holds the rsa parameters
 * @curve: will hold the curve
 * @x: will hold the x coordinate
 * @y: will hold the y coordinate
 * @k: will hold the private key
 *
 * This function will export the ECC private key's parameters found
 * in the given structure. The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int gnutls_x509_privkey_export_ecc_raw (gnutls_x509_privkey_t key, 
                                        gnutls_ecc_curve_t *curve,  
                                        gnutls_datum_t * x, gnutls_datum_t * y,
                                        gnutls_datum_t* k)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  *curve = key->params.flags;

  /* X */
  ret = _gnutls_mpi_dprint_lz (key->params.params[ECC_X], x);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* Y */
  ret = _gnutls_mpi_dprint_lz (key->params.params[ECC_Y], y);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (x);
      return ret;
    }


  /* K */
  ret = _gnutls_mpi_dprint_lz (key->params.params[ECC_K], k);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (x);
      _gnutls_free_datum (y);
      return ret;
    }

  return 0;

}

/**
 * gnutls_x509_privkey_export_rsa_raw:
 * @key: a structure that holds the rsa parameters
 * @m: will hold the modulus
 * @e: will hold the public exponent
 * @d: will hold the private exponent
 * @p: will hold the first prime (p)
 * @q: will hold the second prime (q)
 * @u: will hold the coefficient
 *
 * This function will export the RSA private key's parameters found
 * in the given structure. The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_export_rsa_raw (gnutls_x509_privkey_t key,
                                    gnutls_datum_t * m, gnutls_datum_t * e,
                                    gnutls_datum_t * d, gnutls_datum_t * p,
                                    gnutls_datum_t * q, gnutls_datum_t * u)
{

  return gnutls_x509_privkey_export_rsa_raw2 (key, m, e, d, p, q, u, NULL,
                                              NULL);
}

/**
 * gnutls_x509_privkey_export_rsa_raw2:
 * @key: a structure that holds the rsa parameters
 * @m: will hold the modulus
 * @e: will hold the public exponent
 * @d: will hold the private exponent
 * @p: will hold the first prime (p)
 * @q: will hold the second prime (q)
 * @u: will hold the coefficient
 * @e1: will hold e1 = d mod (p-1)
 * @e2: will hold e2 = d mod (q-1)
 *
 * This function will export the RSA private key's parameters found
 * in the given structure. The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_x509_privkey_export_rsa_raw2 (gnutls_x509_privkey_t key,
                                     gnutls_datum_t * m, gnutls_datum_t * e,
                                     gnutls_datum_t * d, gnutls_datum_t * p,
                                     gnutls_datum_t * q, gnutls_datum_t * u,
                                     gnutls_datum_t * e1, gnutls_datum_t * e2)
{
  int ret;
  gnutls_pk_params_st pk_params;
  
  gnutls_pk_params_init(&pk_params);

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  m->data = e->data = d->data = p->data = q->data = u->data = NULL;
  m->size = e->size = d->size = p->size = q->size = u->size = 0;

  ret = _gnutls_pk_params_copy (&pk_params, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_pk_fixup (GNUTLS_PK_RSA, GNUTLS_EXPORT, &pk_params);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  ret = _gnutls_mpi_dprint_lz (pk_params.params[0], m);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* E */
  ret = _gnutls_mpi_dprint_lz (pk_params.params[1], e);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* D */
  ret = _gnutls_mpi_dprint_lz (pk_params.params[2], d);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* P */
  ret = _gnutls_mpi_dprint_lz (pk_params.params[3], p);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* Q */
  ret = _gnutls_mpi_dprint_lz (pk_params.params[4], q);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* U */
  ret = _gnutls_mpi_dprint_lz (key->params.params[5], u);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* E1 */
  if (e1)
    {
      ret = _gnutls_mpi_dprint_lz (key->params.params[6], e1);
      if (ret < 0)
        {
          gnutls_assert ();
          goto error;
        }
    }

  /* E2 */
  if (e2)
    {
      ret = _gnutls_mpi_dprint_lz (key->params.params[7], e2);
      if (ret < 0)
        {
          gnutls_assert ();
          goto error;
        }
    }

  gnutls_pk_params_release (&pk_params);

  return 0;

error:
  _gnutls_free_datum (m);
  _gnutls_free_datum (d);
  _gnutls_free_datum (e);
  _gnutls_free_datum (p);
  _gnutls_free_datum (q);
  gnutls_pk_params_release (&pk_params);

  return ret;
}

/**
 * gnutls_x509_privkey_export_dsa_raw:
 * @key: a structure that holds the DSA parameters
 * @p: will hold the p
 * @q: will hold the q
 * @g: will hold the g
 * @y: will hold the y
 * @x: will hold the x
 *
 * This function will export the DSA private key's parameters found
 * in the given structure. The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_export_dsa_raw (gnutls_x509_privkey_t key,
                                    gnutls_datum_t * p, gnutls_datum_t * q,
                                    gnutls_datum_t * g, gnutls_datum_t * y,
                                    gnutls_datum_t * x)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* P */
  ret = _gnutls_mpi_dprint_lz (key->params.params[0], p);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* Q */
  ret = _gnutls_mpi_dprint_lz (key->params.params[1], q);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      return ret;
    }


  /* G */
  ret = _gnutls_mpi_dprint_lz (key->params.params[2], g);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      _gnutls_free_datum (q);
      return ret;
    }


  /* Y */
  ret = _gnutls_mpi_dprint_lz (key->params.params[3], y);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      _gnutls_free_datum (g);
      _gnutls_free_datum (q);
      return ret;
    }

  /* X */
  ret = _gnutls_mpi_dprint_lz (key->params.params[4], x);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (y);
      _gnutls_free_datum (p);
      _gnutls_free_datum (g);
      _gnutls_free_datum (q);
      return ret;
    }

  return 0;
}

/**
 * gnutls_x509_privkey_generate:
 * @key: should contain a #gnutls_x509_privkey_t structure
 * @algo: is one of the algorithms in #gnutls_pk_algorithm_t.
 * @bits: the size of the modulus
 * @flags: unused for now.  Must be 0.
 *
 * This function will generate a random private key. Note that this
 * function must be called on an empty private key.
 *
 * Do not set the number of bits directly, use gnutls_sec_param_to_pk_bits().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_generate (gnutls_x509_privkey_t key,
                              gnutls_pk_algorithm_t algo, unsigned int bits,
                              unsigned int flags)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  gnutls_pk_params_init(&key->params);
  
  if (algo == GNUTLS_PK_ECC)
    bits = _gnutls_ecc_bits_to_curve(bits);

  ret = _gnutls_pk_generate (algo, bits, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_asn1_encode_privkey (algo, &key->key, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }
  key->pk_algorithm = algo;

  return 0;

cleanup:
  key->pk_algorithm = GNUTLS_PK_UNKNOWN;
  gnutls_pk_params_release(&key->params);

  return ret;
}

/**
 * gnutls_x509_privkey_verify_params:
 * @key: should contain a #gnutls_x509_privkey_t structure
 *
 * This function will verify the private key parameters.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_verify_params (gnutls_x509_privkey_t key)
{
  int ret;

  ret = _gnutls_pk_verify_params (key->pk_algorithm, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

/**
 * gnutls_x509_privkey_get_key_id:
 * @key: Holds the key
 * @flags: should be 0 for now
 * @output_data: will contain the key ID
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will return a unique ID the depends on the public key
 * parameters. This ID can be used in checking whether a certificate
 * corresponds to the given key.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@output_data_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.  The output will normally be a SHA-1 hash output,
 * which is 20 bytes.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_get_key_id (gnutls_x509_privkey_t key,
                                unsigned int flags,
                                unsigned char *output_data,
                                size_t * output_data_size)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_get_key_id(key->pk_algorithm, &key->params, output_data, output_data_size);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  return ret;
}


#ifdef ENABLE_PKI
/*-
 * _gnutls_x509_privkey_sign_hash2:
 * @signer: Holds the signer's key
 * @hash_algo: The hash algorithm used
 * @hash_data: holds the data to be signed
 * @signature: will contain newly allocated signature
 * @flags: (0) for now
 *
 * This function will sign the given hashed data using a signature algorithm
 * supported by the private key. Signature algorithms are always used
 * together with a hash functions.  Different hash functions may be
 * used for the RSA algorithm, but only SHA-1,SHA-224 and SHA-256 
 * for the DSA keys, depending on their bit size.
 *
 * Use gnutls_x509_crt_get_preferred_hash_algorithm() to determine
 * the hash algorithm.
 *
 * The RSA algorithm is used in PKCS #1 v1.5 mode.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 -*/
static int
_gnutls_x509_privkey_sign_hash2 (gnutls_x509_privkey_t signer,
                                gnutls_digest_algorithm_t hash_algo,
                                unsigned int flags,
                                const gnutls_datum_t * hash_data,
                                gnutls_datum_t * signature)
{
  int ret;
  gnutls_datum_t digest;

  digest.data = gnutls_malloc (hash_data->size);
  if (digest.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  digest.size = hash_data->size;
  memcpy (digest.data, hash_data->data, digest.size);

  ret = pk_prepare_hash (signer->pk_algorithm, hash_algo, &digest);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_soft_sign (signer->pk_algorithm, &signer->params,
                           &digest, signature);

  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = 0;

cleanup:
  _gnutls_free_datum (&digest);
  return ret;
}

/**
 * gnutls_x509_privkey_sign_hash:
 * @key: Holds the key
 * @hash: holds the data to be signed
 * @signature: will contain newly allocated signature
 *
 * This function will sign the given hash using the private key. Do not
 * use this function directly unless you know what it is. Typical signing
 * requires the data to be hashed and stored in special formats 
 * (e.g. BER Digest-Info for RSA).
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Deprecated in: 2.12.0
 */
int
gnutls_x509_privkey_sign_hash (gnutls_x509_privkey_t key,
                               const gnutls_datum_t * hash,
                               gnutls_datum_t * signature)
{
  int result;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_soft_sign (key->pk_algorithm, &key->params,
                              hash, signature);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_privkey_sign_data:
 * @key: Holds the key
 * @digest: should be MD5 or SHA1
 * @flags: should be 0 for now
 * @data: holds the data to be signed
 * @signature: will contain the signature
 * @signature_size: holds the size of signature (and will be replaced
 *   by the new size)
 *
 * This function will sign the given data using a signature algorithm
 * supported by the private key. Signature algorithms are always used
 * together with a hash functions.  Different hash functions may be
 * used for the RSA algorithm, but only SHA-1 for the DSA keys.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@signature_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * Use gnutls_x509_crt_get_preferred_hash_algorithm() to determine
 * the hash algorithm.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Deprecated: Use gnutls_privkey_sign_data().
 */
int
gnutls_x509_privkey_sign_data (gnutls_x509_privkey_t key,
                               gnutls_digest_algorithm_t digest,
                               unsigned int flags,
                               const gnutls_datum_t * data,
                               void *signature, size_t * signature_size)
{
  int result;
  gnutls_datum_t sig = { NULL, 0 };
  gnutls_datum_t hash;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result =
    pk_hash_data (key->pk_algorithm, digest, &key->params, data, &hash);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result =
    _gnutls_x509_privkey_sign_hash2 (key, digest, flags, &hash, signature);

  _gnutls_free_datum(&hash);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }
    
  if (*signature_size < sig.size)
    {
      *signature_size = sig.size;
      _gnutls_free_datum (&sig);
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  *signature_size = sig.size;
  memcpy (signature, sig.data, sig.size);

  _gnutls_free_datum (&sig);

  return 0;
}


/**
 * gnutls_x509_privkey_fix:
 * @key: Holds the key
 *
 * This function will recalculate the secondary parameters in a key.
 * In RSA keys, this can be the coefficient and exponent1,2.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_fix (gnutls_x509_privkey_t key)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  asn1_delete_structure (&key->key);

  ret = _gnutls_asn1_encode_privkey (key->pk_algorithm, &key->key, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

#endif
