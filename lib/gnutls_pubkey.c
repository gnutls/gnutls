/*
 * GnuTLS PKCS#11 support
 * Copyright (C) 2010,2011 Free Software Foundation
 * 
 * Author: Nikos Mavrogiannopoulos
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
 */

#include <gnutls_int.h>
#include <gnutls/pkcs11.h>
#include <stdio.h>
#include <string.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <pkcs11_int.h>
#include <gnutls/abstract.h>
#include <gnutls_sig.h>
#include <gnutls_pk.h>
#include <x509_int.h>
#include <openpgp/openpgp_int.h>
#include <gnutls_num.h>
#include <x509/common.h>
#include <x509_b64.h>
#include <abstract_int.h>
#include <gnutls_ecc.h>

#define PK_PEM_HEADER "PUBLIC KEY"

#define OPENPGP_KEY_PRIMARY 2
#define OPENPGP_KEY_SUBKEY 1

struct gnutls_pubkey_st
{
  gnutls_pk_algorithm_t pk_algorithm;
  unsigned int bits;            /* an indication of the security parameter */

  /* the size of params depends on the public
   * key algorithm
   * RSA: [0] is modulus
   *      [1] is public exponent
   * DSA: [0] is p
   *      [1] is q
   *      [2] is g
   *      [3] is public key
   */
  gnutls_pk_params_st params;

  uint8_t openpgp_key_id[GNUTLS_OPENPGP_KEYID_SIZE];
  int openpgp_key_id_set;

  unsigned int key_usage;       /* bits from GNUTLS_KEY_* */
};

int pubkey_to_bits(gnutls_pk_algorithm_t pk, gnutls_pk_params_st* params)
{
  switch(pk) 
    {
      case GNUTLS_PK_RSA:
        return _gnutls_mpi_get_nbits(params->params[0]);
      case GNUTLS_PK_DSA:
        return _gnutls_mpi_get_nbits(params->params[3]);
      case GNUTLS_PK_ECC:
        return gnutls_ecc_curve_get_size(params->flags)*8;
      default:
        return 0;
    }
}

/**
 * gnutls_pubkey_get_pk_algorithm:
 * @key: should contain a #gnutls_pubkey_t structure
 * @bits: If set will return the number of bits of the parameters (may be NULL)
 *
 * This function will return the public key algorithm of a public
 * key and if possible will return a number of bits that indicates
 * the security parameter of the key.
 *
 * Returns: a member of the #gnutls_pk_algorithm_t enumeration on
 *   success, or a negative error code on error.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_get_pk_algorithm (gnutls_pubkey_t key, unsigned int *bits)
{
  if (bits)
    *bits = key->bits;

  return key->pk_algorithm;
}

/**
 * gnutls_pubkey_get_key_usage:
 * @key: should contain a #gnutls_pubkey_t structure
 * @usage: If set will return the number of bits of the parameters (may be NULL)
 *
 * This function will return the key usage of the public key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_get_key_usage (gnutls_pubkey_t key, unsigned int *usage)
{
  if (usage)
    *usage = key->key_usage;

  return 0;
}

/**
 * gnutls_pubkey_init:
 * @key: The structure to be initialized
 *
 * This function will initialize an public key structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_init (gnutls_pubkey_t * key)
{
  *key = gnutls_calloc (1, sizeof (struct gnutls_pubkey_st));
  if (*key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  return 0;
}

/**
 * gnutls_pubkey_deinit:
 * @key: The structure to be deinitialized
 *
 * This function will deinitialize a public key structure.
 *
 * Since: 2.12.0
 **/
void
gnutls_pubkey_deinit (gnutls_pubkey_t key)
{
  if (!key)
    return;
  gnutls_pk_params_release (&key->params);
  gnutls_free (key);
}

/**
 * gnutls_pubkey_import_x509:
 * @key: The public key
 * @crt: The certificate to be imported
 * @flags: should be zero
 *
 * This function will import the given public key to the abstract
 * #gnutls_pubkey_t structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_import_x509 (gnutls_pubkey_t key, gnutls_x509_crt_t crt,
                           unsigned int flags)
{
  int ret;

  key->pk_algorithm = gnutls_x509_crt_get_pk_algorithm (crt, &key->bits);

  ret = gnutls_x509_crt_get_key_usage (crt, &key->key_usage, NULL);
  if (ret < 0)
    key->key_usage = 0;

  ret = _gnutls_x509_crt_get_mpis (crt, &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

/**
 * gnutls_pubkey_import_privkey:
 * @key: The public key
 * @pkey: The private key
 * @usage: GNUTLS_KEY_* key usage flags.
 * @flags: should be zero
 *
 * Imports the public key from a private.  This function will import
 * the given public key to the abstract #gnutls_pubkey_t structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_import_privkey (gnutls_pubkey_t key, gnutls_privkey_t pkey,
                              unsigned int usage, unsigned int flags)
{
  key->pk_algorithm = gnutls_privkey_get_pk_algorithm (pkey, &key->bits);

  key->key_usage = usage;

  return _gnutls_privkey_get_public_mpis (pkey, &key->params);
}

/**
 * gnutls_pubkey_get_preferred_hash_algorithm:
 * @key: Holds the certificate
 * @hash: The result of the call with the hash algorithm used for signature
 * @mand: If non zero it means that the algorithm MUST use this hash. May be NULL.
 *
 * This function will read the certifcate and return the appropriate digest
 * algorithm to use for signing with this certificate. Some certificates (i.e.
 * DSA might not be able to sign without the preferred algorithm).
 *
 * Returns: the 0 if the hash algorithm is found. A negative error code is
 * returned on error.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_get_preferred_hash_algorithm (gnutls_pubkey_t key,
                                            gnutls_digest_algorithm_t *
                                            hash, unsigned int *mand)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_pk_get_hash_algorithm (key->pk_algorithm,
                                       &key->params,
                                       hash, mand);

  return ret;
}

#ifdef ENABLE_PKCS11

/**
 * gnutls_pubkey_import_pkcs11:
 * @key: The public key
 * @obj: The parameters to be imported
 * @flags: should be zero
 *
 * Imports a public key from a pkcs11 key. This function will import
 * the given public key to the abstract #gnutls_pubkey_t structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_import_pkcs11 (gnutls_pubkey_t key,
                             gnutls_pkcs11_obj_t obj, unsigned int flags)
{
  int ret;

  ret = gnutls_pkcs11_obj_get_type (obj);
  if (ret != GNUTLS_PKCS11_OBJ_PUBKEY)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  key->key_usage = obj->key_usage;

  switch (obj->pk_algorithm)
    {
    case GNUTLS_PK_RSA:
      ret = gnutls_pubkey_import_rsa_raw (key, &obj->pubkey[0],
                                          &obj->pubkey[1]);
      break;
    case GNUTLS_PK_DSA:
      ret = gnutls_pubkey_import_dsa_raw (key, &obj->pubkey[0],
                                          &obj->pubkey[1],
                                          &obj->pubkey[2], &obj->pubkey[3]);
      break;
    case GNUTLS_PK_ECC:
      ret = gnutls_pubkey_import_ecc_x962 (key, &obj->pubkey[0],
                                          &obj->pubkey[1]);
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_UNIMPLEMENTED_FEATURE;
    }

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

#endif /* ENABLE_PKCS11 */

#ifdef ENABLE_OPENPGP

/**
 * gnutls_pubkey_import_openpgp:
 * @key: The public key
 * @crt: The certificate to be imported
 * @flags: should be zero
 *
 * Imports a public key from an openpgp key. This function will import
 * the given public key to the abstract #gnutls_pubkey_t
 * structure. The subkey set as preferred will be imported or the
 * master key otherwise.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_import_openpgp (gnutls_pubkey_t key,
                              gnutls_openpgp_crt_t crt,
                              unsigned int flags)
{
  int ret, idx;
  uint32_t kid32[2];
  uint32_t *k;
  uint8_t keyid[GNUTLS_OPENPGP_KEYID_SIZE];

  ret = gnutls_openpgp_crt_get_preferred_key_id (crt, keyid);
  if (ret == GNUTLS_E_OPENPGP_PREFERRED_KEY_ERROR)
    {
      key->pk_algorithm = gnutls_openpgp_crt_get_pk_algorithm (crt, &key->bits);
      key->openpgp_key_id_set = OPENPGP_KEY_PRIMARY;

      ret = gnutls_openpgp_crt_get_key_id(crt, key->openpgp_key_id);
      if (ret < 0)
        return gnutls_assert_val(ret);

      ret = gnutls_openpgp_crt_get_key_usage (crt, &key->key_usage);
      if (ret < 0)
        key->key_usage = 0;
      
      k = NULL;
    }
  else
    {
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
        key->openpgp_key_id_set = OPENPGP_KEY_SUBKEY;

        KEYID_IMPORT (kid32, keyid);
        k = kid32;

        idx = gnutls_openpgp_crt_get_subkey_idx (crt, keyid);

        ret = gnutls_openpgp_crt_get_subkey_id(crt, idx, key->openpgp_key_id);
        if (ret < 0)
          return gnutls_assert_val(ret);

        ret = gnutls_openpgp_crt_get_subkey_usage (crt, idx, &key->key_usage);
        if (ret < 0)
          key->key_usage = 0;

      key->pk_algorithm = gnutls_openpgp_crt_get_subkey_pk_algorithm (crt, idx, NULL);
    }

  ret =
    _gnutls_openpgp_crt_get_mpis (crt, k, &key->params);
  if (ret < 0)
     return gnutls_assert_val(ret);

  return 0;
}

/**
 * gnutls_pubkey_get_openpgp_key_id:
 * @key: Holds the public key
 * @flags: should be 0 for now
 * @output_data: will contain the key ID
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 * @subkey: Will be non zero if the key ID corresponds to a subkey
 *
 * This function will return a unique ID the depends on the public
 * key parameters. This ID can be used in checking whether a
 * certificate corresponds to the given public key.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.  The output will normally be a SHA-1 hash output,
 * which is 20 bytes.
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and 0 on success.
 *
 * Since: 3.0.0
 **/
int
gnutls_pubkey_get_openpgp_key_id (gnutls_pubkey_t key, unsigned int flags,
                          unsigned char *output_data,
                          size_t * output_data_size,
                          unsigned int *subkey)
{
  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (*output_data_size < sizeof(key->openpgp_key_id))
    {
      *output_data_size = sizeof(key->openpgp_key_id);
      return gnutls_assert_val(GNUTLS_E_SHORT_MEMORY_BUFFER);
    }

  if (key->openpgp_key_id_set == 0)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  if (key->openpgp_key_id_set == OPENPGP_KEY_SUBKEY)
    if (subkey) *subkey = 1;

  if (output_data)
    {
      memcpy(output_data, key->openpgp_key_id, sizeof(key->openpgp_key_id));
    }
  *output_data_size = sizeof(key->openpgp_key_id);

  return 0;
}

#endif

/**
 * gnutls_pubkey_export:
 * @key: Holds the certificate
 * @format: the format of output params. One of PEM or DER.
 * @output_data: will contain a certificate PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the certificate to DER or PEM format.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN CERTIFICATE".
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and 0 on success.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_export (gnutls_pubkey_t key,
                      gnutls_x509_crt_fmt_t format, void *output_data,
                      size_t * output_data_size)
{
  int result;
  ASN1_TYPE spk = ASN1_TYPE_EMPTY;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result = asn1_create_element
       (_gnutls_get_pkix (), "PKIX1.SubjectPublicKeyInfo", &spk))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result =
    _gnutls_x509_encode_and_copy_PKI_params (spk, "",
                                             key->pk_algorithm,
                                             &key->params);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_export_int_named (spk, "",
                                          format, PK_PEM_HEADER,
                                          output_data, output_data_size);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = 0;

cleanup:
  asn1_delete_structure (&spk);

  return result;

}

/**
 * gnutls_pubkey_get_key_id:
 * @key: Holds the public key
 * @flags: should be 0 for now
 * @output_data: will contain the key ID
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will return a unique ID the depends on the public
 * key parameters. This ID can be used in checking whether a
 * certificate corresponds to the given public key.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.  The output will normally be a SHA-1 hash output,
 * which is 20 bytes.
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and 0 on success.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_get_key_id (gnutls_pubkey_t key, unsigned int flags,
                          unsigned char *output_data,
                          size_t * output_data_size)
{
  int ret = 0;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret =
    _gnutls_get_key_id (key->pk_algorithm, &key->params,
                        output_data, output_data_size);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

/**
 * gnutls_pubkey_get_pk_rsa_raw:
 * @key: Holds the certificate
 * @m: will hold the modulus
 * @e: will hold the public exponent
 *
 * This function will export the RSA public key's parameters found in
 * the given structure.  The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_get_pk_rsa_raw (gnutls_pubkey_t key,
                              gnutls_datum_t * m, gnutls_datum_t * e)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (key->pk_algorithm != GNUTLS_PK_RSA)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_mpi_dprint_lz (key->params.params[0], m);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_mpi_dprint_lz (key->params.params[1], e);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (m);
      return ret;
    }

  return 0;
}

/**
 * gnutls_pubkey_get_pk_dsa_raw:
 * @key: Holds the public key
 * @p: will hold the p
 * @q: will hold the q
 * @g: will hold the g
 * @y: will hold the y
 *
 * This function will export the DSA public key's parameters found in
 * the given certificate.  The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_get_pk_dsa_raw (gnutls_pubkey_t key,
                              gnutls_datum_t * p, gnutls_datum_t * q,
                              gnutls_datum_t * g, gnutls_datum_t * y)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (key->pk_algorithm != GNUTLS_PK_DSA)
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

  return 0;
}

/**
 * gnutls_pubkey_get_pk_ecc_raw:
 * @key: Holds the public key
 * @curve: will hold the curve
 * @x: will hold x
 * @y: will hold y
 *
 * This function will export the ECC public key's parameters found in
 * the given certificate.  The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 3.0.0
 **/
int
gnutls_pubkey_get_pk_ecc_raw (gnutls_pubkey_t key, gnutls_ecc_curve_t *curve,
                              gnutls_datum_t * x, gnutls_datum_t * y)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (key->pk_algorithm != GNUTLS_PK_ECC)
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

  return 0;
}

/**
 * gnutls_pubkey_get_pk_ecc_x962:
 * @key: Holds the public key
 * @parameters: DER encoding of an ANSI X9.62 parameters
 * @ecpoint: DER encoding of ANSI X9.62 ECPoint
 *
 * This function will export the ECC public key's parameters found in
 * the given certificate.  The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise a negative error code.
 *
 * Since: 3.0.0
 **/
int gnutls_pubkey_get_pk_ecc_x962 (gnutls_pubkey_t key, gnutls_datum_t* parameters,
                                   gnutls_datum_t * ecpoint)
{
  int ret;

  if (key == NULL || key->pk_algorithm != GNUTLS_PK_ECC)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  ret = _gnutls_x509_write_ecc_pubkey(&key->params, ecpoint);
  if (ret < 0)
    return gnutls_assert_val(ret);
    
  ret = _gnutls_x509_write_ecc_params(&key->params, parameters);
  if (ret < 0)
    {
      _gnutls_free_datum(ecpoint);
      return gnutls_assert_val(ret);
    }
  
  return 0;
}

/**
 * gnutls_pubkey_import:
 * @key: The structure to store the parsed public key. 
 * @data: The DER or PEM encoded certificate. 
 * @format: One of DER or PEM 
 * 
 * This function will convert the given DER or PEM encoded Public key 
 * to the native gnutls_pubkey_t format.The output will be stored 
 * in @key. 
 * If the Certificate is PEM encoded it should have a header of "PUBLIC KEY". 
 * 
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 * negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_import (gnutls_pubkey_t key,
                      const gnutls_datum_t * data,
                      gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  gnutls_datum_t _data;
  ASN1_TYPE spk;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _data.data = data->data;
  _data.size = data->size;

  /* If the Certificate is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      /* Try the first header */
      result =
        _gnutls_fbase64_decode (PK_PEM_HEADER, data->data, data->size, &out);

      if (result <= 0)
        {
          if (result == 0)
            result = GNUTLS_E_INTERNAL_ERROR;
          gnutls_assert ();
          return result;
        }

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  if ((result = asn1_create_element
       (_gnutls_get_pkix (), "PKIX1.SubjectPublicKeyInfo", &spk))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  result = asn1_der_decoding (&spk, _data.data, _data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  result = _gnutls_get_asn_mpis (spk, "", &key->params);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  /* this has already been called by get_asn_mpis() thus it cannot
   * fail.
   */
  key->pk_algorithm = _gnutls_x509_get_pk_algorithm (spk, "", NULL);
  key->bits = pubkey_to_bits(key->pk_algorithm, &key->params);

  result = 0;

cleanup:
  asn1_delete_structure (&spk);

  if (need_free)
    _gnutls_free_datum (&_data);
  return result;
}

/**
 * gnutls_x509_crt_set_pubkey:
 * @crt: should contain a #gnutls_x509_crt_t structure
 * @key: holds a public key
 *
 * This function will set the public parameters from the given public
 * key to the request.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_x509_crt_set_pubkey (gnutls_x509_crt_t crt, gnutls_pubkey_t key)
{
  int result;

  if (crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_encode_and_copy_PKI_params (crt->cert,
                                                    "tbsCertificate.subjectPublicKeyInfo",
                                                    key->pk_algorithm,
                                                    &key->params);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  if (key->key_usage)
    gnutls_x509_crt_set_key_usage (crt, key->key_usage);

  return 0;
}

/**
 * gnutls_x509_crq_set_pubkey:
 * @crq: should contain a #gnutls_x509_crq_t structure
 * @key: holds a public key
 *
 * This function will set the public parameters from the given public
 * key to the request.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_x509_crq_set_pubkey (gnutls_x509_crq_t crq, gnutls_pubkey_t key)
{
  int result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_encode_and_copy_PKI_params
    (crq->crq,
     "certificationRequestInfo.subjectPKInfo",
     key->pk_algorithm, &key->params);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  if (key->key_usage)
    gnutls_x509_crq_set_key_usage (crq, key->key_usage);

  return 0;
}

/**
 * gnutls_pubkey_set_key_usage:
 * @key: a certificate of type #gnutls_x509_crt_t
 * @usage: an ORed sequence of the GNUTLS_KEY_* elements.
 *
 * This function will set the key usage flags of the public key. This
 * is only useful if the key is to be exported to a certificate or
 * certificate request.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_set_key_usage (gnutls_pubkey_t key, unsigned int usage)
{
  key->key_usage = usage;

  return 0;
}

#ifdef ENABLE_PKCS11

/**
 * gnutls_pubkey_import_pkcs11_url:
 * @key: A key of type #gnutls_pubkey_t
 * @url: A PKCS 11 url
 * @flags: One of GNUTLS_PKCS11_OBJ_* flags
 *
 * This function will import a PKCS 11 certificate to a #gnutls_pubkey_t
 * structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_import_pkcs11_url (gnutls_pubkey_t key, const char *url,
                                 unsigned int flags)
{
  gnutls_pkcs11_obj_t pcrt;
  int ret;

  ret = gnutls_pkcs11_obj_init (&pcrt);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = gnutls_pkcs11_obj_import_url (pcrt, url, flags);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = gnutls_pubkey_import_pkcs11 (key, pcrt, 0);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = 0;
cleanup:

  gnutls_pkcs11_obj_deinit (pcrt);

  return ret;
}

#endif /* ENABLE_PKCS11 */

/**
 * gnutls_pubkey_import_rsa_raw:
 * @key: Is a structure will hold the parameters
 * @m: holds the modulus
 * @e: holds the public exponent
 *
 * This function will replace the parameters in the given structure.
 * The new parameters should be stored in the appropriate
 * gnutls_datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an negative error code.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_import_rsa_raw (gnutls_pubkey_t key,
                              const gnutls_datum_t * m,
                              const gnutls_datum_t * e)
{
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
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = e->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[1], e->data, siz))
    {
      gnutls_assert ();
      _gnutls_mpi_release (&key->params.params[0]);
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  key->params.params_nr = RSA_PUBLIC_PARAMS;
  key->pk_algorithm = GNUTLS_PK_RSA;
  key->bits = pubkey_to_bits(GNUTLS_PK_RSA, &key->params);

  return 0;
}

/**
 * gnutls_pubkey_import_ecc_raw:
 * @key: The structure to store the parsed key
 * @curve: holds the curve
 * @x: holds the x
 * @y: holds the y
 *
 * This function will convert the given elliptic curve parameters to a
 * #gnutls_pubkey_t.  The output will be stored in @key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_pubkey_import_ecc_raw (gnutls_pubkey_t key,
                              gnutls_ecc_curve_t curve,
                              const gnutls_datum_t * x,
                              const gnutls_datum_t * y)
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
  key->pk_algorithm = GNUTLS_PK_ECC;

  return 0;

cleanup:
  gnutls_pk_params_release(&key->params);
  return ret;
}

/**
 * gnutls_pubkey_import_ecc_x962:
 * @key: The structure to store the parsed key
 * @parameters: DER encoding of an ANSI X9.62 parameters
 * @ecpoint: DER encoding of ANSI X9.62 ECPoint
 *
 * This function will convert the given elliptic curve parameters to a
 * #gnutls_pubkey_t.  The output will be stored in @key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_pubkey_import_ecc_x962 (gnutls_pubkey_t key,
                               const gnutls_datum_t * parameters,
                               const gnutls_datum_t * ecpoint)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  key->params.params_nr = 0;

  ret = _gnutls_x509_read_ecc_params(parameters->data, parameters->size,
                                     &key->params);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_ecc_ansi_x963_import(ecpoint->data, ecpoint->size,
         &key->params.params[ECC_X], &key->params.params[ECC_Y]);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }
  key->params.params_nr+=2;
  key->pk_algorithm = GNUTLS_PK_ECC;

  return 0;

cleanup:
  gnutls_pk_params_release(&key->params);
  return ret;
}

/**
 * gnutls_pubkey_import_dsa_raw:
 * @key: The structure to store the parsed key
 * @p: holds the p
 * @q: holds the q
 * @g: holds the g
 * @y: holds the y
 *
 * This function will convert the given DSA raw parameters to the
 * native #gnutls_pubkey_t format.  The output will be stored
 * in @key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_import_dsa_raw (gnutls_pubkey_t key,
                              const gnutls_datum_t * p,
                              const gnutls_datum_t * q,
                              const gnutls_datum_t * g,
                              const gnutls_datum_t * y)
{
  size_t siz = 0;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  gnutls_pk_params_init(&key->params);

  siz = p->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[0], p->data, siz))
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = q->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[1], q->data, siz))
    {
      gnutls_assert ();
      _gnutls_mpi_release (&key->params.params[0]);
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = g->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[2], g->data, siz))
    {
      gnutls_assert ();
      _gnutls_mpi_release (&key->params.params[1]);
      _gnutls_mpi_release (&key->params.params[0]);
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = y->size;
  if (_gnutls_mpi_scan_nz (&key->params.params[3], y->data, siz))
    {
      gnutls_assert ();
      _gnutls_mpi_release (&key->params.params[2]);
      _gnutls_mpi_release (&key->params.params[1]);
      _gnutls_mpi_release (&key->params.params[0]);
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  key->params.params_nr = DSA_PUBLIC_PARAMS;
  key->pk_algorithm = GNUTLS_PK_DSA;
  key->bits = pubkey_to_bits(GNUTLS_PK_DSA, &key->params);

  return 0;

}

/**
 * gnutls_pubkey_verify_data:
 * @pubkey: Holds the public key
 * @flags: should be 0 for now
 * @data: holds the signed data
 * @signature: contains the signature
 *
 * This function will verify the given signed data, using the
 * parameters from the certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value (%GNUTLS_E_PK_SIG_VERIFY_FAILED in verification failure).
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_verify_data (gnutls_pubkey_t pubkey, unsigned int flags,
			   const gnutls_datum_t * data,
			   const gnutls_datum_t * signature)
{
  int ret;

  if (pubkey == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = pubkey_verify_data( pubkey->pk_algorithm, GNUTLS_DIG_UNKNOWN, data, signature,
    &pubkey->params);
  if (ret < 0)
    {
      gnutls_assert();
    }

  return ret;
}

/**
 * gnutls_pubkey_verify_data2:
 * @pubkey: Holds the public key
 * @algo: The signature algorithm used
 * @flags: should be 0 for now
 * @data: holds the signed data
 * @signature: contains the signature
 *
 * This function will verify the given signed data, using the
 * parameters from the certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value (%GNUTLS_E_PK_SIG_VERIFY_FAILED in verification failure).
 *
 * Since: 3.0.0
 **/
int
gnutls_pubkey_verify_data2 (gnutls_pubkey_t pubkey, 
                           gnutls_sign_algorithm_t algo,
                           unsigned int flags,
			   const gnutls_datum_t * data,
			   const gnutls_datum_t * signature)
{
  int ret;

  if (pubkey == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = pubkey_verify_data( pubkey->pk_algorithm, _gnutls_sign_get_hash_algorithm(algo), data, signature,
    &pubkey->params);
  if (ret < 0)
    {
      gnutls_assert();
    }

  return ret;
}


/**
 * gnutls_pubkey_verify_hash:
 * @key: Holds the certificate
 * @flags: should be 0 for now
 * @hash: holds the hash digest to be verified
 * @signature: contains the signature
 *
 * This function will verify the given signed digest, using the
 * parameters from the certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value (%GNUTLS_E_PK_SIG_VERIFY_FAILED in verification failure).
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_verify_hash (gnutls_pubkey_t key, unsigned int flags,
                           const gnutls_datum_t * hash,
                           const gnutls_datum_t * signature)
{
  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (flags & GNUTLS_PUBKEY_VERIFY_FLAG_TLS_RSA)
    return _gnutls_rsa_verify (hash, signature, &key->params, 1);
  else
    {
      return pubkey_verify_hashed_data (key->pk_algorithm, hash, signature,
                       &key->params);
    }
}

/**
 * gnutls_pubkey_get_verify_algorithm:
 * @key: Holds the certificate
 * @signature: contains the signature
 * @hash: The result of the call with the hash algorithm used for signature
 *
 * This function will read the certifcate and the signed data to
 * determine the hash algorithm used to generate the signature.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pubkey_get_verify_algorithm (gnutls_pubkey_t key,
                                    const gnutls_datum_t * signature,
                                    gnutls_digest_algorithm_t * hash)
{
  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_verify_algorithm ((gnutls_mac_algorithm_t *)
                                        hash, signature,
                                        key->pk_algorithm,
                                        &key->params);

}


int _gnutls_pubkey_compatible_with_sig(gnutls_pubkey_t pubkey, gnutls_protocol_t ver, 
  gnutls_sign_algorithm_t sign)
{
int hash_size;
int hash_algo;

  if (pubkey->pk_algorithm == GNUTLS_PK_DSA)
    {
      hash_algo = _gnutls_dsa_q_to_hash (pubkey->pk_algorithm, &pubkey->params, &hash_size);

      /* DSA keys over 1024 bits cannot be used with TLS 1.x, x<2 */
      if (!_gnutls_version_has_selectable_sighash (ver))
        {
          if (hash_algo != GNUTLS_DIG_SHA1)
            return gnutls_assert_val(GNUTLS_E_INCOMPAT_DSA_KEY_WITH_TLS_PROTOCOL);
        }
      else if (sign != GNUTLS_SIGN_UNKNOWN)
        {
          if (_gnutls_hash_get_algo_len(_gnutls_sign_get_hash_algorithm(sign)) != hash_size)
            return GNUTLS_E_UNWANTED_ALGORITHM;
        }
        
    }
  else if (pubkey->pk_algorithm == GNUTLS_PK_ECC)
    {
      if (_gnutls_version_has_selectable_sighash (ver) && sign != GNUTLS_SIGN_UNKNOWN)
        {
          hash_algo = _gnutls_dsa_q_to_hash (pubkey->pk_algorithm, &pubkey->params, &hash_size);

          if (_gnutls_hash_get_algo_len(_gnutls_sign_get_hash_algorithm(sign)) != hash_size)
            return GNUTLS_E_UNWANTED_ALGORITHM;
        }
        
    }

  return 0;
}

/* Returns zero if the public key has more than 512 bits */
int _gnutls_pubkey_is_over_rsa_512(gnutls_pubkey_t pubkey)
{
  if (pubkey->pk_algorithm == GNUTLS_PK_RSA && _gnutls_mpi_get_nbits (pubkey->params.params[0]) > 512)
    return 0;
  else
    return GNUTLS_E_INVALID_REQUEST; /* doesn't matter */

}

/* Returns the public key. 
 */
int
_gnutls_pubkey_get_mpis (gnutls_pubkey_t key,
                                 gnutls_pk_params_st * params)
{
  return _gnutls_pk_params_copy(params, &key->params);
}

/* if hash==MD5 then we do RSA-MD5
 * if hash==SHA then we do RSA-SHA
 * params[0] is modulus
 * params[1] is public key
 */
static int
_pkcs1_rsa_verify_sig (const gnutls_datum_t * text,
                       const gnutls_datum_t * prehash,
                       const gnutls_datum_t * signature, 
                       gnutls_pk_params_st * params)
{
  gnutls_mac_algorithm_t hash = GNUTLS_MAC_UNKNOWN;
  int ret;
  opaque digest[MAX_HASH_SIZE], md[MAX_HASH_SIZE], *cmp;
  int digest_size;
  digest_hd_st hd;
  gnutls_datum_t decrypted;

  ret =
    _gnutls_pkcs1_rsa_decrypt (&decrypted, signature, params, 1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* decrypted is a BER encoded data of type DigestInfo
   */

  digest_size = sizeof (digest);
  if ((ret =
       decode_ber_digest_info (&decrypted, &hash, digest, &digest_size)) != 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (&decrypted);
      return ret;
    }

  _gnutls_free_datum (&decrypted);

  if (digest_size != _gnutls_hash_get_algo_len (hash))
    {
      gnutls_assert ();
      return GNUTLS_E_ASN1_GENERIC_ERROR;
    }

  if (prehash && prehash->data && prehash->size == digest_size)
    {
      cmp = prehash->data;
    }
  else
    {
      if (!text)
        {
          gnutls_assert ();
          return GNUTLS_E_INVALID_REQUEST;
        }

      ret = _gnutls_hash_init (&hd, hash);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      _gnutls_hash (&hd, text->data, text->size);
      _gnutls_hash_deinit (&hd, md);

      cmp = md;
    }

  if (memcmp (cmp, digest, digest_size) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  return 0;
}

/* Hashes input data and verifies a signature.
 */
static int
dsa_verify_hashed_data (const gnutls_datum_t * hash,
                const gnutls_datum_t * signature,
                gnutls_pk_algorithm_t pk,
                gnutls_pk_params_st* params)
{
  gnutls_datum_t digest;
  gnutls_digest_algorithm_t algo;
  int hash_len;

  algo = _gnutls_dsa_q_to_hash (pk, params, &hash_len);

  /* SHA1 or better allowed */
  if (!hash->data || hash->size < hash_len)
    {
      gnutls_assert();
      _gnutls_debug_log("Hash size (%d) does not correspond to hash %s(%d) or better.\n", (int)hash->size, gnutls_mac_get_name(algo), hash_len);
          
      if (hash->size != 20) /* SHA1 is allowed */
        return gnutls_assert_val(GNUTLS_E_PK_SIG_VERIFY_FAILED);
    }

  digest.data = hash->data;
  digest.size = hash->size;

  return _gnutls_pk_verify (pk, &digest, signature, params);
}

static int
dsa_verify_data (gnutls_pk_algorithm_t pk,
                 gnutls_digest_algorithm_t algo,
                 const gnutls_datum_t * data,
                 const gnutls_datum_t * signature,
                 gnutls_pk_params_st* params)
{
  int ret;
  opaque _digest[MAX_HASH_SIZE];
  gnutls_datum_t digest;
  digest_hd_st hd;

  if (algo == GNUTLS_DIG_UNKNOWN)
    algo = _gnutls_dsa_q_to_hash (pk, params, NULL);

  ret = _gnutls_hash_init (&hd, algo);
  if (ret < 0)
    return gnutls_assert_val(ret);

  _gnutls_hash (&hd, data->data, data->size);
  _gnutls_hash_deinit (&hd, _digest);

  digest.data = _digest;
  digest.size = _gnutls_hash_get_algo_len(algo);

  return _gnutls_pk_verify (pk, &digest, signature, params);
}

/* Verifies the signature data, and returns GNUTLS_E_PK_SIG_VERIFY_FAILED if 
 * not verified, or 1 otherwise.
 */
int
pubkey_verify_hashed_data (gnutls_pk_algorithm_t pk,
                   const gnutls_datum_t * hash,
                   const gnutls_datum_t * signature,
                   gnutls_pk_params_st * issuer_params)
{

  switch (pk)
    {
    case GNUTLS_PK_RSA:

      if (_pkcs1_rsa_verify_sig
          (NULL, hash, signature, issuer_params) != 0)
        {
          gnutls_assert ();
          return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

      return 1;
      break;

    case GNUTLS_PK_ECC:
    case GNUTLS_PK_DSA:
      if (dsa_verify_hashed_data(hash, signature, pk, issuer_params) != 0)
        {
          gnutls_assert ();
          return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

      return 1;
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;

    }
}

/* Verifies the signature data, and returns GNUTLS_E_PK_SIG_VERIFY_FAILED if 
 * not verified, or 1 otherwise.
 */
int
pubkey_verify_data (gnutls_pk_algorithm_t pk,
                    gnutls_digest_algorithm_t algo,
                    const gnutls_datum_t * data,
                    const gnutls_datum_t * signature,
                    gnutls_pk_params_st * issuer_params)
{

  switch (pk)
    {
    case GNUTLS_PK_RSA:

      if (_pkcs1_rsa_verify_sig
          (data, NULL, signature, issuer_params) != 0)
        {
          gnutls_assert ();
          return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

      return 1;
      break;

    case GNUTLS_PK_ECC:
    case GNUTLS_PK_DSA:
      if (dsa_verify_data(pk, algo, data, signature, issuer_params) != 0)
        {
          gnutls_assert ();
          return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

      return 1;
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;

    }
}

gnutls_digest_algorithm_t
_gnutls_dsa_q_to_hash (gnutls_pk_algorithm_t algo, const gnutls_pk_params_st* params, int* hash_len)
{
  int bits = 0;
  
  if (algo == GNUTLS_PK_DSA)
    bits = _gnutls_mpi_get_nbits (params->params[1]);
  else if (algo == GNUTLS_PK_ECC)
    bits = gnutls_ecc_curve_get_size(params->flags)*8;

  if (bits <= 160)
    {
      if (hash_len) *hash_len = 20;
      return GNUTLS_DIG_SHA1;
    }
  else if (bits <= 192)
    {
      if (hash_len) *hash_len = 24;
      return GNUTLS_DIG_SHA256;
    }
  else if (bits <= 224)
    {
      if (hash_len) *hash_len = 28;
      return GNUTLS_DIG_SHA256;
    }
  else if (bits <= 256)
    {
      if (hash_len) *hash_len = 32;
      return GNUTLS_DIG_SHA256;
    }
  else if (bits <= 384)
    {
      if (hash_len) *hash_len = 48;
      return GNUTLS_DIG_SHA384;
    }
  else
    {
      if (hash_len) *hash_len = 64;
      return GNUTLS_DIG_SHA512;
    }
}
