/*
 * GnuTLS PKCS#11 support
 * Copyright (C) 2010, 2011 Free Software Foundation
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
#include <gnutls_pk.h>
#include <x509_int.h>
#include <openpgp/openpgp_int.h>
#include <openpgp/gnutls_openpgp.h>
#include <gnutls_sig.h>
#include <abstract_int.h>

struct gnutls_privkey_st
{
  gnutls_privkey_type_t type;
  gnutls_pk_algorithm_t pk_algorithm;

  union
  {
    gnutls_x509_privkey_t x509;
#ifdef ENABLE_PKCS11
    gnutls_pkcs11_privkey_t pkcs11;
#endif
#ifdef ENABLE_OPENPGP
    gnutls_openpgp_privkey_t openpgp;
#endif
    struct {
      gnutls_privkey_sign_func sign_func;
      gnutls_privkey_decrypt_func decrypt_func;
      void* userdata;
    } ext;
  } key;

  unsigned int flags;
};

/**
 * gnutls_privkey_get_type:
 * @key: should contain a #gnutls_privkey_t structure
 *
 * This function will return the type of the private key. This is
 * actually the type of the subsystem used to set this private key.
 *
 * Returns: a member of the #gnutls_privkey_type_t enumeration on
 *   success, or a negative error code on error.
 *
 * Since: 2.12.0
 **/
gnutls_privkey_type_t
gnutls_privkey_get_type (gnutls_privkey_t key)
{
  return key->type;
}

/**
 * gnutls_privkey_get_pk_algorithm:
 * @key: should contain a #gnutls_privkey_t structure
 * @bits: If set will return the number of bits of the parameters (may be NULL)
 *
 * This function will return the public key algorithm of a private
 * key and if possible will return a number of bits that indicates
 * the security parameter of the key.
 *
 * Returns: a member of the #gnutls_pk_algorithm_t enumeration on
 *   success, or a negative error code on error.
 *
 * Since: 2.12.0
 **/
int
gnutls_privkey_get_pk_algorithm (gnutls_privkey_t key, unsigned int *bits)
{
  switch (key->type)
    {
#ifdef ENABLE_OPENPGP
    case GNUTLS_PRIVKEY_OPENPGP:
      return gnutls_openpgp_privkey_get_pk_algorithm (key->key.openpgp, bits);
#endif
#ifdef ENABLE_PKCS11
    case GNUTLS_PRIVKEY_PKCS11:
      return gnutls_pkcs11_privkey_get_pk_algorithm (key->key.pkcs11, bits);
#endif
    case GNUTLS_PRIVKEY_X509:
      if (bits)
        *bits = _gnutls_mpi_get_nbits (key->key.x509->params.params[0]);
      return gnutls_x509_privkey_get_pk_algorithm (key->key.x509);
    case GNUTLS_PRIVKEY_EXT:
      if (bits)
        *bits = 0;
      return key->pk_algorithm;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

}

static int
privkey_to_pubkey (gnutls_pk_algorithm_t pk,
                   const gnutls_pk_params_st* priv,
                   gnutls_pk_params_st* pub)
{
  int ret;

  switch (pk)
    {
    case GNUTLS_PK_RSA:
      pub->params[0] = _gnutls_mpi_copy (priv->params[0]);
      pub->params[1] = _gnutls_mpi_copy (priv->params[1]);

      pub->params_nr = RSA_PUBLIC_PARAMS;

      if (pub->params[0] == NULL || pub->params[1] == NULL)
        {
          gnutls_assert ();
          ret = GNUTLS_E_MEMORY_ERROR;
          goto cleanup;
        }

      break;
    case GNUTLS_PK_DSA:
      pub->params[0] = _gnutls_mpi_copy (priv->params[0]);
      pub->params[1] = _gnutls_mpi_copy (priv->params[1]);
      pub->params[2] = _gnutls_mpi_copy (priv->params[2]);
      pub->params[3] = _gnutls_mpi_copy (priv->params[3]);

      pub->params_nr = DSA_PUBLIC_PARAMS;

      if (pub->params[0] == NULL || pub->params[1] == NULL ||
          pub->params[2] == NULL || pub->params[3] == NULL)
        {
          gnutls_assert ();
          ret = GNUTLS_E_MEMORY_ERROR;
          goto cleanup;
        }

      break;
    case GNUTLS_PK_ECC:
      pub->params[0] = _gnutls_mpi_copy (priv->params[0]);
      pub->params[1] = _gnutls_mpi_copy (priv->params[1]);
      pub->params[2] = _gnutls_mpi_copy (priv->params[2]);
      pub->params[3] = _gnutls_mpi_copy (priv->params[3]);
      pub->params[4] = _gnutls_mpi_copy (priv->params[4]);
      pub->params[5] = _gnutls_mpi_copy (priv->params[5]);
      pub->params[6] = _gnutls_mpi_copy (priv->params[6]);
      pub->params[7] = _gnutls_mpi_copy (priv->params[7]);

      pub->params_nr = ECC_PUBLIC_PARAMS;
      pub->flags = priv->flags;

      if (pub->params[0] == NULL || pub->params[1] == NULL ||
          pub->params[2] == NULL || pub->params[3] == NULL ||
          pub->params[4] == NULL || pub->params[5] == NULL ||
          pub->params[6] == NULL || pub->params[7] == NULL)
        {
          gnutls_assert ();
          ret = GNUTLS_E_MEMORY_ERROR;
          goto cleanup;
        }

      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return 0;
cleanup:
  gnutls_pk_params_release(pub);
  return ret;
}


/* Returns the public key of the private key (if possible)
 */
int
_gnutls_privkey_get_public_mpis (gnutls_privkey_t key,
                                 gnutls_pk_params_st * params)
{
  int ret;
  gnutls_pk_algorithm_t pk = gnutls_privkey_get_pk_algorithm (key, NULL);

  switch (key->type)
    {
#ifdef ENABLE_OPENPGP
    case GNUTLS_PRIVKEY_OPENPGP:
      {
        gnutls_pk_params_st tmp_params;
        uint32_t kid[2];
        uint8_t keyid[GNUTLS_OPENPGP_KEYID_SIZE];

        ret =
          gnutls_openpgp_privkey_get_preferred_key_id (key->key.openpgp,
                                                       keyid);
        if (ret == 0)
          {
            KEYID_IMPORT (kid, keyid);
            ret = _gnutls_openpgp_privkey_get_mpis (key->key.openpgp, kid,
                                                    &tmp_params);
          }
        else
          ret = _gnutls_openpgp_privkey_get_mpis (key->key.openpgp, NULL,
                                                  &tmp_params);

        if (ret < 0)
          {
            gnutls_assert ();
            return ret;
          }

        ret = privkey_to_pubkey (pk,
                                 &tmp_params,
                                 params);

        gnutls_pk_params_release(&tmp_params);
      }

      break;
#endif
    case GNUTLS_PRIVKEY_X509:
      ret = privkey_to_pubkey (pk,
                               &key->key.x509->params,
                               params);
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return ret;
}

/**
 * gnutls_privkey_init:
 * @key: The structure to be initialized
 *
 * This function will initialize an private key structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_privkey_init (gnutls_privkey_t * key)
{
  *key = gnutls_calloc (1, sizeof (struct gnutls_privkey_st));
  if (*key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  return 0;
}

/**
 * gnutls_privkey_deinit:
 * @key: The structure to be deinitialized
 *
 * This function will deinitialize a private key structure.
 *
 * Since: 2.12.0
 **/
void
gnutls_privkey_deinit (gnutls_privkey_t key)
{
  if (key == NULL) return;

  if (key->flags & GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE || key->flags & GNUTLS_PRIVKEY_IMPORT_COPY)
    switch (key->type)
      {
#ifdef ENABLE_OPENPGP
      case GNUTLS_PRIVKEY_OPENPGP:
        gnutls_openpgp_privkey_deinit (key->key.openpgp);
        break;
#endif
#ifdef ENABLE_PKCS11
      case GNUTLS_PRIVKEY_PKCS11:
        gnutls_pkcs11_privkey_deinit (key->key.pkcs11);
        break;
#endif
      case GNUTLS_PRIVKEY_X509:
        gnutls_x509_privkey_deinit (key->key.x509);
        break;
      default:
        break;
      }
  gnutls_free (key);
}

/* will fail if the private key contains an actual key.
 */
static int check_if_clean(gnutls_privkey_t key)
{
  if (key->type != 0)
    return GNUTLS_E_INVALID_REQUEST;

  return 0;
}

#ifdef ENABLE_PKCS11

/**
 * gnutls_privkey_import_pkcs11:
 * @pkey: The private key
 * @key: The private key to be imported
 * @flags: Flags for the import
 *
 * This function will import the given private key to the abstract
 * #gnutls_privkey_t structure.
 *
 * The #gnutls_pkcs11_privkey_t object must not be deallocated
 * during the lifetime of this structure.
 *
 * @flags might be zero or one of %GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE
 * and %GNUTLS_PRIVKEY_IMPORT_COPY.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_privkey_import_pkcs11 (gnutls_privkey_t pkey,
                              gnutls_pkcs11_privkey_t key, unsigned int flags)
{
int ret;

  ret = check_if_clean(pkey);
  if (ret < 0)
    {
      gnutls_assert();
      return ret;
    }

  if (flags & GNUTLS_PRIVKEY_IMPORT_COPY)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  pkey->key.pkcs11 = key;
  pkey->type = GNUTLS_PRIVKEY_PKCS11;
  pkey->pk_algorithm = gnutls_pkcs11_privkey_get_pk_algorithm (key, NULL);
  pkey->flags = flags;

  return 0;
}

#endif /* ENABLE_PKCS11 */

/**
 * gnutls_privkey_import_ext:
 * @pkey: The private key
 * @pk: The public key algorithm
 * @userdata: private data to be provided to the callbacks
 * @sign_func: callback for signature operations
 * @decrypt_func: callback for decryption operations
 * @flags: Flags for the import
 *
 * This function will associate the given callbacks with the
 * #gnutls_privkey_t structure. At least one of the two callbacks
 * must be non-null.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_privkey_import_ext (gnutls_privkey_t pkey,
                           gnutls_pk_algorithm_t pk,
                           void* userdata,
                           gnutls_privkey_sign_func sign_func,
                           gnutls_privkey_decrypt_func decrypt_func,
                           unsigned int flags)
{
int ret;

  ret = check_if_clean(pkey);
  if (ret < 0)
    {
      gnutls_assert();
      return ret;
    }
  
  if (sign_func == NULL && decrypt_func == NULL)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  pkey->key.ext.sign_func = sign_func;
  pkey->key.ext.decrypt_func = decrypt_func;
  pkey->key.ext.userdata = userdata;
  pkey->type = GNUTLS_PRIVKEY_EXT;
  pkey->pk_algorithm = pk;
  pkey->flags = flags;

  return 0;
}

/**
 * gnutls_privkey_import_x509:
 * @pkey: The private key
 * @key: The private key to be imported
 * @flags: Flags for the import
 *
 * This function will import the given private key to the abstract
 * #gnutls_privkey_t structure.
 *
 * The #gnutls_x509_privkey_t object must not be deallocated
 * during the lifetime of this structure.
 *
 * @flags might be zero or one of %GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE
 * and %GNUTLS_PRIVKEY_IMPORT_COPY.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_privkey_import_x509 (gnutls_privkey_t pkey,
                            gnutls_x509_privkey_t key, unsigned int flags)
{
int ret;

  ret = check_if_clean(pkey);
  if (ret < 0)
    {
      gnutls_assert();
      return ret;
    }

  if (flags & GNUTLS_PRIVKEY_IMPORT_COPY)
    {
      ret = gnutls_x509_privkey_init(&pkey->key.x509);
      if (ret < 0)
        return gnutls_assert_val(ret);
      
      ret = gnutls_x509_privkey_cpy(pkey->key.x509, key);
      if (ret < 0)
        {
          gnutls_x509_privkey_deinit(pkey->key.x509);
          return gnutls_assert_val(ret);
        }
    }
  else
    pkey->key.x509 = key;

  pkey->type = GNUTLS_PRIVKEY_X509;
  pkey->pk_algorithm = gnutls_x509_privkey_get_pk_algorithm (key);
  pkey->flags = flags;

  return 0;
}

#ifdef ENABLE_OPENPGP
/**
 * gnutls_privkey_import_openpgp:
 * @pkey: The private key
 * @key: The private key to be imported
 * @flags: Flags for the import
 *
 * This function will import the given private key to the abstract
 * #gnutls_privkey_t structure.
 *
 * The #gnutls_openpgp_privkey_t object must not be deallocated
 * during the lifetime of this structure. The subkey set as
 * preferred will be used, or the master key otherwise.
 *
 * @flags might be zero or one of %GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE
 * and %GNUTLS_PRIVKEY_IMPORT_COPY.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_privkey_import_openpgp (gnutls_privkey_t pkey,
                               gnutls_openpgp_privkey_t key,
                               unsigned int flags)
{
int ret, idx;
uint8_t keyid[GNUTLS_OPENPGP_KEYID_SIZE];

  ret = check_if_clean(pkey);
  if (ret < 0)
    {
      gnutls_assert();
      return ret;
    }

  if (flags & GNUTLS_PRIVKEY_IMPORT_COPY)
    {
      ret = gnutls_openpgp_privkey_init(&pkey->key.openpgp);
      if (ret < 0)
        return gnutls_assert_val(ret);
      
      ret = _gnutls_openpgp_privkey_cpy(pkey->key.openpgp, key);
      if (ret < 0)
        {
          gnutls_openpgp_privkey_deinit(pkey->key.openpgp);
          return gnutls_assert_val(ret);
        }
    }
  else
    pkey->key.openpgp = key;

  pkey->type = GNUTLS_PRIVKEY_OPENPGP;
  
  ret = gnutls_openpgp_privkey_get_preferred_key_id (key, keyid);
  if (ret == GNUTLS_E_OPENPGP_PREFERRED_KEY_ERROR)
    {
      pkey->pk_algorithm = gnutls_openpgp_privkey_get_pk_algorithm(key, NULL);
    }
  else
    {
      if (ret < 0)
        return gnutls_assert_val(ret);

      idx = gnutls_openpgp_privkey_get_subkey_idx (key, keyid);
  
      pkey->pk_algorithm = gnutls_openpgp_privkey_get_subkey_pk_algorithm (key, idx, NULL);
    }

  pkey->flags = flags;

  return 0;
}
#endif

/**
 * gnutls_privkey_sign_data:
 * @signer: Holds the key
 * @hash: should be a digest algorithm
 * @flags: should be 0 for now
 * @data: holds the data to be signed
 * @signature: will contain the signature allocate with gnutls_malloc()
 *
 * This function will sign the given data using a signature algorithm
 * supported by the private key. Signature algorithms are always used
 * together with a hash functions.  Different hash functions may be
 * used for the RSA algorithm, but only the SHA family for the DSA keys.
 *
 * Use gnutls_pubkey_get_preferred_hash_algorithm() to determine
 * the hash algorithm.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 * negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_privkey_sign_data (gnutls_privkey_t signer,
                          gnutls_digest_algorithm_t hash,
                          unsigned int flags,
                          const gnutls_datum_t * data,
                          gnutls_datum_t * signature)
{
  int ret;
  gnutls_datum_t digest;

  ret = pk_hash_data (signer->pk_algorithm, hash, NULL, data, &digest);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = pk_prepare_hash (signer->pk_algorithm, hash, &digest);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_privkey_sign_hash (signer, &digest, signature);
  _gnutls_free_datum (&digest);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;

cleanup:
  _gnutls_free_datum (&digest);
  return ret;
}

/**
 * gnutls_privkey_sign_hash:
 * @signer: Holds the signer's key
 * @hash_algo: The hash algorithm used
 * @flags: zero for now
 * @hash_data: holds the data to be signed
 * @signature: will contain newly allocated signature
 *
 * This function will sign the given hashed data using a signature algorithm
 * supported by the private key. Signature algorithms are always used
 * together with a hash functions.  Different hash functions may be
 * used for the RSA algorithm, but only SHA-XXX for the DSA keys.
 *
 * Use gnutls_pubkey_get_preferred_hash_algorithm() to determine
 * the hash algorithm.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_privkey_sign_hash (gnutls_privkey_t signer,
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

  ret = _gnutls_privkey_sign_hash (signer, &digest, signature);
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

/*-
 * _gnutls_privkey_sign_hash:
 * @key: Holds the key
 * @data: holds the data to be signed
 * @signature: will contain the signature allocate with gnutls_malloc()
 *
 * This function will sign the given data using a signature algorithm
 * supported by the private key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 * negative error value.
 -*/
int
_gnutls_privkey_sign_hash (gnutls_privkey_t key,
                           const gnutls_datum_t * hash,
                           gnutls_datum_t * signature)
{
  switch (key->type)
    {
#ifdef ENABLE_OPENPGP
    case GNUTLS_PRIVKEY_OPENPGP:
      return gnutls_openpgp_privkey_sign_hash (key->key.openpgp,
                                                hash, signature);
#endif
#ifdef ENABLE_PKCS11
    case GNUTLS_PRIVKEY_PKCS11:
      return _gnutls_pkcs11_privkey_sign_hash (key->key.pkcs11,
                                               hash, signature);
#endif
    case GNUTLS_PRIVKEY_X509:
      return _gnutls_soft_sign (key->key.x509->pk_algorithm,
                                &key->key.x509->params,
                                hash, signature);
    case GNUTLS_PRIVKEY_EXT:
      if (key->key.ext.sign_func == NULL)
        return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
      return key->key.ext.sign_func(key, key->key.ext.userdata, hash, signature);
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
}

/**
 * gnutls_privkey_decrypt_data:
 * @key: Holds the key
 * @flags: zero for now
 * @ciphertext: holds the data to be decrypted
 * @plaintext: will contain the decrypted data, allocated with gnutls_malloc()
 *
 * This function will decrypt the given data using the algorithm
 * supported by the private key.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 * negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_privkey_decrypt_data (gnutls_privkey_t key,
                             unsigned int flags,
                             const gnutls_datum_t * ciphertext,
                             gnutls_datum_t * plaintext)
{
  if (key->pk_algorithm != GNUTLS_PK_RSA)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  switch (key->type)
    {
#ifdef ENABLE_OPENPGP
    case GNUTLS_PRIVKEY_OPENPGP:
      return _gnutls_openpgp_privkey_decrypt_data (key->key.openpgp, flags,
                                                  ciphertext, plaintext);
#endif
    case GNUTLS_PRIVKEY_X509:
      return _gnutls_pkcs1_rsa_decrypt (plaintext, ciphertext,
                                        &key->key.x509->params,
                                        2);
#ifdef ENABLE_PKCS11
    case GNUTLS_PRIVKEY_PKCS11:
      return _gnutls_pkcs11_privkey_decrypt_data (key->key.pkcs11,
                                                 flags,
                                                 ciphertext, plaintext);
#endif
    case GNUTLS_PRIVKEY_EXT:
      if (key->key.ext.decrypt_func == NULL)
        return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

      return key->key.ext.decrypt_func(key, key->key.ext.userdata, ciphertext, plaintext);
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
}
