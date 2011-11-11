/*
 * Copyright (C) 2010 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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
#include <x509/x509_int.h>
#include <x509/common.h>
#include <random.h>
#include <gnutls_pk.h>
#include <nettle/dsa.h>
#include <nettle/rsa.h>
#include <random.h>
#include <gnutls/crypto.h>
#include "ecc.h"

#define TOMPZ(x) (*((mpz_t*)(x)))

static inline int is_supported_curve(int curve);

static void
rnd_func (void *_ctx, unsigned length, uint8_t * data)
{
  gnutls_rnd (GNUTLS_RND_RANDOM, data, length);
}

static void
_dsa_params_to_pubkey (const gnutls_pk_params_st * pk_params,
                       struct dsa_public_key *pub)
{
  memcpy (&pub->p, pk_params->params[0], sizeof (mpz_t));
  memcpy (&pub->q, pk_params->params[1], sizeof (mpz_t));
  memcpy (&pub->g, pk_params->params[2], sizeof (mpz_t));
  memcpy (&pub->y, pk_params->params[3], sizeof (mpz_t));
}

static void
_dsa_params_to_privkey (const gnutls_pk_params_st * pk_params,
                        struct dsa_private_key *pub)
{
  memcpy (&pub->x, pk_params->params[4], sizeof (mpz_t));
}

static void
_rsa_params_to_privkey (const gnutls_pk_params_st * pk_params,
                        struct rsa_private_key *priv)
{
  memcpy (&priv->d, pk_params->params[2], sizeof (mpz_t));
  memcpy (&priv->p, pk_params->params[3], sizeof (mpz_t));
  memcpy (&priv->q, pk_params->params[4], sizeof (mpz_t));
  memcpy (&priv->c, pk_params->params[5], sizeof (mpz_t));
  memcpy (&priv->a, pk_params->params[6], sizeof (mpz_t));
  memcpy (&priv->b, pk_params->params[7], sizeof (mpz_t));

}

static void 
_ecc_params_to_privkey(const gnutls_pk_params_st * pk_params,
                       ecc_key * priv)
{
        priv->type = PK_PRIVATE;
        memcpy(&priv->prime, pk_params->params[ECC_PRIME], sizeof(mpz_t));
        memcpy(&priv->order, pk_params->params[ECC_ORDER], sizeof(mpz_t));
        memcpy(&priv->A, pk_params->params[ECC_A], sizeof(mpz_t));
        memcpy(&priv->B, pk_params->params[ECC_B], sizeof(mpz_t));
        memcpy(&priv->Gx, pk_params->params[ECC_GX], sizeof(mpz_t));
        memcpy(&priv->Gy, pk_params->params[ECC_GY], sizeof(mpz_t));
        memcpy(&priv->pubkey.x, pk_params->params[ECC_X], sizeof(mpz_t));
        memcpy(&priv->pubkey.y, pk_params->params[ECC_Y], sizeof(mpz_t));
        memcpy(&priv->k, pk_params->params[ECC_K], sizeof(mpz_t));
        mpz_init_set_ui(priv->pubkey.z, 1);
}

static void _ecc_params_clear(ecc_key * key)
{
  mpz_clear(key->pubkey.z);
}

static void 
_ecc_params_to_pubkey(const gnutls_pk_params_st * pk_params,
                       ecc_key * pub)
{
        pub->type = PK_PUBLIC;
        memcpy(&pub->prime, pk_params->params[ECC_PRIME], sizeof(mpz_t));
        memcpy(&pub->order, pk_params->params[ECC_ORDER], sizeof(mpz_t));
        memcpy(&pub->A, pk_params->params[ECC_A], sizeof(mpz_t));
        memcpy(&pub->B, pk_params->params[ECC_B], sizeof(mpz_t));
        memcpy(&pub->Gx, pk_params->params[ECC_GX], sizeof(mpz_t));
        memcpy(&pub->Gy, pk_params->params[ECC_GY], sizeof(mpz_t));
        memcpy(&pub->pubkey.x, pk_params->params[ECC_X], sizeof(mpz_t));
        memcpy(&pub->pubkey.y, pk_params->params[ECC_Y], sizeof(mpz_t));
        mpz_init_set_ui(pub->pubkey.z, 1);
}

static int _wrap_nettle_pk_derive(gnutls_pk_algorithm_t algo, gnutls_datum_t * out,
                                  const gnutls_pk_params_st * priv,
                                  const gnutls_pk_params_st * pub)
{
  int ret;

  switch (algo)
    {
    case GNUTLS_PK_ECC:
      {
        ecc_key ecc_pub, ecc_priv;
        int curve = priv->flags;
        unsigned long sz;

        out->data = NULL;

        if (is_supported_curve(curve) == 0)
          return gnutls_assert_val(GNUTLS_E_ECC_UNSUPPORTED_CURVE);

        _ecc_params_to_pubkey(pub, &ecc_pub);
        _ecc_params_to_privkey(priv, &ecc_priv);
        
        if (ecc_projective_check_point(&ecc_pub.pubkey, pub->params[ECC_B], pub->params[ECC_PRIME]) != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
            goto ecc_cleanup;
          }

        sz = ECC_BUF_SIZE;
        out->data = gnutls_malloc(sz);
        if (out->data == NULL)
          {
            ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
            goto ecc_cleanup;
          }

        ret = ecc_shared_secret(&ecc_priv, &ecc_pub, out->data, &sz);
        if (ret != 0)
          ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

ecc_cleanup:
        _ecc_params_clear(&ecc_pub);
        _ecc_params_clear(&ecc_priv);

        if (ret < 0)
          {
            gnutls_free(out->data);
            return ret;
          }

        out->size = sz;
        break;
      }
    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = 0;

cleanup:

  return ret;
}

static int
_wrap_nettle_pk_encrypt (gnutls_pk_algorithm_t algo,
                         gnutls_datum_t * ciphertext,
                         const gnutls_datum_t * plaintext,
                         const gnutls_pk_params_st * pk_params)
{
  int ret;

  switch (algo)
    {
    case GNUTLS_PK_RSA:
      {
        bigint_t p;

        if (_gnutls_mpi_scan_nz (&p, plaintext->data, plaintext->size) != 0)
          {
            gnutls_assert ();
            return GNUTLS_E_MPI_SCAN_FAILED;
          }

        mpz_powm (p, p, TOMPZ (pk_params->params[1]) /*e */ ,
                  TOMPZ (pk_params->params[0] /*m */ ));

        ret = _gnutls_mpi_dprint_size (p, ciphertext, plaintext->size);
        _gnutls_mpi_release (&p);

        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }

        break;
      }
    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = 0;

cleanup:

  return ret;
}

/* returns the blinded c and the inverse of a random
 * number r;
 */
static bigint_t
rsa_blind (bigint_t c, bigint_t e, bigint_t n, bigint_t * _ri)
{
  bigint_t nc = NULL, r = NULL, ri = NULL;

  /* nc = c*(r^e)
   * ri = r^(-1)
   */
  nc = _gnutls_mpi_alloc_like (n);
  if (nc == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  ri = _gnutls_mpi_alloc_like (n);
  if (nc == NULL)
    {
      gnutls_assert ();
      goto fail;
    }

  r = _gnutls_mpi_randomize (NULL, _gnutls_mpi_get_nbits (n),
                             GNUTLS_RND_NONCE);
  if (r == NULL)
    {
      gnutls_assert ();
      goto fail;
    }

  /* invert r */
  if (mpz_invert (ri, r, n) == 0)
    {
      gnutls_assert ();
      goto fail;
    }

  /* r = r^e */

  _gnutls_mpi_powm (r, r, e, n);

  _gnutls_mpi_mulm (nc, c, r, n);

  *_ri = ri;

  _gnutls_mpi_release (&r);

  return nc;
fail:
  _gnutls_mpi_release (&nc);
  _gnutls_mpi_release (&r);
  return NULL;
}

/* c = c*ri mod n
 */
static inline void
rsa_unblind (bigint_t c, bigint_t ri, bigint_t n)
{
  _gnutls_mpi_mulm (c, c, ri, n);
}

static int
_wrap_nettle_pk_decrypt (gnutls_pk_algorithm_t algo,
                         gnutls_datum_t * plaintext,
                         const gnutls_datum_t * ciphertext,
                         const gnutls_pk_params_st * pk_params)
{
  int ret;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_RSA:
      {
        struct rsa_private_key priv;
        bigint_t c, ri, nc;

        if (_gnutls_mpi_scan_nz (&c, ciphertext->data, ciphertext->size) != 0)
          {
            gnutls_assert ();
            return GNUTLS_E_MPI_SCAN_FAILED;
          }

        nc = rsa_blind (c, pk_params->params[1] /*e */ ,
                        pk_params->params[0] /*m */ , &ri);
        _gnutls_mpi_release (&c);
        if (nc == NULL)
          {
            gnutls_assert ();
            return GNUTLS_E_MEMORY_ERROR;
          }

        memset(&priv, 0, sizeof(priv));
        _rsa_params_to_privkey (pk_params, &priv);

        rsa_compute_root (&priv, TOMPZ (nc), TOMPZ (nc));

        rsa_unblind (nc, ri, pk_params->params[0] /*m */ );

        ret = _gnutls_mpi_dprint_size (nc, plaintext, ciphertext->size);

        _gnutls_mpi_release (&nc);
        _gnutls_mpi_release (&ri);

        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }

        break;
      }
    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = 0;

cleanup:

  return ret;
}

/* in case of DSA puts into data, r,s
 */
static int
_wrap_nettle_pk_sign (gnutls_pk_algorithm_t algo,
                      gnutls_datum_t * signature,
                      const gnutls_datum_t * vdata,
                      const gnutls_pk_params_st * pk_params)
{
  int ret, hash;

  switch (algo)
    {
    case GNUTLS_PK_ECC: /* we do ECDSA */
      {
        ecc_key priv;
        struct dsa_signature sig;
        int hash_len;

        _ecc_params_to_privkey(pk_params, &priv);

        dsa_signature_init (&sig);

        hash = _gnutls_dsa_q_to_hash (algo, pk_params, &hash_len);
        if (hash_len > vdata->size)
          {
            gnutls_assert ();
            _gnutls_debug_log("Security level of algorithm requires hash %s(%d) or better\n", gnutls_mac_get_name(hash), hash_len);
            hash_len = vdata->size;
          }

        ret = ecc_sign_hash(vdata->data, hash_len, 
                            &sig, NULL, rnd_func, &priv);
        if (ret != 0)
          {
            gnutls_assert ();
            ret = GNUTLS_E_PK_SIGN_FAILED;
            goto ecdsa_fail;
          }

        ret = _gnutls_encode_ber_rs (signature, &sig.r, &sig.s);

      ecdsa_fail:
        dsa_signature_clear (&sig);
        _ecc_params_clear( &priv);

        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }
        break;
      }
    case GNUTLS_PK_DSA:
      {
        struct dsa_public_key pub;
        struct dsa_private_key priv;
        struct dsa_signature sig;
        int hash_len;

        memset(&priv, 0, sizeof(priv));
        memset(&pub, 0, sizeof(pub));
        _dsa_params_to_pubkey (pk_params, &pub);
        _dsa_params_to_privkey (pk_params, &priv);

        dsa_signature_init (&sig);

        hash = _gnutls_dsa_q_to_hash (algo, pk_params, &hash_len);
        if (hash_len > vdata->size)
          {
            gnutls_assert ();
            _gnutls_debug_log("Security level of algorithm requires hash %s(%d) or better\n", gnutls_mac_get_name(hash), hash_len);
            hash_len = vdata->size;
          }

        ret =
          _dsa_sign (&pub, &priv, NULL, rnd_func,
                     hash_len, vdata->data, &sig);
        if (ret == 0)
          {
            gnutls_assert ();
            ret = GNUTLS_E_PK_SIGN_FAILED;
            goto dsa_fail;
          }

        ret = _gnutls_encode_ber_rs (signature, &sig.r, &sig.s);

      dsa_fail:
        dsa_signature_clear (&sig);

        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }
        break;
      }
    case GNUTLS_PK_RSA:
      {
        struct rsa_private_key priv;
        bigint_t hash, nc, ri;

        if (_gnutls_mpi_scan_nz (&hash, vdata->data, vdata->size) != 0)
          {
            gnutls_assert ();
            return GNUTLS_E_MPI_SCAN_FAILED;
          }

        memset(&priv, 0, sizeof(priv));
        _rsa_params_to_privkey (pk_params, &priv);

        nc = rsa_blind (hash, pk_params->params[1] /*e */ ,
                        pk_params->params[0] /*m */ , &ri);

        _gnutls_mpi_release (&hash);

        if (nc == NULL)
          {
            gnutls_assert ();
            ret = GNUTLS_E_MEMORY_ERROR;
            goto rsa_fail;
          }

        rsa_compute_root (&priv, TOMPZ (nc), TOMPZ (nc));

        rsa_unblind (nc, ri, pk_params->params[0] /*m */ );

        ret = _gnutls_mpi_dprint (nc, signature);

rsa_fail:
        _gnutls_mpi_release (&nc);
        _gnutls_mpi_release (&ri);

        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }

        break;
      }
    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = 0;

cleanup:

  return ret;
}

static int
_int_rsa_verify (const gnutls_pk_params_st * pk_params,
                 bigint_t m, bigint_t s)
{
  int res;

  mpz_t m1;

  if ((mpz_sgn (TOMPZ (s)) <= 0)
      || (mpz_cmp (TOMPZ (s), TOMPZ (pk_params->params[0])) >= 0))
    return GNUTLS_E_PK_SIG_VERIFY_FAILED;

  mpz_init (m1);

  mpz_powm (m1, TOMPZ (s), TOMPZ (pk_params->params[1]),
            TOMPZ (pk_params->params[0]));

  res = !mpz_cmp (TOMPZ (m), m1);

  mpz_clear (m1);

  if (res == 0)
    res = GNUTLS_E_PK_SIG_VERIFY_FAILED;
  else
    res = 0;

  return res;
}

static int
_wrap_nettle_pk_verify (gnutls_pk_algorithm_t algo,
                        const gnutls_datum_t * vdata,
                        const gnutls_datum_t * signature,
                        const gnutls_pk_params_st * pk_params)
{
  int ret;
  int hash_len;
  bigint_t tmp[2] = { NULL, NULL };

  switch (algo)
    {
    case GNUTLS_PK_ECC: /* ECDSA */
      {
        ecc_key pub;
        struct dsa_signature sig;
        int stat;

        ret = _gnutls_decode_ber_rs (signature, &tmp[0], &tmp[1]);
        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }

        _ecc_params_to_pubkey(pk_params, &pub);
        memcpy (&sig.r, tmp[0], sizeof (sig.r));
        memcpy (&sig.s, tmp[1], sizeof (sig.s));

        _gnutls_dsa_q_to_hash (algo, pk_params, &hash_len);
        if (hash_len > vdata->size)
          hash_len = vdata->size;

        ret = ecc_verify_hash(&sig, vdata->data, hash_len, &stat, &pub);
        if (ret != 0 || stat != 1)
          {
            gnutls_assert();
            ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
          }
        else
          ret = 0;

        _gnutls_mpi_release (&tmp[0]);
        _gnutls_mpi_release (&tmp[1]);
        _ecc_params_clear( &pub);
        break;
      }
    case GNUTLS_PK_DSA:
      {
        struct dsa_public_key pub;
        struct dsa_signature sig;

        ret = _gnutls_decode_ber_rs (signature, &tmp[0], &tmp[1]);
        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }
        memset(&pub, 0, sizeof(pub));
        _dsa_params_to_pubkey (pk_params, &pub);
        memcpy (&sig.r, tmp[0], sizeof (sig.r));
        memcpy (&sig.s, tmp[1], sizeof (sig.s));

        _gnutls_dsa_q_to_hash (algo, pk_params, &hash_len);
        if (hash_len > vdata->size)
          hash_len = vdata->size;

        ret = _dsa_verify (&pub, hash_len, vdata->data, &sig);
        if (ret == 0)
          {
            gnutls_assert();
            ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
          }
        else
          ret = 0;

        _gnutls_mpi_release (&tmp[0]);
        _gnutls_mpi_release (&tmp[1]);
        break;
      }
    case GNUTLS_PK_RSA:
      {
        bigint_t hash;

        if (_gnutls_mpi_scan_nz (&hash, vdata->data, vdata->size) != 0)
          {
            gnutls_assert ();
            return GNUTLS_E_MPI_SCAN_FAILED;
          }

        ret = _gnutls_mpi_scan_nz (&tmp[0], signature->data, signature->size);
        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }

        ret = _int_rsa_verify (pk_params, hash, tmp[0]);
        _gnutls_mpi_release (&tmp[0]);
        _gnutls_mpi_release (&hash);
        break;
      }
    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

cleanup:

  return ret;
}

static inline int is_supported_curve(int curve)
{
  if (gnutls_ecc_curve_get_name(curve) != NULL)
    return 1;
  else
    return 0;
}


static int
wrap_nettle_pk_generate_params (gnutls_pk_algorithm_t algo,
                                unsigned int level /*bits */ ,
                                gnutls_pk_params_st * params)
{
  int ret, i;
  int q_bits;

  memset(params, 0, sizeof(*params));

  switch (algo)
    {

    case GNUTLS_PK_DSA:
      {
        struct dsa_public_key pub;
        struct dsa_private_key priv;

        dsa_public_key_init (&pub);
        dsa_private_key_init (&priv);

        /* the best would be to use _gnutls_pk_bits_to_subgroup_bits()
         * but we do NIST DSA here */
        if (level <= 1024)
          q_bits = 160;
        else
          q_bits = 256;

        ret =
          dsa_generate_keypair (&pub, &priv, NULL,
                                rnd_func, NULL, NULL, level, q_bits);
        if (ret != 1)
          {
            gnutls_assert ();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto dsa_fail;
          }

        params->params_nr = 0;
        for (i = 0; i < DSA_PRIVATE_PARAMS; i++)
          {
            params->params[i] = _gnutls_mpi_alloc_like (&pub.p);
            if (params->params[i] == NULL)
              {
                ret = GNUTLS_E_MEMORY_ERROR;
                goto dsa_fail;
              }
            params->params_nr++;
          }

        ret = 0;
        _gnutls_mpi_set (params->params[0], pub.p);
        _gnutls_mpi_set (params->params[1], pub.q);
        _gnutls_mpi_set (params->params[2], pub.g);
        _gnutls_mpi_set (params->params[3], pub.y);
        _gnutls_mpi_set (params->params[4], priv.x);

dsa_fail:
        dsa_private_key_clear (&priv);
        dsa_public_key_clear (&pub);

        if (ret < 0)
          goto fail;

        break;
      }
    case GNUTLS_PK_RSA:
      {
        struct rsa_public_key pub;
        struct rsa_private_key priv;

        rsa_public_key_init (&pub);
        rsa_private_key_init (&priv);

        _gnutls_mpi_set_ui (&pub.e, 65537);

        ret =
          rsa_generate_keypair (&pub, &priv, NULL,
                                rnd_func, NULL, NULL, level, 0);
        if (ret != 1)
          {
            gnutls_assert ();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto rsa_fail;
          }

        params->params_nr = 0;
        for (i = 0; i < RSA_PRIVATE_PARAMS; i++)
          {
            params->params[i] = _gnutls_mpi_alloc_like (&pub.n);
            if (params->params[i] == NULL)
              {
                ret = GNUTLS_E_MEMORY_ERROR;
                goto rsa_fail;
              }
            params->params_nr++;

          }
          
        ret = 0;

        _gnutls_mpi_set (params->params[0], pub.n);
        _gnutls_mpi_set (params->params[1], pub.e);
        _gnutls_mpi_set (params->params[2], priv.d);
        _gnutls_mpi_set (params->params[3], priv.p);
        _gnutls_mpi_set (params->params[4], priv.q);
        _gnutls_mpi_set (params->params[5], priv.c);
        _gnutls_mpi_set (params->params[6], priv.a);
        _gnutls_mpi_set (params->params[7], priv.b);

rsa_fail:
        rsa_private_key_clear (&priv);
        rsa_public_key_clear (&pub);

        if (ret < 0)
          goto fail;

        break;
      }
    case GNUTLS_PK_ECC:
      {
        ecc_key key;
        ecc_set_type tls_ecc_set;
        const gnutls_ecc_curve_entry_st *st;

        st = _gnutls_ecc_curve_get_params(level);
        if (st == NULL)
          return gnutls_assert_val(GNUTLS_E_ECC_UNSUPPORTED_CURVE);
        
        tls_ecc_set.size = st->size;
        tls_ecc_set.prime = st->prime;
        tls_ecc_set.order = st->order;
        tls_ecc_set.Gx = st->Gx;
        tls_ecc_set.Gy = st->Gy;
        tls_ecc_set.A = st->A;
        tls_ecc_set.B = st->B;

        ret = ecc_make_key(NULL, rnd_func, &key, &tls_ecc_set);
        if (ret != 0)
          return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

        params->params_nr = 0;
        for (i = 0; i < ECC_PRIVATE_PARAMS; i++)
          {
            params->params[i] = _gnutls_mpi_alloc_like(&key.prime);
            if (params->params[i] == NULL)
              {
                ret = GNUTLS_E_MEMORY_ERROR;
                goto ecc_fail;
              }
            params->params_nr++;
          }
        params->flags = level;

        mpz_set(TOMPZ(params->params[ECC_PRIME]), key.prime);
        mpz_set(TOMPZ(params->params[ECC_ORDER]), key.order);
        mpz_set(TOMPZ(params->params[ECC_A]), key.A);
        mpz_set(TOMPZ(params->params[ECC_B]), key.B);
        mpz_set(TOMPZ(params->params[ECC_GX]), key.Gx);
        mpz_set(TOMPZ(params->params[ECC_GY]), key.Gy);
        mpz_set(TOMPZ(params->params[ECC_X]), key.pubkey.x);
        mpz_set(TOMPZ(params->params[ECC_Y]), key.pubkey.y);
        mpz_set(TOMPZ(params->params[ECC_K]), key.k);
        
ecc_fail:
        ecc_free(&key);
        
        if (ret < 0)
          goto fail;

        break;
      }
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return 0;

fail:

  for (i = 0; i < params->params_nr; i++)
    {
      _gnutls_mpi_release (&params->params[i]);
    }
  params->params_nr = 0;

  return ret;
}

static int
wrap_nettle_pk_verify_params (gnutls_pk_algorithm_t algo,
                              const gnutls_pk_params_st * params)
{
  int ret;

  switch (algo)
    {
    case GNUTLS_PK_RSA:
      {
        bigint_t t1 = NULL, t2 = NULL;

        if (params->params_nr != RSA_PRIVATE_PARAMS)
          return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
        
        t1 = _gnutls_mpi_new (256);
        if (t1 == NULL)
          return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

        _gnutls_mpi_mulm (t1, params->params[RSA_PRIME1], params->params[RSA_PRIME2], params->params[RSA_MODULUS]);
        if (_gnutls_mpi_cmp_ui(t1, 0) != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
            goto rsa_cleanup;
          }

        mpz_invert (TOMPZ(t1), TOMPZ (params->params[RSA_PRIME2]), TOMPZ (params->params[RSA_PRIME1]));
        if (_gnutls_mpi_cmp(t1, params->params[RSA_COEF]) != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
            goto rsa_cleanup;
          }

        /* [RSA_PRIME1] = d % p-1, [RSA_PRIME2] = d % q-1 */
        _gnutls_mpi_sub_ui (t1, params->params[RSA_PRIME1], 1);
        t2 = _gnutls_mpi_mod (params->params[RSA_PRIV], t1);
        if (t2 == NULL)
          {
            ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
            goto rsa_cleanup;
          }
  
        if (_gnutls_mpi_cmp(params->params[RSA_E1], t2) != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
            goto rsa_cleanup;
          }
        
        _gnutls_mpi_sub_ui (t1, params->params[RSA_PRIME2], 1);
        _gnutls_mpi_release(&t2);

        t2 = _gnutls_mpi_mod (params->params[RSA_PRIV], t1);
        if (t2 == NULL)
          {
            ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
            goto rsa_cleanup;
          }
  
        if (_gnutls_mpi_cmp(params->params[RSA_E2], t2) != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
            goto rsa_cleanup;
          }
        
        ret = 0;

rsa_cleanup:
        _gnutls_mpi_release(&t1);
        _gnutls_mpi_release(&t2);
      }

      break;
    case GNUTLS_PK_DSA:
      {
        bigint_t t1 = NULL;

        if (params->params_nr != DSA_PRIVATE_PARAMS)
          return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
        
        t1 = _gnutls_mpi_new (256);
        if (t1 == NULL)
          return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

        _gnutls_mpi_powm (t1, params->params[DSA_G], params->params[DSA_X], params->params[DSA_P]);

        if (_gnutls_mpi_cmp(t1, params->params[DSA_Y]) != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
            goto dsa_cleanup;
          }

        ret = 0;

dsa_cleanup:
        _gnutls_mpi_release(&t1);
      }

      break;
    case GNUTLS_PK_ECC:
      {
        int curve = params->flags;
        ecc_key ecc_priv;
        ecc_point *R;
        ecc_point zero;

        if (params->params_nr != ECC_PRIVATE_PARAMS)
          return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

        if (is_supported_curve(curve) == 0)
          return gnutls_assert_val(GNUTLS_E_ECC_UNSUPPORTED_CURVE);

        _ecc_params_to_privkey(params, &ecc_priv);
        R = ecc_new_point();

        /* verify that x,y lie on the curve */
        ret = ecc_projective_check_point(&ecc_priv.pubkey, TOMPZ(params->params[ECC_B]), params->params[ECC_PRIME]);
        if (ret != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
            goto ecc_cleanup;
          }

        memcpy(&zero.x, ecc_priv.Gx, sizeof(mpz_t));
        memcpy(&zero.y, ecc_priv.Gy, sizeof(mpz_t));
        memcpy(&zero.z, ecc_priv.pubkey.z, sizeof(mpz_t)); /* z = 1 */

        /* verify that k*(Gx,Gy)=(x,y) */
        ret = ecc_mulmod(ecc_priv.k, &zero, R, TOMPZ(params->params[ECC_A]), TOMPZ(params->params[ECC_PRIME]), 1);
        if (ret != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
            goto ecc_cleanup;
          }

        if (mpz_cmp(ecc_priv.pubkey.x, R->x) != 0 || mpz_cmp(ecc_priv.pubkey.y, R->y) != 0)
          {
            ret = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
            goto ecc_cleanup;
          }
        
        ret = 0;

ecc_cleanup:
        _ecc_params_clear(&ecc_priv);
        ecc_del_point(R);
      }  
      break;
    default:
      ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
    }

  return ret;
}

static int calc_rsa_exp (gnutls_pk_params_st* params)
{
  bigint_t tmp = _gnutls_mpi_alloc_like (params->params[0]);

  if (params->params_nr < RSA_PRIVATE_PARAMS - 2)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (tmp == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* [6] = d % p-1, [7] = d % q-1 */
  _gnutls_mpi_sub_ui (tmp, params->params[3], 1);
  params->params[6] = _gnutls_mpi_mod (params->params[2] /*d */ , tmp);

  _gnutls_mpi_sub_ui (tmp, params->params[4], 1);
  params->params[7] = _gnutls_mpi_mod (params->params[2] /*d */ , tmp);

  _gnutls_mpi_release (&tmp);

  if (params->params[7] == NULL || params->params[6] == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  return 0;
}


static int
wrap_nettle_pk_fixup (gnutls_pk_algorithm_t algo,
                      gnutls_direction_t direction,
                      gnutls_pk_params_st * params)
{
  int result;

  if (direction == GNUTLS_IMPORT && algo == GNUTLS_PK_RSA)
    {
      /* do not trust the generated values. Some old private keys
       * generated by us have mess on the values. Those were very
       * old but it seemed some of the shipped example private
       * keys were as old.
       */
      mpz_invert (TOMPZ (params->params[RSA_COEF]),
                  TOMPZ (params->params[RSA_PRIME2]), TOMPZ (params->params[RSA_PRIME1]));

      /* calculate exp1 [6] and exp2 [7] */
      _gnutls_mpi_release (&params->params[RSA_E1]);
      _gnutls_mpi_release (&params->params[RSA_E2]);

      result = calc_rsa_exp (params);
      if (result < 0)
        {
          gnutls_assert ();
          return result;
        }
      params->params_nr = RSA_PRIVATE_PARAMS;
    }

  return 0;
}

int crypto_pk_prio = INT_MAX;

gnutls_crypto_pk_st _gnutls_pk_ops = {
  .encrypt = _wrap_nettle_pk_encrypt,
  .decrypt = _wrap_nettle_pk_decrypt,
  .sign = _wrap_nettle_pk_sign,
  .verify = _wrap_nettle_pk_verify,
  .verify_params = wrap_nettle_pk_verify_params,
  .generate = wrap_nettle_pk_generate_params,
  .pk_fixup_private_params = wrap_nettle_pk_fixup,
  .derive = _wrap_nettle_pk_derive,
};
