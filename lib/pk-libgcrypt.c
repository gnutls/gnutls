/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Free Software Foundation
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
#include <gnutls_pk.h>
#include <gcrypt.h>

/* this is based on code from old versions of libgcrypt (centuries ago)
 */

int (*generate) (gnutls_pk_algorithm_t, unsigned int level /*bits */ ,
		 gnutls_pk_params_st *);

int
_wrap_gcry_pk_encrypt(gnutls_pk_algorithm_t algo,
		      gnutls_datum_t * ciphertext,
		      const gnutls_datum_t * plaintext,
		      const gnutls_pk_params_st * pk_params)
{
  gcry_sexp_t s_ciph = NULL, s_data = NULL, s_pkey = NULL;
  int rc = -1;
  int ret;
  bigint_t data = NULL;

  if (_gnutls_mpi_scan_nz(&data, plaintext->data, plaintext->size) != 0) {
    gnutls_assert();
    return GNUTLS_E_MPI_SCAN_FAILED;
  }

  /* make a sexp from pkey */
  switch (algo) {
  case GNUTLS_PK_RSA:
    if (pk_params->params_nr >= 2)
      rc = gcry_sexp_build(&s_pkey, NULL,
			   "(public-key(rsa(n%m)(e%m)))",
			   pk_params->params[0], pk_params->params[1]);
    break;

  default:
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  if (rc != 0) {
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  /* put the data into a simple list */
  if (gcry_sexp_build(&s_data, NULL, "%m", data)) {
    gnutls_assert();
    ret = GNUTLS_E_MEMORY_ERROR;
    goto cleanup;
  }

  _gnutls_mpi_release(&data);

  /* pass it to libgcrypt */
  rc = gcry_pk_encrypt(&s_ciph, s_data, s_pkey);
  gcry_sexp_release(s_data);
  s_data = NULL;
  gcry_sexp_release(s_pkey);
  s_pkey = NULL;

  if (rc != 0) {
    gnutls_assert();
    ret = GNUTLS_E_PK_ENCRYPTION_FAILED;
    goto cleanup;
  } else {
    gcry_sexp_t list = gcry_sexp_find_token(s_ciph, "a", 0);
    bigint_t res;

    if (list == NULL) {
      gnutls_assert();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

    res = gcry_sexp_nth_mpi(list, 1, 0);
    gcry_sexp_release(list);

    if (res == NULL) {
      gnutls_assert();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

    ret = _gnutls_mpi_dprint_size(res, ciphertext, plaintext->size);
    _gnutls_mpi_release(&res);

    if (ret < 0) {
      gnutls_assert();
      goto cleanup;
    }
  }

  gcry_sexp_release(s_ciph);
  return 0;

cleanup:
  _gnutls_mpi_release(&data);
  if (s_ciph)
    gcry_sexp_release(s_ciph);
  if (s_data)
    gcry_sexp_release(s_data);
  if (s_pkey)
    gcry_sexp_release(s_pkey);

  return ret;
}

int
_wrap_gcry_pk_decrypt(gnutls_pk_algorithm_t algo,
		      gnutls_datum_t * plaintext,
		      const gnutls_datum_t * ciphertext,
		      const gnutls_pk_params_st * pk_params)
{
  gcry_sexp_t s_plain = NULL, s_data = NULL, s_pkey = NULL;
  int rc = -1;
  int ret;
  bigint_t data;

  if (_gnutls_mpi_scan_nz(&data, ciphertext->data, ciphertext->size) != 0) {
    gnutls_assert();
    return GNUTLS_E_MPI_SCAN_FAILED;
  }

  /* make a sexp from pkey */
  switch (algo) {
  case GNUTLS_PK_RSA:
    if (pk_params->params_nr >= 6)
      rc = gcry_sexp_build(&s_pkey, NULL,
			   "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
			   pk_params->params[0], pk_params->params[1],
			   pk_params->params[2], pk_params->params[3],
			   pk_params->params[4], pk_params->params[5]);
    break;

  default:
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  if (rc != 0) {
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  }

  /* put the data into a simple list */
  if (gcry_sexp_build(&s_data, NULL, "(enc-val(rsa(a%m)))", data)) {
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  _gnutls_mpi_release(&data);

  /* pass it to libgcrypt */
  rc = gcry_pk_decrypt(&s_plain, s_data, s_pkey);
  gcry_sexp_release(s_data);
  gcry_sexp_release(s_pkey);

  if (rc != 0) {
    gnutls_assert();
    return GNUTLS_E_PK_DECRYPTION_FAILED;
  } else {
    bigint_t res;
    res = gcry_sexp_nth_mpi(s_plain, 0, 0);
    gcry_sexp_release(s_plain);

    if (res == NULL) {
      gnutls_assert();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

    ret = _gnutls_mpi_dprint_size(res, plaintext, ciphertext->size);
    _gnutls_mpi_release(&res);

    if (ret < 0) {
      gnutls_assert();
      goto cleanup;
    }

  }

  return 0;

cleanup:
  _gnutls_mpi_release(&data);
  if (s_plain)
    gcry_sexp_release(s_plain);
  if (s_data)
    gcry_sexp_release(s_data);
  if (s_pkey)
    gcry_sexp_release(s_pkey);

  return ret;

}


/* in case of DSA puts into data, r,s
 */
int
_wrap_gcry_pk_sign(gnutls_pk_algorithm_t algo, gnutls_datum_t * signature,
		   const gnutls_datum_t * vdata,
		   const gnutls_pk_params_st * pk_params)
{
  gcry_sexp_t s_hash = NULL, s_key = NULL, s_sig = NULL;
  gcry_sexp_t list = NULL;
  int rc = -1, ret;
  bigint_t hash;
  bigint_t res[2] = { NULL, NULL };

  if (_gnutls_mpi_scan_nz(&hash, vdata->data, vdata->size) != 0) {
    gnutls_assert();
    return GNUTLS_E_MPI_SCAN_FAILED;
  }

  /* make a sexp from pkey */
  switch (algo) {
  case GNUTLS_PK_DSA:
    if (pk_params->params_nr >= 5)
      rc = gcry_sexp_build(&s_key, NULL,
			   "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
			   pk_params->params[0], pk_params->params[1],
			   pk_params->params[2], pk_params->params[3],
			   pk_params->params[4]);
    else {
      gnutls_assert();
    }

    break;
  case GNUTLS_PK_RSA:
    if (pk_params->params_nr >= 6)
      rc = gcry_sexp_build(&s_key, NULL,
			   "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
			   pk_params->params[0], pk_params->params[1],
			   pk_params->params[2], pk_params->params[3],
			   pk_params->params[4], pk_params->params[5]);
    else {
      gnutls_assert();
    }
    break;

  default:
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  }

  if (rc != 0) {
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  }

  /* put the data into a simple list */
  if (gcry_sexp_build(&s_hash, NULL, "%m", hash)) {
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  _gnutls_mpi_release(&hash);

  /* pass it to libgcrypt */
  rc = gcry_pk_sign(&s_sig, s_hash, s_key);
  gcry_sexp_release(s_hash);
  gcry_sexp_release(s_key);

  if (rc != 0) {
    gnutls_assert();
    ret = GNUTLS_E_PK_SIGN_FAILED;
    goto cleanup;
  }

  ret = GNUTLS_E_INTERNAL_ERROR;

  if (algo == GNUTLS_PK_DSA) {
    list = gcry_sexp_find_token(s_sig, "r", 0);
    if (list == NULL) {
      gnutls_assert();
      gcry_sexp_release(s_sig);
      return GNUTLS_E_INTERNAL_ERROR;
    }

    res[0] = gcry_sexp_nth_mpi(list, 1, 0);
    gcry_sexp_release(list);

    list = gcry_sexp_find_token(s_sig, "s", 0);
    if (list == NULL) {
      gnutls_assert();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

    res[1] = gcry_sexp_nth_mpi(list, 1, 0);
    gcry_sexp_release(list);

    ret = _gnutls_encode_ber_rs(signature, res[0], res[1]);

  } else if (algo == GNUTLS_PK_RSA) {	/* GCRY_PK_RSA */
    list = gcry_sexp_find_token(s_sig, "s", 0);
    if (list == NULL) {
      gnutls_assert();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

    res[0] = gcry_sexp_nth_mpi(list, 1, 0);
    gcry_sexp_release(list);

    ret = _gnutls_mpi_dprint(res[0], signature);
  }

  if (ret < 0) {
    gnutls_assert();
    goto cleanup;
  }

  gcry_sexp_release(s_sig);

  return 0;

cleanup:
  _gnutls_mpi_release(&hash);
  _gnutls_mpi_release(&res[0]);
  _gnutls_mpi_release(&res[1]);
  if (s_sig)
    gcry_sexp_release(s_sig);
  if (list)
    gcry_sexp_release(list);
  if (s_hash)
    gcry_sexp_release(s_hash);
  if (s_key)
    gcry_sexp_release(s_key);

  return ret;
}

int _wrap_gcry_pk_verify( gnutls_pk_algorithm_t algo, 
	const gnutls_datum_t * vdata, const gnutls_datum_t * signature,
	       const gnutls_pk_params_st * pk_params)
{
  gcry_sexp_t s_sig, s_hash, s_pkey;
  int rc = -1, ret;
  bigint_t hash;
  bigint_t tmp[2] = { NULL, NULL };

  if (_gnutls_mpi_scan_nz(&hash, vdata->data, vdata->size) != 0) {
    gnutls_assert();
    return GNUTLS_E_MPI_SCAN_FAILED;
  }

  /* make a sexp from pkey */
  switch (algo) {
  case GNUTLS_PK_DSA:
    if (pk_params->params_nr >= 4)
      rc = gcry_sexp_build(&s_pkey, NULL,
			   "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
			   pk_params->params[0], pk_params->params[1], pk_params->params[2], pk_params->params[3]);
    break;
  case GNUTLS_PK_RSA:
    if (pk_params->params_nr >= 2)
      rc = gcry_sexp_build(&s_pkey, NULL,
			   "(public-key(rsa(n%m)(e%m)))",
			   pk_params->params[0], pk_params->params[1]);
    break;

  default:
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  if (rc != 0) {
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  /* put the data into a simple list */
  if (gcry_sexp_build(&s_hash, NULL, "%m", hash)) {
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  switch (algo) {
  case GNUTLS_PK_DSA:
    ret = _gnutls_decode_ber_rs (signature, &tmp[0], &tmp[1]);
    if (ret < 0)
      {
        gnutls_assert();
        goto cleanup;
      }
    rc = gcry_sexp_build(&s_sig, NULL,
			 "(sig-val(dsa(r%m)(s%m)))", tmp[0], tmp[1]);

    break;
  case GNUTLS_PK_RSA:
    ret = _gnutls_mpi_scan_nz( &tmp[0], signature->data, signature->size);
    if (ret < 0)
      {
        gnutls_assert();
        goto cleanup;
      }
    rc = gcry_sexp_build(&s_sig, NULL, "(sig-val(rsa(s%m)))", tmp[0]);
    break;

  default:
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  if (rc != 0) {
    gnutls_assert();
    ret = GNUTLS_E_INTERNAL_ERROR;
    goto cleanup;
  }

  _gnutls_mpi_release(&tmp[0]);
  _gnutls_mpi_release(&tmp[1]);

  rc = gcry_pk_verify(s_sig, s_hash, s_pkey);

  gcry_sexp_release(s_sig);
  gcry_sexp_release(s_hash);
  gcry_sexp_release(s_pkey);

  if (rc != 0) {
    gnutls_assert();
    ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
    goto cleanup;
  }

  return 0;

cleanup:
  _gnutls_mpi_release(&hash);
  _gnutls_mpi_release(&tmp[0]);
  _gnutls_mpi_release(&tmp[1]);
  if (s_sig)
    gcry_sexp_release(s_sig);
  if (s_hash)
    gcry_sexp_release(s_hash);
  if (s_pkey)
    gcry_sexp_release(s_pkey);

  return ret;
}

static int _dsa_generate_params(bigint_t * resarr, int *resarr_len, int bits)
{

  int ret;
  gcry_sexp_t parms, key, list;

  /* FIXME: Remove me once we depend on 1.3.1 */
  if (bits > 1024 && gcry_check_version("1.3.1") == NULL) {
    gnutls_assert();
    return GNUTLS_E_INVALID_REQUEST;
  }

  if (bits < 512) {
    gnutls_assert();
    return GNUTLS_E_INVALID_REQUEST;
  }

  ret = gcry_sexp_build(&parms, NULL, "(genkey(dsa(nbits %d)))", bits);
  if (ret != 0) {
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  }

  /* generate the DSA key 
   */
  ret = gcry_pk_genkey(&key, parms);
  gcry_sexp_release(parms);

  if (ret != 0) {
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  }

  list = gcry_sexp_find_token(key, "p", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[0] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);

  list = gcry_sexp_find_token(key, "q", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[1] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);

  list = gcry_sexp_find_token(key, "g", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[2] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);

  list = gcry_sexp_find_token(key, "y", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[3] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);


  list = gcry_sexp_find_token(key, "x", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[4] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);


  gcry_sexp_release(key);

  _gnutls_dump_mpi("p: ", resarr[0]);
  _gnutls_dump_mpi("q: ", resarr[1]);
  _gnutls_dump_mpi("g: ", resarr[2]);
  _gnutls_dump_mpi("y: ", resarr[3]);
  _gnutls_dump_mpi("x: ", resarr[4]);

  *resarr_len = 5;

  return 0;

}

static int _rsa_generate_params(bigint_t * resarr, int *resarr_len, int bits)
{

  int ret;
  gcry_sexp_t parms, key, list;

  ret = gcry_sexp_build(&parms, NULL, "(genkey(rsa(nbits %d)))", bits);
  if (ret != 0) {
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  }

  /* generate the RSA key */
  ret = gcry_pk_genkey(&key, parms);
  gcry_sexp_release(parms);

  if (ret != 0) {
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  }

  list = gcry_sexp_find_token(key, "n", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[0] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);

  list = gcry_sexp_find_token(key, "e", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[1] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);

  list = gcry_sexp_find_token(key, "d", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[2] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);

  list = gcry_sexp_find_token(key, "p", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[3] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);


  list = gcry_sexp_find_token(key, "q", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[4] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);


  list = gcry_sexp_find_token(key, "u", 0);
  if (list == NULL) {
    gnutls_assert();
    gcry_sexp_release(key);
    return GNUTLS_E_INTERNAL_ERROR;
  }

  resarr[5] = gcry_sexp_nth_mpi(list, 1, 0);
  gcry_sexp_release(list);

  gcry_sexp_release(key);

  _gnutls_dump_mpi("n: ", resarr[0]);
  _gnutls_dump_mpi("e: ", resarr[1]);
  _gnutls_dump_mpi("d: ", resarr[2]);
  _gnutls_dump_mpi("p: ", resarr[3]);
  _gnutls_dump_mpi("q: ", resarr[4]);
  _gnutls_dump_mpi("u: ", resarr[5]);

  *resarr_len = 6;

  return 0;

}


static
int wrap_gcry_pk_generate_params(gnutls_pk_algorithm_t algo,
				 unsigned int level /*bits */ ,
				 gnutls_pk_params_st * params)
{

  switch (algo) {

  case GNUTLS_PK_DSA:
    params->params_nr = RSA_PRIVATE_PARAMS;
    params->params = gnutls_malloc(sizeof(bigint_t)*params->params_nr);
    if (params->params == NULL)
      {
        gnutls_assert();
	return GNUTLS_E_MEMORY_ERROR;
      }
    return _dsa_generate_params(params->params, &params->params_nr, level);

  case GNUTLS_PK_RSA:
    params->params_nr = DSA_PRIVATE_PARAMS;
    params->params = gnutls_malloc(sizeof(bigint_t)*params->params_nr);
    if (params->params == NULL)
      {
        gnutls_assert();
	return GNUTLS_E_MEMORY_ERROR;
      }
    return _rsa_generate_params(params->params, &params->params_nr, level);

  default:
    gnutls_assert();
    return GNUTLS_E_INVALID_REQUEST;
  }
}


static int wrap_gcry_pk_fixup(gnutls_pk_algorithm_t algo,
			      gnutls_direction_t direction,
			      gnutls_pk_params_st * params)
{
  int ret;

  /* only for RSA we invert the coefficient --pgp type */

  if (algo != GNUTLS_PK_RSA)
    return 0;

  if (params->params[5])
    _gnutls_mpi_release(&params->params[5]);
  params->params[5] =
      _gnutls_mpi_new(_gnutls_mpi_get_nbits(params->params[0]));

  if (params->params[5] == NULL) {
    gnutls_assert();
    return GNUTLS_E_MEMORY_ERROR;
  }

  if (direction == GNUTLS_IMPORT)
    ret = gcry_mpi_invm(params->params[5], params->params[3], params->params[4]);
  else
    ret = gcry_mpi_invm(params->params[5], params->params[4], params->params[3]);
  if (ret == 0) {
    gnutls_assert();
    return GNUTLS_E_INVALID_REQUEST;
  }

  return 0;
}

int crypto_pk_prio = INT_MAX;

gnutls_crypto_pk_st _gnutls_pk_ops = {
  .encrypt = _wrap_gcry_pk_encrypt,
  .decrypt = _wrap_gcry_pk_decrypt,
  .sign = _wrap_gcry_pk_sign,
  .verify = _wrap_gcry_pk_verify,
  .generate = wrap_gcry_pk_generate_params,
  .pk_fixup_private_params = wrap_gcry_pk_fixup,
};
