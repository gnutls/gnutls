/*
 * Copyright (C) 2010
 * Free Software Foundation, Inc.
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
#include <x509/x509_int.h>
#include <x509/common.h>
#include <random.h>
#include <gnutls_pk.h>
#include <nettle/dsa.h>
#include <nettle/rsa.h>
#include <random.h>
#include <gnutls/crypto.h>

#define TOMPZ(x) (*((mpz_t*)(x)))

static void rnd_func(void *_ctx, unsigned length, uint8_t * data)
{
	_gnutls_rnd(GNUTLS_RND_RANDOM, data, length);
}

static void _dsa_params_to_pubkey(const gnutls_pk_params_st * pk_params, struct dsa_public_key *pub)
{
	memcpy(&pub->p, pk_params->params[0], sizeof(mpz_t));
	memcpy(&pub->q, pk_params->params[1], sizeof(mpz_t));
	memcpy(&pub->g, pk_params->params[2], sizeof(mpz_t));
	memcpy(&pub->y, pk_params->params[3], sizeof(mpz_t));
}

static void _dsa_params_to_privkey(const gnutls_pk_params_st * pk_params, struct  dsa_private_key *pub)
{
	memcpy(&pub->x, pk_params->params[4], sizeof(mpz_t));
}

static void _rsa_params_to_privkey(const gnutls_pk_params_st * pk_params, struct rsa_private_key *priv)
{
mpz_t q_1;

	memcpy(&priv->d, pk_params->params[2], sizeof(mpz_t));
	memcpy(&priv->p, pk_params->params[3], sizeof(mpz_t));
	memcpy(&priv->q, pk_params->params[4], sizeof(mpz_t));
	memcpy(&priv->c, pk_params->params[5], sizeof(mpz_t));

	/* FIXME: possibly move it to fixup to avoid those calculations here */	
	
	/* b = d % q-1 */
	mpz_init(q_1);
	mpz_sub_ui(q_1, priv->q, 1);
	
	mpz_fdiv_r(priv->b, priv->d, q_1);

	/* a = d % p-1 */
	mpz_sub_ui(q_1, priv->p, 1);
	mpz_fdiv_r(priv->a, priv->d, q_1);
}

static int
_wrap_nettle_pk_encrypt(gnutls_pk_algorithm_t algo,
			gnutls_datum_t * ciphertext,
			const gnutls_datum_t * plaintext,
			const gnutls_pk_params_st * pk_params)
{
	int ret;

	/* make a sexp from pkey */
	switch (algo) {
	case GNUTLS_PK_RSA: {
		bigint_t p;
		
		if (_gnutls_mpi_scan_nz(&p, plaintext->data, plaintext->size) != 0) {
			gnutls_assert();
			return GNUTLS_E_MPI_SCAN_FAILED;
		}

		mpz_powm(p, p, TOMPZ(pk_params->params[1]), TOMPZ(pk_params->params[0]));

		ret = _gnutls_mpi_dprint(p, ciphertext);
		_gnutls_mpi_release(&p);

		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		break;
	}
	default:
		gnutls_assert();
		ret = GNUTLS_E_INTERNAL_ERROR;
		goto cleanup;
	}

	ret = 0;

cleanup:

	return ret;
}

static int
_wrap_nettle_pk_decrypt(gnutls_pk_algorithm_t algo,
			gnutls_datum_t * plaintext,
			const gnutls_datum_t * ciphertext,
			const gnutls_pk_params_st * pk_params)
{
	int ret;

	/* make a sexp from pkey */
	switch (algo) {
	case GNUTLS_PK_RSA: {
		struct rsa_private_key priv;
		bigint_t c;
		
		if (_gnutls_mpi_scan_nz(&c, ciphertext->data, ciphertext->size) != 0) {
			gnutls_assert();
			return GNUTLS_E_MPI_SCAN_FAILED;
		}

		/* FIXME: implement blinding */

		rsa_private_key_init(&priv);
		_rsa_params_to_privkey(pk_params, &priv);

		rsa_compute_root(&priv, TOMPZ(c), TOMPZ(c));

		ret = _gnutls_mpi_dprint(c, plaintext);
		_gnutls_mpi_release(&c);
		mpz_clear(priv.a);
		mpz_clear(priv.b);

		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		break;
	}
	default:
		gnutls_assert();
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
_wrap_nettle_pk_sign(gnutls_pk_algorithm_t algo,
		     gnutls_datum_t * signature,
		     const gnutls_datum_t * vdata,
		     const gnutls_pk_params_st * pk_params)
{
	int ret;

	switch (algo) {

	case GNUTLS_PK_DSA: {
		struct dsa_public_key pub;
		struct dsa_private_key priv;
		struct dsa_signature sig;
				
		dsa_public_key_init(&pub);
		dsa_private_key_init(&priv);
		_dsa_params_to_pubkey(pk_params, &pub);
		_dsa_params_to_privkey(pk_params, &priv);

		dsa_signature_init(&sig);

		dsa_sign_digest(&pub, &priv, NULL, rnd_func, vdata->data, &sig);

		ret =
			_gnutls_encode_ber_rs(signature, &sig.r,
					  &sig.s);
					  
		dsa_signature_clear(&sig);

		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
		break;
	}
	case GNUTLS_PK_RSA: {
		struct rsa_private_key priv;
		bigint_t hash;
		
		if (_gnutls_mpi_scan_nz(&hash, vdata->data, vdata->size) != 0) {
			gnutls_assert();
			return GNUTLS_E_MPI_SCAN_FAILED;
		}

		rsa_private_key_init(&priv);
		_rsa_params_to_privkey(pk_params, &priv);

		rsa_compute_root(&priv, TOMPZ(hash), TOMPZ(hash));

		ret = _gnutls_mpi_dprint(hash, signature);
		_gnutls_mpi_release(&hash);
		mpz_clear(priv.a);
		mpz_clear(priv.b);

		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		break;
	}
	default:
		gnutls_assert();
		ret = GNUTLS_E_INTERNAL_ERROR;
		goto cleanup;
	}

	ret = 0;

cleanup:

	return ret;
}

static int
_int_rsa_verify(const gnutls_pk_params_st * pk_params,
            bigint_t m,
            bigint_t s)
{
  int res;

  mpz_t m1;

  if ( (mpz_sgn(TOMPZ(s)) <= 0)
       || (mpz_cmp(TOMPZ(s), TOMPZ(pk_params->params[0])) >= 0) )
    return GNUTLS_E_PK_SIG_VERIFY_FAILED;

  mpz_init(m1);

  mpz_powm(m1, TOMPZ(s), TOMPZ(pk_params->params[1]), TOMPZ(pk_params->params[0]));

  res = !mpz_cmp(TOMPZ(m), m1);

  mpz_clear(m1);

  if (res == 0)
	res = GNUTLS_E_PK_SIG_VERIFY_FAILED;
  else res = 0;
  
  return res;
}

static int
_wrap_nettle_pk_verify(gnutls_pk_algorithm_t algo,
		       const gnutls_datum_t * vdata,
		       const gnutls_datum_t * signature,
		       const gnutls_pk_params_st * pk_params)
{
	int ret;
	bigint_t tmp[2] = { NULL, NULL };

	switch (algo) {
	case GNUTLS_PK_DSA: {
		struct dsa_public_key pub;
		struct dsa_signature sig;
				
		ret = _gnutls_decode_ber_rs(signature, &tmp[0], &tmp[1]);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
		dsa_public_key_init(&pub);
		_dsa_params_to_pubkey(pk_params, &pub);
		memcpy(&sig.r, tmp[0], sizeof(sig.r));
		memcpy(&sig.s, tmp[1], sizeof(sig.s));

		ret = dsa_verify_digest(&pub, vdata->data, &sig);
		if (ret == 0)
			ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
		else
			ret = 0;

		_gnutls_mpi_release(&tmp[0]);
		_gnutls_mpi_release(&tmp[1]);
		break;
	}
	case GNUTLS_PK_RSA: {
		bigint_t hash;
		
		if (_gnutls_mpi_scan_nz(&hash, vdata->data, vdata->size) != 0) {
			gnutls_assert();
			return GNUTLS_E_MPI_SCAN_FAILED;
		}

		ret =
		    _gnutls_mpi_scan_nz(&tmp[0], signature->data,
					signature->size);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = _int_rsa_verify(pk_params, hash, tmp[0]);
		_gnutls_mpi_release(&tmp[0]);
		_gnutls_mpi_release(&hash);
		break;
	}
	default:
		gnutls_assert();
		ret = GNUTLS_E_INTERNAL_ERROR;
		goto cleanup;
	}

cleanup:

	return ret;
}

static int
wrap_nettle_pk_generate_params(gnutls_pk_algorithm_t algo,
			       unsigned int level /*bits */ ,
			       gnutls_pk_params_st * params)
{
int ret, i;

	switch (algo) {

	case GNUTLS_PK_DSA: {
		struct dsa_public_key pub;
		struct dsa_private_key priv;
	
		dsa_public_key_init(&pub);
		dsa_private_key_init(&priv);

		ret = dsa_generate_keypair (&pub, &priv, NULL, rnd_func, NULL, NULL, level);
		if (ret != 1) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}
		
		params->params_nr = 0;
		for (i=0;i<DSA_PRIVATE_PARAMS;i++) {
			params->params[i] = _gnutls_mpi_alloc_like(&pub.p);
			if (params->params[i] == NULL) {
				ret = GNUTLS_E_MEMORY_ERROR;
				dsa_private_key_clear(&priv);
				dsa_public_key_clear(&pub);
				goto fail;
			}
			params->params_nr++;
		}
		_gnutls_mpi_set(params->params[0], pub.p);
		_gnutls_mpi_set(params->params[1], pub.q);
		_gnutls_mpi_set(params->params[2], pub.g);
		_gnutls_mpi_set(params->params[3], pub.y);
		_gnutls_mpi_set(params->params[4], priv.x);

		dsa_private_key_clear(&priv);
		dsa_public_key_clear(&pub);
  
		break;
	}
	case GNUTLS_PK_RSA: {
		struct rsa_public_key pub;
		struct rsa_private_key priv;
	
		rsa_public_key_init(&pub);
		rsa_private_key_init(&priv);

		ret = rsa_generate_keypair (&pub, &priv, NULL, rnd_func, NULL, NULL, level, 64);
		if (ret != 1) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}
		
		params->params_nr = 0;
		for (i=0;i<RSA_PRIVATE_PARAMS;i++) {
			params->params[i] = _gnutls_mpi_alloc_like(&pub.n);
			if (params->params[i] == NULL) {
				ret = GNUTLS_E_MEMORY_ERROR;
				rsa_private_key_clear(&priv);
				rsa_public_key_clear(&pub);
				goto fail;
			}
			params->params_nr++;
			
		}
		_gnutls_mpi_set(params->params[0], pub.n);
		_gnutls_mpi_set(params->params[1], pub.e);
		_gnutls_mpi_set(params->params[2], priv.d);
		_gnutls_mpi_set(params->params[3], priv.p);
		_gnutls_mpi_set(params->params[4], priv.q);
		_gnutls_mpi_set(params->params[5], priv.c);

		rsa_private_key_clear(&priv);
		rsa_public_key_clear(&pub);
		
		break;
	}
	default:
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	return 0;

fail:

	for (i=0;i<params->params_nr;i++) {
		_gnutls_mpi_release(&params->params[i]);
	}
	params->params_nr=0;
	
	return ret;
}


static int
wrap_nettle_pk_fixup(gnutls_pk_algorithm_t algo,
		     gnutls_direction_t direction,
		     gnutls_pk_params_st * params)
{
	return 0;
}

int crypto_pk_prio = INT_MAX;

gnutls_crypto_pk_st _gnutls_pk_ops = {
	.encrypt = _wrap_nettle_pk_encrypt,
	.decrypt = _wrap_nettle_pk_decrypt,
	.sign = _wrap_nettle_pk_sign,
	.verify = _wrap_nettle_pk_verify,
	.generate = wrap_nettle_pk_generate_params,
	.pk_fixup_private_params = wrap_nettle_pk_fixup,
};
