/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_global.h>
#include <libtasn1.h>
#include <gnutls_datum.h>
#include "common.h"
#include "x509_int.h"
#include <gnutls_num.h>
#include <gnutls_pk.h>
#include <gnutls_mpi.h>
#include <gnutls_ecc.h>

static int _gnutls_x509_write_rsa_pubkey (gnutls_pk_params_st * params, 
                                   gnutls_datum_t * der);
static int _gnutls_x509_write_dsa_params (gnutls_pk_params_st * params,
                                   gnutls_datum_t * der);
static int _gnutls_x509_write_dsa_pubkey (gnutls_pk_params_st * params,
                                       gnutls_datum_t * der);

/*
 * some x509 certificate functions that relate to MPI parameter
 * setting. This writes the BIT STRING subjectPublicKey.
 * Needs 2 parameters (m,e).
 *
 * Allocates the space used to store the DER data.
 */
static int
_gnutls_x509_write_rsa_pubkey (gnutls_pk_params_st * params,
                               gnutls_datum_t * der)
{
  int result;
  ASN1_TYPE spk = ASN1_TYPE_EMPTY;

  der->data = NULL;
  der->size = 0;

  if (params->params_nr < RSA_PUBLIC_PARAMS)
    {
      gnutls_assert ();
      result = GNUTLS_E_INVALID_REQUEST;
      goto cleanup;
    }

  if ((result = asn1_create_element
       (_gnutls_get_gnutls_asn (), "GNUTLS.RSAPublicKey", &spk))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_write_int (spk, "modulus", params->params[0], 1);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_write_int (spk, "publicExponent", params->params[1], 1);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_der_encode (spk, "", der, 0);
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

/*
 * some x509 certificate functions that relate to MPI parameter
 * setting. This writes an ECPoint.
 *
 * Allocates the space used to store the DER data.
 */
int
_gnutls_x509_write_ecc_pubkey (gnutls_pk_params_st * params,
                               gnutls_datum_t * der)
{
  int result;

  der->data = NULL;
  der->size = 0;

  if (params->params_nr < ECC_PUBLIC_PARAMS)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  result = _gnutls_ecc_ansi_x963_export(params->flags, params->params[ECC_X], params->params[ECC_Y], /*&out*/der);
  if (result < 0)
    return gnutls_assert_val(result);

  return 0;
}

int
_gnutls_x509_write_pubkey_params (gnutls_pk_algorithm_t algo,
                                   gnutls_pk_params_st* params,
                                   gnutls_datum_t * der)
{
  switch(algo)
    {
      case GNUTLS_PK_DSA:
        return _gnutls_x509_write_dsa_params(params, der);
      case GNUTLS_PK_RSA:
        der->data = gnutls_malloc(ASN1_NULL_SIZE);
        if (der->data == NULL)
          return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
        
        memcpy(der->data, ASN1_NULL, ASN1_NULL_SIZE);
        der->size = ASN1_NULL_SIZE;
        return 0;
      case GNUTLS_PK_EC:
        return _gnutls_x509_write_ecc_params(params, der);
      default:
        return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
    }
}

int
_gnutls_x509_write_pubkey (gnutls_pk_algorithm_t algo,
                                   gnutls_pk_params_st* params,
                                   gnutls_datum_t * der)
{
  switch(algo)
    {
      case GNUTLS_PK_DSA:
        return _gnutls_x509_write_dsa_pubkey(params, der);
      case GNUTLS_PK_RSA:
        return _gnutls_x509_write_rsa_pubkey(params, der);
      case GNUTLS_PK_EC:
        return _gnutls_x509_write_ecc_pubkey(params, der);
      default:
        return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
    }
}

/*
 * This function writes the parameters for DSS keys.
 * Needs 3 parameters (p,q,g).
 *
 * Allocates the space used to store the DER data.
 */
static int
_gnutls_x509_write_dsa_params (gnutls_pk_params_st* params,
                               gnutls_datum_t * der)
{
  int result;
  ASN1_TYPE spk = ASN1_TYPE_EMPTY;

  der->data = NULL;
  der->size = 0;

  if (params->params_nr < DSA_PUBLIC_PARAMS-1)
    {
      gnutls_assert ();
      result = GNUTLS_E_INVALID_REQUEST;
      goto cleanup;
    }

  if ((result = asn1_create_element
       (_gnutls_get_gnutls_asn (), "GNUTLS.DSAParameters", &spk))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_write_int (spk, "p", params->params[0], 1);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_write_int (spk, "q", params->params[1], 1);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_write_int (spk, "g", params->params[2], 1);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_der_encode (spk, "", der, 0);
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

/*
 * This function writes the parameters for ECC keys.
 * That is the ECParameters struct.
 *
 * Allocates the space used to store the DER data.
 */
int
_gnutls_x509_write_ecc_params (gnutls_pk_params_st* params,
                               gnutls_datum_t * der)
{
  int result;
  ASN1_TYPE spk = ASN1_TYPE_EMPTY;
  const char* oid;

  der->data = NULL;
  der->size = 0;

  if (params->params_nr < ECC_PUBLIC_PARAMS)
    {
      gnutls_assert ();
      result = GNUTLS_E_INVALID_REQUEST;
      goto cleanup;
    }

  oid = _gnutls_ecc_curve_get_oid(params->flags);
  if (oid == NULL)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);


  if ((result = asn1_create_element
       (_gnutls_get_gnutls_asn (), "GNUTLS.ECParameters", &spk))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  if ((result = asn1_write_value (spk, "", "namedCurve", 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }
  
  if ((result = asn1_write_value (spk, "namedCurve", oid, 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  result = _gnutls_x509_der_encode (spk, "", der, 0);
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

/*
 * This function writes the public parameters for DSS keys.
 * Needs 1 parameter (y).
 *
 * Allocates the space used to store the DER data.
 */
static int
_gnutls_x509_write_dsa_pubkey (gnutls_pk_params_st * params,
                                   gnutls_datum_t * der)
{
  int result;
  ASN1_TYPE spk = ASN1_TYPE_EMPTY;

  der->data = NULL;
  der->size = 0;

  if (params->params_nr < DSA_PUBLIC_PARAMS)
    {
      gnutls_assert ();
      result = GNUTLS_E_INVALID_REQUEST;
      goto cleanup;
    }

  if ((result = asn1_create_element
       (_gnutls_get_gnutls_asn (), "GNUTLS.DSAPublicKey", &spk))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_write_int (spk, "", params->params[3], 1);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_der_encode (spk, "", der, 0);
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

/* Encodes the RSA parameters into an ASN.1 RSA private key structure.
 */
static int
_gnutls_asn1_encode_rsa (ASN1_TYPE * c2, gnutls_pk_params_st * params)
{
  int result;
  uint8_t null = '\0';
  gnutls_pk_params_st pk_params;
  gnutls_datum_t m, e, d, p, q, u, exp1, exp2;

  gnutls_pk_params_init(&pk_params);

  memset (&m, 0, sizeof (m));
  memset (&p, 0, sizeof (p));
  memset (&q, 0, sizeof (q));
  memset (&p, 0, sizeof (p));
  memset (&u, 0, sizeof (u));
  memset (&e, 0, sizeof (e));
  memset (&d, 0, sizeof (d));
  memset (&exp1, 0, sizeof (exp1));
  memset (&exp2, 0, sizeof (exp2));

  result = _gnutls_pk_params_copy (&pk_params, params);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = _gnutls_pk_fixup (GNUTLS_PK_RSA, GNUTLS_EXPORT, &pk_params);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  /* retrieve as data */

  result = _gnutls_mpi_dprint_lz (pk_params.params[0], &m);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_mpi_dprint_lz (pk_params.params[1], &e);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_mpi_dprint_lz (pk_params.params[2], &d);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_mpi_dprint_lz (pk_params.params[3], &p);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_mpi_dprint_lz (pk_params.params[4], &q);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_mpi_dprint_lz (pk_params.params[5], &u);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_mpi_dprint_lz (pk_params.params[6], &exp1);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_mpi_dprint_lz (pk_params.params[7], &exp2);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  /* Ok. Now we have the data. Create the asn1 structures
   */

  /* first make sure that no previously allocated data are leaked */
  if (*c2 != ASN1_TYPE_EMPTY)
    {
      asn1_delete_structure (c2);
      *c2 = ASN1_TYPE_EMPTY;
    }

  if ((result = asn1_create_element
       (_gnutls_get_gnutls_asn (), "GNUTLS.RSAPrivateKey", c2))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  /* Write PRIME 
   */
  if ((result = asn1_write_value (*c2, "modulus",
                                  m.data, m.size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "publicExponent",
                                  e.data, e.size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "privateExponent",
                                  d.data, d.size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "prime1",
                                  p.data, p.size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "prime2",
                                  q.data, q.size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "coefficient",
                                  u.data, u.size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);

      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "exponent1",
                                  exp1.data, exp1.size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "exponent2",
                                  exp2.data, exp2.size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "otherPrimeInfos",
                                  NULL, 0)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "version", &null, 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  result = 0;

cleanup:
  if (result != 0)
    asn1_delete_structure (c2);

  gnutls_pk_params_release (&pk_params);

  _gnutls_free_datum (&m);
  _gnutls_free_datum (&d);
  _gnutls_free_datum (&e);
  _gnutls_free_datum (&p);
  _gnutls_free_datum (&q);
  _gnutls_free_datum (&u);
  _gnutls_free_datum (&exp1);
  _gnutls_free_datum (&exp2);

  return result;
}

/* Encodes the ECC parameters into an ASN.1 ECPrivateKey structure.
 */
static int
_gnutls_asn1_encode_ecc (ASN1_TYPE * c2, gnutls_pk_params_st * params)
{
  int ret;
  uint8_t one = '\x01';
  gnutls_datum pubkey = { NULL, 0 };
  const char *oid;
  
  oid = _gnutls_ecc_curve_get_oid(params->flags);

  if (params->params_nr != ECC_PRIVATE_PARAMS || oid == NULL)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  ret = _gnutls_ecc_ansi_x963_export(params->flags, params->params[ECC_X], params->params[ECC_Y], &pubkey);
  if (ret < 0)
    return gnutls_assert_val(ret);
  
  /* Ok. Now we have the data. Create the asn1 structures
   */

  /* first make sure that no previously allocated data are leaked */
  if (*c2 != ASN1_TYPE_EMPTY)
    {
      asn1_delete_structure (c2);
      *c2 = ASN1_TYPE_EMPTY;
    }

  if ((ret = asn1_create_element
       (_gnutls_get_gnutls_asn (), "GNUTLS.ECPrivateKey", c2))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      ret = _gnutls_asn2err (ret);
      goto cleanup;
    }

  if ((ret = asn1_write_value (*c2, "Version", &one, 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      ret = _gnutls_asn2err (ret);
      goto cleanup;
    }

  ret = _gnutls_x509_write_int (*c2, "privateKey", params->params[ECC_K], 1);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  if ((ret = asn1_write_value (*c2, "publicKey", pubkey.data, pubkey.size*8)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      ret = _gnutls_asn2err (ret);
      goto cleanup;
    }

  /* write our choice */
  if ((ret = asn1_write_value (*c2, "parameters", "namedCurve", 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      ret = _gnutls_asn2err (ret);
      goto cleanup;
    }
  
  if ((ret = asn1_write_value (*c2, "parameters.namedCurve", oid, 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      ret = _gnutls_asn2err (ret);
      goto cleanup;
    }

  _gnutls_free_datum(&pubkey);
  return 0;

cleanup:
  asn1_delete_structure (c2);
  _gnutls_free_datum(&pubkey);

  return ret;
}


/* Encodes the DSA parameters into an ASN.1 DSAPrivateKey structure.
 */
static int
_gnutls_asn1_encode_dsa (ASN1_TYPE * c2, gnutls_pk_params_st * params)
{
  int result, i;
  size_t size[DSA_PRIVATE_PARAMS], total;
  uint8_t *p_data, *q_data, *g_data, *x_data, *y_data;
  uint8_t *all_data = NULL, *p;
  uint8_t null = '\0';

  /* Read all the sizes */
  total = 0;
  for (i = 0; i < DSA_PRIVATE_PARAMS; i++)
    {
      _gnutls_mpi_print_lz (params->params[i], NULL, &size[i]);
      total += size[i];
    }

  /* Encoding phase.
   * allocate data enough to hold everything
   */
  all_data = gnutls_malloc (total);
  if (all_data == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  p = all_data;
  p_data = p;
  p += size[0];
  q_data = p;
  p += size[1];
  g_data = p;
  p += size[2];
  y_data = p;
  p += size[3];
  x_data = p;

  _gnutls_mpi_print_lz (params->params[0], p_data, &size[0]);
  _gnutls_mpi_print_lz (params->params[1], q_data, &size[1]);
  _gnutls_mpi_print_lz (params->params[2], g_data, &size[2]);
  _gnutls_mpi_print_lz (params->params[3], y_data, &size[3]);
  _gnutls_mpi_print_lz (params->params[4], x_data, &size[4]);

  /* Ok. Now we have the data. Create the asn1 structures
   */

  /* first make sure that no previously allocated data are leaked */
  if (*c2 != ASN1_TYPE_EMPTY)
    {
      asn1_delete_structure (c2);
      *c2 = ASN1_TYPE_EMPTY;
    }

  if ((result = asn1_create_element
       (_gnutls_get_gnutls_asn (), "GNUTLS.DSAPrivateKey", c2))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  /* Write PRIME 
   */
  if ((result = asn1_write_value (*c2, "p", p_data, size[0])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "q", q_data, size[1])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "g", g_data, size[2])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "Y", y_data, size[3])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "priv",
                                  x_data, size[4])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  gnutls_free (all_data);

  if ((result = asn1_write_value (*c2, "version", &null, 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = _gnutls_asn2err (result);
      goto cleanup;
    }

  return 0;

cleanup:
  asn1_delete_structure (c2);
  gnutls_free (all_data);

  return result;
}

int _gnutls_asn1_encode_privkey (gnutls_pk_algorithm_t pk, ASN1_TYPE * c2, gnutls_pk_params_st * params)
{
  switch(pk)
    {
      case GNUTLS_PK_RSA:
        return _gnutls_asn1_encode_rsa(c2, params);
      case GNUTLS_PK_DSA:
        return _gnutls_asn1_encode_dsa(c2, params);
      case GNUTLS_PK_EC:
        return _gnutls_asn1_encode_ecc(c2, params);
      default:
        return GNUTLS_E_UNIMPLEMENTED_FEATURE;
    }
}
