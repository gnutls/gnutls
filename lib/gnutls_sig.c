/*
 * Copyright (C) 2001, 2004, 2005, 2006, 2007, 2008, 2009, 2010 Free
 * Software Foundation, Inc.
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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <x509_b64.h>
#include <auth_cert.h>
#include <gnutls_algorithms.h>
#include <gnutls_cert.h>
#include <gnutls_datum.h>
#include <gnutls_mpi.h>
#include <gnutls_global.h>
#include <gnutls_pk.h>
#include <debug.h>
#include <gnutls_buffers.h>
#include <gnutls_sig.h>
#include <gnutls_kx.h>
#include <libtasn1.h>
#include <ext_signature.h>
#include <gnutls_state.h>

static int
_gnutls_tls_sign (gnutls_session_t session,
		  gnutls_cert * cert, gnutls_privkey * pkey,
		  const gnutls_datum_t * hash_concat,
		  gnutls_datum_t * signature);

/* While this is currently equal to the length of RSA/SHA512
 * signature, it should also be sufficient for DSS signature and any
 * other RSA signatures including one with the old MD5/SHA1-combined
 * format.
 */
#define MAX_SIG_SIZE 19 + MAX_HASH_SIZE

/* Create a DER-encoded value as a opaque signature when RSA is used.
 * See RFC 5246 DigitallySigned for the actual format.
 */
static int
_gnutls_rsa_encode_sig (gnutls_mac_algorithm_t algo,
			const gnutls_datum_t * hash,
			gnutls_datum_t * signature)
{
  ASN1_TYPE di;
  const char *oid;
  int result, signature_size;

  oid = _gnutls_x509_mac_to_oid (algo);
  if (!oid)
    {
      gnutls_assert ();
      return GNUTLS_E_UNKNOWN_HASH_ALGORITHM;
    }

  if ((result = asn1_create_element
       (_gnutls_get_gnutls_asn (), "GNUTLS.DigestInfo", &di)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  if ((result = asn1_write_value (di, "digestAlgorithm.algorithm",
				  oid, strlen (oid))) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&di);
      return _gnutls_asn2err (result);
    }

  /* Use NULL parameters. */
  if ((result = asn1_write_value (di, "digestAlgorithm.parameters",
				  "\x05\x00", 2)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&di);
      return _gnutls_asn2err (result);
    }

  if ((result = asn1_write_value (di, "digest",
				  hash->data, hash->size)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&di);
      return _gnutls_asn2err (result);
    }

  signature_size = signature->size;
  result = asn1_der_coding (di, "", signature->data, &signature_size, NULL);
  asn1_delete_structure (&di);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  signature->size = signature_size;

  return 0;
}



/* Generates a signature of all the random data and the parameters.
 * Used in DHE_* ciphersuites.
 */
int
_gnutls_handshake_sign_data (gnutls_session_t session, gnutls_cert * cert,
			     gnutls_privkey * pkey, gnutls_datum_t * params,
			     gnutls_datum_t * signature,
			     gnutls_sign_algorithm_t * sign_algo)
{
  gnutls_datum_t dconcat;
  int ret;
  digest_hd_st td_sha;
  opaque concat[MAX_SIG_SIZE];
  gnutls_protocol_t ver = gnutls_protocol_get_version (session);
  gnutls_digest_algorithm_t hash_algo;

  *sign_algo =
    _gnutls_session_get_sign_algo (session, cert->subject_pk_algorithm,
				   &hash_algo);
  if (*sign_algo == GNUTLS_SIGN_UNKNOWN)
    {
      gnutls_assert ();
      return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
    }

  ret = _gnutls_hash_init (&td_sha, hash_algo);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_hash (&td_sha, session->security_parameters.client_random,
		GNUTLS_RANDOM_SIZE);
  _gnutls_hash (&td_sha, session->security_parameters.server_random,
		GNUTLS_RANDOM_SIZE);
  _gnutls_hash (&td_sha, params->data, params->size);

  switch (cert->subject_pk_algorithm)
    {
    case GNUTLS_PK_RSA:
      if (!_gnutls_version_has_selectable_prf (ver))
	{
	  digest_hd_st td_md5;

	  ret = _gnutls_hash_init (&td_md5, GNUTLS_MAC_MD5);
	  if (ret < 0)
	    {
	      gnutls_assert ();
	      return ret;
	    }

	  _gnutls_hash (&td_md5, session->security_parameters.client_random,
			GNUTLS_RANDOM_SIZE);
	  _gnutls_hash (&td_md5, session->security_parameters.server_random,
			GNUTLS_RANDOM_SIZE);
	  _gnutls_hash (&td_md5, params->data, params->size);

	  _gnutls_hash_deinit (&td_md5, concat);
	  _gnutls_hash_deinit (&td_sha, &concat[16]);

	  dconcat.data = concat;
	  dconcat.size = 36;
	}
      else
	{			/* TLS 1.2 way */
	  gnutls_datum_t hash;

	  _gnutls_hash_deinit (&td_sha, concat);

	  hash.data = concat;
	  hash.size = _gnutls_hash_get_algo_len (hash_algo);
	  dconcat.data = concat;
	  dconcat.size = sizeof concat;

	  _gnutls_rsa_encode_sig (hash_algo, &hash, &dconcat);
	}
      break;
    case GNUTLS_PK_DSA:
      _gnutls_hash_deinit (&td_sha, concat);

      if (hash_algo != GNUTLS_DIG_SHA1)
	{
	  gnutls_assert ();
	  return GNUTLS_E_INTERNAL_ERROR;
	}
      dconcat.data = concat;
      dconcat.size = 20;
      break;

    default:
      gnutls_assert ();
      _gnutls_hash_deinit (&td_sha, NULL);
      return GNUTLS_E_INTERNAL_ERROR;
    }
  ret = _gnutls_tls_sign (session, cert, pkey, &dconcat, signature);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  return ret;

}


/* This will create a PKCS1 or DSA signature, using the given parameters, and the
 * given data. The output will be allocated and be put in signature.
 */
int
_gnutls_sign (gnutls_pk_algorithm_t algo, bigint_t * params,
	      int params_size, const gnutls_datum_t * data,
	      gnutls_datum_t * signature)
{
  int ret;

  switch (algo)
    {
    case GNUTLS_PK_RSA:
      /* encrypt */
      if ((ret = _gnutls_pkcs1_rsa_encrypt (signature, data, params,
					    params_size, 1)) < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      break;
    case GNUTLS_PK_DSA:
      /* sign */
      if ((ret = _gnutls_dsa_sign (signature, data, params, params_size)) < 0)
	{
	  gnutls_assert ();
	  return ret;
	}
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
      break;
    }

  return 0;
}

/* This will create a PKCS1 or DSA signature, as defined in the TLS protocol.
 * Cert is the certificate of the corresponding private key. It is only checked if
 * it supports signing.
 */
static int
_gnutls_tls_sign (gnutls_session_t session,
		  gnutls_cert * cert, gnutls_privkey * pkey,
		  const gnutls_datum_t * hash_concat,
		  gnutls_datum_t * signature)
{

  /* If our certificate supports signing
   */

  if (cert != NULL)
    {
      if (cert->key_usage != 0)
	if (!(cert->key_usage & KEY_DIGITAL_SIGNATURE))
	  {
	    gnutls_assert ();
	    return GNUTLS_E_KEY_USAGE_VIOLATION;
	  }

      /* External signing. */
      if (!pkey || pkey->params_size == 0)
	{
	  if (!session->internals.sign_func)
	    return GNUTLS_E_INSUFFICIENT_CREDENTIALS;

	  return (*session->internals.sign_func)
	    (session, session->internals.sign_func_userdata,
	     cert->cert_type, &cert->raw, hash_concat, signature);
	}
    }

  return _gnutls_sign (pkey->pk_algorithm, pkey->params,
		       pkey->params_size, hash_concat, signature);
}

static int
_gnutls_verify_sig (gnutls_cert * cert,
		    const gnutls_datum_t * hash_concat,
		    gnutls_datum_t * signature, size_t sha1pos,
		    gnutls_pk_algorithm_t pk_algo)
{
  int ret;
  gnutls_datum_t vdata;

  if (cert == NULL || cert->version == 0)
    {				/* this is the only way to check
				 * if it is initialized
				 */
      gnutls_assert ();
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  /* If the certificate supports signing continue.
   */
  if (cert->key_usage != 0)
    if (!(cert->key_usage & KEY_DIGITAL_SIGNATURE))
      {
	gnutls_assert ();
	return GNUTLS_E_KEY_USAGE_VIOLATION;
      }

  if (pk_algo == GNUTLS_PK_UNKNOWN)
    pk_algo = cert->subject_pk_algorithm;
  switch (pk_algo)
    {
    case GNUTLS_PK_RSA:

      vdata.data = hash_concat->data;
      vdata.size = hash_concat->size;

      /* verify signature */
      if ((ret = _gnutls_rsa_verify (&vdata, signature, cert->params,
				     cert->params_size, 1)) < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      break;
    case GNUTLS_PK_DSA:

      vdata.data = &hash_concat->data[sha1pos];
      vdata.size = hash_concat->size - sha1pos;

      /* verify signature */
      if ((ret = _gnutls_dsa_verify (&vdata, signature, cert->params,
				     cert->params_size)) < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }



  return 0;
}


/* Generates a signature of all the random data and the parameters.
 * Used in DHE_* ciphersuites.
 */
int
_gnutls_handshake_verify_data (gnutls_session_t session, gnutls_cert * cert,
			       const gnutls_datum_t * params,
			       gnutls_datum_t * signature,
			       gnutls_sign_algorithm_t algo)
{
  gnutls_datum_t dconcat;
  int ret;
  digest_hd_st td_md5;
  digest_hd_st td_sha;
  opaque concat[MAX_SIG_SIZE];
  gnutls_protocol_t ver = gnutls_protocol_get_version (session);
  gnutls_digest_algorithm_t hash_algo = GNUTLS_DIG_SHA1;

  ret = _gnutls_session_sign_algo_enabled (session, algo);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (!_gnutls_version_has_selectable_prf (ver))
    {
      ret = _gnutls_hash_init (&td_md5, GNUTLS_MAC_MD5);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      _gnutls_hash (&td_md5, session->security_parameters.client_random,
		    GNUTLS_RANDOM_SIZE);
      _gnutls_hash (&td_md5, session->security_parameters.server_random,
		    GNUTLS_RANDOM_SIZE);
      _gnutls_hash (&td_md5, params->data, params->size);
    }

  if (algo != GNUTLS_SIGN_UNKNOWN)
    hash_algo = _gnutls_sign_get_hash_algorithm (algo);

  ret = _gnutls_hash_init (&td_sha, hash_algo);
  if (ret < 0)
    {
      gnutls_assert ();
      if (!_gnutls_version_has_selectable_prf (ver))
	_gnutls_hash_deinit (&td_md5, NULL);
      return ret;
    }

  _gnutls_hash (&td_sha, session->security_parameters.client_random,
		GNUTLS_RANDOM_SIZE);
  _gnutls_hash (&td_sha, session->security_parameters.server_random,
		GNUTLS_RANDOM_SIZE);
  _gnutls_hash (&td_sha, params->data, params->size);

  if (!_gnutls_version_has_selectable_prf (ver))
    {
      _gnutls_hash_deinit (&td_md5, concat);
      _gnutls_hash_deinit (&td_sha, &concat[16]);
      dconcat.data = concat;
      dconcat.size = 36;
    }
  else
    {
      gnutls_datum_t hash;

      _gnutls_hash_deinit (&td_sha, concat);

      hash.data = concat;
      hash.size = _gnutls_hash_get_algo_len (hash_algo);
      dconcat.data = concat;
      dconcat.size = sizeof concat;

      _gnutls_rsa_encode_sig (hash_algo, &hash, &dconcat);
    }

  ret = _gnutls_verify_sig (cert, &dconcat, signature,
			    dconcat.size -
			    _gnutls_hash_get_algo_len (hash_algo),
			    _gnutls_sign_get_pk_algorithm (algo));
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return ret;

}

/* Client certificate verify calculations
 */

/* this is _gnutls_handshake_verify_cert_vrfy for TLS 1.2
 */
static int
_gnutls_handshake_verify_cert_vrfy12 (gnutls_session_t session,
				      gnutls_cert * cert,
				      gnutls_datum_t * signature,
				      gnutls_sign_algorithm_t sign_algo)
{
  int ret;
  opaque concat[MAX_SIG_SIZE];
  digest_hd_st td;
  gnutls_datum_t dconcat;
  gnutls_sign_algorithm_t _sign_algo;
  gnutls_digest_algorithm_t hash_algo;
  digest_hd_st *handshake_td;

  handshake_td = &session->internals.handshake_mac_handle.tls12.sha1;
  hash_algo = handshake_td->algorithm;
  _sign_algo =
    _gnutls_x509_pk_to_sign (cert->subject_pk_algorithm, hash_algo);

  if (_sign_algo != sign_algo)
    {
      handshake_td = &session->internals.handshake_mac_handle.tls12.sha256;
      hash_algo = handshake_td->algorithm;
      _sign_algo =
	_gnutls_x509_pk_to_sign (cert->subject_pk_algorithm, hash_algo);
      if (sign_algo != _sign_algo)
	{
	  gnutls_assert ();
	  return GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM;
	}
    }

  ret = _gnutls_hash_copy (&td, handshake_td);
  if (ret < 0)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  _gnutls_hash_deinit (&td, concat);

  dconcat.data = concat;
  dconcat.size = _gnutls_hash_get_algo_len (hash_algo);

  ret =
    _gnutls_verify_sig (cert, &dconcat, signature, 0,
			cert->subject_pk_algorithm);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return ret;

}

/* Verifies a TLS signature (like the one in the client certificate
 * verify message). 
 */
int
_gnutls_handshake_verify_cert_vrfy (gnutls_session_t session,
				    gnutls_cert * cert,
				    gnutls_datum_t * signature,
				    gnutls_sign_algorithm_t sign_algo)
{
  int ret;
  opaque concat[MAX_SIG_SIZE];
  digest_hd_st td_md5;
  digest_hd_st td_sha;
  gnutls_datum_t dconcat;
  gnutls_protocol_t ver = gnutls_protocol_get_version (session);

  if (session->security_parameters.handshake_mac_handle_type ==
      HANDSHAKE_MAC_TYPE_12)
    {
      return _gnutls_handshake_verify_cert_vrfy12 (session, cert, signature,
						   sign_algo);
    }
  else if (session->security_parameters.handshake_mac_handle_type !=
	   HANDSHAKE_MAC_TYPE_10)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ret =
    _gnutls_hash_copy (&td_md5,
		       &session->internals.handshake_mac_handle.tls10.md5);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    _gnutls_hash_copy (&td_sha,
		       &session->internals.handshake_mac_handle.tls10.sha);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_hash_deinit (&td_md5, NULL);
      return GNUTLS_E_HASH_FAILED;
    }

  if (ver == GNUTLS_SSL3)
    {
      ret = _gnutls_generate_master (session, 1);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      _gnutls_mac_deinit_ssl3_handshake (&td_md5, concat,
					 session->
					 security_parameters.master_secret,
					 GNUTLS_MASTER_SIZE);
      _gnutls_mac_deinit_ssl3_handshake (&td_sha, &concat[16],
					 session->
					 security_parameters.master_secret,
					 GNUTLS_MASTER_SIZE);
    }
  else
    {
      _gnutls_hash_deinit (&td_md5, concat);
      _gnutls_hash_deinit (&td_sha, &concat[16]);
    }

  dconcat.data = concat;
  dconcat.size = 20 + 16;	/* md5+ sha */

  ret =
    _gnutls_verify_sig (cert, &dconcat, signature, 16,
			cert->subject_pk_algorithm);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return ret;

}

/* the same as _gnutls_handshake_sign_cert_vrfy except that it is made for TLS 1.2
 */
static int
_gnutls_handshake_sign_cert_vrfy12 (gnutls_session_t session,
				    gnutls_cert * cert, gnutls_privkey * pkey,
				    gnutls_datum_t * signature)
{
  gnutls_datum_t dconcat;
  int ret;
  opaque concat[MAX_SIG_SIZE];
  digest_hd_st td;
  gnutls_sign_algorithm_t sign_algo;
  gnutls_digest_algorithm_t hash_algo;
  digest_hd_st *handshake_td;

  handshake_td = &session->internals.handshake_mac_handle.tls12.sha1;
  hash_algo = handshake_td->algorithm;
  sign_algo = _gnutls_x509_pk_to_sign (cert->subject_pk_algorithm, hash_algo);

  /* The idea here is to try signing with the one of the algorithms
   * that have been initiated at handshake (SHA1, SHA256). If they
   * are not requested by peer... tough luck
   */
  ret = _gnutls_session_sign_algo_requested (session, sign_algo);
  if (sign_algo == GNUTLS_SIGN_UNKNOWN || ret < 0)
    {
      handshake_td = &session->internals.handshake_mac_handle.tls12.sha256;
      hash_algo = handshake_td->algorithm;
      sign_algo =
	_gnutls_x509_pk_to_sign (cert->subject_pk_algorithm, hash_algo);
      if (sign_algo == GNUTLS_SIGN_UNKNOWN)
	{
	  gnutls_assert ();
	  return GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM;
	}

      ret = _gnutls_session_sign_algo_requested (session, sign_algo);
      if (ret < 0)
	{
	  gnutls_assert ();
	  _gnutls_x509_log
	    ("Server did not allow either '%s' or '%s' for signing\n",
	     gnutls_mac_get_name (hash_algo),
	     gnutls_mac_get_name (session->internals.handshake_mac_handle.
				  tls12.sha1.algorithm));
	  return ret;
	}
    }

  _gnutls_x509_log ("sign handshake cert vrfy: picked %s with %s\n",
		    gnutls_sign_algorithm_get_name (sign_algo),
		    gnutls_mac_get_name (hash_algo));

  ret = _gnutls_hash_copy (&td, handshake_td);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_hash_deinit (&td, concat);

  dconcat.data = concat;
  dconcat.size = _gnutls_hash_get_algo_len (hash_algo);

  ret = _gnutls_tls_sign (session, cert, pkey, &dconcat, signature);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return sign_algo;
}

/* Generates a signature of all the previous sent packets in the 
 * handshake procedure. 
 * 20040227: now it works for SSL 3.0 as well
 * 20091031: works for TLS 1.2 too!
 *
 * For TLS1.x, x<2 returns negative for failure and zero or unspecified for success.
 * For TLS1.2 returns the signature algorithm used on success, or a negative value;
 */
int
_gnutls_handshake_sign_cert_vrfy (gnutls_session_t session,
				  gnutls_cert * cert, gnutls_privkey * pkey,
				  gnutls_datum_t * signature)
{
  gnutls_datum_t dconcat;
  int ret;
  opaque concat[MAX_SIG_SIZE];
  digest_hd_st td_md5;
  digest_hd_st td_sha;
  gnutls_protocol_t ver = gnutls_protocol_get_version (session);

  if (session->security_parameters.handshake_mac_handle_type ==
      HANDSHAKE_MAC_TYPE_12)
    {
      return _gnutls_handshake_sign_cert_vrfy12 (session, cert, pkey,
						 signature);
    }
  else if (session->security_parameters.handshake_mac_handle_type !=
	   HANDSHAKE_MAC_TYPE_10)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ret =
    _gnutls_hash_copy (&td_sha,
		       &session->internals.handshake_mac_handle.tls10.sha);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (ver == GNUTLS_SSL3)
    {
      ret = _gnutls_generate_master (session, 1);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      _gnutls_mac_deinit_ssl3_handshake (&td_sha, &concat[16],
					 session->
					 security_parameters.master_secret,
					 GNUTLS_MASTER_SIZE);
    }
  else
    _gnutls_hash_deinit (&td_sha, &concat[16]);

  switch (cert->subject_pk_algorithm)
    {
    case GNUTLS_PK_RSA:
      ret =
	_gnutls_hash_copy (&td_md5,
			   &session->internals.handshake_mac_handle.tls10.
			   md5);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      if (ver == GNUTLS_SSL3)
	_gnutls_mac_deinit_ssl3_handshake (&td_md5, concat,
					   session->
					   security_parameters.master_secret,
					   GNUTLS_MASTER_SIZE);
      else
	_gnutls_hash_deinit (&td_md5, concat);

      dconcat.data = concat;
      dconcat.size = 36;
      break;
    case GNUTLS_PK_DSA:
      dconcat.data = &concat[16];
      dconcat.size = 20;
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }
  ret = _gnutls_tls_sign (session, cert, pkey, &dconcat, signature);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  return ret;
}
