/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2007, 2009, 2010
 * Free Software Foundation, Inc.
 *
 * Copyright (C) 2011
 * Bardenheuer GmbH, Munich and Bundesdruckerei GmbH, Berlin
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

#ifdef ENABLE_PSK

#include "gnutls_auth.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "gnutls_mpi.h"
#include <gnutls_state.h>
#include <auth_psk.h>
#include <auth_dh_common.h>
#include <gnutls_datum.h>
#include <auth_cert.h>
#include <auth_rsa.h>

static int gen_rsa_psk_client_kx (gnutls_session_t, opaque **);
static int proc_rsa_psk_client_kx (gnutls_session_t, opaque *, size_t);
static int proc_rsa_psk_server_kx (gnutls_session_t, opaque *, size_t);

const mod_auth_st rsa_psk_auth_struct = {
  "RSA PSK",
  _gnutls_gen_cert_server_certificate,
  NULL,                        /* generate_client_certificate */
  _gnutls_gen_psk_server_kx,
  gen_rsa_psk_client_kx,
  NULL,                        /* generate_client_cert_vrfy */
  NULL,                        /* generate_server_certificate_request */
  _gnutls_proc_cert_server_certificate,
  NULL,                        /* process_client_certificate */
  _gnutls_proc_psk_server_kx,
  proc_rsa_psk_client_kx,
  NULL,                        /* process_client_cert_vrfy */
  NULL                         /* process_server_certificate_reuqest */
};


/* Set the PSK premaster secret.
 */
int
set_rsa_psk_session_key (gnutls_session_t session,
			     gnutls_datum_t * rsa_secret)
{
  gnutls_datum_t pwd_psk = { NULL, 0 };
  gnutls_datum_t *ppsk;
  size_t rsa_secret_size;
  int ret;

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      gnutls_psk_client_credentials_t cred;

      cred = (gnutls_psk_client_credentials_t)
	_gnutls_get_cred (session->key, GNUTLS_CRD_PSK, NULL);

      if (cred == NULL)
	{
	  gnutls_assert ();
	  return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

      ppsk = &cred->key;

    }
  else
    {				/* SERVER side */
      psk_auth_info_t info;

      info = _gnutls_get_auth_info (session);

      /* find the key of this username
       */
      ret = _gnutls_psk_pwd_find_entry (session, info->username, &pwd_psk);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}
      ppsk = &pwd_psk;
    }

  rsa_secret_size = rsa_secret->size;

  /* set the session key
   */
  session->key->key.size = 4 + rsa_secret_size + ppsk->size;
  session->key->key.data = gnutls_malloc (session->key->key.size);
  if (session->key->key.data == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_MEMORY_ERROR;
      goto error;
    }

  /* format of the premaster secret:
   * (uint16_t) other_secret size (48)
   * other_secret: 2 byte version + 46 byte random
   * (uint16_t) psk_size
   * the psk
   */
  _gnutls_write_uint16 (rsa_secret_size, session->key->key.data);
  memcpy (&session->key->key.data[2], rsa_secret->data, rsa_secret->size);
  _gnutls_write_datum16 (&session->key->key.data[rsa_secret_size + 2], *ppsk);

  ret = 0;

error:
  _gnutls_free_datum (&pwd_psk);
  return ret;
}

/* Generate client key exchange message
 *
 *
 * struct {
 *    select (KeyExchangeAlgorithm) {
 *       opaque psk_identity<0..2^16-1>;
 *       EncryptedPreMasterSecret;
 *    } exchange_keys;
 * } ClientKeyExchange;
 */
static int
gen_rsa_psk_client_kx (gnutls_session_t session, opaque ** data)
{
  cert_auth_info_t auth = session->key->auth_info;
  gnutls_datum_t sdata;		/* data to send */
  bigint_t params[MAX_PUBLIC_PARAMS_SIZE];
  int params_len = MAX_PUBLIC_PARAMS_SIZE;
  int ret, i;
  gnutls_protocol_t ver;

	if (auth == NULL)
    {
      /* this shouldn't have happened. The proc_certificate
       * function should have detected that.
       */
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  gnutls_datum_t premaster_secret;
  premaster_secret.size = GNUTLS_MASTER_SIZE;
  premaster_secret.data = gnutls_secure_malloc (premaster_secret.size);
	
  if (premaster_secret.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* Generate random */
  ret = _gnutls_rnd (GNUTLS_RND_RANDOM, premaster_secret.data,
		     premaster_secret.size);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* Get version */
  ver = _gnutls_get_adv_version (session);

  /* Set version */
  if (session->internals.rsa_pms_version[0] == 0)
    {
      premaster_secret.data[0] = _gnutls_version_get_major (ver);
      premaster_secret.data[1] = _gnutls_version_get_minor (ver);
    }
  else
    {				/* use the version provided */
      premaster_secret.data[0] = session->internals.rsa_pms_version[0];
      premaster_secret.data[1] = session->internals.rsa_pms_version[1];
    }

  /* move RSA parameters to key (session).
   */
  if ((ret =
       _gnutls_get_public_rsa_params (session, params, &params_len)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

	/* Encrypt premaster secret */
  if ((ret =
       _gnutls_pkcs1_rsa_encrypt (&sdata, &premaster_secret,
				  params, params_len, 2)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  for (i = 0; i < params_len; i++)
    _gnutls_mpi_release (&params[i]);

	
/* retrieve PSK credentials */
  gnutls_psk_client_credentials_t cred;

  cred = (gnutls_psk_client_credentials_t)
    _gnutls_get_cred (session->key, GNUTLS_CRD_PSK, NULL);

  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

	/* TODO: Bei dhe_psk wird keine PSK aufgerufen, wenn die Parameter
	 leer sind. Die Funktion wird an dieser Stelle dann abgebrochen. 
	 Können diese womöglich an anderer Stelle übergeben werden? */
  if (cred->username.data == NULL && cred->key.data == NULL &&
      cred->get_function != NULL)
    {
      char *username;
      gnutls_datum_t key;

      ret = cred->get_function (session, &username, &key);
      if (ret)
	{
	  gnutls_assert ();
	  return ret;
	}

      ret = _gnutls_set_datum (&cred->username, username, strlen (username));
      gnutls_free (username);
      if (ret < 0)
	{
	  gnutls_assert ();
	  _gnutls_free_datum (&key);
	  return ret;
	}

      ret = _gnutls_set_datum (&cred->key, key.data, key.size);
      _gnutls_free_datum (&key);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return GNUTLS_E_MEMORY_ERROR;
	}
    }
  else if (cred->username.data == NULL || cred->key.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

	/* Here we set the PSK key */
	ret = set_rsa_psk_session_key (session, &premaster_secret);
	
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }


/* Create message for client key exchange
 * 
 * struct {
 *   opaque psk_identity<0..2^16-1>;
 *   EncryptedPreMasterSecret; 
 * }
 */
    int message_size = 2 + cred->username.size + 2 + sdata.size;
    *data = gnutls_malloc (message_size);
  if (*data == NULL)
    {
      _gnutls_free_datum (&sdata);
      return GNUTLS_E_MEMORY_ERROR;
    } 

  /* Write psk_identity and EncryptedPreMasterSecret into data stream
  */
  _gnutls_write_datum16 (*data, cred->username);
  _gnutls_write_datum16 (&(*data)[cred->username.size + 2], sdata);
	
  _gnutls_free_datum (&sdata);
  _gnutls_free_datum (&premaster_secret);
 
  return message_size;
}

/*
  Process the client key exchange message
*/
static int
proc_rsa_psk_client_kx (gnutls_session_t session, opaque * data,
		    size_t _data_size)
{
  gnutls_datum_t username;
  psk_auth_info_t info;
  gnutls_datum_t plaintext;
  gnutls_datum_t ciphertext;
  int ret, dsize;
  bigint_t *params;
  int params_len;
  int randomize_key = 0;
  ssize_t data_size = _data_size;
  gnutls_psk_server_credentials_t cred;

  cred = (gnutls_psk_server_credentials_t)
    _gnutls_get_cred (session->key, GNUTLS_CRD_PSK, NULL);

  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  ret = _gnutls_auth_info_set (session, GNUTLS_CRD_PSK,
			      sizeof (psk_auth_info_st), 1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }
	
  /*** 1. Extract user psk_identity ***/
	
  DECR_LEN (data_size, 2);
  username.size = _gnutls_read_uint16 (&data[0]);

  DECR_LEN(data_size, username.size);

  username.data = &data[2];

  /* copy the username to the auth info structures
   */
  info = _gnutls_get_auth_info (session);

  if (username.size > MAX_SRP_USERNAME)
	{
      gnutls_assert();
      return GNUTLS_E_ILLEGAL_SRP_USERNAME;
	}

  memcpy (info->username, username.data, username.size);
  info->username[username.size] = 0;

  /* Adjust data so it points to EncryptedPreMasterSecret */
  data += username.size + 2;


  /*** 2. Decrypt and extract EncryptedPreMasterSecret ***/
	
  DECR_LEN (data_size, 2);
  ciphertext.data = &data[2];
  dsize = _gnutls_read_uint16 (data);

  if (dsize != data_size)
	{
	  gnutls_assert ();
	  return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
  ciphertext.size = dsize;


  ret = _gnutls_get_private_rsa_params (session, &params, &params_len);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_pkcs1_rsa_decrypt (&plaintext, &ciphertext, params, params_len, 2);	/* btype==2 */

  if (ret < 0 || plaintext.size != GNUTLS_MASTER_SIZE)
    {
      /* In case decryption fails then don't inform
       * the peer. Just use a random key. (in order to avoid
       * attack against pkcs-1 formating).
       */
      gnutls_assert ();
      _gnutls_x509_log ("auth_rsa: Possible PKCS #1 format attack\n");
      randomize_key = 1;
    }
  else
    {
      /* If the secret was properly formatted, then
       * check the version number.
       */
      if (_gnutls_get_adv_version_major (session) != plaintext.data[0]
	  || _gnutls_get_adv_version_minor (session) != plaintext.data[1])
	{
	  /* No error is returned here, if the version number check
	   * fails. We proceed normally.
	   * That is to defend against the attack described in the paper
	   * "Attacking RSA-based sessions in SSL/TLS" by Vlastimil Klima,
	   * Ondej Pokorny and Tomas Rosa.
	   */
	  gnutls_assert ();
	  _gnutls_x509_log
	    ("auth_rsa: Possible PKCS #1 version check format attack\n");
	}
    }

	
  gnutls_datum_t premaster_secret;
	
  if (randomize_key != 0)
    {
      premaster_secret.size = GNUTLS_MASTER_SIZE;
      premaster_secret.data = gnutls_malloc (premaster_secret.size);
      if (premaster_secret.data == NULL)
	{
	  gnutls_assert ();
	  return GNUTLS_E_MEMORY_ERROR;
	}

      /* we do not need strong random numbers here.
       */
      ret = _gnutls_rnd (GNUTLS_RND_NONCE, premaster_secret.data,
			 premaster_secret.size);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

    }
  else
    {
      premaster_secret.data = plaintext.data;
      premaster_secret.size = plaintext.size;
    }

	
  /* This is here to avoid the version check attack
   * discussed above.
   */

  premaster_secret.data[0] = _gnutls_get_adv_version_major (session);
  premaster_secret.data[1] = _gnutls_get_adv_version_minor (session);

  ret = set_rsa_psk_session_key (session, &premaster_secret);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_free_datum (&premaster_secret);
  return 0;
}

/*
  Process the server key exchange message 
*/
int
proc_rsa_psk_server_kx (gnutls_session_t session, opaque * data,
		    size_t _data_size)
{

  int ret;

  /* read hint from server key exchange */
  ret = _gnutls_proc_psk_server_kx(session, data, _data_size);
	
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }
	
  return 0;
}

#endif /* ENABLE_PSK */
