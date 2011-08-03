/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2006, 2008, 2010 Free Software
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

/* This file contains functions which are wrappers for the key exchange
 * part of TLS. They are called by the handshake functions (gnutls_handshake)
 */

#include "gnutls_int.h"
#include "gnutls_handshake.h"
#include "gnutls_kx.h"
#include "gnutls_dh.h"
#include "gnutls_errors.h"
#include "algorithms.h"
#include "debug.h"
#include "gnutls_mpi.h"
#include <gnutls_state.h>
#include <gnutls_datum.h>
#include <gnutls_rsa_export.h>
#include <gnutls_mbuffers.h>

/* This is a temporary function to be used before the generate_*
   internal API is changed to use mbuffers. For now we don't avoid the
   extra alloc + memcpy. */
static inline int
send_handshake (gnutls_session_t session, opaque * data, size_t size,
                gnutls_handshake_description_t type)
{
  mbuffer_st *bufel;

  if (data == NULL && size == 0)
    return _gnutls_send_handshake (session, NULL, type);

  if (data == NULL && size > 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  bufel = _gnutls_handshake_alloc(session, size, size);
  if (bufel == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  _mbuffer_set_udata (bufel, data, size);

  return _gnutls_send_handshake (session, bufel, type);
}


/* This file contains important thing for the TLS handshake procedure.
 */

#define MASTER_SECRET "master secret"
#define MASTER_SECRET_SIZE (sizeof(MASTER_SECRET)-1)
static int generate_normal_master (gnutls_session_t session, int);

int
_gnutls_generate_master (gnutls_session_t session, int keep_premaster)
{
  if (session->internals.resumed == RESUME_FALSE)
    return generate_normal_master (session, keep_premaster);
  return 0;
}

/* here we generate the TLS Master secret.
 */
#define PREMASTER session->key->key
static int
generate_normal_master (gnutls_session_t session, int keep_premaster)
{
  int ret = 0;
  char buf[512];

  _gnutls_hard_log ("INT: PREMASTER SECRET[%d]: %s\n", PREMASTER.size,
                    _gnutls_bin2hex (PREMASTER.data, PREMASTER.size, buf,
                                     sizeof (buf), NULL));
  _gnutls_hard_log ("INT: CLIENT RANDOM[%d]: %s\n", 32,
                    _gnutls_bin2hex (session->
                                     security_parameters.client_random, 32,
                                     buf, sizeof (buf), NULL));
  _gnutls_hard_log ("INT: SERVER RANDOM[%d]: %s\n", 32,
                    _gnutls_bin2hex (session->
                                     security_parameters.server_random, 32,
                                     buf, sizeof (buf), NULL));

  if (gnutls_protocol_get_version (session) == GNUTLS_SSL3)
    {
      opaque rnd[2 * GNUTLS_RANDOM_SIZE + 1];

      memcpy (rnd, session->security_parameters.client_random,
              GNUTLS_RANDOM_SIZE);
      memcpy (&rnd[GNUTLS_RANDOM_SIZE],
              session->security_parameters.server_random, GNUTLS_RANDOM_SIZE);

      ret =
        _gnutls_ssl3_generate_random (PREMASTER.data, PREMASTER.size,
                                      rnd, 2 * GNUTLS_RANDOM_SIZE,
                                      GNUTLS_MASTER_SIZE,
                                      session->
                                      security_parameters.master_secret);

    }
  else
    {
      opaque rnd[2 * GNUTLS_RANDOM_SIZE + 1];

      memcpy (rnd, session->security_parameters.client_random,
              GNUTLS_RANDOM_SIZE);
      memcpy (&rnd[GNUTLS_RANDOM_SIZE],
              session->security_parameters.server_random, GNUTLS_RANDOM_SIZE);

      ret =
        _gnutls_PRF (session, PREMASTER.data, PREMASTER.size,
                     MASTER_SECRET, MASTER_SECRET_SIZE,
                     rnd, 2 * GNUTLS_RANDOM_SIZE, GNUTLS_MASTER_SIZE,
                     session->security_parameters.master_secret);
    }

  if (!keep_premaster)
    _gnutls_free_datum (&PREMASTER);

  if (ret < 0)
    return ret;

  _gnutls_hard_log ("INT: MASTER SECRET: %s\n",
                    _gnutls_bin2hex (session->
                                     security_parameters.master_secret,
                                     GNUTLS_MASTER_SIZE, buf, sizeof (buf),
                                     NULL));

  return ret;
}


/* This is called when we want to receive the key exchange message of the
 * server. It does nothing if this type of message is not required
 * by the selected ciphersuite. 
 */
int
_gnutls_send_server_kx_message (gnutls_session_t session, int again)
{
  gnutls_buffer_st data;
  int ret = 0;

  if (session->internals.auth_struct->gnutls_generate_server_kx == NULL)
    return 0;

  _gnutls_buffer_init( &data);

  if (again == 0)
    {
      ret =
        session->internals.auth_struct->gnutls_generate_server_kx (session,
                                                                   &data);

      if (ret == GNUTLS_E_INT_RET_0)
        {
          gnutls_assert ();
          ret = 0;
          goto cleanup;
        }

      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }
    }

  ret = send_handshake (session, data.data, data.length,
                        GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE);
  if (ret < 0)
    {
      gnutls_assert ();
    }
  
cleanup:
  _gnutls_buffer_clear (&data);
  return ret;
}

/* This function sends a certificate request message to the
 * client.
 */
int
_gnutls_send_server_certificate_request (gnutls_session_t session, int again)
{
  gnutls_buffer_st data;
  int ret = 0;

  if (session->internals.
      auth_struct->gnutls_generate_server_certificate_request == NULL)
    return 0;

  if (session->internals.send_cert_req <= 0)
    return 0;

  _gnutls_buffer_init( &data);

  if (again == 0)
    {
      ret =
        session->internals.
        auth_struct->gnutls_generate_server_certificate_request (session,
                                                                 &data);

      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }
    }

  ret = send_handshake (session, data.data, data.length,
                        GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST);
  if (ret < 0)
    {
      gnutls_assert ();
    }
  
cleanup:
  _gnutls_buffer_clear (&data);
  return ret;
}


/* This is the function for the client to send the key
 * exchange message 
 */
int
_gnutls_send_client_kx_message (gnutls_session_t session, int again)
{
  gnutls_buffer_st data;
  int ret = 0;

  if (session->internals.auth_struct->gnutls_generate_client_kx == NULL)
    return 0;

  _gnutls_buffer_init( &data);

  if (again == 0)
    {
      ret =
        session->internals.auth_struct->gnutls_generate_client_kx (session,
                                                                   &data);
      if (ret < 0)
        {
          gnutls_assert();
          goto cleanup;
        }
    }
  ret = send_handshake (session, data.data, data.length,
                        GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE);
  if (ret < 0)
    {
      gnutls_assert ();
    }
  
cleanup:
  _gnutls_buffer_clear (&data);
  return ret;
}


/* This is the function for the client to send the certificate
 * verify message
 */
int
_gnutls_send_client_certificate_verify (gnutls_session_t session, int again)
{
  gnutls_buffer_st data;
  int ret = 0;

  /* This is a packet that is only sent by the client
   */
  if (session->security_parameters.entity == GNUTLS_SERVER)
    return 0;

  /* if certificate verify is not needed just exit 
   */
  if (session->key->certificate_requested == 0)
    return 0;


  if (session->internals.auth_struct->gnutls_generate_client_cert_vrfy ==
      NULL)
    {
      gnutls_assert ();
      return 0;                 /* this algorithm does not support cli_cert_vrfy 
                                 */
    }

  _gnutls_buffer_init( &data);

  if (again == 0)
    {
      ret =
        session->internals.
        auth_struct->gnutls_generate_client_cert_vrfy (session, &data);
      if (ret < 0)
        {
          gnutls_assert();
          goto cleanup;
        }

      if (ret == 0)
          goto cleanup;

    }
  ret = send_handshake (session, data.data, data.length,
                        GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY);

  if (ret < 0)
    {
      gnutls_assert ();
    }
  
cleanup:
  _gnutls_buffer_clear (&data);
  return ret;
}

/* This is called when we want send our certificate
 */
int
_gnutls_send_client_certificate (gnutls_session_t session, int again)
{
  gnutls_buffer_st data;
  int ret = 0;


  if (session->key->certificate_requested == 0)
    return 0;

  if (session->internals.auth_struct->gnutls_generate_client_certificate ==
      NULL)
    return 0;

  _gnutls_buffer_init( &data);

  if (again == 0)
    {
      if (gnutls_protocol_get_version (session) != GNUTLS_SSL3 ||
          session->internals.selected_cert_list_length > 0)
        {
          /* TLS 1.0 or SSL 3.0 with a valid certificate 
           */
          ret =
            session->internals.
            auth_struct->gnutls_generate_client_certificate (session, &data);

          if (ret < 0)
            {
              gnutls_assert();
              goto cleanup;
            }
        }
    }

  /* In the SSL 3.0 protocol we need to send a
   * no certificate alert instead of an
   * empty certificate.
   */
  if (gnutls_protocol_get_version (session) == GNUTLS_SSL3 &&
      session->internals.selected_cert_list_length == 0)
    {
      ret =
        gnutls_alert_send (session, GNUTLS_AL_WARNING,
                           GNUTLS_A_SSL3_NO_CERTIFICATE);

    }
  else
    {                           /* TLS 1.0 or SSL 3.0 with a valid certificate 
                                 */
      ret = send_handshake (session, data.data, data.length,
                            GNUTLS_HANDSHAKE_CERTIFICATE_PKT);
    }

cleanup:
  _gnutls_buffer_clear (&data);
  return ret;
}


/* This is called when we want send our certificate
 */
int
_gnutls_send_server_certificate (gnutls_session_t session, int again)
{
  gnutls_buffer_st data;
  int ret = 0;


  if (session->internals.auth_struct->gnutls_generate_server_certificate ==
      NULL)
    return 0;

  _gnutls_buffer_init( &data);

  if (again == 0)
    {
      ret =
        session->internals.
        auth_struct->gnutls_generate_server_certificate (session, &data);

        if (ret < 0)
          {
            gnutls_assert();
            goto cleanup;
          }
    }
  ret = send_handshake (session, data.data, data.length,
                        GNUTLS_HANDSHAKE_CERTIFICATE_PKT);
  if (ret < 0)
    {
      gnutls_assert ();
    }
  
cleanup:
  _gnutls_buffer_clear (&data);
  return ret;
}


int
_gnutls_recv_server_kx_message (gnutls_session_t session)
{
  gnutls_buffer_st buf;
  int ret = 0;
  optional_t optflag = MANDATORY_PACKET;

  if (session->internals.auth_struct->gnutls_process_server_kx != NULL)
    {

      /* EXCEPTION FOR RSA_EXPORT cipher suite 
       */
      if (_gnutls_session_is_export (session) != 0 &&
          _gnutls_peers_cert_less_512 (session) != 0)
        {
          gnutls_assert ();
          return 0;
        }

      /* Server key exchange packet is optional for PSK. */
      if (_gnutls_session_is_psk (session))
        optflag = OPTIONAL_PACKET;

      ret =
        _gnutls_recv_handshake (session, 
                                GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE,
                                optflag, &buf);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      ret =
        session->internals.auth_struct->gnutls_process_server_kx (session,
                                                                  buf.data,
                                                                  buf.length);
      _gnutls_buffer_clear(&buf);

      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

    }
  return ret;
}

int
_gnutls_recv_server_certificate_request (gnutls_session_t session)
{
  gnutls_buffer_st buf;
  int ret = 0;

  if (session->internals.
      auth_struct->gnutls_process_server_certificate_request != NULL)
    {

      ret =
        _gnutls_recv_handshake (session, 
                                GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST,
                                OPTIONAL_PACKET, &buf);
      if (ret < 0)
        return ret;

      if (ret == 0 && buf.length == 0)
        {
          _gnutls_buffer_clear(&buf);
          return 0;               /* ignored */
        }

      ret =
        session->internals.
        auth_struct->gnutls_process_server_certificate_request (session, buf.data,
                                                                buf.length);
      _gnutls_buffer_clear (&buf);
      if (ret < 0)
        return ret;

    }
  return ret;
}

int
_gnutls_recv_client_kx_message (gnutls_session_t session)
{
  gnutls_buffer_st buf;
  int ret = 0;


  /* Do key exchange only if the algorithm permits it */
  if (session->internals.auth_struct->gnutls_process_client_kx != NULL)
    {

      ret =
        _gnutls_recv_handshake (session, 
                                GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE,
                                MANDATORY_PACKET, &buf);
      if (ret < 0)
        return ret;

      ret =
        session->internals.auth_struct->gnutls_process_client_kx (session,
                                                                  buf.data,
                                                                  buf.length);
      _gnutls_buffer_clear (&buf);
      if (ret < 0)
        return ret;

    }

  return ret;
}


int
_gnutls_recv_client_certificate (gnutls_session_t session)
{
  gnutls_buffer_st buf;
  int ret = 0;
  int optional;

  if (session->internals.auth_struct->gnutls_process_client_certificate ==
      NULL)
    return 0;

  /* if we have not requested a certificate then just return
   */
  if (session->internals.send_cert_req == 0)
    {
      return 0;
    }

  if (session->internals.send_cert_req == GNUTLS_CERT_REQUIRE)
    optional = MANDATORY_PACKET;
  else
    optional = OPTIONAL_PACKET;

  ret =
    _gnutls_recv_handshake (session, GNUTLS_HANDSHAKE_CERTIFICATE_PKT, 
      optional, &buf);

  if (ret < 0)
    {
      /* Handle the case of old SSL3 clients who send
       * a warning alert instead of an empty certificate to indicate
       * no certificate.
       */
      if (optional == OPTIONAL_PACKET &&
          ret == GNUTLS_E_WARNING_ALERT_RECEIVED &&
          gnutls_protocol_get_version (session) == GNUTLS_SSL3 &&
          gnutls_alert_get (session) == GNUTLS_A_SSL3_NO_CERTIFICATE)
        {

          /* SSL3 does not send an empty certificate,
           * but this alert. So we just ignore it.
           */
          gnutls_assert ();
          return 0;
        }

      /* certificate was required 
       */
      if ((ret == GNUTLS_E_WARNING_ALERT_RECEIVED
           || ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
          && optional == MANDATORY_PACKET)
        {
          gnutls_assert ();
          return GNUTLS_E_NO_CERTIFICATE_FOUND;
        }

      return ret;
    }

  if (ret == 0 && buf.length == 0 && optional == OPTIONAL_PACKET)
    {
      /* Client has not sent the certificate message.
       * well I'm not sure we should accept this
       * behaviour.
       */
      gnutls_assert ();
      ret = 0;
      goto cleanup;
    }
  ret =
    session->internals.
    auth_struct->gnutls_process_client_certificate (session, buf.data,
                                                    buf.length);

  if (ret < 0 && ret != GNUTLS_E_NO_CERTIFICATE_FOUND)
    {
      gnutls_assert ();
      goto cleanup;
    }

  /* ok we should expect a certificate verify message now 
   */
  if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND && optional == OPTIONAL_PACKET)
    ret = 0;
  else
    session->key->certificate_requested = 1;

cleanup:
  _gnutls_buffer_clear(&buf);
  return ret;
}

int
_gnutls_recv_server_certificate (gnutls_session_t session)
{
  gnutls_buffer_st buf;
  int ret = 0;

  if (session->internals.auth_struct->gnutls_process_server_certificate !=
      NULL)
    {

      ret =
        _gnutls_recv_handshake (session, 
                                GNUTLS_HANDSHAKE_CERTIFICATE_PKT,
                                MANDATORY_PACKET, &buf);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      ret =
        session->internals.
        auth_struct->gnutls_process_server_certificate (session, buf.data,
                                                        buf.length);
      _gnutls_buffer_clear(&buf);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }

  return ret;
}


/* Recv the client certificate verify. This packet may not
 * arrive if the peer did not send us a certificate.
 */
int
_gnutls_recv_client_certificate_verify_message (gnutls_session_t session)
{
  gnutls_buffer_st buf;
  int ret = 0;


  if (session->internals.auth_struct->gnutls_process_client_cert_vrfy == NULL)
    return 0;

  if (session->internals.send_cert_req == 0 ||
      session->key->certificate_requested == 0)
    {
      return 0;
    }

  ret =
    _gnutls_recv_handshake (session, 
                            GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY,
                            OPTIONAL_PACKET, &buf);
  if (ret < 0)
    return ret;

  if (ret == 0 && buf.length == 0
      && session->internals.send_cert_req == GNUTLS_CERT_REQUIRE)
    {
      /* certificate was required */
      gnutls_assert ();
      ret = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto cleanup;
    }

  ret =
    session->internals.
    auth_struct->gnutls_process_client_cert_vrfy (session, buf.data,
                                                  buf.length);

cleanup:
  _gnutls_buffer_clear(&buf);
  return ret;
}
