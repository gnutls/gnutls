/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson
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

/*
  Status Request (OCSP) TLS extension.  See RFC 6066 section 8:
  https://tools.ietf.org/html/rfc6066#section-8
*/

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include <gnutls_extensions.h>
#include <ext/status_request.h>

typedef struct
{
  gnutls_datum_t *responder_id;
  size_t responder_id_size;
  gnutls_datum_t request_extensions;
  int dealloc;

  gnutls_status_request_ocsp_func ocsp_func;
  void *ocsp_func_ptr;

  int expect_certificate_status;
} status_request_ext_st;

/*
  From RFC 6066.  Client sends:

      struct {
          CertificateStatusType status_type;
          select (status_type) {
              case ocsp: OCSPStatusRequest;
          } request;
      } CertificateStatusRequest;

      enum { ocsp(1), (255) } CertificateStatusType;

      struct {
          ResponderID responder_id_list<0..2^16-1>;
          Extensions  request_extensions;
      } OCSPStatusRequest;

      opaque ResponderID<1..2^16-1>;
      opaque Extensions<0..2^16-1>;
*/

static int
client_send (gnutls_session_t session,
	     gnutls_buffer_st* extdata,
	     status_request_ext_st *priv)
{
  int ret_len = 1 + 2;
  int ret;
  size_t i;

  ret = _gnutls_buffer_append_prefix (extdata, 8, 1);
  if (ret < 0)
    return gnutls_assert_val (ret);

  ret = _gnutls_buffer_append_prefix (extdata, 16, priv->responder_id_size);
  if (ret < 0)
    return gnutls_assert_val (ret);

  for (i = 0; i < priv->responder_id_size; i++)
    {
      if (priv->responder_id[i].size <= 0)
	return gnutls_assert_val (GNUTLS_E_INVALID_REQUEST);

      ret = _gnutls_buffer_append_data_prefix (extdata, 16,
					       priv->responder_id[i].data,
					       priv->responder_id[i].size);
      if (ret < 0)
	return gnutls_assert_val (ret);

      ret_len += 2 + priv->responder_id[i].size;
    }

  ret = _gnutls_buffer_append_data_prefix (extdata, 16,
					   priv->request_extensions.data,
					   priv->request_extensions.size);
  if (ret < 0)
    return gnutls_assert_val (ret);

  ret_len += 2 + priv->request_extensions.size;

  return ret_len;
}

static int
server_recv (gnutls_session_t session,
	     status_request_ext_st *priv,
	     const uint8_t * data,
	     size_t size)
{
  size_t i;

  _gnutls_handshake_log ("EXT[%p]: got ocsp\n", session);

  /* minimum message is type (1) + responder_id_list (2) +
     request_extension (2) = 5 */
  if (size < 5)
    return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

  /* We ignore non-ocsp CertificateStatusType.  The spec is unclear
     what should be done. */
  if (data[0] != '\x01')
    {
      gnutls_assert ();
      _gnutls_handshake_log ("EXT[%p]: unknown status_type %d\n",
			     session, data[0]);
      return 0;
    }
  size--, data++;

  priv->dealloc = 1;

  priv->responder_id_size = _gnutls_read_uint16 (data);
  size -= 2, data += 2;

  if (size <= priv->responder_id_size * 2)
    return gnutls_assert_val (GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

  priv->responder_id = gnutls_malloc (priv->responder_id_size
				      * sizeof (*priv->responder_id));
  if (priv->responder_id == NULL)
    return gnutls_assert_val (GNUTLS_E_MEMORY_ERROR);

  for (i = 0; i < priv->responder_id_size; i++)
    {
      size_t l;

      if (size <= 2)
	return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

      l = _gnutls_read_uint16 (data);
      size -= 2, data += 2;

      if (size <= l)
	return gnutls_assert_val (GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

      priv->responder_id[i].data = gnutls_malloc (l);
      if (priv->responder_id[i].data == NULL)
	return gnutls_assert_val (GNUTLS_E_MEMORY_ERROR);

      memcpy (priv->responder_id[i].data, data, l);
      priv->responder_id[i].size = l;

      size -= l, data += l;
    }

  return 0;
}

/*
  Servers return a certificate response along with their certificate
  by sending a "CertificateStatus" message immediately after the
  "Certificate" message (and before any "ServerKeyExchange" or
  "CertificateRequest" messages).  If a server returns a
  "CertificateStatus" message, then the server MUST have included an
  extension of type "status_request" with empty "extension_data" in
  the extended server hello.
*/

static int
server_send (gnutls_session_t session,
	     gnutls_buffer_st* extdata,
	     status_request_ext_st *priv)
{
  int ret;

  if (priv->ocsp_func == NULL)
    return gnutls_assert_val (GNUTLS_E_SUCCESS);

  ret = priv->ocsp_func (session, priv->ocsp_func_ptr, NULL);
  if (ret == GNUTLS_E_NO_CERTIFICATE_STATUS)
    return 0;
  else if (ret != GNUTLS_E_SUCCESS)
    return gnutls_assert_val (ret);

  ret = _gnutls_buffer_append_data (extdata, "", 0);
  if (ret < 0)
    return gnutls_assert_val (ret);

  priv->expect_certificate_status = 1;

  return 0;
}

static int
client_recv (gnutls_session_t session,
	     status_request_ext_st *priv,
	     const uint8_t * data,
	     size_t size)
{
  if (size != 0)
    return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

  priv->expect_certificate_status = 1;

  return 0;
}

static int
_gnutls_status_request_send_params (gnutls_session_t session,
				    gnutls_buffer_st* extdata)
{
  extension_priv_data_t epriv;
  status_request_ext_st *priv;
  int ret;

  ret = _gnutls_ext_get_session_data (session,
				      GNUTLS_EXTENSION_STATUS_REQUEST,
				      &epriv);
  if (ret < 0)              /* it is ok not to have it */
    return 0;

  priv = epriv.ptr;

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    return client_send (session, extdata, priv);
  return server_send (session, extdata, priv);
}

static int
_gnutls_status_request_recv_params (gnutls_session_t session,
				    const uint8_t * data,
				    size_t size)
{
  extension_priv_data_t epriv;
  status_request_ext_st *priv;
  int ret;

  ret = _gnutls_ext_get_session_data (session,
				      GNUTLS_EXTENSION_STATUS_REQUEST,
				      &epriv);
  if (ret < 0)              /* it is ok not to have it */
    return 0;

  priv = epriv.ptr;

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    return client_recv (session, priv, data, size);
  return server_recv (session, priv, data, size);
}

/**
 * gnutls_status_request_ocsp_client:
 * @session: is a #gnutls_session_t structure.
 * @responder_id: array with #gnutls_datum_t with DER data of responder id
 * @responder_id_size: number of members in @responder_id array
 * @request_extensions: a #gnutls_datum_t with DER encoded OCSP extensions
 *
 * This function is to be used by clients to request OCSP response
 * from the server, using the "status_request" TLS extension.  Only
 * OCSP status type is supported.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 **/
int
gnutls_status_request_ocsp_client (gnutls_session_t session,
				   gnutls_datum_t *responder_id,
				   size_t responder_id_size,
				   gnutls_datum_t *request_extensions)
{
  status_request_ext_st *priv;
  extension_priv_data_t epriv;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    return gnutls_assert_val (GNUTLS_E_INVALID_REQUEST);

  epriv.ptr = priv = gnutls_calloc (1, sizeof (*priv));
  if (priv == NULL)
    return gnutls_assert_val (GNUTLS_E_MEMORY_ERROR);

  priv->responder_id = responder_id;
  priv->responder_id_size = responder_id_size;
  if (request_extensions)
    {
      priv->request_extensions.data = request_extensions->data;
      priv->request_extensions.size = request_extensions->size;
    }

  _gnutls_ext_set_session_data (session,
				GNUTLS_EXTENSION_STATUS_REQUEST,
				epriv);

  return 0;
}

/**
 * gnutls_status_request_ocsp_server:
 * @session: is a #gnutls_session_t structure.
 * @ocsp_func: function pointer to OCSP status request callback.
 * @ptr: opaque pointer passed to callback function
 *
 * This function is to be used by server to register a callback to
 * handle OCSP status requests from the client.  The callback will be
 * invoked if the client supplied a status-request OCSP extension.
 * The callback function prototype is:
 *
 * typedef int (*gnutls_status_request_ocsp_func)
 *    (gnutls_session_t session, void *ptr, gnutls_datum_t *ocsp_response);
 *
 * The callback may be invoked up to two times for each handshake.  It
 * is called the first time when the client hello requested the status
 * request extension.  In this case, ocsp_response is NULL.  The
 * purpose of the first callback invocation is to determine whether
 * the server will acknowledge the client's request to use the
 * extension.  The callback may return
 * %GNUTLS_E_NO_CERTIFICATE_STATUS, in which case the server will not
 * enable the extension.  If the callback returns %GNUTLS_E_SUCCESS,
 * the server enable the extension.  If the callback returns another
 * error code, the handshake will terminate.
 *
 * If the first call to the callback enabled the extension, there will
 * usually be a second phase, with a non-NULL ocsp_response.  Now the
 * server is ready to send the CertificateStatus, and it expects the
 * callback to provide the OCSP response data.  The callback can at
 * this point return %GNUTLS_E_NO_CERTIFICATE_STATUS to avoid sending
 * a CertificateStatus message.  If the callback returns
 * %GNUTLS_E_SUCCESS the ocsp_response will be sent off to the client.
 * If the callback returns an error, the handshake will terminate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 **/
int
gnutls_status_request_ocsp_server (gnutls_session_t session,
				   gnutls_status_request_ocsp_func ocsp_func,
				   void *ptr)
{
  status_request_ext_st *priv;
  extension_priv_data_t epriv;

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    return gnutls_assert_val (GNUTLS_E_INVALID_REQUEST);

  epriv.ptr = priv = gnutls_calloc (1, sizeof (*priv));
  if (priv == NULL)
    return gnutls_assert_val (GNUTLS_E_MEMORY_ERROR);

  priv->ocsp_func = ocsp_func;
  priv->ocsp_func_ptr = ptr;

  _gnutls_ext_set_session_data (session,
				GNUTLS_EXTENSION_STATUS_REQUEST,
				epriv);

  return 0;
}

static void
_gnutls_status_request_deinit_data (extension_priv_data_t epriv)
{
  status_request_ext_st *priv = epriv.ptr;
  size_t i;

  if (priv->dealloc)
    {
      for (i = 0; i < priv->responder_id_size; i++)
	gnutls_free (priv->responder_id[i].data);
      gnutls_free (priv->responder_id);
      gnutls_free (priv->request_extensions.data);
    }

  gnutls_free (priv);
}

static int
_gnutls_status_request_pack (extension_priv_data_t epriv,
			     gnutls_buffer_st * ps)
{
  return -1;
}

static int
_gnutls_status_request_unpack (gnutls_buffer_st * ps,
			       extension_priv_data_t * _priv)
{
  return -1;
}

extension_entry_st ext_mod_status_request = {
  .name = "STATUS REQUEST",
  .type = GNUTLS_EXTENSION_STATUS_REQUEST,
  .parse_type = GNUTLS_EXT_TLS,
  .recv_func = _gnutls_status_request_recv_params,
  .send_func = _gnutls_status_request_send_params,
  .pack_func = _gnutls_status_request_pack,
  .unpack_func = _gnutls_status_request_unpack,
  .deinit_func = _gnutls_status_request_deinit_data
};
