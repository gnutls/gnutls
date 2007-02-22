/*
 * Copyright (C) 2007 Free Software Foundation
 * Author: Simon Josefsson
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

/*
 * This file implements the authz extensions in
 * draft-housley-tls-authz-extns-07 using the supplemental handshake
 * record type, which see RFC 4680 and gnutls_supplemental.c.
 *
 * There are three parts of this file.  The first is the client hello
 * and server hello extensions, which are used to negotiate use of
 * supplemental authz data.  If they successfully negotiate that the
 * client will send some format(s) and/or the server will send some
 * format(s), this will request that gnutls_handshake() invoke a
 * supplemental phase in the corresponding direction.
 *
 * It may be possible that client authz data format type negotiation
 * fails, but server authz data format type negotiation succeeds.  In
 * that case, only the server will send supplemental data, and the
 * client will only expect to receive supplemental data.
 *
 * The second part is parsing and generating the authz supplemental
 * data itself, by using the callbacks.
 *
 * The third part is the public APIs for use in the callbacks, and of
 * course gnutls_authz_enable() to request that authz should be used.
 */

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"
#include <ext_authz.h>

static int
format_in_list_p (unsigned char format,
		  const unsigned char *data,
		  size_t data_size)
{
  size_t i;
  for (i = 0; i < data_size; i++)
    if (format == data[i])
      return 1;
  return 0;
}

static int
recv_extension (gnutls_session_t session,
		const opaque * data,
		size_t data_size,
		int *formats)
{
  size_t total_size;
  const int *in = formats;
  int *out = formats;

  if (data_size == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

  total_size = *data++;
  data_size--;

  if (data_size != total_size)
    {
      gnutls_assert ();
      return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

  while (*in)
    if (format_in_list_p (*in - 1, data, data_size))
      {
	_gnutls_debug_log ("EXT[%x]: Keeping authz format %02x\n",
			   session, *in);
	*out++ = *in++;
      }
    else
      {
	_gnutls_debug_log ("EXT[%x]: Disabling authz format %02x\n",
			   session, *in);
	in++;
      }
  *out = 0;

  return 0;
}

static int
send_extension (gnutls_session_t session,
		opaque * data,
		size_t _data_size,
		int *authz_formats)
{
  ssize_t data_size = _data_size;
  size_t total_size;
  opaque *sizepos;

  if (!authz_formats[0])
    {
      gnutls_assert ();
      return 0;
    }

  /* Make room for size. */
  DECR_LENGTH_RET (data_size, 1, GNUTLS_E_SHORT_MEMORY_BUFFER);
  sizepos = data++;

  for (total_size = 0; authz_formats[total_size]; total_size++)
    {
      _gnutls_debug_log ("EXT[%x]: Sending authz format %02x\n",
			 session, authz_formats[total_size]);
      DECR_LENGTH_RET (data_size, 1, GNUTLS_E_SHORT_MEMORY_BUFFER);
      *data++ = authz_formats[total_size] - 1;
    }

  *sizepos = total_size;

  return 1 + total_size;
}

int
_gnutls_authz_ext_client_recv_params (gnutls_session_t session,
				      const opaque * data,
				      size_t data_size)
{
  int *client_formats =
    session->security_parameters.extensions.authz_client_formats;
  int ret;

  ret = recv_extension (session, data, data_size, client_formats);
  if (ret < 0)
    return ret;

  if (*client_formats)
    {
      if (session->security_parameters.entity == GNUTLS_CLIENT)
	{
	  _gnutls_debug_log ("EXT[%x]: Will send supplemental data\n",
			     session);
	  session->security_parameters.extensions.do_send_supplemental = 1;
	}
      else
	session->security_parameters.extensions.authz_recvd_client = 1;
    }

  return 0;
}

int
_gnutls_authz_ext_client_send_params (gnutls_session_t session,
				      opaque * data,
				      size_t _data_size)
{
  int *client_formats =
    session->security_parameters.extensions.authz_client_formats;
  int ret;

  /* Should we be sending this? */
  if (session->security_parameters.entity == GNUTLS_SERVER
      && !session->security_parameters.extensions.authz_recvd_client)
    {
      gnutls_assert ();
      return 0;
    }

  ret = send_extension (session, data, _data_size, client_formats);

  if (session->security_parameters.entity == GNUTLS_SERVER && ret > 0)
    {
      _gnutls_debug_log ("EXT[%x]: Will expect supplemental data\n",
			 session);
      session->security_parameters.extensions.do_recv_supplemental = 1;
    }

  return ret;
}

int
_gnutls_authz_ext_server_recv_params (gnutls_session_t session,
				      const opaque * data,
				      size_t data_size)
{
  int *server_formats =
    session->security_parameters.extensions.authz_server_formats;
  int ret;

  ret = recv_extension (session, data, data_size, server_formats);
  if (ret < 0)
    return ret;

  if (*server_formats)
    {
      if (session->security_parameters.entity == GNUTLS_CLIENT)
	{
	  _gnutls_debug_log ("EXT[%x]: Will expect supplemental data\n",
			     session);
	  session->security_parameters.extensions.do_recv_supplemental = 1;
	}
      else
	session->security_parameters.extensions.authz_recvd_server = 1;
    }

  return 0;
}

int
_gnutls_authz_ext_server_send_params (gnutls_session_t session,
				      opaque * data,
				      size_t _data_size)
{
  int *server_formats =
    session->security_parameters.extensions.authz_server_formats;
  int ret;

  /* Should we be sending this? */
  if (session->security_parameters.entity == GNUTLS_SERVER
      && !session->security_parameters.extensions.authz_recvd_server)
    {
      gnutls_assert ();
      return 0;
    }

  ret = send_extension (session, data, _data_size, server_formats);

  if (session->security_parameters.entity == GNUTLS_SERVER && ret > 0)
    {
      _gnutls_debug_log ("EXT[%x]: Will send supplemental data\n",
			 session);
      session->security_parameters.extensions.do_send_supplemental = 1;
    }

  return ret;
}

int
_gnutls_authz_supp_recv_params (gnutls_session_t session,
				const opaque * data,
				size_t data_size)
{
  int authz_formats[MAX_AUTHZ_FORMATS + 1];
  gnutls_datum_t info[MAX_AUTHZ_FORMATS];
  gnutls_datum_t hash[MAX_AUTHZ_FORMATS];
  int hashtype[MAX_AUTHZ_FORMATS];
  ssize_t dsize = data_size;
  const opaque *p = data;
  size_t i;
  gnutls_authz_recv_callback_func callback =
    session->security_parameters.extensions.authz_recv_callback;

  if (!callback)
    {
      gnutls_assert ();
      return 0;
    }

  /* XXX Will there be more than one data item for each authz format?
     If so, we can't know the maximum size of the list of authz data,
     so replace the static arrays with dynamically allocated lists.
     Let's worry about that when someone reports it.  */

  i = 0;
  do
    {
      DECR_LEN (dsize, 2);
      authz_formats[i] = _gnutls_read_uint16 (p) + 1;
      p += 2;

      _gnutls_debug_log ("EXT[%x]: authz_format[%d]=%02x\n",
			 session, i, authz_formats[i]);

      DECR_LEN (dsize, 2);
      info[i].size = _gnutls_read_uint16 (p);
      p += 2;

      _gnutls_debug_log ("EXT[%x]: data[%d]=%d bytes\n",
			 session, i, info[i].size);

      info[i].data = p;

      DECR_LEN (dsize, info[i].size);
      p += info[i].size;

      if (authz_formats[i] == GNUTLS_AUTHZ_X509_ATTR_CERT_URL
	  || authz_formats[i] == GNUTLS_AUTHZ_SAML_ASSERTION_URL)
	{
	  DECR_LEN (dsize, 1);
	  _gnutls_debug_log ("EXT[%x]: hashtype[%d]=%02x\n",
			     session, i, *p);
	  if (*p == '\x00')
	    hashtype[i] = GNUTLS_MAC_SHA1;
	  else if (*p == '\x01')
	    hashtype[i] = GNUTLS_MAC_SHA256;
	  else
	    {
	      gnutls_assert ();
	      return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
	    }
	  p++;

	  hash[i].data = p;
	  hash[i].size = _gnutls_hash_get_algo_len (hashtype[i]);

	  _gnutls_debug_log ("EXT[%x]: hash[%d]=%d\n",
			     session, i, hash[i].size);

	  DECR_LEN (dsize, hash[i].size);
	  p += hash[i].size;
	}
      else
	{
	  hashtype[i] = 0;
	  hash[i].data = NULL;
	  hash[i].size = 0;
	}

      i++;

      if (i == MAX_AUTHZ_FORMATS)
	{
	  gnutls_assert ();
	  return GNUTLS_E_SHORT_MEMORY_BUFFER;
	}
    }
  while (dsize > 0);

  authz_formats[i] = 0;

  return callback (session, authz_formats, info, hashtype, hash);
}

int
_gnutls_authz_supp_send_params (gnutls_session_t session,
				gnutls_buffer *buf)
{
  int *server_formats =
    session->security_parameters.extensions.authz_server_formats;
  int *client_formats =
    session->security_parameters.extensions.authz_client_formats;
  gnutls_authz_send_callback_func callback =
    session->security_parameters.extensions.authz_send_callback;
  gnutls_buffer *authz_buf =
    &session->security_parameters.extensions.authz_data;
  int ret;

  if (!callback)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _gnutls_buffer_init (authz_buf);

  ret = callback (session, client_formats, server_formats);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_buffer_append (buf, authz_buf->data, authz_buf->length);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_buffer_clear (authz_buf);

  return ret;
}

static int
add_data (gnutls_session_t session,
	  const char *data,
	  size_t len,
	  gnutls_authz_data_format_type_t format,
	  gnutls_mac_algorithm_t hash_type,
	  const char *hash)
{
  gnutls_buffer *buffer = &session->security_parameters.extensions.authz_data;
  size_t hash_len = hash ? _gnutls_hash_get_algo_len (hash_type) : 0;
  unsigned char str[4];
  int ret;

  if (len + 4 > 0xFFFF)
    {
      gnutls_assert();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (hash && hash_type != GNUTLS_MAC_SHA256 && hash_type != GNUTLS_MAC_SHA1)
    {
      gnutls_assert();
      return GNUTLS_E_INVALID_REQUEST;
    }

  str[0] = '\x00';
  str[1] = format - 1;

  str[2] = (len << 8) & 0xFF;
  str[3] = len & 0xFF;

  ret = _gnutls_buffer_append (buffer, str, 4);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_buffer_append (buffer, data, len);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (hash)
    {
      if (hash_type == GNUTLS_MAC_SHA1)
	str[0] = '\x00';
      else if (hash_type == GNUTLS_MAC_SHA256)
	str[0] = '\x01';

      ret = _gnutls_buffer_append (buffer, str, 1);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      ret = _gnutls_buffer_append (buffer, hash, hash_len);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}
    }

  return 0;
}

/**
 * gnutls_authz_send_x509_attr_cert:
 * @session: is a #gnutls_session_t structure.
 * @data: buffer with a X.509 attribute certificate.
 * @len: length of buffer.
 *
 * Send a X.509 attribute certificate as authorization data.  This
 * function may only be called inside a @send_callback set by
 * gnutls_authz_enable().
 *
 * Returns: Returns 0 on success, or an error code on failures.  If
 *   the supplied data was too long (the authorization extension only
 *   support 64kb large attribute certificates),
 *   %GNUTLS_E_INVALID_REQUEST is returned.
 **/
int
gnutls_authz_send_x509_attr_cert (gnutls_session_t session,
				  const char *data,
				  size_t len)
{
  return add_data (session, data, len, GNUTLS_AUTHZ_X509_ATTR_CERT, 0, NULL);
}

/**
 * gnutls_authz_send_saml_assertion:
 * @session: is a #gnutls_session_t structure.
 * @data: buffer with a SAML assertion.
 * @len: length of buffer.
 *
 * Send a SAML assertion as authorization data.  This function may
 * only be called inside a @send_callback set by
 * gnutls_authz_enable().
 *
 * Returns: Returns 0 on success, or an error code on failures.  If
 *   the supplied data was too long (the authorization extension only
 *   support 64kb large SAML assertions), %GNUTLS_E_INVALID_REQUEST is
 *   returned.
 **/
int
gnutls_authz_send_saml_assertion (gnutls_session_t session,
				  const char *data,
				  size_t len)
{
  return add_data (session, data, len, GNUTLS_AUTHZ_SAML_ASSERTION, 0, NULL);
}

/**
 * gnutls_authz_send_x509_attr_cert_url:
 * @session: is a #gnutls_session_t structure.
 * @url: buffer with a URL pointing to X.509 attribute certificate.
 * @urllen: length of buffer.
 * @hash_type: type of hash in @hash.
 * @hash: buffer with hash of URL target.
 *
 * Send a URL to an X.509 attribute certificate as authorization data,
 * including a hash used to make sure the retrieved data was the
 * intended data.  This function may only be called inside a
 * @send_callback set by gnutls_authz_enable().
 *
 * Returns: Returns 0 on success, or an error code on failures.  If
 *   the supplied data was too long (the authorization extension only
 *   support 64kb large URLs), %GNUTLS_E_INVALID_REQUEST is returned.
 **/
int
gnutls_authz_send_x509_attr_cert_url (gnutls_session_t session,
				      const char *url,
				      size_t urllen,
				      gnutls_mac_algorithm_t hash_type,
				      const char *hash)
{
  return add_data (session, url, urllen, GNUTLS_AUTHZ_X509_ATTR_CERT_URL,
		   hash_type, hash);
}

/**
 * gnutls_authz_send_saml_assertion_url:
 * @session: is a #gnutls_session_t structure.
 * @url: buffer with a URL pointing to a SAML assertion.
 * @urllen: length of buffer.
 * @hash_type: type of hash in @hash.
 * @hash: buffer with hash of URL target.
 *
 * Send a URL to a SAML assertion as authorization data, including a
 * hash used to make sure the retrieved data was the intended data.
 * This function may only be called inside a @send_callback set by
 * gnutls_authz_enable().
 *
 * Returns: Returns 0 on success, or an error code on failures.  If
 *   the supplied data was too long (the authorization extension only
 *   support 64kb large URLs), %GNUTLS_E_INVALID_REQUEST is returned.
 **/
int
gnutls_authz_send_saml_assertion_url (gnutls_session_t session,
				      const char *url,
				      size_t urllen,
				      gnutls_mac_algorithm_t hash_type,
				      const char *hash)
{
  return add_data (session, url, urllen, GNUTLS_AUTHZ_X509_ATTR_CERT_URL,
		   hash_type, hash);
}

/**
 * gnutls_authz_enable:
 * @session: is a #gnutls_session_t structure.
 * @client_formats: zero-terminated list of
 *   #gnutls_authz_data_format_type_t elements with authorization
 *   data formats.
 * @server_formats: zero-terminated list of
 *   #gnutls_authz_data_format_type_t elements with authorization
 *   data formats.
 * @recv_callback: your callback function which will receive
 *   authz information when it is received.
 * @send_callback: your callback function which is responsible for
 *   generating authorization data to send.
 *
 * Indicate willingness to send and receive authorization data, and
 * which formats.
 *
 * For clients, @client_formats indicate which formats the client is
 * willing to send, and @server_formats indicate which formats the
 * client can receive.
 *
 * For servers, @client_formats indicate which formats the server is
 * willing to accept from the client, and @server_formats indicate
 * which formats the server is willing to send.  Before the list is
 * sent to the client, the formats which the client do not support are
 * removed.  If no supported formats remains, either or both of the
 * extensions will not be sent.
 *
 * The @send_callback is invoked during the handshake if negotiation
 * of the authorization extension was successful.  The function
 * prototype is:
 *
 * int (*gnutls_authz_send_callback_func) (gnutls_session_t @session,
 * const int *@client_formats, const int *@server_formats);
 *
 * The @client_format contains a list of successfully negotiated
 * formats which the client may send data for to the server.  The
 * @server_formats contains a list of successfully neogitated formats
 * which the server may send data for to the client.  The callback is
 * supposed to invoke gnutls_authz_send_x509_attr_cert(),
 * gnutls_authz_send_saml_assertion(),
 * gnutls_authz_send_x509_attr_cert_url(), or
 * gnutls_authz_send_saml_assertion_url() for the data it wishes to
 * send, passing along the @session parameter, and the data.  The
 * @client_format function should return 0 on success, or an error
 * code, which may be used to abort the handshake on failures.
 *
 * The @recv_callback is invoked during the handshake when
 * authorization data is received.  The prototype of the callback
 * should be:
 *
 * int (*gnutls_authz_recv_callback_func) (gnutls_session_t session,
 * const char *authz_formats, gnutls_datum_t *datums);
 *
 * The @authz_formats contains a list of formats for which data where
 * received.  The data for each format is stored in the @datums array,
 * where the data associated with the @authz_formats[0] format is
 * stored in @datums[0].  The function should return 0 on success, but
 * may return an error, which may cause the handshake to abort.
 *
 * Note that there is no guarantee that @send_callback or
 * @recv_callback is invoked just because gnutls_authz_enable was
 * invoked.  Whether the callbacks are invoked depend on whether
 * negotiation of the extension succeeds.  Therefor, if verification
 * of authorization data is done by the @recv_callback, care should be
 * made that if the callback is never invoked, it is not interpretetd
 * as successful authorization verification.  It is suggested to add
 * some logic check whether authorization data was successfully
 * verified after the call to gnutls_handshake().  That logic could
 * shut down the connection if the authorization data is insufficient.
 *
 * This function have no effect if it is called during a handshake.
 **/
void
gnutls_authz_enable (gnutls_session_t session,
		     const int *client_formats,
		     const int *server_formats,
		     gnutls_authz_recv_callback_func recv_callback,
		     gnutls_authz_send_callback_func send_callback)
{
  int *session_client_formats =
    session->security_parameters.extensions.authz_client_formats;
  int *session_server_formats =
    session->security_parameters.extensions.authz_server_formats;
  size_t i;

  if (session->internals.handshake_state != STATE0)
    return;

  for (i = 0; client_formats[i]; i++)
    if (i < MAX_AUTHZ_FORMATS)
      session_client_formats[i] = client_formats[i];
  if (i < MAX_AUTHZ_FORMATS)
    session_client_formats[i] = 0;
  else
    session_client_formats[MAX_AUTHZ_FORMATS] = 0;

  for (i = 0; server_formats[i]; i++)
    if (i < MAX_AUTHZ_FORMATS)
      session_server_formats[i] = server_formats[i];
  if (i < MAX_AUTHZ_FORMATS)
    session_server_formats[i] = 0;
  else
    session_server_formats[MAX_AUTHZ_FORMATS] = 0;

  session->security_parameters.extensions.authz_recv_callback = recv_callback;
  session->security_parameters.extensions.authz_send_callback = send_callback;
}
