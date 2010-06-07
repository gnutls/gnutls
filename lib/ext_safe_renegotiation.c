/*
 * Copyright (C) 2009, 2010 Free Software Foundation, Inc.
 *
 * Author: Steve Dispensa (<dispensa@phonefactor.com>)
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
#include <ext_safe_renegotiation.h>
#include <gnutls_errors.h>

int
_gnutls_safe_renegotiation_recv_params (gnutls_session_t session,
					const opaque * data,
					size_t _data_size)
{
  tls_ext_st *ext = &session->security_parameters.extensions;
  int len = data[0];
  ssize_t data_size = _data_size;

  DECR_LEN (data_size, len + 1 /* count the first byte and payload */ );

  if (session->internals.priorities.safe_renegotiation == SR_DISABLED)
    {
      gnutls_assert ();
      return 0;
    }

  /* It is not legal to receive this extension on a renegotiation and
   * not receive it on the initial negotiation.
   */
  if (session->internals.initial_negotiation_completed != 0 &&
      session->internals.connection_using_safe_renegotiation == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_SAFE_RENEGOTIATION_FAILED;
    }

  if (len > sizeof (ext->ri_extension_data))
    {
      gnutls_assert ();
      return GNUTLS_E_SAFE_RENEGOTIATION_FAILED;
    }

  if (len > 0)
    memcpy (ext->ri_extension_data, &data[1], len);
  ext->ri_extension_data_len = len;

  /* "safe renegotiation received" means on *this* handshake; "connection using
   * safe renegotiation" means that the initial hello received on the connection
   * indicated safe renegotiation.
   */
  session->internals.safe_renegotiation_received = 1;
  session->internals.connection_using_safe_renegotiation = 1;

  return 0;
}

int
_gnutls_safe_renegotiation_send_params (gnutls_session_t session,
					opaque * data, size_t _data_size)
{
  /* The format of this extension is a one-byte length of verify data followed
   * by the verify data itself. Note that the length byte does not include
   * itself; IOW, empty verify data is represented as a length of 0. That means
   * the minimum extension is one byte: 0x00.
   */
  ssize_t data_size = _data_size;
  tls_ext_st *ext = &session->security_parameters.extensions;

  if (session->internals.priorities.safe_renegotiation == SR_DISABLED)
    {
      gnutls_assert ();
      return 0;
    }

  data[0] = 0;

  /* Always offer the extension if we're a client */
  if (session->internals.connection_using_safe_renegotiation ||
      session->security_parameters.entity == GNUTLS_CLIENT)
    {
      DECR_LEN (data_size, 1);
      data[0] = ext->client_verify_data_len;

      DECR_LEN (data_size, ext->client_verify_data_len);

      if (ext->client_verify_data_len > 0)
	memcpy (&data[1], ext->client_verify_data,
		ext->client_verify_data_len);

      if (session->security_parameters.entity == GNUTLS_SERVER)
	{
	  data[0] += ext->server_verify_data_len;

	  DECR_LEN (data_size, ext->server_verify_data_len);

	  if (ext->server_verify_data_len > 0)
	    memcpy (&data[1 + ext->client_verify_data_len],
		    ext->server_verify_data, ext->server_verify_data_len);
	}
    }
  else
    return 0;

  return 1 + data[0];		/* don't forget the length byte */
}

/**
 * gnutls_safe_renegotiation_status:
 * @session: is a #gnutls_session_t structure.
 *
 * Can be used to check whether safe renegotiation is being used
 * in the current session.
 *
 * Returns: 0 when safe renegotiation is not used and non zero when
 *   safe renegotiation is used.
 *
 * Since: 2.10.0
 **/
int
gnutls_safe_renegotiation_status (gnutls_session_t session)
{
  return session->internals.connection_using_safe_renegotiation;
}
