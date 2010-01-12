/*
 * Copyright (C) 2009 Free Software Foundation
 *
 * Author: Steve Dispensa (<dispensa@phonefactor.com>)
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

#include <gnutls_int.h>
#include <ext_safe_renegotiation.h>
#include <gnutls_errors.h>

int
_gnutls_safe_renegotiation_recv_params (gnutls_session_t session, 
		const opaque * data, size_t _data_size)
{
  tls_ext_st *ext = &session->security_parameters.extensions;

  int len = data[0];
  ssize_t data_size = _data_size;

  DECR_LEN (data_size, len+1 /* count the first byte and payload */);

  int conservative_len = len;
  if (len > sizeof (ext->ri_extension_data))
    conservative_len = sizeof (ext->ri_extension_data);

  memcpy (ext->ri_extension_data, &data[1], conservative_len);
  ext->ri_extension_data_len = conservative_len;

  /* "safe renegotiation received" means on *this* handshake; "connection using
   * safe renegotiation" means that the initial hello received on the connection
   * indicatd safe renegotiation. 
   */
  ext->safe_renegotiation_received = 1;
  ext->connection_using_safe_renegotiation = 1;

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

  /* Always offer the extension if we're a client */
  if (ext->connection_using_safe_renegotiation ||
     session->security_parameters.entity == GNUTLS_CLIENT)
    {
      DECR_LEN (data_size, 1);
      data[0] = ext->client_verify_data_len;

      DECR_LEN (data_size, ext->client_verify_data_len);

      memcpy(&data[1], 
	     ext->client_verify_data, 
	     ext->client_verify_data_len);

      if (session->security_parameters.entity == GNUTLS_SERVER)
	{
	  data[0] += ext->server_verify_data_len;

	  DECR_LEN (data_size, ext->server_verify_data_len);

	  memcpy(&data[1 + ext->client_verify_data_len],
		 ext->server_verify_data,
		 ext->server_verify_data_len);
	}
    }

  return 1 + data[0]; /* don't forget the length byte */
}

/**
  * gnutls_safe_negotiation_set_initial - Used to enable and disable initial safe renegotiation
  * @session: is a #gnutls_session_t structure.
  * @value: 0 to disable and 1 to enable
  *
  * Used to enable and disable initial safe renegotiation for the current
  * session. By default it is allowed for a client to not advertise safe
  * renegotiation capability but there might be cases where signalling
  * a client of its insecurity by rejecting session might be beneficial.
  * This option has meaning only in server side.
  **/
void
gnutls_safe_negotiation_set_initial (gnutls_session_t session, int value)
{
  session->internals.priorities.initial_safe_renegotiation = value;
}

/**
  * gnutls_safe_negotiation_set - Used to enable and disable safe renegotiation
  * @session: is a #gnutls_session_t structure.
  * @value: 0 to disable and 1 to enable
  *
  * Used to enable and disable safe renegotiation for the current
  * session. Normally you shouldn't cope with this function since the
  * default (enable) is sufficient, but there might be servers that
  * cannot handle or correctly handle the extension.
  **/
void gnutls_safe_renegotiation_set (gnutls_session_t session, int value)
{
	session->internals.priorities.unsafe_renegotiation = 1-value;
}
