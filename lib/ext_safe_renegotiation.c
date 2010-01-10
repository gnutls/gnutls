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
#include "gnutls_errors.h"

/* Each peer processes the extension in the same way - by moving the "current"
 * value to "previous" and setting new "current" values.
 */
int
_gnutls_safe_renegotiation_recv_params (gnutls_session_t session, 
		const opaque * data, size_t _data_size)
{
  ssize_t data_size = _data_size;
  uint8_t len;

  DECR_LEN (data_size, 1);
  len = data[0];
  DECR_LEN (data_size, len);
  
  if (len >= MAX_VERIFY_DATA_SIZE)
    {
      gnutls_assert();
      return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

  memcpy (session->security_parameters.extensions.previous_verify_data,
	  session->security_parameters.extensions.current_verify_data,
	  session->security_parameters.extensions.current_verify_data_len);

  session->security_parameters.extensions.previous_verify_data_len =
	  session->security_parameters.extensions.current_verify_data_len;

  memcpy (session->security_parameters.extensions.current_verify_data,
	  &data[1], len);

  if (session->security_parameters.entity == GNUTLS_SERVER)
    len *= 2;

  session->security_parameters.extensions.current_verify_data_len = len;

  session->security_parameters.extensions.safe_renegotiation_received = 1;
  

  return 0;
}

/* As a client, this sends the verify information that was saved during the
 * previous finished message. As a server, echo back whatever we just received.
 */
int
_gnutls_safe_renegotiation_send_params (gnutls_session_t session, 
		opaque * data, size_t data_size)
{
  uint8_t len = 0; /* return 0 if we're not sending this ext */

  if(session->security_parameters.extensions.safe_renegotiation_received ||
     session->security_parameters.entity == GNUTLS_CLIENT)
    {
      if (!session->security_parameters.extensions.disable_safe_renegotiation)
        {
          len = session->security_parameters.extensions.current_verify_data_len;

	  /* client only sends its verification data */
	  if (session->security_parameters.entity == GNUTLS_CLIENT)
	    {
              len /= 2;
            }

          if (data_size < len + 1) /* save room for the length byte */
            {
              gnutls_assert ();
              return GNUTLS_E_SHORT_MEMORY_BUFFER;
            }

          data[0] = len++; /* return total length = len + length byte */
          memcpy (&data[1], 
	          session->security_parameters.extensions.current_verify_data,
	          session->security_parameters.extensions.current_verify_data_len);
        }
    }

  return len;
}

/**
  * gnutls_safe_renegotiation_set - Used to enable and disable safe renegotiation
  * @session: is a #gnutls_session_t structure.
  * @value: 0 to disable and 1 to enable
  *
  * Used to enable and disable safe renegotiation for the current
  * session. Normally you shouldn't cope with this function since the
  * default (enable) is sufficient, but there might be servers that
  * cannot handle or correctly handle the extension.
  **/
void
gnutls_safe_renegotiation_set (gnutls_session_t session, int value)
{
	session->security_parameters.extensions.disable_safe_renegotiation = 1-value;
}

