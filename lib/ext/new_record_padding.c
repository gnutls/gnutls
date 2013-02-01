/*
 * Copyright (C) 2012 Nikos Mavrogiannopoulos
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

/* This file contains the code for the Max Record Size TLS extension.
 */

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"
#include <gnutls_extensions.h>
#include <ext/new_record_padding.h>

static int new_record_padding_recv_params (gnutls_session_t session,
                                           const uint8_t * data,
                                           size_t data_size);
static int new_record_padding_send_params (gnutls_session_t session,
  gnutls_buffer_st* extdata);
static int new_record_padding_after_handshake(gnutls_session_t session);

extension_entry_st ext_mod_new_record_padding = {
  .name = "NEW_RECORD_PADDING",
  .type = GNUTLS_EXTENSION_NEW_RECORD_PADDING,
  .parse_type = GNUTLS_EXT_TLS,

  .recv_func = new_record_padding_recv_params,
  .send_func = new_record_padding_send_params,
  .pack_func = NULL,
  .unpack_func = NULL,
  .deinit_func = NULL,
  .handshake_func = new_record_padding_after_handshake
};

static int
new_record_padding_recv_params (gnutls_session_t session,
                                const uint8_t * data, size_t _data_size)
{
  ssize_t data_size = _data_size;
  extension_priv_data_t epriv;

  if (data_size > 0)
    return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      if (session->internals.priorities.new_record_padding != 0)
        {
          epriv.num = 1;
          _gnutls_ext_set_session_data (session,
				GNUTLS_EXTENSION_NEW_RECORD_PADDING,
				epriv);
        }
    }
  else /* client */
    {
      if (session->internals.priorities.new_record_padding != 0)
        {
          epriv.num = 1;
          _gnutls_ext_set_session_data (session,
				GNUTLS_EXTENSION_NEW_RECORD_PADDING,
				epriv);
        }
    }

  return 0;
}

static int new_record_padding_after_handshake(gnutls_session_t session)
{
  extension_priv_data_t epriv;
  int ret;

  ret = _gnutls_ext_get_session_data (session,
				      GNUTLS_EXTENSION_NEW_RECORD_PADDING,
				      &epriv);
  if (ret < 0)
    return 0; /* fine */
  
  if (epriv.num != 0)
    session->security_parameters.new_record_padding = 1;
  
  return 0;
}

/* returns data_size or a negative number on failure
 */
static int
new_record_padding_send_params (gnutls_session_t session, gnutls_buffer_st* extdata)
{
extension_priv_data_t epriv;
int ret;

  /* this function sends the client extension data (dnsname) */
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      if (session->internals.priorities.new_record_padding != 0)
        return GNUTLS_E_INT_RET_0; /* advertize it */
    }
  else
    {                           /* server side */
      ret = _gnutls_ext_get_session_data (session,
                                          GNUTLS_EXTENSION_NEW_RECORD_PADDING,
				          &epriv);
      if (ret < 0)
        return 0;

      if (epriv.num != 0)
        return GNUTLS_E_INT_RET_0;
    }

  return 0;
}


