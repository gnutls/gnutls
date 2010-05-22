/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2010 Free Software
 * Foundation, Inc.
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
#include <ext_srp.h>

#ifdef ENABLE_SRP

#include "gnutls_auth.h"
#include "auth_srp.h"
#include "gnutls_errors.h"
#include "gnutls_algorithms.h"
#include <gnutls_num.h>

int
_gnutls_srp_recv_params (gnutls_session_t session, const opaque * data,
			 size_t _data_size)
{
  uint8_t len;
  ssize_t data_size = _data_size;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      if (data_size > 0)
	{
	  len = data[0];
	  DECR_LEN (data_size, len);

	  if (MAX_SRP_USERNAME < len)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_ILLEGAL_SRP_USERNAME;
	    }
	  memcpy (session->security_parameters.extensions.srp_username,
		  &data[1], len);
	  /* null terminated */
	  session->security_parameters.extensions.srp_username[len] = 0;
	}
    }
  return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated locally
 */
int
_gnutls_srp_send_params (gnutls_session_t session, opaque * data,
			 size_t data_size)
{
  unsigned len;

  if (_gnutls_kx_priority (session, GNUTLS_KX_SRP) < 0 &&
      _gnutls_kx_priority (session, GNUTLS_KX_SRP_DSS) < 0 &&
      _gnutls_kx_priority (session, GNUTLS_KX_SRP_RSA) < 0)
    {
      /* algorithm was not allowed in this session
       */
      return 0;
    }

  /* this function sends the client extension data (username) */
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      gnutls_srp_client_credentials_t cred = (gnutls_srp_client_credentials_t)
	_gnutls_get_cred (session->key, GNUTLS_CRD_SRP, NULL);

      if (cred == NULL)
	return 0;

      if (cred->username != NULL)
	{			/* send username */
	  len = MIN (strlen (cred->username), 255);

	  if (data_size < len + 1)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_SHORT_MEMORY_BUFFER;
	    }

	  data[0] = (uint8_t) len;
	  memcpy (&data[1], cred->username, len);
	  return len + 1;
	}
      else if (cred->get_function != NULL)
	{
	  /* Try the callback
	   */
	  char *username = NULL, *password = NULL;

	  if (cred->get_function (session, &username, &password) < 0
	      || username == NULL || password == NULL)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_ILLEGAL_SRP_USERNAME;
	    }

	  len = MIN (strlen (username), 255);

	  if (data_size < len + 1)
	    {
	      gnutls_free (username);
	      gnutls_free (password);
	      gnutls_assert ();
	      return GNUTLS_E_SHORT_MEMORY_BUFFER;
	    }

	  session->internals.srp_username = username;
	  session->internals.srp_password = password;

	  data[0] = (uint8_t) len;
	  memcpy (&data[1], username, len);
	  return len + 1;
	}
    }
  return 0;
}

#endif /* ENABLE_SRP */
