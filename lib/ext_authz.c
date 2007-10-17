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
 * This file used to implement TLS-authz as specified in
 * draft-housley-tls-authz-extns-07.  This technique may be patented
 * in the future, and it is not of crucial importance for the Internet
 * community.  After deliberation we have concluded that the best
 * thing we can do in this situation is to encourage society not to
 * adopt this technique.  We have decided to lead the way with our own
 * actions.
 *
*/

#include "gnutls_int.h"

int
gnutls_authz_send_x509_attr_cert (gnutls_session_t session,
				  const char *data,
				  size_t len)
{
  return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int
gnutls_authz_send_saml_assertion (gnutls_session_t session,
				  const char *data,
				  size_t len)
{
  return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int
gnutls_authz_send_x509_attr_cert_url (gnutls_session_t session,
				      const char *url,
				      size_t urllen,
				      gnutls_mac_algorithm_t hash_type,
				      const char *hash)
{
  return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int
gnutls_authz_send_saml_assertion_url (gnutls_session_t session,
				      const char *url,
				      size_t urllen,
				      gnutls_mac_algorithm_t hash_type,
				      const char *hash)
{
  return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

void
gnutls_authz_enable (gnutls_session_t session,
		     const int *client_formats,
		     const int *server_formats,
		     gnutls_authz_recv_callback_func recv_callback,
		     gnutls_authz_send_callback_func send_callback)
{
  return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}
