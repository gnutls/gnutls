/*
 * Copyright (C) 2016 Dmitry Eremin-Solenikov
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
 */
/* This file contains workaround for CryptoPro sending and receiving
 * special extension when using older GOST cipher suites.
 *
 * Clients might expect to receive this extension from server. Thus we send it
 * if client has asked for one and old ciphersuite is selected.
 *
 * Servers might (and will) send this extension if old ciphersuite is selected.
 * Thus just ignore it on the client side.
 *
 * For data description, see TLSGostExtensionHashHMACSelect in 
 * https://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04#appendix-A.1
 */

#include "gnutls_int.h"
#include <gnutls/gnutls.h>
#include <ext/cryptopro.h>

#define GNUTLS_GOSTR341001_MAJOR	0x00
#define GNUTLS_GOSTR341001_28147_MINOR	0x81
#define GNUTLS_GOSTR341001_NULL_MINOR	0x83

static int
_gnutls_cryptopro_recv_params(gnutls_session_t session,
			      const uint8_t * data,
			      size_t data_size)
{
	/* Just ignore it, no use of that extension */

	return 0;
}

static const uint8_t cryptopro_server_data[] = {
	0x30, 0x1e, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85,
	0x03, 0x02, 0x02, 0x09, 0x30, 0x08, 0x06, 0x06,
	0x2a, 0x85, 0x03, 0x02, 0x02, 0x16, 0x30, 0x08,
	0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x17
};

static int
_gnutls_cryptopro_send_params(gnutls_session_t session,
			      gnutls_buffer_st * extdata)
{
	if (session->security_parameters.entity == GNUTLS_SERVER) {
		if (session->security_parameters.cs->id[0] == GNUTLS_GOSTR341001_MAJOR &&
		    (session->security_parameters.cs->id[1] == GNUTLS_GOSTR341001_28147_MINOR ||
		     session->security_parameters.cs->id[1] == GNUTLS_GOSTR341001_NULL_MINOR)) {
			_gnutls_buffer_append_data(extdata, cryptopro_server_data, sizeof(cryptopro_server_data));
			return sizeof(cryptopro_server_data);
		}
	} else {
		/* We might receive this extension even if we did not ask for it.
		 * CryptoPro/OpenSSL servers will send it if GOSTR341001 ciphersuite
		 * was selected. */
#ifdef ENABLE_GOST
		_gnutls_extension_list_add(session, &ext_mod_cryptopro, 0);
#endif
		return 0;
	}
	return 0;
}

const extension_entry_st ext_mod_cryptopro = {
	.name = "CryptoPro",
	.type = GNUTLS_EXTENSION_CRYPTOPRO,
	.parse_type = GNUTLS_EXT_TLS,

	.recv_func = _gnutls_cryptopro_recv_params,
	.send_func = _gnutls_cryptopro_send_params,
};
