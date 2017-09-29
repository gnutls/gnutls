/*
 * Copyright (C) 2017 Red Hat, Inc.
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

#ifndef GNUTLS_EXT_LIB_H
#define GNUTLS_EXT_LIB_H

#include <gnutls/gnutls.h>
#include "hello_ext.h"

void _gnutls_hello_ext_default_deinit(gnutls_ext_priv_data_t priv);

int
_gnutls_hello_ext_set_datum(gnutls_session_t session,
			    extensions_t id, const gnutls_datum_t *data);
int
_gnutls_hello_ext_get_datum(gnutls_session_t session,
			    extensions_t id, gnutls_datum_t *data /* constant contents */);

#endif
