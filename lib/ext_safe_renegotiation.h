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

#ifndef EXT_SAFE_RENEGOTIATION_H
# define EXT_SAFE_RENEGOTIATION_H

int _gnutls_safe_renegotiation_recv_params (gnutls_session_t state,
					    const opaque * data,
					    size_t data_size);
int _gnutls_safe_renegotiation_send_params (gnutls_session_t state,
					    opaque * data, size_t);

#endif /* EXT_SAFE_RENEGOTIATION_H */
