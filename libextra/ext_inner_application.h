/*
 * Copyright (C) 2005, 2008, 2010 Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson
 *
 * This file is part of GnuTLS-EXTRA.
 *
 * GnuTLS-extra is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * GnuTLS-extra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

int _gnutls_inner_application_recv_params (gnutls_session_t session,
					   const opaque * data,
					   size_t data_size);
int _gnutls_inner_application_send_params (gnutls_session_t session,
					   opaque * data, size_t);
