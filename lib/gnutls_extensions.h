/*
 * Copyright (C) 2001,2003 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gnutls_int.h>

const char *_gnutls_extension_get_name(uint16 type);
int _gnutls_parse_extensions( gnutls_session, const opaque*, int);
int _gnutls_gen_extensions( gnutls_session session, opaque** data);

typedef int (*ext_recv_func)( gnutls_session, const opaque*, size_t); /* recv data */
typedef int (*ext_send_func)( gnutls_session, opaque*, size_t); /* send data */

ext_send_func _gnutls_ext_func_send(uint16 type);
ext_recv_func _gnutls_ext_func_recv(uint16 type);

typedef struct {
	const char *name;
	uint16 type;
	ext_recv_func gnutls_ext_func_recv;
	ext_send_func gnutls_ext_func_send;
} gnutls_extension_entry;
