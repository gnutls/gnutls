/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

void* _gnutls_ext_func_send(uint16 type);
void* _gnutls_ext_func_recv(uint16 type);
const char *_gnutls_extension_get_name(uint16 type);
int _gnutls_parse_extensions( GNUTLS_STATE, const opaque*, int);
int _gnutls_gen_extensions( GNUTLS_STATE state, opaque** data);

typedef struct {
	const char *name;
	uint16 type;
	int (*gnutls_ext_func_recv)( GNUTLS_STATE, const opaque*, int); /* recv data */
	int (*gnutls_ext_func_send)( GNUTLS_STATE, opaque*, int); /* send data */
} gnutls_extension_entry;
