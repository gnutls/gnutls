/*
 * Copyright (C) 2017 Free Software Foundation, Inc.
 *
 * Author: Ander Juaristi
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

#ifndef PSK_PARSER_H
#define PSK_PARSER_H
#include <gnutls/gnutls.h>

struct psk_ext_parser_st {
	const unsigned char *data;
	ssize_t len;
	size_t id_len;
	size_t id_read;
	int next_index;

	const unsigned char *binder_data;
	ssize_t binder_len;
};

typedef struct psk_ext_parser_st psk_ext_parser_st;

struct psk_st {
	/* constant values */
	gnutls_datum_t identity;
	uint32_t ob_ticket_age;
};

int _gnutls13_psk_ext_parser_init(psk_ext_parser_st *p,
				  const unsigned char *data, size_t len);
int _gnutls13_psk_ext_parser_next_psk(psk_ext_parser_st *p, struct psk_st *psk);
int _gnutls13_psk_ext_parser_find_binder(psk_ext_parser_st *p, int psk_index,
					 gnutls_datum_t *binder_out);

#endif
