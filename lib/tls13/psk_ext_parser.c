/*
 * Copyright (C) 2017-2018 Free Software Foundation, Inc.
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * Author: Ander Juaristi, Nikos Mavrogiannopoulos
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
#include "tls13/psk_ext_parser.h"


static int advance_to_end_of_object(psk_ext_parser_st *p)
{
	size_t adv;

	/* Advance the pointer to the end of the current object */
	if (p->obj_read < p->obj_len) {
		adv = p->obj_len - p->obj_read;
		DECR_LEN(p->len, adv);
		p->data += adv;
	}

	return 0;
}

int _gnutls13_psk_ext_parser_init(psk_ext_parser_st *p,
				  const unsigned char *data, size_t _len)
{
	uint16_t identities_len;
	ssize_t len = _len;

	if (!p || !data || !len)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	memset(p, 0, sizeof(*p));

	identities_len = _gnutls_read_uint16(data);

	if (identities_len > 0) {
		DECR_LEN(len, 2);
		data += 2;

		p->obj_len = identities_len;
		p->data = (unsigned char *) data;
		p->len = len;
	}

	return identities_len;
}

int _gnutls13_psk_ext_parser_next_psk(psk_ext_parser_st *p, struct psk_st *psk)
{
	if (p->obj_read >= p->obj_len)
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

	/* Read a PskIdentity structure */
	psk->identity.size = _gnutls_read_uint16(p->data);
	if (psk->identity.size == 0)
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

	DECR_LEN(p->len, 2);
	p->data += 2;
	p->obj_read += 2;

	psk->identity.data = p->data;

	DECR_LEN(p->len, psk->identity.size);
	p->data += psk->identity.size;
	p->obj_read += psk->identity.size;

	psk->ob_ticket_age = _gnutls_read_uint32(p->data);
	DECR_LEN(p->len, 4);
	p->data += 4;
	p->obj_read += 4;

	return p->next_index++;
}

int _gnutls13_psk_ext_parser_find_binder(psk_ext_parser_st *p, int psk_index,
					 gnutls_datum_t *binder_out)
{
	uint16_t binders_len;
	uint8_t binder_len;
	int cur_index = 0, binder_found = 0;

	if (p == NULL || psk_index < 0 || binder_out == NULL)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if (p->obj_len == 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	/* Place the pointer at the start of the binders */
	if (advance_to_end_of_object(p) < 0)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

	DECR_LEN(p->len, 2);
	binders_len = _gnutls_read_uint16(p->data);
	if (binders_len > 0) {
		p->data += 2;

		p->obj_len = binders_len;
		p->obj_read = 0;
	} else {
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
	}

	/* Start traversing the binders */
	while (!binder_found && p->len > 0) {
		DECR_LEN(p->len, 1);
		binder_len = *(p->data);

		if (binder_len == 0)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		p->data++;
		p->obj_read++;

		if (cur_index == psk_index) {
			/* We found the binder with the supplied index */
			binder_out->data = gnutls_malloc(binder_len);
			if (!binder_out->data)
				return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

			binder_out->size = binder_len;
			DECR_LEN(p->len, binder_len);
			memcpy(binder_out->data, p->data, binder_len);
			p->data += binder_len;
			p->obj_read += binder_len;

			binder_found = 1;
		} else {
			/* Not our binder - continue to the next one */
			DECR_LEN(p->len, binder_len);
			p->data += binder_len;
			p->obj_read += binder_len;

			cur_index++;
		}
	}

	if (binder_found)
		return 0;
	else
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
}
