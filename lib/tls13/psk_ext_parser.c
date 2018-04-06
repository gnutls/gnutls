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

#include "gnutls_int.h"
#include "tls13/psk_ext_parser.h"

/* Returns GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE when no identities
 * are present, or >= 0, on success.
 */
int _gnutls13_psk_ext_parser_init(psk_ext_parser_st *p,
				  const unsigned char *data, size_t _len)
{
	uint16_t identities_len;
	ssize_t len = _len;

	if (!p || !data || !len)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	memset(p, 0, sizeof(*p));

	DECR_LEN(len, 2);
	identities_len = _gnutls_read_uint16(data);
	data += 2;

	if (identities_len == 0)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	p->id_len = identities_len;
	p->data = (unsigned char *) data;
	p->len = len;

	DECR_LEN(len, p->id_len);
	data += p->id_len;

	DECR_LEN(len, 2);
	p->binder_len = _gnutls_read_uint16(data);

	p->binder_data = p->data + p->id_len + 2;
	DECR_LEN(len, p->binder_len);

	return 0;
}

int _gnutls13_psk_ext_parser_next_psk(psk_ext_parser_st *p, struct psk_st *psk)
{
	if (p->id_read >= p->id_len)
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

	/* Read a PskIdentity structure */
	DECR_LEN(p->len, 2);
	psk->identity.size = _gnutls_read_uint16(p->data);
	if (psk->identity.size == 0)
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

	p->data += 2;
	p->id_read += 2;

	psk->identity.data = (void*)p->data;

	DECR_LEN(p->len, psk->identity.size);
	p->data += psk->identity.size;
	p->id_read += psk->identity.size;

	DECR_LEN(p->len, 4);
	psk->ob_ticket_age = _gnutls_read_uint32(p->data);

	p->data += 4;
	p->id_read += 4;

	return p->next_index++;
}

/* Output is a pointer to data, which shouldn't be de-allocated. */
int _gnutls13_psk_ext_parser_find_binder(psk_ext_parser_st *p, int psk_index,
					 gnutls_datum_t *binder_out)
{
	uint8_t binder_len;
	int cur_index = 0, binder_found = 0;
	ssize_t len;
	const uint8_t *data;
	ssize_t read_data = 0;

	if (p == NULL || psk_index < 0 || binder_out == NULL)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if (p->id_len == 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	len = p->binder_len;
	data = p->binder_data;

	if (len == 0)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	/* Start traversing the binders */
	while (!binder_found && len > 0) {
		DECR_LEN(len, 1);
		binder_len = *(data);

		if (binder_len == 0)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

		data++;
		read_data++;

		if (cur_index == psk_index) {
			/* We found the binder with the supplied index */
			DECR_LEN(len, binder_len);
			binder_out->data = (void*)data;
			binder_out->size = binder_len;

			data += binder_len;
			read_data += binder_len;

			binder_found = 1;
		} else {
			/* Not our binder - continue to the next one */
			DECR_LEN(len, binder_len);
			data += binder_len;
			read_data += binder_len;

			cur_index++;
		}
	}

	if (binder_found)
		return 0;
	else
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
}
