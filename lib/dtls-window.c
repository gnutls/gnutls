/*
 * Copyright (C) 2009-2016 Free Software Foundation, Inc.
 * Copyright (C) 2013-2016 Nikos Mavrogiannopoulos
 *
 * Authors: Jonathan Bastien-Filiatrault
 *          Nikos Mavrogiannopoulos
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* Functions that relate to DTLS window handling.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "debug.h"
#include "dtls.h"
#include "record.h"
#include <mbuffers.h>
#include <buffers.h>
#include <constate.h>
#include <state.h>
#include <gnutls/dtls.h>

#define window_table rp->record_sw
#define window_size rp->record_sw_size
#define window_head_idx rp->record_sw_head_idx

#define LOAD_UINT48(out, ubytes) \
	for (i = 2; i < 8; i++) { \
		out <<= 8; \
		out |= ubytes[i] & 0xff; \
	}

void _dtls_reset_window(gnutls_session_t session, uint8_t _seq[8])
{
	record_parameters_st *rp;
	int ret;
	unsigned i;
	uint64_t seq = 0;

	ret =
	    _gnutls_epoch_get(session, EPOCH_READ_CURRENT, &rp);
	if (ret < 0)
		return;

	LOAD_UINT48(seq, _seq);

	if (seq == 0) {
		window_size = 0;
		window_head_idx = 0;
		return;
	}

	window_size = 1;
	window_head_idx = 0;
	window_table[window_head_idx] = seq - 1;
}

static void slide_window(struct record_parameters_st *rp,
			 unsigned int places)
{
	unsigned int old_head = window_head_idx;

	if (places < window_size) {
		window_head_idx += places;
		window_head_idx %= DTLS_RECORD_WINDOW_SIZE;

		window_table[window_head_idx] =
		    window_table[old_head] + places;
	} else {
		unsigned int last_idx =
		    (window_head_idx + window_size - 1) % window_size;
		window_table[window_head_idx] = window_table[last_idx];
	}
}

/* Checks if a sequence number is not replayed. If replayed
 * returns a negative error code, otherwise zero.
 */
int _dtls_record_check(struct record_parameters_st *rp, uint64 * _seq)
{
	uint64_t seq = 0, diff;
	unsigned int i, offset = 0;
	unsigned int last_idx;

	LOAD_UINT48(seq, _seq->i);

	/* only two values allowed in window_size */
	if (window_size == 0) {
		window_size = 1;
		window_head_idx = 0;
		last_idx = window_size - 1;
		window_table[last_idx] = window_table[window_head_idx] =
		    seq;
		return 0;
	}

	last_idx = (window_head_idx + window_size - 1) % window_size;

	if (seq <= window_table[window_head_idx]) {
		return -1;
	}

	if (seq <= window_table[last_idx]) {
		/* is between first and last */
		diff = window_table[last_idx] - seq;

		if (diff >= window_size) {
			return -1;
		}

		if (diff > last_idx) {
			diff = diff - last_idx;
			offset = window_size - 1 - diff;
		} else
			offset = last_idx - diff;

		if (window_table[offset] == seq) {
			return -1;
		} else
			window_table[offset] = seq;
	} else {		/* seq > last */

		diff = seq - window_table[last_idx];

		if (window_size + diff <= DTLS_RECORD_WINDOW_SIZE) {
			window_size += diff;
		} else {
			if (window_size < DTLS_RECORD_WINDOW_SIZE) {
				offset =
				    DTLS_RECORD_WINDOW_SIZE - window_size;
				window_size = DTLS_RECORD_WINDOW_SIZE;
				diff -= offset;
			}

			/* diff > 0 */
			slide_window(rp, diff);
		}

		offset = (window_head_idx + window_size - 1) % window_size;
		window_table[offset] = seq;
	}
	return 0;
}
