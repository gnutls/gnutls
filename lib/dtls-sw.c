/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Authors: Fridolin Pokorny
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

/* Functions that relate to DTLS sliding window handling.
 */

#ifndef DTLS_SW_NO_INCLUDES
#include "gnutls_int.h"
#include "errors.h"
#include "debug.h"
#include "dtls.h"
#include "record.h"
#endif

/*
 * DTLS sliding window handling
 */
#define DTLS_EPOCH_SHIFT		(6*CHAR_BIT)
#define DTLS_SEQ_NUM_MASK		0x0000FFFFFFFFFFFF
#define DTLS_WINDOW_HAVE_RECV_PACKET(W) ((W)->dtls_sw_have_recv != 0)

#define DTLS_WINDOW_INIT_AT(W, S)	(W)->dtls_sw_bits = ((W)->dtls_sw_have_recv) = 0; (W)->dtls_sw_start = (S&DTLS_SEQ_NUM_MASK)
#define DTLS_WINDOW_INIT(W)		DTLS_WINDOW_INIT_AT(W, 0)

#define DTLS_WINDOW_INSIDE(W, S)	((((S) & DTLS_SEQ_NUM_MASK) > (W)->dtls_sw_start) && \
						(((S)  & DTLS_SEQ_NUM_MASK) - (W)->dtls_sw_start <= (sizeof((W)->dtls_sw_bits) * CHAR_BIT)))

#define DTLS_WINDOW_OFFSET(W, S)	((((S) & DTLS_SEQ_NUM_MASK) - (W)->dtls_sw_start) - 1)

#define DTLS_WINDOW_RECEIVED(W, S)	(((W)->dtls_sw_bits & ((uint64_t) 1 << DTLS_WINDOW_OFFSET(W, S))) != 0)

#define DTLS_WINDOW_MARK(W, S)		((W)->dtls_sw_bits |= ((uint64_t) 1 << DTLS_WINDOW_OFFSET(W, S)))

/* We forcefully advance the window once we have received more than
 * 8 packets since the first one. That way we ensure that we don't
 * get stuck on connections with many lost packets. */
#define DTLS_WINDOW_UPDATE(W)		\
					if (((W)->dtls_sw_bits & 0xffffffffffff0000LL) != 0) { \
						(W)->dtls_sw_bits = (W)->dtls_sw_bits >> 1; \
						(W)->dtls_sw_start++; \
					} \
					while ((W)->dtls_sw_bits & (uint64_t) 1) { \
						(W)->dtls_sw_bits = (W)->dtls_sw_bits >> 1; \
						(W)->dtls_sw_start++; \
					}

#define LOAD_UINT64(out, ubytes) \
	for (i = 0; i < 8; i++) { \
		out <<= 8; \
		out |= ubytes[i] & 0xff; \
	}

void _dtls_reset_window(struct record_parameters_st *rp)
{
	DTLS_WINDOW_INIT(rp);
}

/* Checks if a sequence number is not replayed. If a replayed
 * packet is detected it returns a negative value (but no sensible error code).
 * Otherwise zero.
 */
int _dtls_record_check(struct record_parameters_st *rp, uint64 * _seq)
{
	uint64_t seq_num = 0;
	unsigned i;

	LOAD_UINT64(seq_num, _seq->i);

	if ((seq_num >> DTLS_EPOCH_SHIFT) != rp->epoch) {
		return gnutls_assert_val(-1);
	}

	if (!DTLS_WINDOW_HAVE_RECV_PACKET(rp)) {
		DTLS_WINDOW_INIT_AT(rp, seq_num);
		rp->dtls_sw_have_recv = 1;
		return 0;
	}

	/* are we inside sliding window? */
	if (!DTLS_WINDOW_INSIDE(rp, seq_num)) {
		return gnutls_assert_val(-2);
	}

	/* already received? */
	if (DTLS_WINDOW_RECEIVED(rp, seq_num)) {
		return gnutls_assert_val(-3);
	}

	DTLS_WINDOW_MARK(rp, seq_num);
	DTLS_WINDOW_UPDATE(rp);

	return 0;
}
