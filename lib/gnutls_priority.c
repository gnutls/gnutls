/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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

#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_algorithms.h"

/* the prototypes for these are in gnutls.h */

void gnutls_set_cipher_priority( GNUTLS_STATE state, int num, ...) {
	
	va_list ap;
	int i;
	BulkCipherAlgorithm* _ap;
	
	va_start( ap, num);

	_ap = ap;

	if (state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority!=NULL)
		gnutls_free(state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority);
	state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority = gnutls_malloc(sizeof(int*)*num);
	state->gnutls_internals.BulkCipherAlgorithmPriority.algorithms = num;
	for (i=0;i<num;i++) {
		state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority[i] = _ap[i];
	}
	va_end(ap);
}

void gnutls_set_kx_priority( GNUTLS_STATE state, int num, ...) {
	
	va_list ap;
	int i;
	KXAlgorithm *_ap;
	
	va_start( ap, num);

	_ap = ap;

	if (state->gnutls_internals.KXAlgorithmPriority.algorithm_priority!=NULL)
		gnutls_free(state->gnutls_internals.KXAlgorithmPriority.algorithm_priority);
	state->gnutls_internals.KXAlgorithmPriority.algorithm_priority = gnutls_malloc(sizeof(int*)*num);
	state->gnutls_internals.KXAlgorithmPriority.algorithms = num;
	for (i=0;i<num;i++) {
		state->gnutls_internals.KXAlgorithmPriority.algorithm_priority[i] = _ap[i];
	}
	va_end(ap);
}

void gnutls_set_mac_priority( GNUTLS_STATE state, int num, ...) {
	
	va_list ap;
	int i;
	MACAlgorithm *_ap;
	
	va_start( ap, num);
	_ap = ap;
	
	if (state->gnutls_internals.MACAlgorithmPriority.algorithm_priority!=NULL)
		gnutls_free(state->gnutls_internals.MACAlgorithmPriority.algorithm_priority);	
	state->gnutls_internals.MACAlgorithmPriority.algorithm_priority = gnutls_malloc(sizeof(int*)*num);
	state->gnutls_internals.MACAlgorithmPriority.algorithms = num;
	for (i=0;i<num;i++) {
		state->gnutls_internals.MACAlgorithmPriority.algorithm_priority[i] = _ap[i];
	}
	va_end(ap);
}