/*
 * Copyright (C) 2022 Red Hat, Inc.
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#ifndef GNUTLS_LIB_AUDIT_INT_H
# define GNUTLS_LIB_AUDIT_INT_H

# ifdef HAVE_CONFIG_H
#  include <config.h>
# endif

# include "audit.h"
# include <stdint.h>

typedef enum {
	GNUTLS_AUDIT_KX_ECDHE = 0,
	GNUTLS_AUDIT_KX_DHE = 1,
	GNUTLS_AUDIT_KX_PSK = 2,
	GNUTLS_AUDIT_KX_ECDHE_PSK = 3,
	GNUTLS_AUDIT_KX_DHE_PSK = 4
} gnutls_audit_key_exchange_algorithm_t;

typedef uint64_t gnutls_audit_context_t;

extern gnutls_audit_context_t _gnutls_audit_lib_context;

struct gnutls_audit_context_stack_head_st {
	gnutls_audit_context_t context;
	struct gnutls_audit_context_stack_head_st *next;
};

struct gnutls_audit_context_stack_st {
	struct gnutls_audit_context_stack_head_st *head;
};

void _gnutls_audit_init(void);
int _gnutls_audit_push_context(struct gnutls_audit_context_stack_st *stack,
			       gnutls_audit_context_t data);
int _gnutls_audit_pop_context(struct gnutls_audit_context_stack_st *stack);
void _gnutls_audit_clear_context(struct gnutls_audit_context_stack_st *stack);

#endif				/* GNUTLS_LIB_AUDIT_INT_H */
