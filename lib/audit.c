/*
 * Copyright (C) 2001-2012 Free Software Foundation, Inc.
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

#include "gnutls_int.h"
#include "audit_int.h"

#ifdef ENABLE_CRYPTO_AUDITING

gnutls_audit_context_t _gnutls_audit_lib_context;

void _gnutls_audit_init(void)
{
	_gnutls_audit_lib_context = (gnutls_audit_context_t) _gnutls_audit_init;
}

int
_gnutls_audit_push_context(struct gnutls_audit_context_stack_st *stack,
			   gnutls_audit_context_t data)
{
	struct gnutls_audit_context_stack_head_st *head;
	gnutls_audit_context_t parent = stack->head ?
	    stack->head->context : _gnutls_audit_lib_context;

	head = gnutls_malloc(sizeof(struct gnutls_audit_context_stack_head_st));
	if (!head)
		return GNUTLS_E_MEMORY_ERROR;

	head->context = data;
	head->next = stack->head;
	stack->head = head;

	CRYPTO_AUDITING_NEW_CONTEXT(head->context, parent);

	return 0;
}

int _gnutls_audit_pop_context(struct gnutls_audit_context_stack_st *stack)
{
	struct gnutls_audit_context_stack_head_st *head = stack->head;

	if (!head)
		return GNUTLS_E_INVALID_REQUEST;

	stack->head = head->next;
	gnutls_free(head);

	return 0;
}

void _gnutls_audit_clear_context(struct gnutls_audit_context_stack_st *stack)
{
	struct gnutls_audit_context_stack_head_st *prev;
	struct gnutls_audit_context_stack_head_st *head = stack->head;

	while (head) {
		prev = head;
		head = head->next;
		gnutls_free(prev);
	}
}

#else

void _gnutls_audit_init(void)
{
}

int
_gnutls_audit_push_context(struct gnutls_audit_context_stack_st *stack
			   MAYBE_UNUSED,
			   gnutls_audit_context_t data MAYBE_UNUSED)
{
	return 0;
}

int
_gnutls_audit_pop_context(struct gnutls_audit_context_stack_st *stack
			  MAYBE_UNUSED)
{
	return 0;
}

void
_gnutls_audit_clear_context(struct gnutls_audit_context_stack_st *stack
			    MAYBE_UNUSED)
{
}

#endif				/* ENABLE_CRYPTO_AUDITING */
