/*
 * Copyright (C) 2025 Red Hat
 *
 * Author: Daiki Ueno
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

#define CRAU_IMPLEMENTATION 1
#define CRAU_CONTEXT_STACK_DEPTH 8
#include "audit.h"

static _Thread_local struct crau_context_stack_st stack;

/**
 * gnutls_audit_push_context:
 * @context: an opaque context
 *
 * Push a new crypto-auditing context to the thread-local context
 * stack. The call must match the following gnutls_audit_pop_context()
 * call. This is useful for the applications that define their own
 * probe points for application level protocols.
 *
 * Since: 3.8.11
 **/
void gnutls_audit_push_context(long context)
{
	crau_push_context(&stack, context);
}

/**
 * gnutls_audit_pop_context:
 *
 * Pop the current crypto-auditing context from the thread-local
 * context stack. This is useful for the applications that define
 * their own probe points for application level protocols.
 *
 * Since: 3.8.11
 **/
void gnutls_audit_pop_context(void)
{
	crau_pop_context(&stack);
}

/**
 * gnutls_audit_current_context:
 *
 * Return the current crypto-auditing context from the thread-local
 * context stack. This is useful for the applications that define
 * their own probe points for application level protocols.
 *
 * Returns: an opaque context
 *
 * Since: 3.8.11
 **/
long gnutls_audit_current_context(void)
{
	return crau_current_context(&stack);
}

void _gnutls_audit_push_context_with_data(long context, ...)
{
	va_list ap;

	va_start(ap, context);
	crau_push_context_with_datav(&stack, context, ap);
	va_end(ap);
}

#undef _gnutls_audit_data
void _gnutls_audit_data(long unused, ...)
{
	va_list ap;

	va_start(ap, unused);
	crau_datav(&stack, ap);
	va_end(ap);
}
