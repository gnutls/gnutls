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
#include "crau/crau.h"

#ifndef GNUTLS_LIB_AUDIT_H
#define GNUTLS_LIB_AUDIT_H

void _gnutls_audit_push_context_with_data(long context, ...);
#define _gnutls_audit_new_context_with_data(...) \
	_gnutls_audit_push_context_with_data(CRAU_AUTO_CONTEXT, __VA_ARGS__)

void _gnutls_audit_data(long unused, ...);
#define _gnutls_audit_data(...) _gnutls_audit_data(0, __VA_ARGS__)

#endif /* GNUTLS_LIB_AUDIT_H */
