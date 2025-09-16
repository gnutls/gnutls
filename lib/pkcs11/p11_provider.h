/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Author: Zoltan Fridrich
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

#ifndef GNUTLS_LIB_P11_PROVIDER_H
#define GNUTLS_LIB_P11_PROVIDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pkcs11_int.h"

int _p11_provider_init(const char *module_path, const uint8_t *pin,
		       size_t pin_size);
void _p11_provider_deinit(void);
bool _p11_provider_is_initialized(void);
ck_session_handle_t _p11_provider_open_session(void);
void _p11_provider_close_session(ck_session_handle_t session);
struct ck_function_list *_p11_provider_get_module(void);
ck_slot_id_t _p11_provider_get_slot(void);

#endif /* GNUTLS_LIB_P11_PROVIDER_H */
