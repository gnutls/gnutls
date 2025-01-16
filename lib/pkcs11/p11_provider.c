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

#include "errors.h"
#include "gnutls_int.h"
#include "cipher_int.h"
#include "p11_provider.h"

#define P11_KIT_FUTURE_UNSTABLE_API
#include <p11-kit/iter.h>
#include <p11-kit/pkcs11.h>

static struct {
	CK_FUNCTION_LIST *module;
	CK_SLOT_ID slot;
	uint8_t *pin;
	size_t pin_size;
	bool initialized;
} p11_provider;

int _p11_provider_init(const char *module_path, const uint8_t *pin,
		       size_t pin_size)
{
	int ret;
	CK_RV rv;
	P11KitIter *iter = NULL;
	CK_FUNCTION_LIST *modules[2] = { 0 };
	CK_SLOT_ID slot = 0;
	uint8_t *_pin = NULL;

	if (p11_provider.initialized)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	modules[0] = p11_kit_module_load(module_path, 0);
	if (modules[0] == NULL)
		return gnutls_assert_val(GNUTLS_E_PKCS11_LOAD_ERROR);

	rv = p11_kit_module_initialize(modules[0]);
	if (rv != CKR_OK) {
		p11_kit_module_release(modules[0]);
		return gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
	}

	iter = p11_kit_iter_new(NULL, P11_KIT_ITER_WITH_TOKENS |
					      P11_KIT_ITER_WITHOUT_OBJECTS);
	if (iter == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}

	p11_kit_iter_begin(iter, modules);
	rv = p11_kit_iter_next(iter);
	if (rv != CKR_OK) {
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_ERROR);
		goto error;
	}

	slot = p11_kit_iter_get_slot(iter);
	p11_kit_iter_free(iter);

	_pin = gnutls_malloc(pin_size);
	if (_pin == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}
	memcpy(_pin, pin, pin_size);

	p11_provider.module = modules[0];
	p11_provider.slot = slot;
	p11_provider.pin = _pin;
	p11_provider.pin_size = pin_size;
	p11_provider.initialized = true;
	return 0;

error:
	if (iter != NULL)
		p11_kit_iter_free(iter);
	gnutls_free(_pin);
	p11_kit_module_finalize(modules[0]);
	p11_kit_module_release(modules[0]);
	return ret;
}

void _p11_provider_deinit(void)
{
	if (!p11_provider.initialized)
		return;

	gnutls_free(p11_provider.pin);
	p11_kit_module_finalize(p11_provider.module);
	p11_kit_module_release(p11_provider.module);
	memset(&p11_provider, 0, sizeof(p11_provider));
}

bool _p11_provider_is_initialized(void)
{
	return p11_provider.initialized;
}

CK_SESSION_HANDLE _p11_provider_open_session(void)
{
	CK_RV rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	rv = p11_provider.module->C_OpenSession(
		p11_provider.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
		NULL, &session);
	if (rv != CKR_OK)
		return CK_INVALID_HANDLE;

	rv = p11_provider.module->C_Login(session, CKU_USER, p11_provider.pin,
					  p11_provider.pin_size);
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
		p11_provider.module->C_CloseSession(session);
		return CK_INVALID_HANDLE;
	}

	return session;
}

void _p11_provider_close_session(CK_SESSION_HANDLE session)
{
	if (session == CK_INVALID_HANDLE)
		return;

	p11_provider.module->C_Logout(session);
	p11_provider.module->C_CloseSession(session);
}

CK_FUNCTION_LIST *_p11_provider_get_module(void)
{
	return p11_provider.module;
}

CK_SLOT_ID _p11_provider_get_slot(void)
{
	return p11_provider.slot;
}
