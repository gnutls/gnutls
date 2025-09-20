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
#include "pkcs11_int.h"
#include "p11_cipher.h"
#include "p11_mac.h"
#include "p11_provider.h"

static struct {
	struct ck_function_list *module;
	ck_slot_id_t slot;
	gnutls_datum_t pin;
	bool initialized;
} p11_provider;

int _p11_provider_init(const char *url, const uint8_t *pin_data,
		       size_t pin_size)
{
	int ret;
	struct p11_kit_uri *uinfo = NULL;
	gnutls_datum_t pin = { NULL, 0 };
	struct ck_function_list *module;
	ck_slot_id_t slot;

	if (p11_provider.initialized)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	PKCS11_CHECK_INIT;

	uinfo = p11_kit_uri_new();
	if (uinfo == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	ret = p11_kit_uri_parse(url, P11_KIT_URI_FOR_TOKEN, uinfo);
	if (ret != P11_KIT_URI_OK) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		goto cleanup;
	}

	ret = _gnutls_set_datum(&pin, pin_data, pin_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = pkcs11_find_slot(&module, &slot, uinfo, NULL, NULL, NULL);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _p11_ciphers_init(module, slot);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _p11_macs_init(module, slot);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	p11_provider.module = module;
	p11_provider.slot = slot;
	p11_provider.pin = _gnutls_steal_datum(&pin);
	p11_provider.initialized = true;
	return 0;

cleanup:
	p11_kit_uri_free(uinfo);
	_gnutls_free_key_datum(&pin);
	return ret;
}

void _p11_provider_deinit(void)
{
	if (!p11_provider.initialized)
		return;

	_p11_ciphers_deinit();
	_p11_macs_deinit();

	_gnutls_free_key_datum(&p11_provider.pin);
	p11_provider.initialized = false;
}

bool _p11_provider_is_initialized(void)
{
	return p11_provider.initialized;
}

ck_session_handle_t _p11_provider_open_session(void)
{
	ck_rv_t rv;
	ck_session_handle_t session = CK_INVALID_HANDLE;

	rv = p11_provider.module->C_OpenSession(
		p11_provider.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
		NULL, &session);
	if (rv != CKR_OK)
		return CK_INVALID_HANDLE;

	rv = p11_provider.module->C_Login(session, CKU_USER,
					  p11_provider.pin.data,
					  p11_provider.pin.size);
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
		p11_provider.module->C_CloseSession(session);
		return CK_INVALID_HANDLE;
	}

	return session;
}

void _p11_provider_close_session(ck_session_handle_t session)
{
	if (session == CK_INVALID_HANDLE)
		return;

	p11_provider.module->C_Logout(session);
	p11_provider.module->C_CloseSession(session);
}

struct ck_function_list *_p11_provider_get_module(void)
{
	return p11_provider.module;
}

ck_slot_id_t _p11_provider_get_slot(void)
{
	return p11_provider.slot;
}
