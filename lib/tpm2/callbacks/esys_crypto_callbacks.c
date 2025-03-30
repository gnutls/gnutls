/*
 * Copyright © 2018-2021 David Woodhouse.
 * Copyright © 2019,2021 Red Hat, Inc.
 *
 * Author: David Dudas <david.dudas03@e-uvt.ro>
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

#include "config.h"

#include "esys_crypto_callbacks.h"
#include "tpm2/callbacks/rsa/rsa_callbacks.h"
#include "tpm2/callbacks/hash/hash_callbacks.h"
#include "tpm2/callbacks/hmac/hmac_callbacks.h"
#include "tpm2/callbacks/random/random_callbacks.h"
#include "tpm2/callbacks/ecdh/ecdh_callbacks.h"
#include "tpm2/callbacks/aes/aes_callbacks.h"
#include "dlwrap/tss2_esys.h"
#include "tss2_esys.h"
#include "errors.h"

int _gnutls_setup_tss2_callbacks(ESYS_CONTEXT *ctx)
{
	TSS2_RC rc;

	struct ESYS_CRYPTO_CALLBACKS callbacks = { 0 };

	_gnutls_set_tss2_rsa_callbacks(&callbacks);
	_gnutls_set_tss2_hash_callbacks(&callbacks);
	_gnutls_set_tss2_hmac_callbacks(&callbacks);
	_gnutls_set_tss2_random_callbacks(&callbacks);
	_gnutls_set_tss2_ecdh_callbacks(&callbacks);
	_gnutls_set_tss2_aes_callbacks(&callbacks);

	rc = GNUTLS_TSS2_ESYS_FUNC(Esys_SetCryptoCallbacks)(ctx, &callbacks);
	if (rc) {
		_gnutls_debug_log(
			"tpm2: Esys_SetCryptoCallbacks failed: 0x%x\n", rc);
		return gnutls_assert_val(GNUTLS_E_TPM_ERROR);
	}

	return 0;
}
