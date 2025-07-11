/*
 * Copyright © 2025 David Dudas
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

#include "hmac_callbacks.h"
#include "gnutls/crypto.h"

#include <tss2/tss2_esys.h>

typedef struct {
	gnutls_hmac_hd_t hmac_hd;
	gnutls_mac_algorithm_t alg;
} gnutls_esys_hmac_blob;

static gnutls_mac_algorithm_t _gnutls_convert_tpm2_mac_alg(TPM2_ALG_ID alg)
{
	switch (alg) {
	case TPM2_ALG_SHA1:
		return GNUTLS_MAC_SHA1;
	case TPM2_ALG_SHA256:
		return GNUTLS_MAC_SHA256;
	case TPM2_ALG_SHA384:
		return GNUTLS_MAC_SHA384;
	case TPM2_ALG_SHA512:
		return GNUTLS_MAC_SHA512;
	default:
		return GNUTLS_MAC_UNKNOWN;
	}
}

static TSS2_RC _gnutls_hmac_start(ESYS_CRYPTO_CONTEXT_BLOB **ctx,
				  TPM2_ALG_ID hashAlg, const uint8_t *key,
				  size_t size, void *userdata)
{
	gnutls_mac_algorithm_t gnutls_alg =
		_gnutls_convert_tpm2_mac_alg(hashAlg);
	if (gnutls_alg == GNUTLS_MAC_UNKNOWN)
		return TSS2_ESYS_RC_NOT_IMPLEMENTED;

	gnutls_esys_hmac_blob *blob = gnutls_malloc(sizeof(*blob));
	if (!blob)
		return TSS2_ESYS_RC_MEMORY;

	if (gnutls_hmac_init(&blob->hmac_hd, gnutls_alg, key, size) < 0) {
		gnutls_free(blob);
		return TSS2_ESYS_RC_GENERAL_FAILURE;
	}

	blob->alg = gnutls_alg;
	*ctx = (ESYS_CRYPTO_CONTEXT_BLOB *)blob;
	return TSS2_RC_SUCCESS;
}

static TSS2_RC _gnutls_hmac_update(ESYS_CRYPTO_CONTEXT_BLOB *ctx,
				   const uint8_t *buffer, size_t size,
				   void *userdata)
{
	gnutls_esys_hmac_blob *blob = (gnutls_esys_hmac_blob *)ctx;

	if (gnutls_hmac(blob->hmac_hd, buffer, size) < 0)
		return TSS2_ESYS_RC_GENERAL_FAILURE;

	return TSS2_RC_SUCCESS;
}

static TSS2_RC _gnutls_hmac_finish(ESYS_CRYPTO_CONTEXT_BLOB **ctx,
				   uint8_t *buffer, size_t *size,
				   void *userdata)
{
	gnutls_esys_hmac_blob *blob = (gnutls_esys_hmac_blob *)*ctx;

	size_t mac_size = gnutls_hmac_get_len(blob->alg);
	if (*size < mac_size)
		return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;

	gnutls_hmac_output(blob->hmac_hd, buffer);

	*size = mac_size;

	gnutls_hmac_deinit(blob->hmac_hd, NULL);
	gnutls_free(blob);
	*ctx = NULL;
	return TSS2_RC_SUCCESS;
}

static void _gnutls_hmac_abort(ESYS_CRYPTO_CONTEXT_BLOB **ctx, void *userdata)
{
	if (!ctx || !*ctx)
		return;

	gnutls_esys_hmac_blob *blob = (gnutls_esys_hmac_blob *)*ctx;
	gnutls_hmac_deinit(blob->hmac_hd, NULL);
	gnutls_free(blob);
	*ctx = NULL;
}

void _gnutls_set_tss2_hmac_callbacks(ESYS_CRYPTO_CALLBACKS *callbacks)
{
	callbacks->hmac_start = _gnutls_hmac_start;
	callbacks->hmac_update = _gnutls_hmac_update;
	callbacks->hmac_finish = _gnutls_hmac_finish;
	callbacks->hmac_abort = _gnutls_hmac_abort;
}
