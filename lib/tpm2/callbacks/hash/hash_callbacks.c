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

#include "gnutls/crypto.h"
#include "hash_callbacks.h"

#include <tss2/tss2_esys.h>

typedef struct {
	gnutls_hash_hd_t hash_hd;
	gnutls_digest_algorithm_t alg;
} gnutls_esys_hash_blob;

static gnutls_digest_algorithm_t
_gnutls_convert_tpm2_digest_alg(TPM2_ALG_ID alg)
{
	switch (alg) {
	case TPM2_ALG_SHA1:
		return GNUTLS_DIG_SHA1;
	case TPM2_ALG_SHA256:
		return GNUTLS_DIG_SHA256;
	case TPM2_ALG_SHA384:
		return GNUTLS_DIG_SHA384;
	case TPM2_ALG_SHA512:
		return GNUTLS_DIG_SHA512;
	default:
		return GNUTLS_DIG_UNKNOWN;
	}
}

static TSS2_RC _gnutls_hash_start(ESYS_CRYPTO_CONTEXT_BLOB **ctx,
				  TPM2_ALG_ID hashAlg, void *userdata)
{
	gnutls_digest_algorithm_t gnutls_alg =
		_gnutls_convert_tpm2_digest_alg(hashAlg);
	if (gnutls_alg == GNUTLS_DIG_UNKNOWN)
		return TSS2_ESYS_RC_NOT_IMPLEMENTED;

	gnutls_esys_hash_blob *blob = gnutls_malloc(sizeof(*blob));
	if (!blob)
		return TSS2_ESYS_RC_MEMORY;

	if (gnutls_hash_init(&blob->hash_hd, gnutls_alg) < 0) {
		gnutls_free(blob);
		return TSS2_ESYS_RC_GENERAL_FAILURE;
	}

	blob->alg = gnutls_alg;
	*ctx = (ESYS_CRYPTO_CONTEXT_BLOB *)blob;
	return TSS2_RC_SUCCESS;
}

static TSS2_RC _gnutls_hash_update(ESYS_CRYPTO_CONTEXT_BLOB *ctx,
				   const uint8_t *buffer, size_t size,
				   void *userdata)
{
	gnutls_esys_hash_blob *blob = (gnutls_esys_hash_blob *)ctx;
	if (gnutls_hash(blob->hash_hd, buffer, size) < 0)
		return TSS2_ESYS_RC_GENERAL_FAILURE;

	return TSS2_RC_SUCCESS;
}

static TSS2_RC _gnutls_hash_finish(ESYS_CRYPTO_CONTEXT_BLOB **ctx,
				   uint8_t *buffer, size_t *size,
				   void *userdata)
{
	gnutls_esys_hash_blob *blob = (gnutls_esys_hash_blob *)*ctx;

	size_t hash_size = gnutls_hash_get_len(blob->alg);
	if (*size < hash_size)
		return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;

	gnutls_hash_output(blob->hash_hd, buffer);

	*size = hash_size;

	gnutls_hash_deinit(blob->hash_hd, NULL);
	gnutls_free(blob);
	*ctx = NULL;
	return TSS2_RC_SUCCESS;
}

static void _gnutls_hash_abort(ESYS_CRYPTO_CONTEXT_BLOB **ctx, void *userdata)
{
	if (!ctx || !*ctx)
		return;

	gnutls_esys_hash_blob *blob = (gnutls_esys_hash_blob *)*ctx;
	gnutls_hash_deinit(blob->hash_hd, NULL);
	gnutls_free(blob);
	*ctx = NULL;
}

void _gnutls_set_tss2_hash_callbacks(ESYS_CRYPTO_CALLBACKS *callbacks)
{
	callbacks->hash_start = _gnutls_hash_start;
	callbacks->hash_update = _gnutls_hash_update;
	callbacks->hash_finish = _gnutls_hash_finish;
	callbacks->hash_abort = _gnutls_hash_abort;
}
