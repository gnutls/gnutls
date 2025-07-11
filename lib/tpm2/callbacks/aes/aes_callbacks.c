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

#include "aes_callbacks.h"
#include "gnutls_int.h"

#include <tss2/tss2_esys.h>

static const uint8_t tpm2_aes_iv_size = 16;

static gnutls_cipher_algorithm_t
_gnutls_convert_tpm2_cipher_alg(TPMI_AES_KEY_BITS key_bits, TPM2_ALG_ID mode)
{
	if (mode != TPM2_ALG_CFB)
		return GNUTLS_CIPHER_UNKNOWN;

	switch (key_bits) {
	case 128:
		return GNUTLS_CIPHER_AES_128_CFB;
	case 192:
		return GNUTLS_CIPHER_AES_192_CFB;
	case 256:
		return GNUTLS_CIPHER_AES_256_CFB;
	default:
		return GNUTLS_CIPHER_UNKNOWN;
	}
}

static TSS2_RC _gnutls_aes_encrypt(uint8_t *key, TPM2_ALG_ID tpm_sym_alg,
				   TPMI_AES_KEY_BITS key_bits,
				   TPM2_ALG_ID tpm_mode, uint8_t *buffer,
				   size_t buffer_size, uint8_t *iv,
				   void *userdata)
{
	gnutls_cipher_hd_t handle;
	gnutls_cipher_algorithm_t cipher =
		_gnutls_convert_tpm2_cipher_alg(key_bits, tpm_mode);

	if (cipher == GNUTLS_CIPHER_UNKNOWN)
		return TSS2_ESYS_RC_NOT_IMPLEMENTED;

	gnutls_datum_t key_datum = { key, (key_bits + 7) / 8 };
	gnutls_datum_t iv_datum = { iv, tpm2_aes_iv_size };

	if (gnutls_cipher_init(&handle, cipher, &key_datum, &iv_datum) < 0)
		return TSS2_ESYS_RC_GENERAL_FAILURE;

	if (gnutls_cipher_encrypt2(handle, buffer, buffer_size, buffer,
				   buffer_size) < 0) {
		gnutls_cipher_deinit(handle);
		return TSS2_ESYS_RC_GENERAL_FAILURE;
	}

	gnutls_cipher_deinit(handle);
	return TSS2_RC_SUCCESS;
}

static TSS2_RC _gnutls_aes_decrypt(uint8_t *key, TPM2_ALG_ID tpm_sym_alg,
				   TPMI_AES_KEY_BITS key_bits,
				   TPM2_ALG_ID tpm_mode, uint8_t *buffer,
				   size_t buffer_size, uint8_t *iv,
				   void *userdata)
{
	gnutls_cipher_hd_t handle;
	gnutls_cipher_algorithm_t cipher =
		_gnutls_convert_tpm2_cipher_alg(key_bits, tpm_mode);

	if (cipher == GNUTLS_CIPHER_UNKNOWN)
		return TSS2_ESYS_RC_NOT_IMPLEMENTED;

	gnutls_datum_t key_datum = { key, key_bits / 8 };
	gnutls_datum_t iv_datum = { iv, tpm2_aes_iv_size };

	if (gnutls_cipher_init(&handle, cipher, &key_datum, &iv_datum) < 0)
		return TSS2_ESYS_RC_GENERAL_FAILURE;

	if (gnutls_cipher_decrypt2(handle, buffer, buffer_size, buffer,
				   buffer_size) < 0) {
		gnutls_cipher_deinit(handle);
		return TSS2_ESYS_RC_GENERAL_FAILURE;
	}

	gnutls_cipher_deinit(handle);
	return TSS2_RC_SUCCESS;
}

void _gnutls_set_tss2_aes_callbacks(ESYS_CRYPTO_CALLBACKS *callbacks)
{
	callbacks->aes_encrypt = _gnutls_aes_encrypt;
	callbacks->aes_decrypt = _gnutls_aes_decrypt;
}
