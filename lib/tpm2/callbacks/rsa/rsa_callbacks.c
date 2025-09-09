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

#include "rsa_callbacks.h"
#include "gnutls/abstract.h"
#include "gnutls/gnutls.h"
#include "mem.h"

#include <string.h>
#include <tss2/tss2_esys.h>

static TSS2_RC _gnutls_rsa_pk_encrypt(TPM2B_PUBLIC *pub_tpm_key, size_t in_size,
				      BYTE *in_buffer, size_t max_out_size,
				      BYTE *out_buffer, size_t *out_size,
				      const char *label, void *userdata)
{
	gnutls_pubkey_t pubkey;
	gnutls_datum_t modulus = {
		.data = pub_tpm_key->publicArea.unique.rsa.buffer,
		.size = pub_tpm_key->publicArea.unique.rsa.size,
	};

	gnutls_datum_t exponent = { NULL, 0 };

	int ret;

	if (pub_tpm_key->publicArea.parameters.rsaDetail.exponent != 0) {
		uint32_t exp =
			pub_tpm_key->publicArea.parameters.rsaDetail.exponent;

		size_t exp_size = 0;
		if (exp < 256) {
			exp_size = 1;
		} else if (exp < 65536) {
			exp_size = 2;
		} else {
			exp_size = 3;
		}

		exponent.size = exp_size;
		exponent.data = gnutls_malloc(exp_size);
		if (!exponent.data)
			return TSS2_ESYS_RC_GENERAL_FAILURE;

		for (size_t i = 0; i < exp_size; i++) {
			exponent.data[exp_size - 1 - i] = (exp >> (8 * i)) &
							  0xFF;
		}
	} else {
		static uint8_t default_exp[] = { 0x01, 0x00, 0x01 };
		exponent.data = default_exp;
		exponent.size = sizeof(default_exp);
	}

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0)
		return TSS2_ESYS_RC_GENERAL_FAILURE;

	ret = gnutls_pubkey_import_rsa_raw(pubkey, &modulus, &exponent);
	if (ret < 0) {
		gnutls_pubkey_deinit(pubkey);
		return TSS2_ESYS_RC_GENERAL_FAILURE;
	}

	gnutls_datum_t input = { .data = in_buffer, .size = in_size };
	gnutls_datum_t output = { 0 };

	ret = gnutls_pubkey_encrypt_data(pubkey, 0, &input, &output);
	gnutls_pubkey_deinit(pubkey);

	if (ret < 0)
		return TSS2_ESYS_RC_GENERAL_FAILURE;

	if (output.size > max_out_size) {
		zeroize_key(output.data, output.size);
		return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;
	}

	memcpy(out_buffer, output.data, output.size);
	*out_size = output.size;

	zeroize_key(output.data, output.size);
	return TSS2_RC_SUCCESS;
}

void _gnutls_set_tss2_rsa_callbacks(ESYS_CRYPTO_CALLBACKS *callbacks)
{
	callbacks->rsa_pk_encrypt = _gnutls_rsa_pk_encrypt;
}
