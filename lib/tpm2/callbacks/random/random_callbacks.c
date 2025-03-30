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

#include "random_callbacks.h"
#include "gnutls/crypto.h"

#include <tss2/tss2_esys.h>

static TSS2_RC _gnutls_get_random2b(TPM2B_NONCE *nonce, size_t num_bytes,
				    void *userdata)
{
	if (num_bytes > sizeof(nonce->buffer))
		return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;

	if (gnutls_rnd(GNUTLS_RND_RANDOM, nonce->buffer, num_bytes) < 0)
		return TSS2_ESYS_RC_GENERAL_FAILURE;

	nonce->size = num_bytes;
	return TSS2_RC_SUCCESS;
}

void _gnutls_set_tss2_random_callbacks(ESYS_CRYPTO_CALLBACKS *callbacks)
{
	callbacks->get_random2b = _gnutls_get_random2b;
}
