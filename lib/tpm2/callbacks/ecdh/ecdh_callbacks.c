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

#include "gnutls/abstract.h"
#include "gnutls/gnutls.h"
#include "ecdh_callbacks.h"
#include "datum.h"
#include "mem.h"

#include <string.h>
#include <tss2/tss2_esys.h>

static gnutls_ecc_curve_t _gnutls_convert_tpm2_ecc_curve(TPM2_ECC_CURVE curve)
{
	switch (curve) {
	case TPM2_ECC_NIST_P192:
		return GNUTLS_ECC_CURVE_SECP192R1;
	case TPM2_ECC_NIST_P224:
		return GNUTLS_ECC_CURVE_SECP224R1;
	case TPM2_ECC_NIST_P256:
		return GNUTLS_ECC_CURVE_SECP256R1;
	case TPM2_ECC_NIST_P384:
		return GNUTLS_ECC_CURVE_SECP384R1;
	case TPM2_ECC_NIST_P521:
		return GNUTLS_ECC_CURVE_SECP521R1;
	case TPM2_ECC_BN_P256:
	case TPM2_ECC_BN_P638:
	case TPM2_ECC_SM2_P256:
		/* These curves are not supported by GnuTLS */
	default:
		return GNUTLS_ECC_CURVE_INVALID;
	}
}

static TSS2_RC _gnutls_get_ecdh_point(TPM2B_PUBLIC *tpm_key,
				      size_t max_out_size,
				      TPM2B_ECC_PARAMETER *Z, TPMS_ECC_POINT *Q,
				      BYTE *out_buffer, size_t *out_size,
				      void *userdata)
{
	int ret;
	gnutls_privkey_t privkey = NULL;
	gnutls_pubkey_t peerkey = NULL;
	gnutls_datum_t x = { tpm_key->publicArea.unique.ecc.x.buffer,
			     tpm_key->publicArea.unique.ecc.x.size };
	gnutls_datum_t y = { tpm_key->publicArea.unique.ecc.y.buffer,
			     tpm_key->publicArea.unique.ecc.y.size };
	gnutls_datum_t shared = { 0 };
	gnutls_ecc_curve_t curve = _gnutls_convert_tpm2_ecc_curve(
		tpm_key->publicArea.parameters.eccDetail.curveID);

	if (curve == GNUTLS_ECC_CURVE_INVALID)
		return TSS2_ESYS_RC_NOT_IMPLEMENTED;

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0)
		return TSS2_ESYS_RC_GENERAL_FAILURE;

	ret = gnutls_privkey_generate(privkey, GNUTLS_PK_EC,
				      GNUTLS_CURVE_TO_BITS(curve), 0);
	if (ret < 0)
		goto fail;

	ret = gnutls_pubkey_init(&peerkey);
	if (ret < 0)
		goto fail;

	ret = gnutls_pubkey_import_ecc_raw(peerkey, curve, &x, &y);
	if (ret < 0)
		goto fail;

	ret = gnutls_privkey_derive_secret(privkey, peerkey, 0, &shared, 0);
	if (ret < 0)
		goto fail;

	if (shared.size > sizeof(Z->buffer)) {
		ret = TSS2_ESYS_RC_INSUFFICIENT_BUFFER;
		goto fail;
	}
	memcpy(Z->buffer, shared.data, shared.size);
	Z->size = shared.size;

	gnutls_datum_t qx, qy;
	gnutls_privkey_export_ecc_raw(privkey, NULL, &qx, &qy, NULL);
	memcpy(Q->x.buffer, qx.data, qx.size);
	Q->x.size = qx.size;
	memcpy(Q->y.buffer, qy.data, qy.size);
	Q->y.size = qy.size;

	if (out_buffer && out_size) {
		size_t total = qx.size + qy.size;
		if (total > max_out_size) {
			ret = TSS2_ESYS_RC_INSUFFICIENT_BUFFER;
			goto fail;
		}
		memcpy(out_buffer, qx.data, qx.size);
		memcpy(out_buffer + qx.size, qy.data, qy.size);
		*out_size = total;
	}

	ret = TSS2_RC_SUCCESS;

fail:
	_gnutls_free_key_datum(&shared);
	if (peerkey)
		gnutls_pubkey_deinit(peerkey);
	if (privkey)
		gnutls_privkey_deinit(privkey);
	return ret;
}

void _gnutls_set_tss2_ecdh_callbacks(ESYS_CRYPTO_CALLBACKS *callbacks)
{
	callbacks->get_ecdh_point = _gnutls_get_ecdh_point;
}
