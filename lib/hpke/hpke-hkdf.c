/*
 * Copyright © 2026 David Dudas
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

#include "hpke-hkdf.h"
#include "hpke-builders.h"

#include "errors.h"

#include <gnutls/crypto.h>

#define HPKE_MAX_EXTRACT_KEY_SIZE 94

int _gnutls_hpke_labeled_extract(const gnutls_mac_algorithm_t mac,
				 const gnutls_datum_t *suite_id,
				 const gnutls_datum_t *salt,
				 const gnutls_datum_t *label,
				 const gnutls_datum_t *ikm, gnutls_datum_t *out)
{
	unsigned char extract_key_buf[HPKE_MAX_EXTRACT_KEY_SIZE] = { 0 };
	gnutls_datum_t extract_key = { extract_key_buf, 0 };

	out->size = gnutls_hmac_get_len(mac);
	if (out->size == 0) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	_gnutls_hpke_build_labeled_extract_key(suite_id, label, ikm,
					       &extract_key);

	int ret = gnutls_hkdf_extract(mac, &extract_key, salt, out->data);
	if (ret < 0) {
		out->size = 0;
		gnutls_assert_val(ret);
	}

	zeroize_key(extract_key.data, extract_key.size);

	return ret;
}
