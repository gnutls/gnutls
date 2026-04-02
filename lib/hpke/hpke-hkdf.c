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

int _gnutls_hpke_labeled_extract(
	const gnutls_mac_algorithm_t mac, const unsigned char *suite_id,
	const size_t suite_id_size, const unsigned char *salt,
	const size_t salt_size, const unsigned char *label,
	const size_t label_size, const gnutls_datum_t *ikm,
	unsigned char *hash_out_buf, size_t *hash_out_len)
{
	int ret;
	unsigned char extract_key_buf[HPKE_MAX_EXTRACT_KEY_SIZE] = { 0 };
	size_t extract_key_size = 0;

	size_t hash_size = gnutls_hmac_get_len(mac);
	if (hash_size == 0) {
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	}

	_gnutls_hpke_build_labeled_extract_key(suite_id, suite_id_size, label,
					       label_size, ikm, extract_key_buf,
					       &extract_key_size);

	gnutls_datum_t extract_key = { extract_key_buf, extract_key_size };
	gnutls_datum_t salt_datum = { (unsigned char *)salt, salt_size };
	ret = gnutls_hkdf_extract(mac, &extract_key, &salt_datum, hash_out_buf);
	if (ret < 0) {
		gnutls_assert_val(ret);
	}
	*hash_out_len = hash_size;

	gnutls_memset(extract_key_buf, 0, extract_key_size);

	return ret;
}
