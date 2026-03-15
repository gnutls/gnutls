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

#ifndef HPKE_HKDF_HELPER_H
#define HPKE_HKDF_HELPER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <gnutls/gnutls.h>

int _gnutls_hpke_labeled_extract(
	const gnutls_mac_algorithm_t mac, const unsigned char *suite_id,
	const size_t suite_id_size, const unsigned char *salt,
	const size_t salt_size, const unsigned char *label,
	const size_t label_size, const gnutls_datum_t *ikm,
	unsigned char *hash_out_buf, size_t *hash_out_len);

#endif /* HPKE_HKDF_HELPER_H */
