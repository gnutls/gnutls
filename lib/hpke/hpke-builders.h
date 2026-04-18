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

#ifndef HPKE_BUILDERS_HELPER_H
#define HPKE_BUILDERS_HELPER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <gnutls/gnutls.h>

#include <stdint.h>

void _gnutls_hpke_build_key_context_for_scheduling(
	const uint8_t mode, const gnutls_datum_t *psk_id_hash,
	const gnutls_datum_t *info_hash, gnutls_datum_t *key_schedule_context);

void _gnutls_hpke_build_expand_info(const gnutls_datum_t *suite_id,
				    const gnutls_datum_t *label,
				    const gnutls_datum_t *context,
				    const size_t L,
				    gnutls_datum_t *expand_info);

void _gnutls_hpke_build_labeled_extract_key(const gnutls_datum_t *suite_id,
					    const gnutls_datum_t *label,
					    const gnutls_datum_t *ikm,
					    gnutls_datum_t *extract_key);

void _gnutls_hpke_build_kem_suite_id(const uint16_t kem_id,
				     unsigned char *suite_id);

void _gnutls_hpke_build_ikm_label(const gnutls_datum_t *suite_id,
				  const gnutls_datum_t *dh,
				  gnutls_datum_t *ikm_label);

void _gnutls_hpke_build_info_label(const gnutls_datum_t *pkR_raw,
				   const gnutls_datum_t *pkS_raw,
				   const gnutls_datum_t *pkE_raw,
				   const gnutls_datum_t *suite_id,
				   const uint16_t Nh,
				   gnutls_datum_t *info_label);

void _gnutls_hpke_build_suite_id_for_scheduling(const uint16_t kem_id,
						const uint16_t kdf_id,
						const uint16_t aead_id,
						unsigned char *suite_id);

#endif /* HPKE_BUILDERS_HELPER_H */
