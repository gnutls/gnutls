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
	const uint8_t mode, const unsigned char *psk_id_hash,
	const size_t psk_id_hash_len, const unsigned char *info_hash,
	const size_t info_hash_len, unsigned char *key_schedule_context_buf,
	size_t *key_schedule_context_len);

void _gnutls_hpke_build_expand_info(
	const unsigned char *suite_id, const size_t suite_id_size,
	const unsigned char *label, const size_t label_size,
	const unsigned char *context, const size_t context_size, const size_t L,
	unsigned char *expand_info_buf, size_t *expand_info_len);

void _gnutls_hpke_build_labeled_extract_key(const unsigned char *suite_id,
					    const size_t suite_id_size,
					    const unsigned char *label,
					    const size_t label_size,
					    const gnutls_datum_t *ikm,
					    unsigned char *extract_key_buf,
					    size_t *extract_key_len);

void _gnutls_hpke_build_kem_suite_id(const uint16_t kem_id,
				     unsigned char *suite_id);

void _gnutls_hpke_build_ikm_label(const unsigned char *suite_id,
				  const size_t suite_id_size,
				  const unsigned char *dh, const size_t dh_size,
				  unsigned char *ikm_label_buf,
				  size_t *ikm_label_len);

void _gnutls_hpke_build_info_label(
	const unsigned char *receiver_pubkey_raw,
	size_t receiver_pubkey_raw_size, const unsigned char *sender_pubkey_raw,
	size_t sender_pubkey_raw_size,
	const unsigned char *ephemeral_pubkey_raw,
	size_t ephemeral_pubkey_raw_size, const unsigned char *suite_id,
	const size_t suite_id_size, const uint16_t Nsecret,
	unsigned char *info_label_buf, size_t *info_label_len);

void _gnutls_hpke_build_suite_id_for_scheduling(const uint16_t kem_id,
						const uint16_t kdf_id,
						const uint16_t aead_id,
						unsigned char *suite_id);

#endif /* HPKE_BUILDERS_HELPER_H */
