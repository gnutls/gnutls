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

#include "hpke-builders.h"

#include <string.h>

static const unsigned char hpke_v1_label[] = "HPKE-v1";
static const unsigned char eae_prk_label[] = "eae_prk";
static const unsigned char shared_secret_label[] = "shared_secret";

static void _gnutls_hpke_append_buf(unsigned char *dst, size_t *dst_len,
				    const unsigned char *src, size_t src_len)
{
	memcpy(dst + *dst_len, src, src_len);
	*dst_len += src_len;
}

void _gnutls_hpke_build_key_context_for_scheduling(
	const uint8_t mode, const unsigned char *psk_id_hash,
	const size_t psk_id_hash_len, const unsigned char *info_hash,
	const size_t info_hash_len, unsigned char *key_schedule_context_buf,
	size_t *key_schedule_context_len)
{
	*key_schedule_context_len = 0;

	_gnutls_hpke_append_buf(key_schedule_context_buf,
				key_schedule_context_len, &mode, 1);
	_gnutls_hpke_append_buf(key_schedule_context_buf,
				key_schedule_context_len, psk_id_hash,
				psk_id_hash_len);
	_gnutls_hpke_append_buf(key_schedule_context_buf,
				key_schedule_context_len, info_hash,
				info_hash_len);
}

void _gnutls_hpke_build_expand_info(
	const unsigned char *suite_id, const size_t suite_id_size,
	const unsigned char *label, const size_t label_size,
	const unsigned char *context, const size_t context_size, const size_t L,
	unsigned char *expand_info_buf, size_t *expand_info_len)
{
	*expand_info_len = 0;

	unsigned char L_buf[2];
	L_buf[0] = (L >> 8) & 0xff;
	L_buf[1] = L & 0xff;

	_gnutls_hpke_append_buf(expand_info_buf, expand_info_len, L_buf, 2);
	_gnutls_hpke_append_buf(expand_info_buf, expand_info_len, hpke_v1_label,
				sizeof(hpke_v1_label) - 1);
	_gnutls_hpke_append_buf(expand_info_buf, expand_info_len, suite_id,
				suite_id_size);
	_gnutls_hpke_append_buf(expand_info_buf, expand_info_len, label,
				label_size);
	if (context != NULL) {
		_gnutls_hpke_append_buf(expand_info_buf, expand_info_len,
					context, context_size);
	}
}

void _gnutls_hpke_build_labeled_extract_key(const unsigned char *suite_id,
					    const size_t suite_id_size,
					    const unsigned char *label,
					    const size_t label_size,
					    const gnutls_datum_t *ikm,
					    unsigned char *extract_key_buf,
					    size_t *extract_key_len)
{
	*extract_key_len = 0;

	_gnutls_hpke_append_buf(extract_key_buf, extract_key_len, hpke_v1_label,
				sizeof(hpke_v1_label) - 1);
	_gnutls_hpke_append_buf(extract_key_buf, extract_key_len, suite_id,
				suite_id_size);
	_gnutls_hpke_append_buf(extract_key_buf, extract_key_len, label,
				label_size);
	if (ikm != NULL) {
		_gnutls_hpke_append_buf(extract_key_buf, extract_key_len,
					ikm->data, ikm->size);
	}
}

void _gnutls_hpke_build_kem_suite_id(const uint16_t kem_id,
				     unsigned char *suite_id)
{
	suite_id[0] = 'K';
	suite_id[1] = 'E';
	suite_id[2] = 'M';
	suite_id[3] = (kem_id >> 8) & 0xff;
	suite_id[4] = kem_id & 0xff;
}

void _gnutls_hpke_build_ikm_label(const unsigned char *suite_id,
				  const size_t suite_id_size,
				  const unsigned char *dh, const size_t dh_size,
				  unsigned char *ikm_label_buf,
				  size_t *ikm_label_len)
{
	*ikm_label_len = 0;

	_gnutls_hpke_append_buf(ikm_label_buf, ikm_label_len, hpke_v1_label,
				sizeof(hpke_v1_label) - 1);
	_gnutls_hpke_append_buf(ikm_label_buf, ikm_label_len, suite_id,
				suite_id_size);
	_gnutls_hpke_append_buf(ikm_label_buf, ikm_label_len, eae_prk_label,
				sizeof(eae_prk_label) - 1);
	_gnutls_hpke_append_buf(ikm_label_buf, ikm_label_len, dh, dh_size);
}

void _gnutls_hpke_build_info_label(
	const unsigned char *receiver_pubkey_raw,
	size_t receiver_pubkey_raw_size, const unsigned char *sender_pubkey_raw,
	size_t sender_pubkey_raw_size,
	const unsigned char *ephemeral_pubkey_raw,
	size_t ephemeral_pubkey_raw_size, const unsigned char *suite_id,
	const size_t suite_id_size, const uint16_t Nsecret,
	unsigned char *info_label_buf, size_t *info_label_len)
{
	*info_label_len = 0;

	unsigned char Nsecret_buf[2];
	Nsecret_buf[0] = (Nsecret >> 8) & 0xff;
	Nsecret_buf[1] = Nsecret & 0xff;

	_gnutls_hpke_append_buf(info_label_buf, info_label_len, Nsecret_buf, 2);
	_gnutls_hpke_append_buf(info_label_buf, info_label_len, hpke_v1_label,
				sizeof(hpke_v1_label) - 1);
	_gnutls_hpke_append_buf(info_label_buf, info_label_len, suite_id,
				suite_id_size);
	_gnutls_hpke_append_buf(info_label_buf, info_label_len,
				shared_secret_label,
				sizeof(shared_secret_label) - 1);
	_gnutls_hpke_append_buf(info_label_buf, info_label_len,
				ephemeral_pubkey_raw,
				ephemeral_pubkey_raw_size);
	_gnutls_hpke_append_buf(info_label_buf, info_label_len,
				receiver_pubkey_raw, receiver_pubkey_raw_size);
	_gnutls_hpke_append_buf(info_label_buf, info_label_len,
				sender_pubkey_raw, sender_pubkey_raw_size);
}

void _gnutls_hpke_build_suite_id_for_scheduling(const uint16_t kem_id,
						const uint16_t kdf_id,
						const uint16_t aead_id,
						unsigned char *suite_id)
{
	suite_id[0] = 'H';
	suite_id[1] = 'P';
	suite_id[2] = 'K';
	suite_id[3] = 'E';
	suite_id[4] = (kem_id >> 8) & 0xff;
	suite_id[5] = kem_id & 0xff;
	suite_id[6] = (kdf_id >> 8) & 0xff;
	suite_id[7] = kdf_id & 0xff;
	suite_id[8] = (aead_id >> 8) & 0xff;
	suite_id[9] = aead_id & 0xff;
}
