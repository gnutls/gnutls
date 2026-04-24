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
#include "../num.h"

#include <string.h>

static const unsigned char hpke_v1_label[] = "HPKE-v1";
static const unsigned char eae_prk_label[] = "eae_prk";
static const unsigned char shared_secret_label[] = "shared_secret";

static void append_datum(gnutls_datum_t *dst, const gnutls_datum_t *src)
{
	memcpy(dst->data + dst->size, src->data, src->size);
	dst->size += src->size;
}

static void append_bytes(gnutls_datum_t *dst, const unsigned char *src,
			 const size_t src_size)
{
	memcpy(dst->data + dst->size, src, src_size);
	dst->size += src_size;
}

void _gnutls_hpke_build_key_context_for_scheduling(
	const uint8_t mode, const gnutls_datum_t *psk_id_hash,
	const gnutls_datum_t *info_hash, gnutls_datum_t *key_schedule_context)

{
	key_schedule_context->size = 0;

	append_bytes(key_schedule_context, &mode, 1);
	append_datum(key_schedule_context, psk_id_hash);
	append_datum(key_schedule_context, info_hash);
}

void _gnutls_hpke_build_expand_info(const gnutls_datum_t *suite_id,
				    const gnutls_datum_t *label,
				    const gnutls_datum_t *context,
				    const size_t L, gnutls_datum_t *expand_info)
{
	expand_info->size = 0;

	unsigned char L_buf[2];
	L_buf[0] = (L >> 8) & 0xff;
	L_buf[1] = L & 0xff;

	append_bytes(expand_info, L_buf, 2);
	append_bytes(expand_info, hpke_v1_label, sizeof(hpke_v1_label) - 1);
	append_datum(expand_info, suite_id);
	append_datum(expand_info, label);

	if (context != NULL) {
		append_datum(expand_info, context);
	}
}

void _gnutls_hpke_build_labeled_extract_key(const gnutls_datum_t *suite_id,
					    const gnutls_datum_t *label,
					    const gnutls_datum_t *ikm,
					    gnutls_datum_t *extract_key)
{
	extract_key->size = 0;

	append_bytes(extract_key, hpke_v1_label, sizeof(hpke_v1_label) - 1);
	append_datum(extract_key, suite_id);
	append_datum(extract_key, label);

	if (ikm != NULL) {
		append_datum(extract_key, ikm);
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

void _gnutls_hpke_build_ikm_label(const gnutls_datum_t *suite_id,
				  const gnutls_datum_t *dh,
				  gnutls_datum_t *ikm_label)
{
	ikm_label->size = 0;

	append_bytes(ikm_label, hpke_v1_label, sizeof(hpke_v1_label) - 1);
	append_datum(ikm_label, suite_id);
	append_bytes(ikm_label, eae_prk_label, sizeof(eae_prk_label) - 1);
	append_datum(ikm_label, dh);
}

void _gnutls_hpke_build_info_label(const gnutls_datum_t *pkR_raw,
				   const gnutls_datum_t *pkS_raw,
				   const gnutls_datum_t *pkE_raw,
				   const gnutls_datum_t *suite_id,
				   const uint16_t Nh,
				   gnutls_datum_t *info_label)
{
	info_label->size = 0;

	unsigned char Nh_buf[2];
	Nh_buf[0] = (Nh >> 8) & 0xff;
	Nh_buf[1] = Nh & 0xff;

	append_bytes(info_label, Nh_buf, 2);
	append_bytes(info_label, hpke_v1_label, sizeof(hpke_v1_label) - 1);
	append_datum(info_label, suite_id);
	append_bytes(info_label, shared_secret_label,
		     sizeof(shared_secret_label) - 1);
	append_datum(info_label, pkE_raw);
	append_datum(info_label, pkR_raw);
	append_datum(info_label, pkS_raw);
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
	_gnutls_write_uint16(kem_id, &suite_id[4]);
	_gnutls_write_uint16(kdf_id, &suite_id[6]);
	_gnutls_write_uint16(aead_id, &suite_id[8]);
}
