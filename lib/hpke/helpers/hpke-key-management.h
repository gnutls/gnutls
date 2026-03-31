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

#ifndef HPKE_KEY_MANAGEMENT_HELPER_H
#define HPKE_KEY_MANAGEMENT_HELPER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <gnutls/hpke.h>

#define GNUTLS_HPKE_MAX_DHKEM_PUBKEY_SIZE 133
#define GNUTLS_HPKE_MAX_HASH_SIZE 64
#define GNUTLS_HPKE_SUITE_ID_SIZE 5
#define GNUTLS_HPKE_MAX_LABELED_EXPAND_INFO_SIZE 158

int _gnutls_hpke_pubkey_to_datum(const gnutls_pubkey_t pk,
				 unsigned char *pubkey_raw,
				 size_t *pubkey_raw_size);

int _gnutls_hpke_datum_to_pubkey(const gnutls_ecc_curve_t curve,
				 const gnutls_datum_t *datum,
				 gnutls_pubkey_t *pk);

int _gnutls_hpke_keypair_from_ikm(const gnutls_hpke_kem_t kem,
				  const gnutls_datum_t *ikme,
				  gnutls_privkey_t *privkey,
				  gnutls_pubkey_t *pubkey);

int _gnutls_hpke_generate_keypair(const gnutls_datum_t *ikme,
				  const gnutls_hpke_kem_t kem,
				  const gnutls_pubkey_t receiver_pubkey,
				  gnutls_privkey_t *ephemeral_privkey,
				  gnutls_pubkey_t *ephemeral_pubkey);

int _gnutls_hpke_privkey_clone(gnutls_privkey_t src, gnutls_privkey_t *dst);

int _gnutls_hpke_pubkey_clone(gnutls_pubkey_t src, gnutls_pubkey_t *dst);

#endif /* HPKE_KEY_MANAGEMENT_HELPER_H */
