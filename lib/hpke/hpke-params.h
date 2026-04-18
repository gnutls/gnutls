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

#ifndef HPKE_PARAMS_HELPER_H
#define HPKE_PARAMS_HELPER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "gnutls/hpke.h"

int _gnutls_is_kem_dh(const gnutls_hpke_kem_t kem);

gnutls_ecc_curve_t _gnutls_hpke_kem_to_curve(const gnutls_hpke_kem_t kem);

gnutls_pk_algorithm_t
_gnutls_hpke_get_kem_associated_pk_algorithm(const gnutls_hpke_kem_t kem);

gnutls_mac_algorithm_t _gnutls_hpke_kdf_to_mac(const gnutls_hpke_kdf_t kdf);

gnutls_mac_algorithm_t _gnutls_hpke_kem_to_mac(const gnutls_hpke_kem_t kem);

gnutls_cipher_algorithm_t
_gnutls_hpke_aead_to_cipher(const gnutls_hpke_aead_t aead);

#endif /* HPKE_PARAMS_HELPER_H */
