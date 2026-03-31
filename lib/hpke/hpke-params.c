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

#include "hpke-params.h"

int _gnutls_is_kem_dh(const gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
	case GNUTLS_HPKE_KEM_DHKEM_P384:
	case GNUTLS_HPKE_KEM_DHKEM_P521:
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return 1;
	default:
		return 0;
	}
}

gnutls_ecc_curve_t _gnutls_hpke_kem_to_curve(const gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
		return GNUTLS_ECC_CURVE_SECP256R1;
	case GNUTLS_HPKE_KEM_DHKEM_P384:
		return GNUTLS_ECC_CURVE_SECP384R1;
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		return GNUTLS_ECC_CURVE_SECP521R1;
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		return GNUTLS_ECC_CURVE_X25519;
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return GNUTLS_ECC_CURVE_X448;
	default:
		return GNUTLS_ECC_CURVE_INVALID;
	}
}

gnutls_pk_algorithm_t
_gnutls_hpke_get_kem_associated_pk_algorithm(const gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
	case GNUTLS_HPKE_KEM_DHKEM_P384:
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		return GNUTLS_PK_EC;
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		return GNUTLS_PK_ECDH_X25519;
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return GNUTLS_PK_ECDH_X448;
	default:
		return GNUTLS_PK_UNKNOWN;
	}
}

gnutls_mac_algorithm_t _gnutls_hpke_kdf_to_mac(const gnutls_hpke_kdf_t kdf)
{
	switch (kdf) {
	case GNUTLS_HPKE_KDF_HKDF_SHA256:
		return GNUTLS_MAC_SHA256;
	case GNUTLS_HPKE_KDF_HKDF_SHA384:
		return GNUTLS_MAC_SHA384;
	case GNUTLS_HPKE_KDF_HKDF_SHA512:
		return GNUTLS_MAC_SHA512;
	default:
		return GNUTLS_MAC_UNKNOWN;
	}
}

gnutls_mac_algorithm_t _gnutls_hpke_kem_to_mac(const gnutls_hpke_kem_t kem)
{
	switch (kem) {
	case GNUTLS_HPKE_KEM_DHKEM_P256:
		return GNUTLS_MAC_SHA256;
	case GNUTLS_HPKE_KEM_DHKEM_P384:
		return GNUTLS_MAC_SHA384;
	case GNUTLS_HPKE_KEM_DHKEM_P521:
		return GNUTLS_MAC_SHA512;
	case GNUTLS_HPKE_KEM_DHKEM_X25519:
		return GNUTLS_MAC_SHA256;
	case GNUTLS_HPKE_KEM_DHKEM_X448:
		return GNUTLS_MAC_SHA512;
	default:
		return GNUTLS_MAC_UNKNOWN;
	}
}

gnutls_cipher_algorithm_t
_gnutls_hpke_aead_to_cipher(const gnutls_hpke_aead_t aead)
{
	switch (aead) {
	case GNUTLS_HPKE_AEAD_AES_128_GCM:
		return GNUTLS_CIPHER_AES_128_GCM;
	case GNUTLS_HPKE_AEAD_AES_256_GCM:
		return GNUTLS_CIPHER_AES_256_GCM;
	case GNUTLS_HPKE_AEAD_CHACHA20_POLY1305:
		return GNUTLS_CIPHER_CHACHA20_POLY1305;
	default:
		return GNUTLS_CIPHER_UNKNOWN;
	}
}
