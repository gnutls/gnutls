/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>

#define CHECK_AUTH(auth, ret) if (gnutls_auth_get_type(state) != auth) { \
	gnutls_assert(); \
	return ret; \
	}

void _gnutls_state_cert_type_set( GNUTLS_STATE state, CertificateType ct) {
	state->security_parameters.cert_type = ct;
}

/**
  * gnutls_cipher_get - Returns the currently used cipher.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used cipher.
  **/
GNUTLS_BulkCipherAlgorithm gnutls_cipher_get( GNUTLS_STATE state) {
	return state->security_parameters.read_bulk_cipher_algorithm;
}

/**
  * gnutls_cert_type_get - Returns the currently used certificate type.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used certificate type. The certificate type
  * is by default X.509, unless it is negotiated as a TLS extension.
  *
  **/
GNUTLS_CertificateType gnutls_cert_type_get( GNUTLS_STATE state) {
	return state->security_parameters.cert_type;
}

/**
  * gnutls_kx_get - Returns the key exchange algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the key exchange algorithm used in the last handshake.
  **/
GNUTLS_KXAlgorithm gnutls_kx_get( GNUTLS_STATE state) {
	return state->security_parameters.kx_algorithm;
}

/**
  * gnutls_mac_get - Returns the currently used mac algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used mac algorithm.
  **/
GNUTLS_MACAlgorithm gnutls_mac_get( GNUTLS_STATE state) {
	return state->security_parameters.read_mac_algorithm;
}

/**
  * gnutls_compression_get - Returns the currently used compression algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used compression method.
  **/
GNUTLS_CompressionMethod gnutls_compression_get( GNUTLS_STATE state) {
	return state->security_parameters.read_compression_algorithm;
}
