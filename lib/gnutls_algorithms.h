/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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

#include "gnutls_auth.h"

/* functions for version */

GNUTLS_Version _gnutls_version_lowest( GNUTLS_STATE state);
GNUTLS_Version _gnutls_version_max( GNUTLS_STATE state);
int _gnutls_version_priority(GNUTLS_STATE state, GNUTLS_Version version);
int _gnutls_version_is_supported(GNUTLS_STATE state, const GNUTLS_Version version);
int _gnutls_version_get_major( GNUTLS_Version ver);
int _gnutls_version_get_minor( GNUTLS_Version ver);
GNUTLS_Version _gnutls_version_get( int major, int minor);

/* functions for macs */
int   _gnutls_mac_get_digest_size(MACAlgorithm algorithm);
const char* gnutls_mac_get_name(MACAlgorithm algorithm);
int   _gnutls_mac_is_ok(MACAlgorithm algorithm);
int   _gnutls_mac_priority(GNUTLS_STATE state, MACAlgorithm algorithm);
int   _gnutls_mac_count(void);

/* functions for cipher suites */
int   _gnutls_supported_ciphersuites(GNUTLS_STATE state, GNUTLS_CipherSuite **ciphers);
int   _gnutls_supported_ciphersuites_sorted(GNUTLS_STATE state, GNUTLS_CipherSuite **ciphers);
int   _gnutls_supported_compression_methods(GNUTLS_STATE state, uint8 **comp);

const char* _gnutls_cipher_suite_get_name(GNUTLS_CipherSuite algorithm);
BulkCipherAlgorithm _gnutls_cipher_suite_get_cipher_algo(const GNUTLS_CipherSuite algorithm);
KXAlgorithm _gnutls_cipher_suite_get_kx_algo(const GNUTLS_CipherSuite algorithm);
MACAlgorithm _gnutls_cipher_suite_get_mac_algo(const GNUTLS_CipherSuite algorithm);
GNUTLS_Version _gnutls_cipher_suite_get_version(const GNUTLS_CipherSuite algorithm);
GNUTLS_CipherSuite  _gnutls_cipher_suite_get_suite_name(GNUTLS_CipherSuite algorithm);

/* functions for ciphers */
int _gnutls_cipher_priority(GNUTLS_STATE state, BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_block_size(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_is_block(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_count(void);
int _gnutls_cipher_is_ok(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_key_size(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_iv_size(BulkCipherAlgorithm algorithm);
const char *gnutls_cipher_get_name(BulkCipherAlgorithm algorithm);

/* functions for key exchange */
int _gnutls_kx_priority(GNUTLS_STATE state, KXAlgorithm algorithm);

MOD_AUTH_STRUCT * _gnutls_kx_auth_struct(KXAlgorithm algorithm);
const char *gnutls_kx_get_name(KXAlgorithm algorithm);
int _gnutls_kx_is_ok(KXAlgorithm algorithm);
int _gnutls_kx_count(void);

/* functions for compression */
int _gnutls_compression_priority(GNUTLS_STATE state, CompressionMethod algorithm);
int _gnutls_compression_is_ok(CompressionMethod algorithm);
int _gnutls_compression_count(void);
int _gnutls_compression_get_num(CompressionMethod algorithm);
CompressionMethod _gnutls_compression_get_id(int num);
const char *gnutls_compression_get_name(CompressionMethod algorithm);

/* Type to KX mappings */
KXAlgorithm _gnutls_map_kx_get_kx(CredType type);
CredType _gnutls_map_kx_get_cred(KXAlgorithm algorithm);
