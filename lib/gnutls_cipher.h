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

int _gnutls_encrypt( GNUTLS_STATE state, const char* data, size_t data_size, uint8** ciphertext, ContentType type);
int _gnutls_decrypt(GNUTLS_STATE state, char *ciphertext,
		    size_t ciphertext_size, uint8 ** data,
		    ContentType type);
int _gnutls_TLSCompressed2TLSCiphertext(GNUTLS_STATE state,
						      GNUTLSCiphertext**
						      cipher,
						      GNUTLSCompressed *
						      compressed);
int _gnutls_freeTLSCiphertext(GNUTLSCiphertext * ciphertext);
int _gnutls_set_cipher( GNUTLS_STATE state, BulkCipherAlgorithm algo);
int _gnutls_set_mac( GNUTLS_STATE state, MACAlgorithm algo);
int _gnutls_set_compression( GNUTLS_STATE state, CompressionMethod algo);
int _gnutls_connection_state_init(GNUTLS_STATE state);
int _gnutls_TLSCiphertext2TLSCompressed(GNUTLS_STATE state,
						      GNUTLSCompressed**
						      compress,
						      GNUTLSCiphertext *
						      ciphertext);
