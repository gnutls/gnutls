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

typedef enum Optional { OPTIONAL_PACKET, MANDATORY_PACKET } Optional;

int _gnutls_send_handshake(int cd, GNUTLS_STATE state, void* i_data, uint32 i_datasize, HandshakeType type);
int gnutls_send_hello_request(int cd, GNUTLS_STATE state);
int _gnutls_recv_hello_request(int cd, GNUTLS_STATE state, void* data, uint32 data_size);
int _gnutls_send_hello(int cd, GNUTLS_STATE state, int again);
int _gnutls_recv_hello(int cd, GNUTLS_STATE state, char* data, int datalen);
int gnutls_handshake(int cd, GNUTLS_STATE state);
int _gnutls_recv_handshake( int cd, GNUTLS_STATE state, uint8**, int*, HandshakeType, Optional optional);
int _gnutls_generate_session_id( char* session_id, uint8* len);
int gnutls_handshake_common(int cd, GNUTLS_STATE state);
int gnutls_handshake_client(int cd, GNUTLS_STATE state);
int gnutls_handshake_server(int cd, GNUTLS_STATE state);
void _gnutls_set_server_random( GNUTLS_STATE state, uint8* random);
void _gnutls_set_client_random( GNUTLS_STATE state, uint8* random);
int _gnutls_create_random( opaque* dst);
int _gnutls_remove_unwanted_ciphersuites( GNUTLS_STATE state, GNUTLS_CipherSuite ** cipherSuites, int numCipherSuites);
void gnutls_set_max_handshake_data_buffer_size( GNUTLS_STATE state, int max);

#define set_adv_version( state, major, minor) \
	state->gnutls_internals.adv_version_major = data[pos]; \
	state->gnutls_internals.adv_version_minor = data[pos+1]
