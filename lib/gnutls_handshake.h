/*
 * Copyright (C) 2000,2003 Nikos Mavroyanopoulos
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

int _gnutls_send_handshake( gnutls_session session, void* i_data, uint32 i_datasize, HandshakeType type);
int gnutls_send_hello_request( gnutls_session session);
int _gnutls_recv_hello_request( gnutls_session session, void* data, uint32 data_size);
int _gnutls_send_hello( gnutls_session session, int again);
int _gnutls_recv_hello( gnutls_session session, opaque* data, int datalen);
int gnutls_handshake( gnutls_session session);
int _gnutls_recv_handshake( gnutls_session session, uint8**, int*, HandshakeType, Optional optional);
int _gnutls_generate_session_id( opaque* session_id, uint8* len);
int _gnutls_handshake_common( gnutls_session session);
int _gnutls_handshake_client( gnutls_session session);
int _gnutls_handshake_server( gnutls_session session);
void _gnutls_set_server_random( gnutls_session session, uint8* random);
void _gnutls_set_client_random( gnutls_session session, uint8* random);
int _gnutls_tls_create_random( opaque* dst);
int _gnutls_remove_unwanted_ciphersuites( gnutls_session session, GNUTLS_CipherSuite ** cipherSuites, int numCipherSuites, gnutls_pk_algorithm);
void gnutls_handshake_set_max_packet_length( gnutls_session session, int max);
int _gnutls_find_pk_algos_in_ciphersuites( opaque* data, int datalen);
int _gnutls_server_select_suite(gnutls_session session, opaque *data, int datalen);

#define STATE session->internals.handshake_state
/* This returns true if we have got there
 * before (and not finished due to an interrupt).
 */
#define AGAIN(target) STATE==target?1:0
