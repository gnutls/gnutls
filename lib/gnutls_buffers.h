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

int _gnutls_record_buffer_put(ContentType type, GNUTLS_STATE state, char *data, int length);
int _gnutls_record_buffer_get_size(ContentType type, GNUTLS_STATE state);
int _gnutls_record_buffer_get(ContentType type, GNUTLS_STATE state, char *data, int length);
ssize_t _gnutls_io_read_buffered( GNUTLS_STATE, opaque **iptr, size_t n, ContentType);
void _gnutls_io_clear_read_buffer( GNUTLS_STATE);
int _gnutls_io_clear_peeked_data( GNUTLS_STATE state);

ssize_t _gnutls_io_write_buffered( GNUTLS_STATE, const void *iptr, size_t n );

int _gnutls_handshake_buffer_get( GNUTLS_STATE state, char *data, int length);
int _gnutls_handshake_buffer_get_size( GNUTLS_STATE state);
int _gnutls_handshake_buffer_peek( GNUTLS_STATE state, char *data, int length);
int _gnutls_handshake_buffer_put( GNUTLS_STATE state, char *data, int length);
int _gnutls_handshake_buffer_clear( GNUTLS_STATE state);

#define _gnutls_handshake_io_buffer_clear( state) \
        gnutls_free( state->gnutls_internals.handshake_send_buffer.data); \
        gnutls_free( state->gnutls_internals.handshake_recv_buffer.data); \
        state->gnutls_internals.handshake_send_buffer.data = NULL; \
        state->gnutls_internals.handshake_recv_buffer.data = NULL; \
        state->gnutls_internals.handshake_send_buffer.size = 0; \
        state->gnutls_internals.handshake_recv_buffer.size = 0; \
        state->gnutls_internals.handshake_send_buffer_prev_size = 0

ssize_t _gnutls_handshake_io_recv_int( GNUTLS_STATE, ContentType, HandshakeType, void *, size_t);
ssize_t _gnutls_handshake_io_send_int( GNUTLS_STATE, ContentType, HandshakeType, const void *, size_t);
ssize_t _gnutls_io_write_flush( GNUTLS_STATE state);
ssize_t _gnutls_handshake_io_write_flush( GNUTLS_STATE state);

size_t gnutls_record_check_pending(GNUTLS_STATE state);
