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

int gnutls_insertDataBuffer(ContentType type, GNUTLS_STATE state, char *data, int length);
int gnutls_getDataBufferSize(ContentType type, GNUTLS_STATE state);
int gnutls_getDataFromBuffer(ContentType type, GNUTLS_STATE state, char *data, int length);
ssize_t _gnutls_read_buffered(int fd, GNUTLS_STATE, opaque **iptr, size_t n, ContentType);
void _gnutls_read_clear_buffer( GNUTLS_STATE);
int _gnutls_clear_peeked_data( SOCKET cd, GNUTLS_STATE state);

ssize_t _gnutls_write(int fd, GNUTLS_STATE, const void *iptr, size_t n, int );

/* used in SSL3 */
int gnutls_getHashDataFromBuffer( GNUTLS_STATE state, char *data, int length);
int gnutls_getHashDataBufferSize( GNUTLS_STATE state);
int gnutls_readHashDataFromBuffer( GNUTLS_STATE state, char *data, int length);
int gnutls_insertHashDataBuffer( GNUTLS_STATE state, char *data, int length);
int gnutls_clearHashDataBuffer( GNUTLS_STATE state);

ssize_t _gnutls_handshake_recv_int(int fd, GNUTLS_STATE, ContentType, HandshakeType, void *, size_t);
ssize_t _gnutls_handshake_send_int(int fd, GNUTLS_STATE, ContentType, HandshakeType, void *, size_t);
