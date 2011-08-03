/*
 * Copyright (C) 2000-2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */
#ifndef GNUTLS_BUFFERS_H
#define GNUTLS_BUFFERS_H

#define MBUFFER_FLUSH 1

int
_gnutls_record_buffer_put (gnutls_session_t session,
  content_type_t type, uint64* seq, mbuffer_st* bufel);

inline static int
_gnutls_record_buffer_get_size (content_type_t type, gnutls_session_t session)
{
  return session->internals.record_buffer.byte_length;
}

int _gnutls_record_buffer_get (content_type_t type,
                               gnutls_session_t session, opaque * data,
                               size_t length, opaque seq[8]);
ssize_t _gnutls_io_read_buffered (gnutls_session_t, size_t n, content_type_t);
int _gnutls_io_clear_peeked_data (gnutls_session_t session);

ssize_t _gnutls_io_write_buffered (gnutls_session_t session,
                                   mbuffer_st * bufel, unsigned int mflag);

int _gnutls_handshake_io_cache_int (gnutls_session_t,
                                     gnutls_handshake_description_t,
                                     mbuffer_st * bufel);

ssize_t
_gnutls_handshake_io_recv_int (gnutls_session_t session,
                               gnutls_handshake_description_t htype,
                               handshake_buffer_st * hsk);

ssize_t _gnutls_io_write_flush (gnutls_session_t session);
int
_gnutls_io_check_recv (gnutls_session_t session, unsigned int ms);
ssize_t _gnutls_handshake_io_write_flush (gnutls_session_t session);

inline static void _gnutls_handshake_buffer_clear(handshake_buffer_st* hsk)
{
  _gnutls_buffer_clear(&hsk->data);
  hsk->htype = -1;
}

inline static void _gnutls_handshake_buffer_init(handshake_buffer_st* hsk)
{
  memset(hsk, 0, sizeof(*hsk));
  _gnutls_buffer_init(&hsk->data);
  hsk->htype = -1;
}

inline static void _gnutls_handshake_recv_buffer_clear(gnutls_session_t session)
{
int i;
  for (i=0;i<session->internals.handshake_recv_buffer_size;i++)
    _gnutls_handshake_buffer_clear(&session->internals.handshake_recv_buffer[i]);
  session->internals.handshake_recv_buffer_size = 0;
}

inline static void _gnutls_handshake_recv_buffer_init(gnutls_session_t session)
{
int i;
  for (i=0;i<MAX_HANDSHAKE_MSGS;i++)
    {
      _gnutls_handshake_buffer_init(&session->internals.handshake_recv_buffer[i]);
    }
  session->internals.handshake_recv_buffer_size = 0;
}

ssize_t
_gnutls_recv_in_buffers (gnutls_session_t session, content_type_t type,
                  gnutls_handshake_description_t htype);

#define _gnutls_handshake_io_buffer_clear( session) \
        _mbuffer_head_clear( &session->internals.handshake_send_buffer); \
        _gnutls_handshake_recv_buffer_clear( session);

#endif
