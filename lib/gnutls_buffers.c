/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
 * 2009, 2010 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* This is the only file that uses the berkeley sockets API.
 * 
 * Also holds all the buffering code used in gnutls.
 * The buffering code works as:
 *
 * RECORD LAYER: 
 *  1. uses a buffer to hold data (application/handshake),
 *    we got but they were not requested, yet.
 *  (see gnutls_record_buffer_put(), gnutls_record_buffer_get_size() etc.)
 *
 *  2. uses a buffer to hold data that were incomplete (ie the read/write
 *    was interrupted)
 *  (see _gnutls_io_read_buffered(), _gnutls_io_write_buffered() etc.)
 * 
 * HANDSHAKE LAYER:
 *  1. Uses a buffer to hold data that was not sent or received
 *  complete. (E.g. sent 10 bytes of a handshake packet that is 20 bytes
 *  long).
 * (see _gnutls_handshake_send_int(), _gnutls_handshake_recv_int())
 *
 *  2. Uses buffer to hold the last received handshake message.
 *  (see _gnutls_handshake_buffer_put() etc.)
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>
#include <gnutls_record.h>
#include <gnutls_buffers.h>
#include <gnutls_mbuffers.h>
#include <gnutls_state.h>
#include <gnutls_dtls.h>
#include <system.h>
#include <gnutls_constate.h> /* gnutls_epoch_get */
#include <errno.h>

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

/* this is the maximum number of messages allowed to queue.
 */
#define MAX_QUEUE 16

/* Buffers received packets of type APPLICATION DATA and
 * HANDSHAKE DATA.
 */
int
_gnutls_record_buffer_put (gnutls_session_t session,
  content_type_t type, uint64* seq, mbuffer_st* bufel)
{

  bufel->type = type;
  memcpy(&bufel->record_sequence, seq, sizeof(*seq));

  switch (type)
    {
    case GNUTLS_APPLICATION_DATA:
      _mbuffer_enqueue(&session->internals.application_data_buffer, bufel);
      _gnutls_buffers_log ("BUF[REC]: Inserted %d bytes of Data(%d)\n",
                           (int) bufel->msg.size, (int) type);
      break;

    case GNUTLS_HANDSHAKE:
      _mbuffer_enqueue(&session->internals.handshake_data_buffer, bufel);
      _gnutls_buffers_log ("BUF[HSK]: Inserted %d bytes of Data(%d)\n",
                           (int) bufel->msg.size, (int) type);
      break;

    default:
      return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
    }

  return 0;
}

int
_gnutls_record_buffer_get_size (content_type_t type, gnutls_session_t session)
{
  switch (type)
    {
    case GNUTLS_APPLICATION_DATA:
      return session->internals.application_data_buffer.byte_length;

    case GNUTLS_HANDSHAKE:
      return session->internals.handshake_data_buffer.byte_length;

    default:
      return GNUTLS_E_INVALID_REQUEST;
    }
}

/**
 * gnutls_record_check_pending:
 * @session: is a #gnutls_session_t structure.
 *
 * This function checks if there are any data to receive in the gnutls
 * buffers.
 *
 * Note that you could also use select() to check for data in a TCP
 * connection, instead of this function.  GnuTLS leaves some data in
 * the tcp buffer in order for select to work. However the select() 
 * alternative is not recommended and will be deprecated in later
 * GnuTLS revisions.
 *
 * Returns: the size of that data or 0.
 **/
size_t
gnutls_record_check_pending (gnutls_session_t session)
{
  return _gnutls_record_buffer_get_size (GNUTLS_APPLICATION_DATA, session);
}

int
_gnutls_record_buffer_get (content_type_t type,
                           gnutls_session_t session, opaque * data,
                           size_t length, opaque seq[8])
{
gnutls_datum_t msg;
mbuffer_head_st* head;
mbuffer_st* bufel;

  if (length == 0 || data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  switch (type)
    {
    case GNUTLS_APPLICATION_DATA:
      head = &session->internals.application_data_buffer;
      break;

    case GNUTLS_HANDSHAKE:
      head = &session->internals.handshake_data_buffer;
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  bufel = _mbuffer_get_first(head, &msg);
  if (bufel == NULL)
    return gnutls_assert_val(GNUTLS_E_AGAIN);

  if (msg.size <= length)
    length = msg.size;

  if (seq)
    memcpy(seq, bufel->record_sequence.i, 8);

  memcpy(data, msg.data, length);
  _mbuffer_remove_bytes(head, length);
  
  return length;
}

inline static void
reset_errno (gnutls_session_t session)
{
  session->internals.errnum = 0;
}

inline static int
get_errno (gnutls_session_t session)
{
  if (session->internals.errnum != 0)
    return session->internals.errnum;
  else
    return session->internals.errno_func (session->
                                          internals.transport_recv_ptr);
}


static ssize_t
_gnutls_dgram_read (gnutls_session_t session, mbuffer_st **bufel,
		    gnutls_pull_func pull_func)
{
  ssize_t i, ret;
  char *ptr;
  size_t max_size = _gnutls_get_max_decrypted_data(session);
  size_t recv_size = MAX_RECV_SIZE(session);
  gnutls_transport_ptr_t fd = session->internals.transport_recv_ptr;

  if (recv_size > max_size)
    return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

  *bufel = _mbuffer_alloc (0, _gnutls_get_max_decrypted_data(session));
  if (*bufel == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

  ptr = (*bufel)->msg.data;

  session->internals.direction = 0;

  reset_errno (session);

  i = pull_func (fd, ptr, recv_size);

  if (i < 0)
    {
      int err = get_errno (session);

      _gnutls_read_log ("READ: %d returned from %p, errno=%d gerrno=%d\n",
			(int) i, fd, errno, session->internals.errnum);

      if (err == EAGAIN)
        {
          ret = GNUTLS_E_AGAIN;
          goto cleanup;
        }
      else if (err == EINTR)
        {
          ret = GNUTLS_E_INTERRUPTED;
          goto cleanup;
        }
      else
        {
          gnutls_assert ();
          ret = GNUTLS_E_PULL_ERROR;
          goto cleanup;
        }
    }
  else
    {
      _gnutls_read_log ("READ: Got %d bytes from %p\n", (int) i, fd);
      if (i == 0) 
        {
          /* If we get here, we likely have a stream socket.
           * FIXME: this probably breaks DCCP. */
          gnutls_assert ();
          ret = GNUTLS_E_INTERNAL_ERROR;
          goto cleanup;
        }

      _mbuffer_set_udata_size (*bufel, i);
    }

  _gnutls_read_log ("READ: read %d bytes from %p\n", (int) i, fd);
  
  return i;
  
cleanup:
  _mbuffer_xfree(bufel);
  return ret;
}

static ssize_t
_gnutls_stream_read (gnutls_session_t session, mbuffer_st **bufel,
		     size_t size, gnutls_pull_func pull_func)
{
  size_t left;
  ssize_t i = 0;
  size_t max_size = _gnutls_get_max_decrypted_data(session);
  char *ptr;
  gnutls_transport_ptr_t fd = session->internals.transport_recv_ptr;

  *bufel = _mbuffer_alloc (0, GMAX(max_size, size));
  if (!*bufel)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  ptr = (*bufel)->msg.data;

  session->internals.direction = 0;

  left = size;
  while (left > 0)
    {
      reset_errno (session);

      i = pull_func (fd, &ptr[size - left], left);

      if (i < 0)
        {
          int err = get_errno (session);

          _gnutls_read_log ("READ: %d returned from %p, errno=%d gerrno=%d\n",
                            (int) i, fd, errno, session->internals.errnum);

          if (err == EAGAIN || err == EINTR)
            {
              if (size - left > 0)
                {

                  _gnutls_read_log ("READ: returning %d bytes from %p\n",
                                    (int) (size - left), fd);

                  goto finish;
                }

              if (err == EAGAIN)
                return GNUTLS_E_AGAIN;
              return GNUTLS_E_INTERRUPTED;
            }
          else
            {
              gnutls_assert ();
              return GNUTLS_E_PULL_ERROR;
            }
        }
      else
        {

          _gnutls_read_log ("READ: Got %d bytes from %p\n", (int) i, fd);

          if (i == 0)
            break;              /* EOF */
        }

      left -= i;
      (*bufel)->msg.size += i;
    }

finish:

  _gnutls_read_log ("READ: read %d bytes from %p\n",
                        (int) (size - left), fd);

  return (size - left);
}


/* This function is like read. But it does not return -1 on error.
 * It does return gnutls_errno instead.
 *
 * Flags are only used if the default recv() function is being used.
 */
static ssize_t
_gnutls_read (gnutls_session_t session, mbuffer_st **bufel,
	      size_t size, gnutls_pull_func pull_func)
{
  if (_gnutls_is_dtls (session))
    /* Size is not passed, since a whole datagram will be read. */
    return _gnutls_dgram_read (session, bufel, pull_func);
  else
    return _gnutls_stream_read (session, bufel, size, pull_func);
}

static ssize_t
_gnutls_writev_emu (gnutls_session_t session, const giovec_t * giovec,
                    int giovec_cnt)
{
  int ret, j = 0;
  gnutls_transport_ptr_t fd = session->internals.transport_send_ptr;
  size_t total = 0;

  for (j = 0; j < giovec_cnt; j++)
    {
      ret = session->internals.push_func (fd, giovec[j].iov_base, giovec[j].iov_len);

      if (ret == -1)
        break;

      total += ret;
    }

  if (total > 0)
    return total;

  return ret;
}

static ssize_t
_gnutls_writev (gnutls_session_t session, const giovec_t * giovec,
                int giovec_cnt)
{
  int i;
  gnutls_transport_ptr_t fd = session->internals.transport_send_ptr;

  reset_errno (session);

  if (session->internals.push_func != NULL)
    i = _gnutls_writev_emu (session, giovec, giovec_cnt);
  else
    i = session->internals.vec_push_func (fd, giovec, giovec_cnt);

  if (i == -1)
    {
      int err = get_errno (session);
      _gnutls_debug_log ("errno: %d\n", err);
      if (err == EAGAIN)
        return GNUTLS_E_AGAIN;
      else if (err == EINTR)
        return GNUTLS_E_INTERRUPTED;
      else
        {
          gnutls_assert ();
          return GNUTLS_E_PUSH_ERROR;
        }
    }
  return i;
}

#define RCVLOWAT session->internals.lowat

/* This function is only used with berkeley style sockets.
 * Clears the peeked data (read with MSG_PEEK).
 */
int
_gnutls_io_clear_peeked_data (gnutls_session_t session)
{
  mbuffer_st *peekdata;
  int ret, sum;

  if (session->internals.have_peeked_data == 0 || RCVLOWAT == 0)
    return 0;

  /* this was already read by using MSG_PEEK - so it shouldn't fail */
  sum = 0;
  do
    {                           /* we need this to finish now */
      ret =
        _gnutls_read (session, &peekdata, RCVLOWAT - sum,
                      session->internals.pull_func);
      if (ret > 0)
        sum += ret;
      _mbuffer_xfree (&peekdata);
    }
  while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN
         || sum < RCVLOWAT);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  session->internals.have_peeked_data = 0;

  return 0;
}

/* This function is like recv(with MSG_PEEK). But it does not return -1 on error.
 * It does return gnutls_errno instead.
 * This function reads data from the socket and keeps them in a buffer, of up to
 * MAX_RECV_SIZE. 
 *
 * This is not a general purpose function. It returns EXACTLY the data requested,
 * which are stored in a local (in the session) buffer.
 *
 */
ssize_t
_gnutls_io_read_buffered (gnutls_session_t session, size_t total,
                          content_type_t recv_type)
{
  ssize_t ret = 0, ret2 = 0;
  size_t min;
  mbuffer_st *bufel = NULL;
  size_t recvlowat, recvdata, readsize;

  if (total > MAX_RECV_SIZE(session) || total == 0)
    {
      gnutls_assert ();         /* internal error */
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* If an external pull function is used, then do not leave
   * any data into the kernel buffer.
   */
  if (session->internals.pull_func != system_read)
    {
      recvlowat = 0;
    }
  else
    {
      /* leave peeked data to the kernel space only if application data
       * is received and we don't have any peeked 
       * data in gnutls session.
       */
      if (recv_type != GNUTLS_APPLICATION_DATA
          && session->internals.have_peeked_data == 0)
        recvlowat = 0;
      else
        recvlowat = RCVLOWAT;
    }



  /* calculate the actual size, ie. get the minimum of the
   * buffered data and the requested data.
   */
  min = MIN (session->internals.record_recv_buffer.byte_length, total);
  if (min > 0)
    {
      /* if we have enough buffered data
       * then just return them.
       */
      if (min == total)
        {
          return min;
        }
    }

  if(_gnutls_is_dtls(session)
     && session->internals.record_recv_buffer.byte_length != 0)
    {
      /* Attempt to read across records while using DTLS. */
      gnutls_assert();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* min is over zero. recvdata is the data we must
   * receive in order to return the requested data.
   */
  recvdata = total - min;
  readsize = recvdata - recvlowat;

  /* Check if the previously read data plus the new data to
   * receive are longer than the maximum receive buffer size.
   */
  if ((session->internals.record_recv_buffer.byte_length + recvdata) >
      MAX_RECV_SIZE(session))
    {
      gnutls_assert ();         /* internal error */
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* READ DATA - but leave RCVLOWAT bytes in the kernel buffer.
   */
  if (readsize > 0)
    {
      ret =
        _gnutls_read (session, &bufel, readsize,
                      session->internals.pull_func);

      /* return immediately if we got an interrupt or eagain
       * error.
       */
      if (ret < 0 && gnutls_error_is_fatal (ret) == 0)
        {
          _mbuffer_xfree (&bufel);
          return ret;
        }
    }

  /* copy fresh data to our buffer.
   */
  if (ret > 0)
    {
      _gnutls_read_log
        ("RB: Have %d bytes into buffer. Adding %d bytes.\n",
         (int) session->internals.record_recv_buffer.byte_length, (int) ret);
      _gnutls_read_log ("RB: Requested %d bytes\n", (int) total);

      _mbuffer_enqueue (&session->internals.record_recv_buffer, bufel);
    }
  else
    _mbuffer_xfree (&bufel);


  /* This is hack in order for select to work. Just leave recvlowat data,
   * into the kernel buffer (using a read with MSG_PEEK), thus making
   * select think, that the socket is ready for reading.
   * MSG_PEEK is only used with berkeley style sockets.
   */
  if (ret == readsize && recvlowat > 0 && !_gnutls_is_dtls(session) && 
    session->internals.pull_func == system_read)
    {
      ret2 = _gnutls_read (session, &bufel, recvlowat, system_read_peek);

      if (ret2 < 0 && gnutls_error_is_fatal (ret2) == 0)
        {
          _mbuffer_xfree (&bufel);
          return ret2;
        }

      if (ret2 > 0)
        {
          _gnutls_read_log ("RB-PEEK: Read %d bytes in PEEK MODE.\n",
                            (int) ret2);
          _gnutls_read_log
            ("RB-PEEK: Have %d bytes into buffer. Adding %d bytes.\nRB: Requested %d bytes\n",
             (int) session->internals.record_recv_buffer.byte_length,
             (int) ret2, (int) total);
          session->internals.have_peeked_data = 1;
          _mbuffer_enqueue (&session->internals.record_recv_buffer, bufel);
        }
      else
        _mbuffer_xfree (&bufel);
    }

  if (ret < 0 || ret2 < 0)
    {
      gnutls_assert ();
      /* that's because they are initialized to 0 */
      return MIN (ret, ret2);
    }

  ret += ret2;

  if (ret > 0 && ret < recvlowat)
    {
      gnutls_assert ();
      return GNUTLS_E_AGAIN;
    }

  if (ret == 0)
    {                           /* EOF */
      gnutls_assert ();
      return 0;
    }

  if(_gnutls_is_dtls(session))
    ret = MIN(total, session->internals.record_recv_buffer.byte_length);
  else
    ret = session->internals.record_recv_buffer.byte_length;

  if ((ret > 0) && ((size_t) ret < total))
    {
      /* Short Read */
      gnutls_assert ();
      return GNUTLS_E_AGAIN;
    }
  else
    {
      return ret;
    }
}

/* This function is like write. But it does not return -1 on error.
 * It does return gnutls_errno instead.
 *
 * This function takes full responsibility of freeing msg->data.
 *
 * In case of E_AGAIN and E_INTERRUPTED errors, you must call
 * gnutls_write_flush(), until it returns ok (0).
 *
 * We need to push exactly the data in msg->size, since we cannot send
 * less data. In TLS the peer must receive the whole packet in order
 * to decrypt and verify the integrity.
 *
 */
ssize_t
_gnutls_io_write_buffered (gnutls_session_t session,
                           mbuffer_st * bufel, unsigned int mflag)
{
  mbuffer_head_st *const send_buffer = &session->internals.record_send_buffer;

  _mbuffer_enqueue (send_buffer, bufel);

  _gnutls_write_log
    ("WRITE: enqueued %d bytes for %p. Total %d bytes.\n",
     (int) bufel->msg.size, session->internals.transport_recv_ptr,
     (int) send_buffer->byte_length);

  if (mflag == MBUFFER_FLUSH)
    return _gnutls_io_write_flush (session);
  else
    return bufel->msg.size;
}

typedef ssize_t (*send_func) (gnutls_session_t, const giovec_t *, int);

/* This function writes the data that are left in the
 * TLS write buffer (ie. because the previous write was
 * interrupted.
 */
ssize_t
_gnutls_io_write_flush (gnutls_session_t session)
{
  gnutls_datum_t msg;
  mbuffer_head_st *send_buffer = &session->internals.record_send_buffer;
  int ret;
  ssize_t sent = 0, tosend = 0;
  giovec_t iovec[MAX_QUEUE];
  int i = 0;
  mbuffer_st *cur;

  _gnutls_write_log ("WRITE FLUSH: %d bytes in buffer.\n",
                     (int) send_buffer->byte_length);

  for (cur = _mbuffer_get_first (send_buffer, &msg);
       cur != NULL; cur = _mbuffer_get_next (cur, &msg))
    {
      iovec[i].iov_base = msg.data;
      iovec[i++].iov_len = msg.size;
      tosend += msg.size;

      /* we buffer up to MAX_QUEUE messages */
      if (i >= sizeof (iovec) / sizeof (iovec[0]))
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
    }

  ret = _gnutls_writev (session, iovec, i);
  if (ret >= 0)
    {
      _mbuffer_remove_bytes (send_buffer, ret);
      _gnutls_write_log ("WRITE: wrote %d bytes, %d bytes left.\n",
                         ret, (int) send_buffer->byte_length);

      sent += ret;
    }
  else if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN)
    {
      _gnutls_write_log ("WRITE interrupted: %d bytes left.\n",
                         (int) send_buffer->byte_length);
      return ret;
    }
  else
    {
      _gnutls_write_log ("WRITE error: code %d, %d bytes left.\n",
                         ret, (int) send_buffer->byte_length);

      gnutls_assert ();
      return ret;
    }

  if (sent < tosend)
    {
      gnutls_assert ();
      return GNUTLS_E_AGAIN;
    }

  return sent;
}

#include "debug.h"
/* Checks whether there are received data within
 * a timeframe.
 *
 * Returns 0 if data were received, GNUTLS_E_TIMEDOUT
 * on timeout and a negative value on error.
 */
int
_gnutls_io_check_recv (gnutls_session_t session, void* data, size_t data_size, unsigned int ms)
{
  gnutls_transport_ptr_t fd = session->internals.transport_send_ptr;
  int ret;
  
  if (session->internals.pull_timeout_func == system_recv_timeout && 
    session->internals.pull_func != system_read)
    return gnutls_assert_val(GNUTLS_E_PULL_ERROR);

  ret = session->internals.pull_timeout_func(fd, data, data_size, ms);
  if (ret == -1)
    return gnutls_assert_val(GNUTLS_E_PULL_ERROR);
  
  if (ret > 0)
    return 0;
  else return GNUTLS_E_TIMEDOUT;
}

/* This function writes the data that are left in the
 * Handshake write buffer (ie. because the previous write was
 * interrupted.
 *
 */
ssize_t
_gnutls_handshake_io_write_flush (gnutls_session_t session)
{
  mbuffer_head_st *const send_buffer =
    &session->internals.handshake_send_buffer;
  gnutls_datum_t msg;
  int ret;
  uint16_t epoch;
  ssize_t total = 0;
  mbuffer_st *cur;

  _gnutls_write_log ("HWRITE FLUSH: %d bytes in buffer.\n",
                     (int) send_buffer->byte_length);

  if (IS_DTLS(session))
    return _dtls_transmit(session);

  for (cur = _mbuffer_get_first (send_buffer, &msg);
       cur != NULL; cur = _mbuffer_get_first (send_buffer, &msg))
    {
      epoch = cur->epoch;

      ret = _gnutls_send_int (session, cur->type,
                              cur->htype,
                              epoch,
                              msg.data, msg.size, 0);

      if (ret >= 0)
        {
          total += ret;
          
          ret = _mbuffer_remove_bytes (send_buffer, ret);
          if (ret == 1)
            _gnutls_epoch_refcount_dec(session, epoch);

          _gnutls_write_log ("HWRITE: wrote %d bytes, %d bytes left.\n",
                             ret, (int) send_buffer->byte_length);

        }
      else
        {
          _gnutls_write_log ("HWRITE error: code %d, %d bytes left.\n",
                             ret, (int) send_buffer->byte_length);

          gnutls_assert ();
          return ret;
        }
    }

  return _gnutls_io_write_flush (session);

}


/* This is a send function for the gnutls handshake 
 * protocol. Just makes sure that all data have been sent.
 *
 */
int
_gnutls_handshake_io_cache_int (gnutls_session_t session,
                                gnutls_handshake_description_t htype,
                                mbuffer_st * bufel)
{
  mbuffer_head_st * send_buffer;

  if (IS_DTLS(session))
    {
      bufel->handshake_sequence = session->internals.dtls.hsk_write_seq-1;
    }
  
  send_buffer =
    &session->internals.handshake_send_buffer;

  bufel->epoch = (uint16_t)_gnutls_epoch_refcount_inc(session, EPOCH_WRITE_CURRENT);

  bufel->htype = htype;
  if (bufel->htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC)
    bufel->type = GNUTLS_CHANGE_CIPHER_SPEC;
  else
    bufel->type = GNUTLS_HANDSHAKE;

  _mbuffer_enqueue (send_buffer, bufel);

  _gnutls_write_log
    ("HWRITE: enqueued [%s] %d. Total %d bytes.\n",
     _gnutls_handshake2str (bufel->htype), (int) bufel->msg.size, (int) send_buffer->byte_length);

  return 0;
}

/* Skips a handshake packet
 */
int
_gnutls_handshake_io_recv_skip (gnutls_session_t session,
                               content_type_t type,
                               gnutls_handshake_description_t htype,
                               size_t ptr_size)
{
  opaque * ptr;
  int ret;

  if (ptr_size == 0) return 0;

  ptr = gnutls_malloc(ptr_size);
  if (ptr == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

  ret = _gnutls_handshake_io_recv_int(session, type, htype, ptr, ptr_size);
  gnutls_free(ptr);

  if (ret < 0)
    return gnutls_assert_val(ret);

  return 0;
}

/* This is a receive function for the gnutls handshake 
 * protocol. Makes sure that we have received all data.
 */
ssize_t
_gnutls_handshake_io_recv_int (gnutls_session_t session,
                               content_type_t type,
                               gnutls_handshake_description_t htype,
                               void *iptr, size_t ptr_size)
{
  size_t left;
  ssize_t i;
  opaque *ptr;
  size_t dsize;

  ptr = iptr;
  left = ptr_size;

  if (ptr_size == 0 || iptr == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (session->internals.handshake_recv_buffer.length > 0)
    {
      size_t tmp;

      /* if we have already received some data */
      if (ptr_size <= session->internals.handshake_recv_buffer.length)
        {
          /* if requested less data then return it.
           */
          gnutls_assert ();

          tmp = ptr_size;
          _gnutls_buffer_pop_data (&session->internals.handshake_recv_buffer,
                                   iptr, &tmp);
          return tmp;
        }
      gnutls_assert ();

      tmp = ptr_size;
      _gnutls_buffer_pop_data (&session->internals.handshake_recv_buffer,
                               iptr, &tmp);
      left -= tmp;
    }

  while (left > 0)
    {
      dsize = ptr_size - left;
      i = _gnutls_recv_int (session, type, htype, &ptr[dsize], left, NULL);
      if (i < 0)
        {

          if (dsize > 0 && (i == GNUTLS_E_INTERRUPTED || i == GNUTLS_E_AGAIN))
            {
              gnutls_assert ();

              _gnutls_buffer_append_data (&session->internals.
                                          handshake_recv_buffer, iptr, dsize);
            }

          return i;
        }
      else
        {
          if (i == 0)
            break;              /* EOF */
        }

      left -= i;

    }

  session->internals.handshake_recv_buffer.length = 0;

  return ptr_size - left;
}

/* Buffer for handshake packets. Keeps the packets in order
 * for finished messages to use them. Used in HMAC calculation
 * and finished messages.
 */
int
_gnutls_handshake_buffer_put (gnutls_session_t session, opaque * data,
                              size_t length)
{

  if (length == 0)
    return 0;

  if ((session->internals.max_handshake_data_buffer_size > 0) &&
      ((length + session->internals.handshake_hash_buffer.length) >
       session->internals.max_handshake_data_buffer_size))
    {
      gnutls_assert ();
      return GNUTLS_E_HANDSHAKE_TOO_LARGE;
    }

  _gnutls_buffers_log ("BUF[HSK]: Inserted %d bytes of Data\n", (int) length);
  if (_gnutls_buffer_append_data (&session->internals.handshake_hash_buffer,
                                  data, length) < 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  return 0;
}

int
_gnutls_handshake_buffer_get_size (gnutls_session_t session)
{

  return session->internals.handshake_hash_buffer.length;
}

/* this function does not touch the buffer
 * and returns data from it (peek mode!)
 */
int
_gnutls_handshake_buffer_get_ptr (gnutls_session_t session,
                                  opaque ** data_ptr, size_t * length)
{
  if (length != NULL)
    *length = session->internals.handshake_hash_buffer.length;

  _gnutls_buffers_log ("BUF[HSK]: Peeked %d bytes of Data\n",
                       (int) session->internals.handshake_hash_buffer.length);

  if (data_ptr != NULL)
    *data_ptr = session->internals.handshake_hash_buffer.data;

  return 0;
}

/* Does not free the buffer
 */
int
_gnutls_handshake_buffer_empty (gnutls_session_t session)
{

  _gnutls_buffers_log ("BUF[HSK]: Emptied buffer\n");

  session->internals.handshake_hash_buffer.length = 0;

  return 0;
}


int
_gnutls_handshake_buffer_clear (gnutls_session_t session)
{

  _gnutls_buffers_log ("BUF[HSK]: Cleared Data from buffer\n");
  _gnutls_buffer_clear (&session->internals.handshake_hash_buffer);

  return 0;
}

