/*
 * Copyright (C) 2009 Free Software Foundation (copyright assignement pending)
 *
 * Author: Jonathan Bastien-Filiatrault
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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

/* Functions that relate to DTLS retransmission and reassembly.
 */

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "debug.h"
#include "gnutls_dtls.h"
#include "gnutls_record.h"
#include <gnutls_mbuffers.h>
#include <gnutls_buffers.h>
#include <gnutls_constate.h>
#include <gnutls_state.h>
#include <gnutls/dtls.h>


/* This function fragments and transmits a previously buffered
 * outgoing message. */
static inline int
transmit_message (gnutls_session_t session,
		  mbuffer_st *bufel)
{
  opaque *data, *mtu_data;
  int ret = 0;
  unsigned int offset, frag_len, data_size;
  const uint mtu = session->internals.dtls.mtu;

  if (bufel->type == GNUTLS_CHANGE_CIPHER_SPEC)
    {
      _gnutls_dtls_log ("DTLS[%p]: Sending Packet[%u] fragment %s(%d) with "
			"length: %u, offset: %u, fragment length: %u\n",
			session, bufel->sequence,
			_gnutls_handshake2str (bufel->htype),
			bufel->htype, data_size, offset, frag_len);

      return _gnutls_send_int (session, bufel->type, -1,
        bufel->epoch, 
        _mbuffer_get_uhead_ptr(bufel), 
        _mbuffer_get_uhead_size(bufel), 0);
    }

  mtu_data = gnutls_malloc(mtu + DTLS_HANDSHAKE_HEADER_SIZE);
  if (mtu_data == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

  data = _mbuffer_get_udata_ptr( bufel);
  data_size = _mbuffer_get_udata_size(bufel);

  /* Write fixed headers
   */

  /* Handshake type */
  mtu_data[0] = (uint8_t) bufel->htype;

  /* Total length */
  _gnutls_write_uint24 (data_size, &mtu_data[1]);

  /* Handshake sequence */
  _gnutls_write_uint16 (bufel->sequence, &mtu_data[4]);

  /* Chop up and send handshake message into mtu-size pieces. */
  for (offset=0; offset <= data_size; offset += mtu)
    {
      /* Calculate fragment length */
      if(offset + mtu > data_size)
        frag_len = data_size - offset;
      else
        frag_len = mtu;

      /* Fragment offset */
      _gnutls_write_uint24 (offset, &mtu_data[6]);

      /* Fragment length */
      _gnutls_write_uint24 (frag_len, &mtu_data[9]);

      memcpy (&mtu_data[12], data+offset, frag_len);

      _gnutls_dtls_log ("DTLS[%p]: Sending Packet[%u] fragment %s(%d) with "
			"length: %u, offset: %u, fragment length: %u\n",
			session, bufel->sequence,
			_gnutls_handshake2str (bufel->htype),
			bufel->htype, data_size, offset, frag_len);

      /* FIXME: We should collaborate with the record layer to pack as
       * many records possible into a single datagram. We should also
       * tell the record layer which epoch to use for encryption. 
       */
      ret = _gnutls_send_int (session, bufel->type, bufel->htype, 
        bufel->epoch, mtu_data, DTLS_HANDSHAKE_HEADER_SIZE + frag_len, 0);
      if (ret < 0)
        break;
   }

  gnutls_free (mtu_data);

  return ret;
}

static int drop_usage_count(gnutls_session_t session)
{
  int ret;
  mbuffer_head_st *const send_buffer =
    &session->internals.handshake_send_buffer;
  mbuffer_st *cur;

  for (cur = send_buffer->head;
       cur != NULL; cur = cur->next)
    {
      ret = _gnutls_epoch_refcount_dec(session, cur->epoch);
      if (ret < 0)
        return gnutls_assert_val(ret);
    }

  return 0;
}

/* This function transmits the flight that has been previously
 * buffered.
 *
 * This function is called from the handshake layer and calls the
 * record layer.
 */
int
_dtls_transmit (gnutls_session_t session)
{
int ret;

  /* PREPARING -> SENDING state transition */
  mbuffer_head_st *const send_buffer =
    &session->internals.handshake_send_buffer;
  mbuffer_st *cur;
  unsigned int total_timeout = 0;
  gnutls_handshake_description_t last_type = 0;

  do 
    {
      _gnutls_dtls_log ("DTLS[%p]: Start of flight transmission.\n", session);

      for (cur = send_buffer->head;
           cur != NULL; cur = cur->next)
        {
          transmit_message (session, cur);
          last_type = cur->htype;
        }

      ret = _gnutls_io_write_flush (session);
      if (ret < 0)
        return gnutls_assert_val(ret);

      /* last message in handshake -> no ack */
      if (last_type == GNUTLS_HANDSHAKE_FINISHED &&
        ((session->security_parameters.entity == GNUTLS_SERVER && session->internals.resumed == RESUME_FALSE) ||
         (session->security_parameters.entity == GNUTLS_CLIENT && session->internals.resumed == RESUME_TRUE)))
        {
          opaque c;
          ret = _gnutls_io_check_recv(session, &c, 1, session->internals.dtls.retrans_timeout);
          if (ret == GNUTLS_E_TIMEDOUT)
            ret = 0;
          else if (ret >= 0)
            {
              if (c == GNUTLS_HANDSHAKE) /* retransmit */
                ret = GNUTLS_E_TIMEDOUT;
            }
          total_timeout += session->internals.dtls.retrans_timeout;
        }
      else /* all other messages -> implicit ack (receive of next flight) */
        {
          ret = _gnutls_io_check_recv(session, NULL, 0, session->internals.dtls.retrans_timeout);
          total_timeout += session->internals.dtls.retrans_timeout;
        }

      if (total_timeout >= session->internals.dtls.total_timeout) {
        ret = gnutls_assert_val(GNUTLS_E_TIMEDOUT);
        goto cleanup;
      }
    } while(ret == GNUTLS_E_TIMEDOUT);

  if (ret < 0)
    {
      ret = gnutls_assert_val(ret);
      goto cleanup;
    }

  _gnutls_dtls_log ("DTLS[%p]: End of flight transmission.\n", session);
  ret = 0;

cleanup:
  drop_usage_count(session);
  _mbuffer_clear(send_buffer);

  /* SENDING -> WAITING state transition */
  return ret;
}

#define window_table session->internals.dtls.record_sw
#define window_size session->internals.dtls.record_sw_size

/* FIXME: could we modify that code to avoid using
 * uint64_t?
 */

static void rot_window(gnutls_session_t session, int places)
{
  window_size -= places;
  memmove(window_table, &window_table[places], window_size*sizeof(window_table[0]));
}

#define MOVE_SIZE 20
/* Checks if a sequence number is not replayed. If replayed
 * returns a negative value, otherwise zero.
 */
int _dtls_record_check(gnutls_session_t session, uint64 * _seq)
{
uint64_t seq = 0, diff;
int i, offset = 0;

  for (i=0;i<8;i++) 
    {
      seq |= _seq->i[i];
      seq <<= 8;
    }

  if (window_size == 0)
    {
      window_size = 1;
      window_table[0] = seq;
      return 0;
    }

  if (seq <= window_table[0])
    {
      return -1;
    }

  if (window_size == DTLS_RECORD_WINDOW_SIZE) {
    rot_window(session, MOVE_SIZE);
  }

  if (seq < window_table[window_size-1])
    {
      /* is between first and last */
      diff = window_table[window_size-1] - seq;

      if (diff >= window_size) 
        {
          return -1;
        }

      offset = window_size-1-diff;

      if (window_table[offset] == seq)
        {
          return -1;
        }
      else
        {
          window_table[offset] = seq;
        }
    }
  else /* seq >= last */
    {
      if (seq == window_table[window_size-1]) 
        {
          return -1;
        }

      diff = seq - window_table[window_size-1];
      if (diff <= DTLS_RECORD_WINDOW_SIZE - window_size)
        { /* fits in our empty space */
          offset = diff + window_size-1;

          window_table[offset] = seq;
          window_size = offset + 1;
        }
      else
        {
          if (diff > DTLS_RECORD_WINDOW_SIZE/2)
            { /* difference is too big */
              window_table[DTLS_RECORD_WINDOW_SIZE-1] = seq;
              window_size = DTLS_RECORD_WINDOW_SIZE;
            }
          else
            {
              rot_window(session, diff);
              offset = diff + window_size-1;
              window_table[offset] = seq;
              window_size = offset + 1;            
            }
        }
    }
  return 0;
}


/**
 * gnutls_dtls_set_timeouts:
 * @session: is a #gnutls_session_t structure.
 * @retrans_timeout: The time at which a retransmission will occur in milliseconds
 * @total_timeout: The time at which the connection will be aborted, in milliseconds.
 *
 * This function will set the timeouts required for the DTLS handshake
 * protocol. The retransmission timeout is the time after which a
 * message from the peer is not received, the previous messages will
 * be retransmitted. The total timeout is the time after which the
 * handshake will be aborted with %GNUTLS_E_TIMEDOUT.
 *
 * If the retransmission timeout is zero then the handshake will operate
 * in a non-blocking way, i.e., return %GNUTLS_E_AGAIN.
 *
 **/
void gnutls_dtls_set_timeouts (gnutls_session_t session, unsigned int retrans_timeout,
  unsigned int total_timeout)
{
  session->internals.dtls.retrans_timeout  = retrans_timeout;
  session->internals.dtls.total_timeout  = total_timeout;
}

/**
 * gnutls_dtls_set_mtu:
 * @session: is a #gnutls_session_t structure.
 * @mtu: The maximum transfer unit of the interface
 *
 * This function will set the maximum transfer unit of the interface
 * that DTLS packets are expected to leave from.
 *
 **/
void gnutls_dtls_set_mtu (gnutls_session_t session, unsigned int mtu)
{
  session->internals.dtls.mtu  = mtu;
}

/**
 * gnutls_dtls_get_mtu:
 * @session: is a #gnutls_session_t structure.
 *
 * This function will return the actual maximum transfer unit for
 * application data. I.e. DTLS headers are subtracted from the
 * actual MTU.
 *
 **/
unsigned int gnutls_dtls_get_mtu (gnutls_session_t session)
{
int ret;

  ret = _gnutls_record_overhead_rt(session);
  if (ret >= 0)
    return session->internals.dtls.mtu - ret;
  else
    return session->internals.dtls.mtu - RECORD_HEADER_SIZE(session);
}
