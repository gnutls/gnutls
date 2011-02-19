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
#include <gnutls/dtls.h>

/* This function is called once a handshake message is ready to be
 * queued in the next outgoing flight. The actual transmission occurs
 * in _gnutls_dtls_transmit.
 *
 * This function is called from the handshake layer.
 */
int
_gnutls_dtls_handshake_enqueue (gnutls_session_t session,
				mbuffer_st* bufel,
				gnutls_handshake_description_t type,
				uint16_t sequence)
{
  dtls_hsk_retransmit_buffer *msg;
  record_parameters_st * params;
  int ret;

  ret = _gnutls_epoch_get( session, EPOCH_WRITE_CURRENT, &params);
  if (ret < 0)
    return gnutls_assert_val(ret);

  msg = gnutls_malloc (sizeof(dtls_hsk_retransmit_buffer));
  if (msg == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  msg->bufel = bufel;

  msg->next = NULL;

  msg->epoch = params->epoch;
  msg->type = type;
  msg->sequence = sequence;

  _gnutls_dtls_log ("DTLS[%p]: Enqueued Packet[%u] %s(%d) with length: %u\n",
		    session, (uint)sequence, _gnutls_handshake2str (type),
		    type, msg->bufel->msg.size);

  *(session->internals.dtls.retransmit_end) = msg;
  session->internals.dtls.retransmit_end = &msg->next;

  return 0;
}

/* This function fragments and transmits a previously buffered
 * outgoing message. */
static inline int
transmit_message (gnutls_session_t session,
		  dtls_hsk_retransmit_buffer *msg)
{
  opaque *data, *mtu_data;
  int ret = 0;
  unsigned int offset, frag_len, data_size;
  const uint mtu = session->internals.dtls.hsk_mtu;

  if (msg->type == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC)
    {
      return _gnutls_send_int (session, GNUTLS_CHANGE_CIPHER_SPEC, -1,
        msg->epoch, 
        _mbuffer_get_uhead_ptr(msg->bufel), 
        _mbuffer_get_uhead_size(msg->bufel), 0);
    }

  mtu_data = gnutls_malloc(mtu + DTLS_HANDSHAKE_HEADER_SIZE);
  if (mtu_data == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

  data = _mbuffer_get_udata_ptr( msg->bufel);
  data_size = _mbuffer_get_udata_size(msg->bufel);

  /* Write fixed headers
   */

  /* Handshake type */
  mtu_data[0] = (uint8_t) msg->type;

  /* Total length */
  _gnutls_write_uint24 (data_size, &mtu_data[1]);

  /* Handshake sequence */
  _gnutls_write_uint16 (msg->sequence, &mtu_data[4]);

  /* Chop up and send handshake message into mtu-size pieces. */
  for (offset=0; offset < data_size; offset += mtu)
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
			session, msg->sequence,
			_gnutls_handshake2str (msg->type),
			msg->type, data_size, offset, frag_len);

      /* FIXME: We should collaborate with the record layer to pack as
       * many records possible into a single datagram. We should also
       * tell the record layer which epoch to use for encryption. 
       */
      ret = _gnutls_send_int (session, GNUTLS_HANDSHAKE, msg->type, msg->epoch,
        mtu_data, DTLS_HANDSHAKE_HEADER_SIZE + frag_len, 0);
      if (ret < 0)
        break;
   }

  gnutls_free (mtu_data);
  return ret;
}

/* This function transmits the flight that has been previously
 * buffered.
 *
 * This function is called from the handshake layer and calls the
 * record layer.
 */
int
_gnutls_dtls_transmit (gnutls_session_t session)
{
int ret;

  /* PREPARING -> SENDING state transition */
  dtls_hsk_retransmit_buffer *msg;
  unsigned int total_timeout = 0;

  do 
    {
      _gnutls_dtls_log ("DTLS[%p]: Start of flight transmission.\n", session);

      for (msg = session->internals.dtls.retransmit; msg != NULL; msg = msg->next)
        transmit_message (session, msg);

      ret = _gnutls_io_write_flush (session);
      if (ret < 0)
        return gnutls_assert_val(ret);

      ret = _gnutls_io_check_recv(session, session->internals.dtls.retrans_timeout);
      total_timeout += session->internals.dtls.retrans_timeout;

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
  _gnutls_dtls_clear_outgoing_buffer (session);

  /* SENDING -> WAITING state transition */
  return ret;
}

/* This function clears the outgoing flight buffer. */
void
_gnutls_dtls_clear_outgoing_buffer (gnutls_session_t session)
{
  dtls_hsk_retransmit_buffer *msg, *next;

  _gnutls_dtls_log ("DTLS[%p]: Clearing outgoing buffer.\n", session);

  for (msg = session->internals.dtls.retransmit; msg != NULL;)
    {
      next = msg->next;

      _mbuffer_xfree(&msg->bufel);
      gnutls_free (msg);

      msg = next;
    }

  session->internals.dtls.retransmit_end = &session->internals.dtls.retransmit;
  session->internals.dtls.retransmit = NULL;
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
