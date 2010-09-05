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

/* This function is called once a handshake message is ready to be
 * queued in the next outgoing flight. The actual transmission occurs
 * in _gnutls_dtls_transmit.
 *
 * This function is called from the handshake layer.
 */
int
_gnutls_dtls_handshake_enqueue (gnutls_session_t session,
				opaque *data,
				uint32_t datasize,
				gnutls_handshake_description_t type,
				uint16_t sequence)
{
  dtls_hsk_retransmit_buffer *msg;

  msg = gnutls_malloc (sizeof(dtls_hsk_retransmit_buffer));
  if (msg == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  msg->msg.size = datasize - DTLS_HANDSHAKE_HEADER_SIZE;

  msg->msg.data = gnutls_malloc (msg->msg.size);
  if (msg->msg.data == NULL)
    {
      gnutls_free (msg);
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  memcpy (msg->msg.data, data + DTLS_HANDSHAKE_HEADER_SIZE, msg->msg.size);

  msg->next = NULL;
  /* FIXME: dummy epoch */
  msg->epoch = 0;
  msg->type = type;
  msg->sequence = sequence;

  _gnutls_dtls_log ("DTLS[%p]: Enqueued Packet[%u] %s(%d) with length: %u\n",
		    session, (uint)sequence, _gnutls_handshake2str (type),
		    type, msg->msg.size);

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
  opaque *data;
  uint offset, frag_len;
  const uint mtu = session->internals.dtls.hsk_mtu;

  data = gnutls_malloc (DTLS_HANDSHAKE_HEADER_SIZE + mtu);
  if (data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* Write fixed headers
   */

  /* Handshake type */
  data[0] = (uint8_t) msg->type;

  /* Total length */
  _gnutls_write_uint24 (msg->msg.size, &data[1]);

  /* Handshake sequence */
  _gnutls_write_uint16 (msg->sequence, &data[4]);

  /* Chop up and send handshake message into mtu-size pieces. */
  for (offset=0; offset < msg->msg.size; offset += mtu)
    {
      /* Calculate fragment length */
      if(offset + mtu > msg->msg.size)
	frag_len = msg->msg.size - offset;
      else
	frag_len = mtu;

      /* Fragment offset */
      _gnutls_write_uint24 (offset, &data[6]);

      /* Fragment length */
      _gnutls_write_uint24 (frag_len, &data[9]);

      memcpy (&data[12], msg->msg.data + offset, frag_len);

      _gnutls_dtls_log ("DTLS[%p]: Sending Packet[%u] fragment %s(%d) with "
			"length: %u, offset: %u, fragment length: %u\n",
			session, msg->sequence,
			_gnutls_handshake2str (msg->type),
			msg->type, msg->msg.size, offset, frag_len);

      /* FIXME: We should collaborate with the record layer to pack as
	 many records possible into a single datagram. We should also
	 tell the record layer which epoch to use for encryption. */
      _gnutls_send_int (session, GNUTLS_HANDSHAKE, msg->type, EPOCH_WRITE_CURRENT,
			data, DTLS_HANDSHAKE_HEADER_SIZE + frag_len, 0);
   }

  gnutls_free (data);
  return 0;
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
  /* PREPARING -> SENDING state transition */
  dtls_hsk_retransmit_buffer *msg;

  _gnutls_dtls_log ("DTLS[%p]: Start of flight transmission.\n", session);

  for (msg = session->internals.dtls.retransmit; msg != NULL; msg = msg->next)
    transmit_message (session, msg);
  _gnutls_io_write_flush (session);


  _gnutls_dtls_log ("DTLS[%p]: End of flight transmission.\n", session);

  _gnutls_dtls_clear_outgoing_buffer (session);

  /* SENDING -> WAITING state transition */
  return 0;
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

      gnutls_free (msg->msg.data);
      gnutls_free (msg);

      msg = next;
    }

  session->internals.dtls.retransmit_end = &session->internals.dtls.retransmit;
  session->internals.dtls.retransmit = NULL;
}
