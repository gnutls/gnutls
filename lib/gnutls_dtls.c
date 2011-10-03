/*
 * Copyright (C) 2009,2011 Free Software Foundation
 *
 * Authors: Jonathan Bastien-Filiatrault
 *          Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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
  const unsigned int mtu = gnutls_dtls_get_data_mtu(session) - DTLS_HANDSHAKE_HEADER_SIZE;

  if (bufel->type == GNUTLS_CHANGE_CIPHER_SPEC)
    {
      _gnutls_dtls_log ("DTLS[%p]: Sending Packet[%u] fragment %s(%d)\n",
			session, bufel->handshake_sequence,
			_gnutls_handshake2str (bufel->htype),
			bufel->htype);

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
  _gnutls_write_uint16 (bufel->handshake_sequence, &mtu_data[4]);

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

      memcpy (&mtu_data[DTLS_HANDSHAKE_HEADER_SIZE], data+offset, frag_len);

      _gnutls_dtls_log ("DTLS[%p]: Sending Packet[%u] fragment %s(%d) with "
			"length: %u, offset: %u, fragment length: %u\n",
			session, bufel->handshake_sequence,
			_gnutls_handshake2str (bufel->htype),
			bufel->htype, data_size, offset, frag_len);

      ret = _gnutls_send_int (session, bufel->type, bufel->htype, 
        bufel->epoch, mtu_data, DTLS_HANDSHAKE_HEADER_SIZE + frag_len, 0);
      if (ret < 0)
        {
          gnutls_assert();
          break;
        }
   }

  gnutls_free (mtu_data);

  return ret;
}

static int drop_usage_count(gnutls_session_t session, mbuffer_head_st *const send_buffer)
{
  int ret;
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

#define RETRANSMIT_WINDOW 2

/* This function is to be called from record layer once
 * a handshake replay is detected. It will make sure
 * it transmits only once per few seconds. Otherwise
 * it is the same as _dtls_transmit().
 */
int _dtls_retransmit(gnutls_session_t session)
{
time_t now = gnutls_time (0);

  if (now - session->internals.dtls.last_retransmit > RETRANSMIT_WINDOW)
    {
      session->internals.dtls.last_retransmit = now;
      return _dtls_transmit(session);
    }
  else
    return 0;

}

#define UPDATE_TIMER \
      session->internals.dtls.actual_retrans_timeout *= 2; \
      session->internals.dtls.actual_retrans_timeout %= MAX_DTLS_TIMEOUT

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
  gnutls_handshake_description_t last_type = 0;
  time_t now = gnutls_time (0);

  /* If we have already sent a flight and we are operating in a 
   * non blocking way, check if it is time to retransmit or just
   * return.
   */
  if (session->internals.dtls.flight_init != 0 && session->internals.dtls.blocking == 0)
    {
      /* just in case previous run was interrupted */
      ret = _gnutls_io_write_flush (session);

      if (session->internals.dtls.last_flight == 0)
        {
          /* check for ACK */
          ret = _gnutls_io_check_recv(session, 0);
          if (ret == GNUTLS_E_TIMEDOUT)
            {
              /* if no retransmission is required yet just return 
               */
              if (now-session->internals.dtls.handshake_start_time < session->internals.dtls.actual_retrans_timeout)
                {
                  session->internals.dtls.handshake_last_call = now;
                  goto nb_timeout;
                }
            }
          else /* received ack */
            {
              ret = 0;
              goto cleanup;
            }
        }
      else
        return ret;
    }


  do 
    {
      if (now-session->internals.dtls.handshake_start_time >= session->internals.dtls.total_timeout/1000) 
        {
          ret = gnutls_assert_val(GNUTLS_E_TIMEDOUT);
          goto cleanup;
        }

      _gnutls_dtls_log ("DTLS[%p]: %sstart of flight transmission.\n", session,  (session->internals.dtls.flight_init == 0)?"":"re-");

      for (cur = send_buffer->head;
           cur != NULL; cur = cur->next)
        {
          transmit_message (session, cur);
          last_type = cur->htype;
        }

      if (session->internals.dtls.flight_init == 0)
        {
          session->internals.dtls.flight_init = 1;
          session->internals.dtls.handshake_last_call = now;
          session->internals.dtls.actual_retrans_timeout = session->internals.dtls.retrans_timeout;

          if (last_type == GNUTLS_HANDSHAKE_FINISHED && _dtls_is_async(session))
            {
              /* we cannot do anything here. We just return 0 and
               * if a retransmission occurs because peer didn't receive it
               * we rely on the record layer calling this function again.
               */
              session->internals.dtls.last_flight = 1;
            }
          else
            session->internals.dtls.last_flight = 0;


        }

      ret = _gnutls_io_write_flush (session);
      if (ret < 0)
        return gnutls_assert_val(ret);

      /* last message in handshake -> no ack */
      if (session->internals.dtls.last_flight != 0)
        {
          /* we cannot do anything here. We just return 0 and
           * if a retransmission occurs because peer didn't receive it
           * we rely on the record layer calling this function again.
           */
          return 0;
        }
      else /* all other messages -> implicit ack (receive of next flight) */
        {
          if (session->internals.dtls.blocking != 0)
            ret = _gnutls_io_check_recv(session, session->internals.dtls.actual_retrans_timeout);
          else
            {
              ret = _gnutls_io_check_recv(session, 0);
              if (ret == GNUTLS_E_TIMEDOUT)
                {
                  UPDATE_TIMER;
                  goto nb_timeout;
                }
            }
        }

      UPDATE_TIMER;
      now = gnutls_time (0);
    } while(ret == GNUTLS_E_TIMEDOUT);

  if (ret < 0)
    {
      ret = gnutls_assert_val(ret);
      goto cleanup;
    }

  ret = 0;

cleanup:
  _gnutls_dtls_log ("DTLS[%p]: End of flight transmission.\n", session);

  session->internals.dtls.flight_init = 0;
  drop_usage_count(session, send_buffer);
  _mbuffer_head_clear(send_buffer);

  /* SENDING -> WAITING state transition */
  return ret;

nb_timeout:
    return GNUTLS_E_AGAIN;
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
 * returns a negative error code, otherwise zero.
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
 * The DTLS protocol recommends the values of 1 sec and 60 seconds
 * respectively.
 *
 * If the retransmission timeout is zero then the handshake will operate
 * in a non-blocking way, i.e., return %GNUTLS_E_AGAIN.
 *
 * Since: 3.0.0
 **/
void gnutls_dtls_set_timeouts (gnutls_session_t session, unsigned int retrans_timeout,
  unsigned int total_timeout)
{
  session->internals.dtls.retrans_timeout = retrans_timeout;
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
 * Since: 3.0.0
 **/
void gnutls_dtls_set_mtu (gnutls_session_t session, unsigned int mtu)
{
  session->internals.dtls.mtu  = mtu;
}

/**
 * gnutls_dtls_get_data_mtu:
 * @session: is a #gnutls_session_t structure.
 *
 * This function will return the actual maximum transfer unit for
 * application data. I.e. DTLS headers are subtracted from the
 * actual MTU.
 *
 * Returns: the maximum allowed transfer unit.
 *
 * Since: 3.0.0
 **/
unsigned int gnutls_dtls_get_data_mtu (gnutls_session_t session)
{
int ret;

  ret = _gnutls_record_overhead_rt(session);
  if (ret >= 0)
    return session->internals.dtls.mtu - ret;
  else
    return session->internals.dtls.mtu - RECORD_HEADER_SIZE(session);
}

/**
 * gnutls_dtls_get_mtu:
 * @session: is a #gnutls_session_t structure.
 *
 * This function will return the MTU size as set with
 * gnutls_dtls_set_mtu(). This is not the actual MTU
 * of data you can transmit. Use gnutls_dtls_get_data_mtu()
 * for that reason.
 *
 * Returns: the set maximum transfer unit.
 *
 * Since: 3.0.0
 **/
unsigned int gnutls_dtls_get_mtu (gnutls_session_t session)
{
  return session->internals.dtls.mtu;
}

#define COOKIE_SIZE 16
#define COOKIE_MAC_SIZE 16

/*   MAC
 * 16 bytes
 *
 * total 19 bytes
 */

#define C_HASH GNUTLS_MAC_SHA1
#define C_HASH_SIZE 20

/**
 * gnutls_dtls_cookie_send:
 * @key: is a random key to be used at cookie generation
 * @client_data: contains data identifying the client (i.e. address)
 * @client_data_size: The size of client's data
 * @prestate: The previous cookie returned by gnutls_dtls_cookie_verify()
 * @ptr: A transport pointer to be used by @push_func
 * @push_func: A function that will be used to reply
 *
 * This function can be used to prevent denial of service
 * attacks to a DTLS server by requiring the client to
 * reply using a cookie sent by this function. That way
 * it can be ensured that a client we allocated resources
 * for (i.e. #gnutls_session_t) is the one that the 
 * original incoming packet was originated from.
 *
 * Returns: the number of bytes sent, or a negative error code.  
 *
 * Since: 3.0.0
 **/
int gnutls_dtls_cookie_send(gnutls_datum_t* key, void* client_data, size_t client_data_size, 
  gnutls_dtls_prestate_st* prestate,
  gnutls_transport_ptr_t ptr, gnutls_push_func push_func)
{
opaque hvr[20+DTLS_HANDSHAKE_HEADER_SIZE+COOKIE_SIZE];
int hvr_size = 0, ret;
uint8_t digest[C_HASH_SIZE];

  if (key == NULL || key->data == NULL || key->size == 0)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

/* send
 *  struct {
 *    ContentType type - 1 byte GNUTLS_HANDSHAKE;
 *    ProtocolVersion version; - 2 bytes (254,255)
 *    uint16 epoch; - 2 bytes (0, 0)
 *    uint48 sequence_number; - 4 bytes (0,0,0,0)
 *    uint16 length; - 2 bytes (COOKIE_SIZE+1+2)+DTLS_HANDSHAKE_HEADER_SIZE
 *    opaque fragment[DTLSPlaintext.length];
 *  } DTLSPlaintext;
 *
 *
 * struct {
 *    HandshakeType msg_type; 1 byte - GNUTLS_HANDSHAKE_HELLO_VERIFY_REQUEST
 *    uint24 length; - COOKIE_SIZE+3
 *    uint16 message_seq; - 2 bytes (0,0)
 *    uint24 fragment_offset; - 3 bytes (0,0,0)
 *    uint24 fragment_length; - same as length
 * }
 *
 * struct {
 *   ProtocolVersion server_version;
 *   opaque cookie<0..32>;
 * } HelloVerifyRequest;
 */ 

  hvr[hvr_size++] = GNUTLS_HANDSHAKE;
  /* version */
  hvr[hvr_size++] = 254;
  hvr[hvr_size++] = 255;
  
  /* epoch + seq */
  memset(&hvr[hvr_size], 0, 8);
  hvr_size += 7;
  hvr[hvr_size++] = prestate->record_seq;

  /* length */
  _gnutls_write_uint16(DTLS_HANDSHAKE_HEADER_SIZE+COOKIE_SIZE+3, &hvr[hvr_size]);
  hvr_size += 2;

  /* now handshake headers */
  hvr[hvr_size++] = GNUTLS_HANDSHAKE_HELLO_VERIFY_REQUEST;
  _gnutls_write_uint24(COOKIE_SIZE+3, &hvr[hvr_size]);
  hvr_size += 3;
  
  /* handshake seq */
  hvr[hvr_size++] = 0;
  hvr[hvr_size++] = prestate->hsk_write_seq;

  _gnutls_write_uint24(0, &hvr[hvr_size]);
  hvr_size += 3;

  _gnutls_write_uint24(COOKIE_SIZE+3, &hvr[hvr_size]);
  hvr_size += 3;

  /* version */
  hvr[hvr_size++] = 254;
  hvr[hvr_size++] = 255;
  hvr[hvr_size++] = COOKIE_SIZE;

  ret = _gnutls_hmac_fast(C_HASH, key->data, key->size, client_data, client_data_size, digest);
  if (ret < 0)
    return gnutls_assert_val(ret);

  memcpy(&hvr[hvr_size], digest, COOKIE_MAC_SIZE);
  hvr_size+= COOKIE_MAC_SIZE;

  ret = push_func(ptr, hvr, hvr_size);
  if (ret < 0)
    ret = GNUTLS_E_PUSH_ERROR;

  return ret;
}

/**
 * gnutls_dtls_cookie_verify:
 * @key: is a random key to be used at cookie generation
 * @client_data: contains data identifying the client (i.e. address)
 * @client_data_size: The size of client's data
 * @_msg: An incoming message that initiates a connection.
 * @msg_size: The size of the message.
 * @prestate: The cookie of this client.
 *
 * This function will verify an incoming message for
 * a valid cookie. If a valid cookie is returned then
 * it should be associated with the session using
 * gnutls_dtls_prestate_set();
 *
 * Returns: %GNUTLS_E_SUCCESS (0) on success, or a negative error code.  
 *
 * Since: 3.0.0
 **/
int gnutls_dtls_cookie_verify(gnutls_datum_t* key, 
  void* client_data, size_t client_data_size, 
  void* _msg, size_t msg_size, gnutls_dtls_prestate_st* prestate)
{
gnutls_datum_t cookie;
int sid_size;
int pos, ret;
uint8_t * msg = _msg;
uint8_t digest[C_HASH_SIZE];

  if (key == NULL || key->data == NULL || key->size == 0)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  /* format:
   * version - 2 bytes
   * random - 32 bytes
   * session_id - 1 byte length + content
   * cookie - 1 byte length + content
   */

  pos = 34+DTLS_RECORD_HEADER_SIZE+DTLS_HANDSHAKE_HEADER_SIZE;

  if (msg_size < pos+1)
    return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

  sid_size = msg[pos++];

  if (sid_size > 32 || msg_size < pos+sid_size+1)
    return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

  pos += sid_size;
  cookie.size = msg[pos++];

  if (msg_size < pos+cookie.size+1)
    return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
  
  cookie.data = &msg[pos];
  if (cookie.size != COOKIE_SIZE)
    {
      if (cookie.size > 0) _gnutls_audit_log(NULL, "Received cookie with illegal size %d. Expected %d\n", (int)cookie.size, COOKIE_SIZE);
      return gnutls_assert_val(GNUTLS_E_BAD_COOKIE);
    }

  ret = _gnutls_hmac_fast(C_HASH, key->data, key->size, client_data, client_data_size, digest);
  if (ret < 0)
    return gnutls_assert_val(ret);

  if (memcmp(digest, cookie.data, COOKIE_MAC_SIZE) != 0)
    return gnutls_assert_val(GNUTLS_E_BAD_COOKIE);
  
  prestate->record_seq = msg[10]; /* client's record seq */
  prestate->hsk_read_seq =  msg[DTLS_RECORD_HEADER_SIZE+5]; /* client's hsk seq */
  prestate->hsk_write_seq = 0;/* we always send zero for this msg */
  
  return 0;
}

/**
 * gnutls_dtls_prestate_set:
 * @session: a new session
 * @prestate: contains the client's prestate
 *
 * This function will associate the prestate acquired by
 * the cookie authentication with the client, with the newly 
 * established session.
 *
 * Since: 3.0.0
 **/
void gnutls_dtls_prestate_set(gnutls_session_t session, gnutls_dtls_prestate_st* prestate)
{
  record_parameters_st *params;
  int ret;

  if (prestate == NULL)
    return;

  /* we do not care about read_params, since we accept anything
   * the peer sends.
   */
  ret = _gnutls_epoch_get (session, EPOCH_WRITE_CURRENT, &params);
  if (ret < 0)
    return;

  params->write.sequence_number.i[7] = prestate->record_seq;

  session->internals.dtls.hsk_read_seq = prestate->hsk_read_seq;
  session->internals.dtls.hsk_write_seq = prestate->hsk_write_seq + 1;
}

/**
 * gnutls_record_get_discarded:
 * @session: is a #gnutls_session_t structure.
 *
 * Returns the number of discarded packets in a
 * DTLS connection.
 *
 * Returns: The number of discarded packets.
 *
 * Since: 3.0.0
 **/
unsigned int gnutls_record_get_discarded (gnutls_session_t session)
{
  return session->internals.dtls.packets_dropped;
}

