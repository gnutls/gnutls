/*
 * Copyright (C) 2002-2012 Free Software Foundation, Inc.
 *
 * Author: Olga Smolenchuk
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

#include <gnutls_errors.h>
#include <gnutls_int.h>
#include <gnutls_dtls.h>
#include <gnutls_record.h>
#include <ext/heartbeat.h>
#include <gnutls_extensions.h>
#include <random.h>

/**
  * gnutls_heartbeat_enable:
  * @session: is a #gnutls_session_t structure.
  * @type: one of %GNUTLS_HB_*
  *
  * This function will allow heartbeat messages to be
  * received.
  **/
void
gnutls_heartbeat_enable (gnutls_session_t session, unsigned int type)
{
  extension_priv_data_t epriv;

  epriv.num = type;
  _gnutls_ext_set_session_data (session, GNUTLS_EXTENSION_HEARTBEAT,
                                epriv);
}

/*-
 * Convenience helper:
 *
 * Returns:
 * textual policy description or NULL.
 -*/
static inline const char *
_gnutls_heartbeat (unsigned policy)
{
  if (policy & GNUTLS_HB_PEER_ALLOWED_TO_SEND)
    return "PEER ALLOWED TO SEND";
  else if (policy & GNUTLS_HB_PEER_NOT_ALLOWED_TO_SEND)
    return "PEER NOT ALLOWED TO SEND";
  return "Unknown policy";
}

/**
  * gnutls_heartbeat_allowed:
  * @session: is a #gnutls_session_t structure.
  * @type: non zero is for sending, and zero for receiving
  *
  * This function will check whether heartbeats are allowed
  * in this session.
  *
  * Returns: Non zero if heartbeats are allowed.
  *
  **/
int
gnutls_heartbeat_allowed (gnutls_session_t session, unsigned int type)
{
  extension_priv_data_t epriv;

  if (_gnutls_ext_get_session_data
      (session, GNUTLS_EXTENSION_HEARTBEAT, &epriv) < 0)
    return 0;                   /* Not enabled */

  if (type != 0)
    {
      if (epriv.num & LOCAL_ALLOWED_TO_SEND)
        return 1;
    }
  else if (epriv.num & GNUTLS_HB_PEER_ALLOWED_TO_SEND)
    return 1;
    
  return 0;
}

static int
heartbeat_allow_recv (gnutls_session_t session)
{
  return gnutls_heartbeat_allowed(session, 0);
}

static int
heartbeat_allow_send (gnutls_session_t session)
{
  return gnutls_heartbeat_allowed(session, 1);
}

/**
 * _gnutls_heartbeat_send_data:
 * @session: is a #gnutls_session_t structure.
 * @data: contains the data to send.
 * @data_size: is the length of the data.
 * @request: true if Request message is about to be send.
 *
 * This function has the similar semantics with gnutls_record_send() The only
 * difference is that it uses GNUTLS_HEARTBEAT content type.
 *
 * This function send either HeartBeat request or response message
 * with proper padding. It set timeout and timestamp without check - it's up to
 * caller to make sure no messages are already in-flight and handle timeout expiration.
 *
 * Returns: The number of bytes sent, or a negative error code.  The
 *   number of bytes sent might be less than @data_size.  The maximum
 *   number of bytes this function can send in a single call depends
 *   on the negotiated maximum record size.
 **/
ssize_t
_gnutls_heartbeat_send_data (gnutls_session_t session, const void *data,
                             size_t data_size, int request)
{
  int ret;
  char pr[128];
  gnutls_buffer_st response;
  uint8_t payload[16];
  uint8_t type = request ? HEARTBEAT_REQUEST : HEARTBEAT_RESPONSE;
  _gnutls_buffer_init (&response);

  ret = gnutls_rnd (GNUTLS_RND_RANDOM, payload, 16);
  if (ret < 0)
    return gnutls_assert_val(ret);

  BUFFER_APPEND (&response, &type, 1);
  BUFFER_APPEND_PFX2 (&response, data, data_size);

  BUFFER_APPEND (&response, payload, 16);
  ret = _gnutls_send_int (session, GNUTLS_HEARTBEAT, -1,
                          EPOCH_WRITE_CURRENT, response.data,
                          response.length, MBUFFER_FLUSH);
  if (request)
    {
      if (ret >= 0)
        {
          _gnutls_record_log
              ("REC[%p]: HB %zu bytes sent OK [%d in packet], saved for response verification:%s\n",
               session, data_size, ret, _gnutls_bin2hex ((uint8_t *) data,
                                                         data_size, pr,
                                                         sizeof (pr),
                                                         NULL));
          session->internals.dtls.heartbeat_timeout = HEARTBEAT_TIMEOUT;
          gettime (&session->internals.dtls.heartbeat_sent);
          _gnutls_buffer_reset (&session->internals.heartbeat_payload);
          BUFFER_APPEND (&session->internals.heartbeat_payload, data,
                         data_size);
        }
    }
  _gnutls_record_log ("REC[%p]: HB sent: %d\n", session, ret);

  _gnutls_buffer_clear (&response);
  return gnutls_assert_val (ret);
}

/**
 * gnutls_heartbeat_ping:
 * @session: is a #gnutls_session_t structure.
 * @data_size: is the length of the random data.
 * @wait_for_it: wait for pong or timeout instead of returning
 * immediately.
 *
 * This function has the similar semantics with gnutls_record_send().
 * The only difference is that it uses GNUTLS_HEARTBEAT content type
 * and auto-generate data to send.
 *
 * This function send HeartBeat request message with proper padding.
 *
 *
 * Returns: The number of bytes sent, or a negative error code. The
 *   number of bytes sent might be less than @data_size.  The maximum
 *   number of bytes this function can send in a single call depends
 *   on the negotiated maximum record size. GNUTLS_E_HEARTBEAT_FLIGHT
 *   is returned if HB Request is alredy in flight.
 **/
ssize_t
gnutls_heartbeat_ping (gnutls_session_t session, size_t data_size)
{
  int ret = GNUTLS_E_HEARTBEAT_FLIGHT;

  if (data_size > MAX_HEARTBEAT_LENGTH)
    return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

  if (!heartbeat_allow_send (session))
    return GNUTLS_E_INVALID_REQUEST;

  _gnutls_record_log
      ("REC[%p]: sending HB_REQUEST with length: %zu to peer\n",
       session, data_size);

  if (gnutls_heartbeat_timeout (session, 1) == GNUTLS_E_ILLEGAL_PARAMETER)
    {
      uint8_t data[data_size];
      ret = _gnutls_rnd (GNUTLS_RND_NONCE, data, data_size);
      if (ret >= 0)
        ret = _gnutls_heartbeat_send_data (session, data, data_size, 1);
    }
  else
    _gnutls_record_log
        ("REC[%p]: HB_REQUEST with length %zu already in-flight: %d\n",
         session, data_size, gnutls_heartbeat_timeout (session, 1));

  return ret;
}

/**
 * simple wrapper for ping with random length
 **/
ssize_t
gnutls_heartbeat_ping_rnd (gnutls_session_t session)
{
  uint8_t rnd;
  int ret;
  
  ret = gnutls_rnd (GNUTLS_RND_NONCE, &rnd, 1);
  if (ret < 0)
    return gnutls_assert_val(ret);
  
  return gnutls_heartbeat_ping (session, rnd + 1);
}

/**
 * Process HB message in buffer.
 * @bufel: the (suspected) HeartBeat message (TLV+padding)
 *
 * Returns:
 * processing result
 * GNUTLS_E_AGAIN if processed OK
 * GNUTLS_E_HEARTBEAT_PONG_FAILED on response send failure for request message
 * GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER on payload mismatch for response message
 **/
int
_gnutls_heartbeat_handle (gnutls_session_t session, mbuffer_st * bufel)
{
  char pr[128];
  uint8_t *msg = _mbuffer_get_udata_ptr (bufel);
  size_t hb_len, len = _mbuffer_get_udata_size (bufel);

  if (!heartbeat_allow_recv (session))
    return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET);

  if (len < 4)
    return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

  hb_len = _gnutls_read_uint16 (msg + 1);
  if (hb_len > len - 3)
    return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET);

  switch (msg[0])
    {
    case HEARTBEAT_REQUEST:
      _gnutls_record_log
          ("REC[%p]: received HEARTBEAT_REQUEST, responding...\n",
           session);
      if (_gnutls_heartbeat_send_data (session, msg + 3, hb_len, 0) >= 0)
        return GNUTLS_E_AGAIN;  /* HB responded, no APP_DATA so needs to be called again */
      else
        {                       /* immediate response failed, TBD: save received data somewhere and let upper layers handle it, loosing single ping is non-critical for HB */
          return GNUTLS_E_HEARTBEAT_PONG_FAILED;
        }
      break;

    case HEARTBEAT_RESPONSE:

      if (session->internals.heartbeat_payload.length != hb_len)
        return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

      if (memcmp (msg + 3, session->internals.heartbeat_payload.data,
                  hb_len) != 0)
        {
          _gnutls_record_log ("REC[%p]: HB: %s - received\n", session,
                              _gnutls_bin2hex (msg + 3, hb_len, pr,
                                               sizeof (pr), NULL));
          _gnutls_record_log ("REC[%p]: HB: %s - expected\n", session,
                              _gnutls_bin2hex (session->internals.
                                               heartbeat_payload.data,
                                               hb_len, pr, sizeof (pr),
                                               NULL));
          return gnutls_assert_val (GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
        }
      _gnutls_record_log
          ("REC[%p]: HB: %zu response bytes received OK (%d msec. left before timeout)\n",
           session, hb_len, gnutls_heartbeat_timeout (session, 1));

      session->internals.dtls.heartbeat_timeout = HEARTBEAT_TIMEOUT;
      _gnutls_buffer_reset (&session->internals.heartbeat_payload);
      return GNUTLS_E_AGAIN;

    default:
      _gnutls_record_log
          ("REC[%p]: HB: received unknown type %u\n",
           session, msg[0]);
      return gnutls_assert_val (GNUTLS_E_UNEXPECTED_PACKET);
    }

  return gnutls_assert_val (GNUTLS_E_INTERNAL_ERROR);
}

/**
 * Update HB timeouts: should be called on retransmit to set new timeout.
 * @check_only: guarantees lack of side-effects (no variables are written)
 *
 * Returns:
 * number of milliseconds left before timeout expiration OR
 * GNUTLS_E_TIMEDOUT if timeout expired
 * GNUTLS_E_SUCCESS if timeout updated
 * GNUTLS_E_ILLEGAL_PARAMETER if no HB message is in-flight
 **/
int
gnutls_heartbeat_timeout (gnutls_session_t session, int check_only)
{
  struct timespec now;
  unsigned int ms;
  if (session->internals.heartbeat_payload.length)
    {
      _gnutls_debug_log
          ("HB: %zu bytes are in-flight already: %u msec timeout.\n",
           session->internals.heartbeat_payload.length,
           (unsigned int) session->internals.dtls.heartbeat_timeout);
      gettime (&now);
      ms = _dtls_timespec_sub_ms (&now,
                                  &session->internals.dtls.heartbeat_sent);
      if (ms > session->internals.dtls.heartbeat_timeout)
        {
          if (check_only)
            return GNUTLS_E_TIMEDOUT;
          _gnutls_buffer_reset (&session->internals.heartbeat_payload);

          if (session->internals.dtls.heartbeat_timeout * 2 >
              MAX_HEARTBEAT_TIMEOUT)
            {                   /* update impossible */
              session->internals.dtls.heartbeat_timeout =
                  HEARTBEAT_TIMEOUT;
              return GNUTLS_E_TIMEDOUT;
            }
          else
            {
              session->internals.dtls.heartbeat_timeout *= 2;
              gettime (&session->internals.dtls.heartbeat_sent);
              return GNUTLS_E_SUCCESS;
            }
        }
      else
        {
          return ms;
        }
    }
  return GNUTLS_E_ILLEGAL_PARAMETER;
}

static int
_gnutls_heartbeat_recv_params (gnutls_session_t session,
                               const uint8_t * data, size_t _data_size)
{
  heartbeat_policy_t pol;
  extension_priv_data_t epriv;

  if (_gnutls_ext_get_session_data
      (session, GNUTLS_EXTENSION_HEARTBEAT, &epriv) < 0)
    {
      if (session->security_parameters.entity == GNUTLS_CLIENT)
        return gnutls_assert_val (GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
      return 0; /* Not enabled */
    }

  if (_data_size == 0)
    return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;

  _gnutls_debug_log ("HB: received parameter %u (%zu bytes)\n",
                     (unsigned)data[0], _data_size);

  pol = epriv.num;

  switch (data[0])
    {
    case 1:
      pol |= LOCAL_ALLOWED_TO_SEND;
      break;
    case 2:
      pol |= LOCAL_NOT_ALLOWED_TO_SEND;
      break;
    default:
      return gnutls_assert_val (GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
    }

  epriv.num = pol;
  _gnutls_ext_set_session_data (session, GNUTLS_EXTENSION_HEARTBEAT,
                                epriv);

  return 0;
}

static int
_gnutls_heartbeat_send_params (gnutls_session_t session,
                               gnutls_buffer_st * extdata)
{
  extension_priv_data_t epriv;
  uint8_t p;

  if (_gnutls_ext_get_session_data
      (session, GNUTLS_EXTENSION_HEARTBEAT, &epriv) < 0)
    return 0; /* nothing to send - not enabled */

  if (epriv.num & GNUTLS_HB_PEER_ALLOWED_TO_SEND)
    p = 1;
  else if (epriv.num & GNUTLS_HB_PEER_NOT_ALLOWED_TO_SEND)
    p = 2;

  _gnutls_debug_log ("HB: sending parameter %u\n", (unsigned)p);
  if (_gnutls_buffer_append_data (extdata, &p, 1) < 0)
    return gnutls_assert_val (GNUTLS_E_MEMORY_ERROR);

  return 1; /* number of bytes added for sending */
}

static int
_gnutls_heartbeat_pack (extension_priv_data_t _priv, gnutls_buffer_st * ps)
{
  int ret;
  BUFFER_APPEND_NUM (ps, _priv.num);
  return GNUTLS_E_SUCCESS;
}

static int
_gnutls_heartbeat_unpack (gnutls_buffer_st * ps,
                          extension_priv_data_t * _priv)
{
  int ret;
  extension_priv_data_t epriv;
  BUFFER_POP_NUM (ps, epriv.num);
  *_priv = epriv;
  ret = 0;
error:
  return ret;
}


extension_entry_st ext_mod_heartbeat = {
  .name = "HEARTBEAT",
  .type = GNUTLS_EXTENSION_HEARTBEAT,
  .parse_type = GNUTLS_EXT_TLS,

  .recv_func = _gnutls_heartbeat_recv_params,
  .send_func = _gnutls_heartbeat_send_params,
  .pack_func = _gnutls_heartbeat_pack,
  .unpack_func = _gnutls_heartbeat_unpack,
  .deinit_func = NULL
};
