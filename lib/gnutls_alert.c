/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_alert.h>
#include <gnutls_record.h>
#include <debug.h>

/**
  * gnutls_alert_send - This function sends an alert message to the peer
  * @state: is a &GNUTLS_STATE structure.
  * @level: is the level of the alert
  * @desc: is the alert description
  *
  * This function will send an alert to the peer in order to inform
  * him of something important (eg. his Certificate could not be verified).
  * If the alert level is Fatal then the peer is expected to close the
  * connection, otherwise he may ignore the alert and continue.
  * Returns 0 on success.
  *
  **/
int gnutls_alert_send( GNUTLS_STATE state, GNUTLS_AlertLevel level, GNUTLS_AlertDescription desc)
{
	uint8 data[2];
	int ret;
	
	data[0] = (uint8) level;
	data[1] = (uint8) desc;

	_gnutls_record_log( "REC: Sending Alert[%d|%d] - %s\n", data[0], data[1], _gnutls_alert2str((int)data[1]));

	if ( (ret = gnutls_send_int( state, GNUTLS_ALERT, -1, data, 2)) >= 0)
		return 0;
	else
		return ret;
}

/* Sends the appropriate alert, depending
 * on the error message.
 */
/**
  * gnutls_alert_send_appropriate - This function sends an alert to the peer depending on the error code
  * @state: is a &GNUTLS_STATE structure.
  * @err: is an integer
  *
  * Sends an alert to the peer depending on the error code returned by a gnutls
  * function. All alerts sent by this function are fatal, so connection should
  * be considered terminated after calling this function. The only exception
  * is when err == GNUTLS_E_REHANDSHAKE, then a warning alert is sent to
  * the peer indicating the no renegotiation will be performed.
  *
  * This function may also return GNUTLS_E_AGAIN, or GNUTLS_E_INTERRUPTED.
  *
  * If the return value is GNUTLS_E_UNIMPLEMENTED_FEATURE, then no alert has
  * been sent to the peer.
  *
  **/
int gnutls_alert_send_appropriate( GNUTLS_STATE state, int err) {
int ret = GNUTLS_E_UNIMPLEMENTED_FEATURE;
	switch (err) { /* send appropriate alert */
		case GNUTLS_E_DECRYPTION_FAILED:
			/* GNUTLS_A_DECRYPTION_FAILED is not sent, because
			 * it is not defined in SSL3.
			 */
			ret = gnutls_alert_send( state, GNUTLS_AL_FATAL, GNUTLS_A_BAD_RECORD_MAC);
			break;
		case GNUTLS_E_DECOMPRESSION_FAILED:
			ret = gnutls_alert_send( state, GNUTLS_AL_FATAL, GNUTLS_A_DECOMPRESSION_FAILURE);
			break;
		case GNUTLS_E_ILLEGAL_PARAMETER:
                        ret = gnutls_alert_send( state, GNUTLS_AL_FATAL, GNUTLS_A_ILLEGAL_PARAMETER);
                        break;
		case GNUTLS_E_ASN1_PARSING_ERROR:
		case GNUTLS_E_NO_CERTIFICATE_FOUND:
                        ret = gnutls_alert_send( state, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
                        break;
		case GNUTLS_E_UNKNOWN_CIPHER_SUITE:
                        ret = gnutls_alert_send( state, GNUTLS_AL_FATAL, GNUTLS_A_HANDSHAKE_FAILURE);
                        break;
		case GNUTLS_E_UNEXPECTED_PACKET:
                        ret = gnutls_alert_send( state, GNUTLS_AL_FATAL, GNUTLS_A_UNEXPECTED_MESSAGE);
                        break;
		case GNUTLS_E_REHANDSHAKE:
                        ret = gnutls_alert_send( state, GNUTLS_AL_WARNING, GNUTLS_A_NO_RENEGOTIATION);
                        break;
		case GNUTLS_E_UNSUPPORTED_VERSION_PACKET:
                        ret = gnutls_alert_send( state, GNUTLS_AL_WARNING, GNUTLS_A_PROTOCOL_VERSION);
			break;
		case GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE:
                        ret = gnutls_alert_send( state, GNUTLS_AL_WARNING, GNUTLS_A_UNSUPPORTED_CERTIFICATE);
			break;
		case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
			ret = gnutls_alert_send( state, GNUTLS_AL_FATAL, GNUTLS_A_RECORD_OVERFLOW);
			break;
	}
	return ret;
}

/**
  * gnutls_alert_get_last - Returns the last alert number received.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the last alert number received. This function
  * should be called if GNUTLS_E_WARNING_ALERT_RECEIVED or
  * GNUTLS_E_FATAL_ALERT_RECEIVED has been returned by a gnutls function.
  * The peer may send alerts if he thinks some things were not 
  * right. Check gnutls.h for the available alert descriptions.
  **/
GNUTLS_AlertDescription gnutls_alert_get_last( GNUTLS_STATE state) {
	return state->gnutls_internals.last_alert;
}
