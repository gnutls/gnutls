/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_alert.h>
#include <gnutls_record.h>
#include <debug.h>

typedef struct {
	AlertDescription alert;
	const char *desc;
} gnutls_alert_entry;

static const gnutls_alert_entry sup_alerts[] = {
	{ GNUTLS_A_CLOSE_NOTIFY, "Close notify" },
	{ GNUTLS_A_UNEXPECTED_MESSAGE,	 "Unexpected message" },
	{ GNUTLS_A_BAD_RECORD_MAC,	 "Bad record MAC" },
	{ GNUTLS_A_DECRYPTION_FAILED,	 "Decryption failed" },
	{ GNUTLS_A_RECORD_OVERFLOW,	 "Record overflow" }, 
	{ GNUTLS_A_DECOMPRESSION_FAILURE, "Decompression failed" },
	{ GNUTLS_A_HANDSHAKE_FAILURE,	 "Handshake failed" },
	{ GNUTLS_A_BAD_CERTIFICATE,	 "Certificate is bad" },
	{ GNUTLS_A_UNSUPPORTED_CERTIFICATE,	 "Certificate is not supported" },
	{ GNUTLS_A_CERTIFICATE_REVOKED,	 "Certificate was revoked" },
	{ GNUTLS_A_CERTIFICATE_EXPIRED,	 "Certificate is expired" },
	{ GNUTLS_A_CERTIFICATE_UNKNOWN,	 "Unknown certificate" },
	{ GNUTLS_A_ILLEGAL_PARAMETER,	 "Illegal parameter" },
	{ GNUTLS_A_UNKNOWN_CA,	 	 "CA is unknown" },
	{ GNUTLS_A_ACCESS_DENIED,	 "Access was denied" },
	{ GNUTLS_A_DECODE_ERROR,	 "Decode error" },
	{ GNUTLS_A_DECRYPT_ERROR,	 "Decrypt error" },
	{ GNUTLS_A_EXPORT_RESTRICTION,	 "Export restriction" },
	{ GNUTLS_A_PROTOCOL_VERSION,	 "Error in protocol version" },
	{ GNUTLS_A_INSUFFICIENT_SECURITY,"Insufficient security" },
	{ GNUTLS_A_USER_CANCELED,	 "User canceled" },
	{ GNUTLS_A_NO_RENEGOTIATION,	 "No renegotiation is allowed" },
	{0, NULL}
};

#define GNUTLS_ALERT_LOOP(b) \
        const gnutls_alert_entry *p; \
                for(p = sup_alerts; p->desc != NULL; p++) { b ; }

#define GNUTLS_ALERT_ID_LOOP(a) \
                        GNUTLS_ALERT_LOOP( if(p->alert == alert) { a; break; })


/**
  * gnutls_alert_get_name - Returns a string describing the alert number given
  * @alert: is an alert number &gnutls_session structure.
  *
  * Returns a string that describes the given alert number.
  * See. gnutls_alert_get().
  *
  **/
const char* gnutls_alert_get_name( int alert) {
const char* ret = NULL;

	GNUTLS_ALERT_ID_LOOP( ret = p->desc);

	return ret;
}

/**
  * gnutls_alert_send - This function sends an alert message to the peer
  * @session: is a &gnutls_session structure.
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
int gnutls_alert_send( gnutls_session session, GNUTLS_AlertLevel level, GNUTLS_AlertDescription desc)
{
	uint8 data[2];
	int ret;
	
	data[0] = (uint8) level;
	data[1] = (uint8) desc;

	_gnutls_record_log( "REC: Sending Alert[%d|%d] - %s\n", data[0], data[1], gnutls_alert_get_name((int)data[1]));

	if ( (ret = gnutls_send_int( session, GNUTLS_ALERT, -1, data, 2)) >= 0)
		return 0;
	else
		return ret;
}

/* Sends the appropriate alert, depending
 * on the error message.
 */
/**
  * gnutls_alert_send_appropriate - This function sends an alert to the peer depending on the error code
  * @session: is a &gnutls_session structure.
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
int gnutls_alert_send_appropriate( gnutls_session session, int err) {
int ret = GNUTLS_E_UNIMPLEMENTED_FEATURE;
	switch (err) { /* send appropriate alert */
		case GNUTLS_E_DECRYPTION_FAILED:
			/* GNUTLS_A_DECRYPTION_FAILED is not sent, because
			 * it is not defined in SSL3.
			 */
			ret = gnutls_alert_send( session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_RECORD_MAC);
			break;
		case GNUTLS_E_DECOMPRESSION_FAILED:
			ret = gnutls_alert_send( session, GNUTLS_AL_FATAL, GNUTLS_A_DECOMPRESSION_FAILURE);
			break;
		case GNUTLS_E_ILLEGAL_PARAMETER:
                        ret = gnutls_alert_send( session, GNUTLS_AL_FATAL, GNUTLS_A_ILLEGAL_PARAMETER);
                        break;
		case GNUTLS_E_ASN1_ELEMENT_NOT_FOUND:
		case GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND:
		case GNUTLS_E_ASN1_DER_ERROR:
		case GNUTLS_E_ASN1_VALUE_NOT_FOUND:
		case GNUTLS_E_ASN1_GENERIC_ERROR:
		case GNUTLS_E_ASN1_VALUE_NOT_VALID:
		case GNUTLS_E_ASN1_TAG_ERROR:
		case GNUTLS_E_ASN1_TAG_IMPLICIT:
		case GNUTLS_E_ASN1_TYPE_ANY_ERROR:
		case GNUTLS_E_ASN1_SYNTAX_ERROR:
		case GNUTLS_E_ASN1_DER_OVERFLOW:
		case GNUTLS_E_NO_CERTIFICATE_FOUND:
                        ret = gnutls_alert_send( session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
                        break;
		case GNUTLS_E_UNKNOWN_CIPHER_SUITE:
		case GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM:
                        ret = gnutls_alert_send( session, GNUTLS_AL_FATAL, GNUTLS_A_HANDSHAKE_FAILURE);
                        break;
		case GNUTLS_E_UNEXPECTED_PACKET:
                        ret = gnutls_alert_send( session, GNUTLS_AL_FATAL, GNUTLS_A_UNEXPECTED_MESSAGE);
                        break;
		case GNUTLS_E_REHANDSHAKE:
                        ret = gnutls_alert_send( session, GNUTLS_AL_WARNING, GNUTLS_A_NO_RENEGOTIATION);
                        break;
		case GNUTLS_E_UNSUPPORTED_VERSION_PACKET:
                        ret = gnutls_alert_send( session, GNUTLS_AL_WARNING, GNUTLS_A_PROTOCOL_VERSION);
			break;
		case GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE:
                        ret = gnutls_alert_send( session, GNUTLS_AL_WARNING, GNUTLS_A_UNSUPPORTED_CERTIFICATE);
			break;
		case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
			ret = gnutls_alert_send( session, GNUTLS_AL_FATAL, GNUTLS_A_RECORD_OVERFLOW);
			break;
		case GNUTLS_E_INTERNAL_ERROR:
			ret = gnutls_alert_send( session, GNUTLS_AL_FATAL, GNUTLS_A_INTERNAL_ERROR);
			break;
	}
	return ret;
}

/**
  * gnutls_alert_get - Returns the last alert number received.
  * @session: is a &gnutls_session structure.
  *
  * Returns the last alert number received. This function
  * should be called if GNUTLS_E_WARNING_ALERT_RECEIVED or
  * GNUTLS_E_FATAL_ALERT_RECEIVED has been returned by a gnutls function.
  * The peer may send alerts if he thinks some things were not 
  * right. Check gnutls.h for the available alert descriptions.
  **/
GNUTLS_AlertDescription gnutls_alert_get( gnutls_session session) {
	return session->internals.last_alert;
}

