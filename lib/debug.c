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

#include <stdio.h>
#include <stdlib.h>
#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"

#ifdef DEBUG

void _gnutls_dump_mpi(char* prefix, MPI a)
{
	char buf[400];
	size_t n = sizeof buf;
	
	if (gcry_mpi_print(GCRYMPI_FMT_HEX, buf, &n, a))
		strcpy(buf, "[can't print value]");
	fprintf(stderr, "MPI: length: %d\n\t%s%s\n", (n-1)/2, prefix, buf);
}


char *_gnutls_bin2hex(const unsigned char *old, const size_t oldlen)
{
	unsigned char *new = NULL;
	int i, j;

	new = calloc(1, oldlen * 2 * sizeof(char) + 1);
	if (!new)
		return (new);

	for (i = j = 0; i < oldlen; j+=2) {
		sprintf(&new[j], "%.2x", old[i]);
		i++;
	}
	new[j] = '\0';

	return (new);
}

void _gnutls_print_state(GNUTLS_STATE state)
{

	fprintf(stderr, "GNUTLS State:\n");
	fprintf(stderr, "Connection End: %d\n",
		state->security_parameters.entity);
	fprintf(stderr, "Cipher Algorithm: %d\n",
		state->security_parameters.bulk_cipher_algorithm);
	fprintf(stderr, "Key Size: %d\n",
		state->security_parameters.key_size);
	fprintf(stderr, "Key Material: %d\n",
		state->security_parameters.key_material_length);
	fprintf(stderr, "MAC algorithm: %d\n",
		state->security_parameters.mac_algorithm);
	fprintf(stderr, "Hash size: %d\n",
		state->security_parameters.hash_size);
	fprintf(stderr, "Compression Algorithm: %d\n",
		state->security_parameters.compression_algorithm);
	fprintf(stderr, "\n");

}

char* _gnutls_alert2str( int alert) {
static char str[512];

	switch(alert) {
		case GNUTLS_CLOSE_NOTIFY:
			strcpy(str, "Close Notify");
			break;
		case GNUTLS_UNEXPECTED_MESSAGE:
			strcpy(str, "Unexpected message");
			break;
		case GNUTLS_BAD_RECORD_MAC:
			strcpy(str, "Bad record MAC");
			break;

		case GNUTLS_DECRYPTION_FAILED:
			strcpy(str, "Decryption Failed");
			break;
		case GNUTLS_RECORD_OVERFLOW:
			strcpy(str, "Record Overflow");
			break;

		case GNUTLS_DECOMPRESSION_FAILURE:
			strcpy(str, "Decompression Failed");
			break;

		case GNUTLS_HANDSHAKE_FAILURE:
			strcpy(str, "Handshake failed");
			break;
		case GNUTLS_BAD_CERTIFICATE:
			strcpy(str, "Certificate is bad");
			break;
		case GNUTLS_UNSUPPORTED_CERTIFICATE:
			strcpy(str, "Certificate is not supported");
			break;
		case GNUTLS_CERTIFICATE_REVOKED:
			strcpy(str, "Certificate was revoked");
			break;
		case GNUTLS_CERTIFICATE_EXPIRED:
			strcpy(str, "Certificate is expired");
			break;
		case GNUTLS_CERTIFICATE_UNKNOWN:
			strcpy(str, "Unknown Certificate");
			break;
		case GNUTLS_ILLEGAL_PARAMETER:
			strcpy(str, "Illegal Parameter");
			break;
		case GNUTLS_UNKNOWN_CA:
			strcpy(str, "CA is not known");
			break;
		case GNUTLS_ACCESS_DENIED:
			strcpy(str, "Access was denied");
			break;
		case GNUTLS_DECODE_ERROR:
			strcpy(str, "Decode error");
			break;
		case GNUTLS_DECRYPT_ERROR:
			strcpy(str, "Decrypt error");
			break;
		case GNUTLS_EXPORT_RESTRICTION:
			strcpy(str, "Export Restriction");
			break;
		case GNUTLS_PROTOCOL_VERSION:
			strcpy(str, "Error in protocol version");
			break;
		case GNUTLS_INSUFFICIENT_SECURITY:
			strcpy(str, "Insufficient Security");
			break;
		case GNUTLS_USER_CANCELED:
			strcpy(str, "User Canceled");
			break;
		case GNUTLS_NO_RENEGOTIATION:
			strcpy(str, "No renegotiation is allowed");
			break;
		default:
			strcpy(str, "Unknown Alert");
			
	}	
	return str;	
	
}


char* _gnutls_packet2str( int packet) {
static char str[512];

	switch(packet) {
		case GNUTLS_CHANGE_CIPHER_SPEC:
			strcpy(str, "Change Cipher Spec");
			break;		
		case GNUTLS_ALERT:
			strcpy(str, "Alert");
			break;		
		case GNUTLS_HANDSHAKE:
			strcpy(str, "Handshake");
			break;
		case GNUTLS_APPLICATION_DATA:
			strcpy(str, "Application Data");
			break;

		default:
			strcpy(str, "Unknown Packet");
			
	}	
	return str;	
	
}

char* _gnutls_handshake2str( int handshake) {
static char str[512];

	switch(handshake) {
		case GNUTLS_HELLO_REQUEST:
			strcpy(str, "HELLO REQUEST");
			break;		
		case GNUTLS_CLIENT_HELLO:
			strcpy(str, "CLIENT HELLO");
			break;		
		case GNUTLS_SERVER_HELLO:
			strcpy(str, "SERVER HELLO");
			break;
		case GNUTLS_CERTIFICATE:
			strcpy(str, "CERTIFICATE");
			break;
		case GNUTLS_SERVER_KEY_EXCHANGE:
			strcpy(str, "SERVER KEY EXCHANGE");
			break;
		case GNUTLS_CERTIFICATE_REQUEST:
			strcpy(str, "CERTIFICATE REQUEST");
			break;
		case GNUTLS_SERVER_HELLO_DONE:
			strcpy(str, "SERVER HELLO DONE");
			break;
		case GNUTLS_CERTIFICATE_VERIFY:
			strcpy(str, "CERTIFICATE VERIFY");
			break;
		case GNUTLS_CLIENT_KEY_EXCHANGE:
			strcpy(str, "CLIENT KEY EXCHANGE");
			break;
		case GNUTLS_FINISHED:
			strcpy(str, "FINISHED");
			break;
		default:
			strcpy(str, "Unknown Handshake");
			
	}	
	return str;	
	
}
#endif
