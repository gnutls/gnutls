/*
 *      Copyright (C) 2000,2002,2003 Nikos Mavroyanopoulos
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
#include "gnutls_int.h"
#include "gnutls_errors.h"
#include <gcrypt.h>

#ifdef DEBUG


void _gnutls_print_state(gnutls_session session)
{

	_gnutls_debug_log( "GNUTLS State:\n");
	_gnutls_debug_log( "Connection End: %d\n",
		session->security_parameters.entity);
	_gnutls_debug_log( "Cipher Algorithm: %d\n",
		session->security_parameters.read_bulk_cipher_algorithm);
	_gnutls_debug_log( "MAC algorithm: %d\n",
		session->security_parameters.read_mac_algorithm);
	_gnutls_debug_log( "Compression Algorithm: %d\n",
		session->security_parameters.read_compression_algorithm);
	_gnutls_debug_log( "\n");

}

#endif

const char* _gnutls_packet2str( int packet) {
	switch(packet) {
		case GNUTLS_CHANGE_CIPHER_SPEC:
			return "Change Cipher Spec";
		case GNUTLS_ALERT:
			return "Alert";
		case GNUTLS_HANDSHAKE:
			return "Handshake";
		case GNUTLS_APPLICATION_DATA:
			return "Application Data";

		default:
			return "Unknown Packet";
	}	
}

const char* _gnutls_handshake2str( int handshake) {

	switch(handshake) {
		case GNUTLS_HELLO_REQUEST:
			return "HELLO REQUEST";
			break;
		case GNUTLS_CLIENT_HELLO:
			return "CLIENT HELLO";
			break;		
		case GNUTLS_SERVER_HELLO:
			return "SERVER HELLO";
			break;
		case GNUTLS_CERTIFICATE_PKT:
			return "CERTIFICATE";
			break;
		case GNUTLS_SERVER_KEY_EXCHANGE:
			return "SERVER KEY EXCHANGE";
			break;
		case GNUTLS_CERTIFICATE_REQUEST:
			return "CERTIFICATE REQUEST";
			break;
		case GNUTLS_SERVER_HELLO_DONE:
			return "SERVER HELLO DONE";
			break;
		case GNUTLS_CERTIFICATE_VERIFY:
			return "CERTIFICATE VERIFY";
			break;
		case GNUTLS_CLIENT_KEY_EXCHANGE:
			return "CLIENT KEY EXCHANGE";
			break;
		case GNUTLS_FINISHED:
			return "FINISHED";
			break;
		default:
			return "Unknown Handshake packet";
			
	}	
}

void _gnutls_dump_mpi(char* prefix, GNUTLS_MPI a)
{
	char buf[1024];
	size_t n = sizeof buf;
	
	if (gcry_mpi_print(GCRYMPI_FMT_HEX, buf, n, &n, a))
		strcpy(buf, "[can't print value]"); /* Flawfinder: ignore */
	_gnutls_hard_log( "GNUTLS_MPI: length: %d\n\t%s%s\n", (n-1)/2, prefix, buf);
}
