/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

/* This file contains the code for the Max Record Size TLS extension.
 */

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"
#include <ext_max_record.h>

/* 
 * In case of a server: if a MAX_RECORD_SIZE extension type is received then it stores
 * into the session the new value. The server may use gnutls_get_max_record_size(),
 * in order to access it.
 *
 * In case of a client: If a different max record size (than the default) has
 * been specified then it sends the extension.
 *
 */

int _gnutls_max_record_recv_params( gnutls_session session, const opaque* data, int data_size) {
	ssize_t new_size;
	
	if (session->security_parameters.entity == GNUTLS_SERVER) {
		if (data_size > 0) {
			DECR_LEN( data_size, 1);
			
			new_size = _gnutls_mre_num2record(data[0]);

			if (new_size < 0) {
				gnutls_assert();
				return new_size;
			}

			session->security_parameters.max_record_send_size = new_size;
			session->security_parameters.max_record_recv_size = new_size;
		}
	} else { /* CLIENT SIDE - we must check if the sent record size is the right one 
	          */
		if (data_size > 0) {

			if ( data_size != 1) {
				gnutls_assert();
				return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
			}

			new_size = _gnutls_mre_num2record(data[0]);

			if (new_size < 0 || new_size != session->internals.proposed_record_size) {
				gnutls_assert();
				return GNUTLS_E_ILLEGAL_PARAMETER;
			} else {
				session->security_parameters.max_record_recv_size = session->internals.proposed_record_size;
			}

		}
	
	
	}
	
	return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated localy
 */
int _gnutls_max_record_send_params( gnutls_session session, opaque* data, int data_size) {
	uint16 len;
	/* this function sends the client extension data (dnsname) */
	if (session->security_parameters.entity == GNUTLS_CLIENT) {

		if (session->internals.proposed_record_size != DEFAULT_MAX_RECORD_SIZE) {
			gnutls_assert();
			
			len = 1;
			if (data_size < len) {
				gnutls_assert();
				return GNUTLS_E_INVALID_REQUEST;
			}
			
			data[0] = (uint8) _gnutls_mre_record2num( session->internals.proposed_record_size);
			return len;
		}

	} else { /* server side */

		if (session->security_parameters.max_record_recv_size != DEFAULT_MAX_RECORD_SIZE) {
			len = 1;
			if (data_size < len) {
				gnutls_assert();
				return GNUTLS_E_INVALID_REQUEST;
			}
			
			data[0] = (uint8) _gnutls_mre_record2num( session->security_parameters.max_record_recv_size);
			return len;
		}	
	
	
	}

	return 0;
}

/* Maps numbers to record sizes according to the
 * extensions draft.
 */
int _gnutls_mre_num2record( int num) {
	switch( num) {
	case 1:
		return 512;
	case 2:
		return 1024;
	case 3:
		return 2048;
	case 4:
		return 4096;
	default:
		return GNUTLS_E_ILLEGAL_PARAMETER;
	}
}

/* Maps record size to numbers according to the
 * extensions draft.
 */
int _gnutls_mre_record2num( uint16 record_size) {
	switch(record_size) {
	case 512:
		return 1;
	case 1024:
		return 2;
	case 2048:
		return 3;
	case 4096:
		return 4;
	default:
		return GNUTLS_E_ILLEGAL_PARAMETER;
	}

}
