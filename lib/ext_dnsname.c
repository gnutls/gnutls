/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "auth_x509.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"

/* This file should have been called ext_name_ind.c
 * 
 * In case of a server: if a DNSNAME extension type is received then it stores
 * into the state the value of DNSNAME. The server may use gnutls_ext_get_name_ind(),
 * in order to access it.
 *
 * In case of a client: If a proper DNSNAME extension type is found in the state then
 * it sends the extension to the peer.
 *
 */

int _gnutls_name_ind_recv_params( GNUTLS_STATE state, const opaque* data, int data_size) {
	uint16 len;
	if (state->security_parameters.entity == GNUTLS_SERVER) {
		if (data_size > 0) {
			len = READuint16( data);
			if (len > data_size || len >= MAX_DNSNAME_SIZE || len < 3) {
				gnutls_assert();
				return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
			}
			
			switch(data[2]) {
				case 0:
					if (sizeof( state->security_parameters.extensions.name.dnsname) > len-2) {
						state->security_parameters.extensions.name.type = GNUTLS_DNSNAME;
						/* note that dnsname is in UTF-8
						 * format.
						 */
						memcpy( state->security_parameters.extensions.name.dnsname, &data[3], len-1);
						state->security_parameters.extensions.name.dnsname[len-1]=0; /* null terminated */
						break;
					}
			}
		}
	}
	return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated localy
 */
int _gnutls_name_ind_send_params( GNUTLS_STATE state, opaque** data) {
	uint16 len;
	/* this function sends the client extension data (dnsname) */
	if (state->security_parameters.entity == GNUTLS_CLIENT) {

		switch (state->security_parameters.extensions.name.type) {
			case GNUTLS_DNSNAME:
				if ( (len = strlen(state->security_parameters.extensions.name.dnsname)) > 0) { /* send dnsname */
					(*data) = gnutls_malloc(len+3); /* hold the size and the type also */
					
					WRITEuint16( len+1, *data);
					(*data)[2] = 0;
					memcpy( &(*data)[3], state->security_parameters.extensions.name.dnsname, len);
					return len + 3;
				}
				return 0;
			default:
				return GNUTLS_E_UNIMPLEMENTED_FEATURE;
		}
	}
	return GNUTLS_E_UNKNOWN_ERROR;
}

/**
  * gnutls_ext_get_name_ind - Used to get the name indicator send by a client
  * @state: is a &GNUTLS_STATE structure.
  * @ind: is a name indicator type
  *
  * This function will allow you to get the name indication (if any),
  * a client has sent. The name indication may be any of the enumeration
  * GNUTLS_NAME_IND.
  *
  * If 'ind' is GNUTLS_DNSNAME, then this function is to be used by servers 
  * that support virtual hosting.
  * The client may give the server the dnsname they connected to.
  *
  * The return value depends on the 'ind' type. In case of GNUTLS_DNSNAME,
  * it is a null terminated string. If no name indication was given (maybe the client
  * does not support this extension) this function returns NULL.
  *
  **/
const void* gnutls_ext_get_name_ind( GNUTLS_STATE state, GNUTLS_NAME_IND ind) {
	if (state->security_parameters.entity==GNUTLS_CLIENT) return NULL;

	switch( ind) {
		case GNUTLS_DNSNAME:
			if ( state->security_parameters.extensions.name.dnsname[0] == 0 ||
				state->security_parameters.extensions.name.type!=ind) return NULL;
			return state->security_parameters.extensions.name.dnsname;
	}
	
	return NULL;
}

/**
  * gnutls_ext_set_name_ind - Used to set a name indicator to be sent as an extension
  * @state: is a &GNUTLS_STATE structure.
  * @name: is a null terminated string that contains the dns name.
  * @ind: specified the indicator type
  *
  * This function is to be used by clients that want to inform 
  * ( via a TLS extension mechanism) the server of the name they
  * connected to. This should be used by clients that connect
  * to servers that do virtual hosting.
  *
  * The value of 'name' depends on the 'ind' type. In case of GNUTLS_DNSNAME,
  * a null terminated string is expected. 
  *
  **/
int gnutls_ext_set_name_ind( GNUTLS_STATE state, GNUTLS_NAME_IND ind, const void* name) {
const char* dnsname;

	if (state->security_parameters.entity==GNUTLS_SERVER) return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	state->security_parameters.extensions.name.type = ind;
	
	switch(ind) {
		case GNUTLS_DNSNAME:
			dnsname = name;
			if (strlen( dnsname) >= MAX_DNSNAME_SIZE) return GNUTLS_E_MEMORY_ERROR;
			strcpy( state->security_parameters.extensions.name.dnsname, dnsname);
			return 0;
	}
	
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}
