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

#include "gnutls_int.h"
#include "gnutls_extensions.h"
#include "gnutls_errors.h"
#include "ext_srp.h"
#include "ext_max_record.h"
#include <ext_cert_type.h>
#include "gnutls_num.h"

/* Key Exchange Section */
#define GNUTLS_EXTENSION_ENTRY(type, ext_func_recv, ext_func_send) \
	{ #type, type, ext_func_recv, ext_func_send }

typedef struct {
	char *name;
	uint16 type;
	int (*gnutls_ext_func_recv)( GNUTLS_STATE, const opaque*, int); /* recv data */
	int (*gnutls_ext_func_send)( GNUTLS_STATE, opaque*, int); /* send data */
} gnutls_extension_entry;

static gnutls_extension_entry extensions[] = {
#ifdef ENABLE_SRP
	GNUTLS_EXTENSION_ENTRY( GNUTLS_EXTENSION_SRP, _gnutls_srp_recv_params, _gnutls_srp_send_params),
#endif
	GNUTLS_EXTENSION_ENTRY( GNUTLS_EXTENSION_MAX_RECORD_SIZE, _gnutls_max_record_recv_params, _gnutls_max_record_send_params),
	GNUTLS_EXTENSION_ENTRY( GNUTLS_EXTENSION_CERT_TYPE, _gnutls_cert_type_recv_params, _gnutls_cert_type_send_params),
	{0}
};

#define GNUTLS_EXTENSION_LOOP2(b) \
        gnutls_extension_entry *p; \
                for(p = extensions; p->name != NULL; p++) { b ; }

#define GNUTLS_EXTENSION_LOOP(a) \
                        GNUTLS_EXTENSION_LOOP2( if(p->type == type) { a; break; } )


/* EXTENSION functions */

void* _gnutls_ext_func_recv(uint16 type)
{
	void* ret=NULL;
	GNUTLS_EXTENSION_LOOP(ret = p->gnutls_ext_func_recv);
	return ret;

}
void* _gnutls_ext_func_send(uint16 type)
{
	void* ret=NULL;
	GNUTLS_EXTENSION_LOOP(ret = p->gnutls_ext_func_send);
	return ret;

}

const char *_gnutls_extension_get_name(uint16 type)
{
	char *ret = NULL;

	/* avoid prefix */
	GNUTLS_EXTENSION_LOOP(ret = p->name + sizeof("EXTENSION_") - 1);

	return ret;
}

/* Checks if the extension we just received is one of the 
 * requested ones. Otherwise it's a fatal error.
 */
static int _gnutls_extension_list_check( GNUTLS_STATE state, uint8 type) {
int i;
	if (state->security_parameters.entity==GNUTLS_CLIENT) {
		for(i=0;i<state->gnutls_internals.extensions_sent_size;i++) {
			if (type==state->gnutls_internals.extensions_sent[i])
				return 0; /* ok found */
		}
		return GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION;
	}

	return 0;
}

int _gnutls_parse_extensions( GNUTLS_STATE state, const opaque* data, int data_size) {
int next, ret;
int pos=0;
uint16 type;
const opaque* sdata;
int (*ext_func_recv)( GNUTLS_STATE, const opaque*, int);
uint16 size;

#ifdef DEBUG
int i;

	if (state->security_parameters.entity==GNUTLS_CLIENT)
		for (i=0;i<state->gnutls_internals.extensions_sent_size;i++) {
			_gnutls_log("EXT: expecting extension %d\n", state->gnutls_internals.extensions_sent[i]);
		}
#endif

	DECR_LENGTH_RET( data_size, 2, 0);
	next = READuint16( data);
	pos+=2;

	DECR_LENGTH_RET( data_size, next, 0);
	
	do {
		DECR_LENGTH_RET( next, 1, 0);
		type = READuint16( &data[pos]);
		pos+=2;
		
		if ( (ret=_gnutls_extension_list_check( state, type)) < 0) {
			gnutls_assert();
			return ret;
		}

		DECR_LENGTH_RET( next, 2, 0);
		size = READuint16(&data[pos]);
		pos+=2;
				
		DECR_LENGTH_RET( next, size, 0);
		sdata = &data[pos];
		pos+=size;
		
		ext_func_recv = _gnutls_ext_func_recv(type);
		if (ext_func_recv == NULL) continue;
		if ( (ret=ext_func_recv( state, sdata, size)) < 0) {
			gnutls_assert();
			return ret;
		}
		
	} while(next > 2);

	return 0;

}

/* Adds the extension we want to send in the extensions list.
 * This list is used to check whether the (later) received
 * extensions are the ones we requested.
 */
static void _gnutls_extension_list_add( GNUTLS_STATE state, uint8 type) {

	if (state->security_parameters.entity==GNUTLS_CLIENT) {
		if (state->gnutls_internals.extensions_sent_size <
			sizeof(state->gnutls_internals.extensions_sent)) {
	
			state->gnutls_internals.extensions_sent[state->gnutls_internals.extensions_sent_size] = type;
			state->gnutls_internals.extensions_sent_size++;
		} else {
#ifdef DEBUG
			_gnutls_log("EXT: Increase MAX_EXT_TYPES\n");
#endif
		}
	}

	return;
}

int _gnutls_gen_extensions( GNUTLS_STATE state, opaque** data) {
int next, size;
uint16 pos=0;
opaque sdata[1024];
int sdata_size = sizeof(sdata);
int (*ext_func_send)( GNUTLS_STATE, opaque*, int);


	(*data) = gnutls_malloc(2); /* allocate size for size */
	pos+=2;
	
	if ((*data)==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	next = MAX_EXT_TYPES; /* maximum supported extensions */
	do {
		next--;
		ext_func_send = _gnutls_ext_func_send(next);
		if (ext_func_send == NULL) continue;
		size = ext_func_send( state, sdata, sdata_size);

		if (size > 0) {
			(*data) = gnutls_realloc( (*data), pos+size+4);
			if ((*data)==NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}

			/* write extension type */
			WRITEuint16( next, &(*data)[pos]);
			pos+=2;
			
			/* write size */
			WRITEuint16( size, &(*data)[pos]);
			pos+=2;
			
			memcpy( &(*data)[pos], sdata, size);
			pos+=size;
			
			/* add this extension to the extension list
			 */
			_gnutls_extension_list_add( state, next);
		}
		
	} while(next >= 0);

	size = pos;
	pos-=2; /* remove the size of the size header! */

	WRITEuint16( pos, (*data));

	if (size==2) { /* empty */
		size = 0;
		gnutls_free(*data);
		(*data) = NULL;
	}
	return size;

}

