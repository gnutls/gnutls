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
#include "gnutls_extensions.h"
#include "gnutls_errors.h"
#include "ext_srp.h"
#include "ext_dnsname.h"
#include "gnutls_num.h"

/* Key Exchange Section */
#define GNUTLS_EXTENSION_ENTRY(type, ext_func_recv, ext_func_send) \
	{ #type, type, ext_func_recv, ext_func_send }

typedef struct {
	char *name;
	int type;
	int (*gnutls_ext_func_recv)( GNUTLS_STATE, const opaque*, int); /* recv data */
	int (*gnutls_ext_func_send)( GNUTLS_STATE, opaque**); /* send data */
} gnutls_extension_entry;

#define MAX_EXT 20 /* maximum supported extension */
static gnutls_extension_entry extensions[] = {
	GNUTLS_EXTENSION_ENTRY( GNUTLS_EXTENSION_SRP, _gnutls_srp_recv_params, _gnutls_srp_send_params),
	GNUTLS_EXTENSION_ENTRY( GNUTLS_EXTENSION_DNSNAME, _gnutls_dnsname_recv_params, _gnutls_dnsname_send_params),
	{0}
};

#define GNUTLS_EXTENSION_LOOP2(b) \
        gnutls_extension_entry *p; \
                for(p = extensions; p->name != NULL; p++) { b ; }

#define GNUTLS_EXTENSION_LOOP(a) \
                        GNUTLS_EXTENSION_LOOP2( if(p->type == type) { a; break; } )


/* EXTENSION functions */

void* _gnutls_ext_func_recv(int type)
{
	void* ret=NULL;
	GNUTLS_EXTENSION_LOOP(ret = p->gnutls_ext_func_recv);
	return ret;

}
void* _gnutls_ext_func_send(int type)
{
	void* ret=NULL;
	GNUTLS_EXTENSION_LOOP(ret = p->gnutls_ext_func_send);
	return ret;

}

const char *_gnutls_extension_get_name(int type)
{
	char *ret = NULL;

	/* avoid prefix */
	GNUTLS_EXTENSION_LOOP(ret = p->name + sizeof("EXTENSION_") - 1);

	return ret;
}

int _gnutls_parse_extensions( GNUTLS_STATE state, const opaque* data, int data_size) {
int next;
int pos=0;
uint8 type;
const opaque* sdata;
int (*ext_func_recv)( GNUTLS_STATE, const opaque*, int);
uint16 size;

	if (data_size < 2) return 0;

	next = READuint16( data);
	pos+=2;

	if (data_size < next) return 0;
	
	do {
		next--; if (next < 0) return 0;
		memcpy( &type, &data[pos], 1);
		pos++;

		next-=2; if (next < 0) return 0;

		size = READuint16(&data[pos]);
		pos+=2;
				
		sdata = &data[pos];
		pos+=size;
		next-=size; if (next < 0) return 0;
		
		ext_func_recv = _gnutls_ext_func_recv(type);
		if (ext_func_recv == NULL) continue;
		ext_func_recv( state, sdata, size);
		
	} while(next > 2);

	return 0;

}

int _gnutls_gen_extensions( GNUTLS_STATE state, opaque** data) {
int next, size;
uint16 pos=0;
opaque* sdata;
int (*ext_func_send)( GNUTLS_STATE, opaque**);


	(*data) = gnutls_malloc(2); /* allocate size for size */
	pos+=2;
	
	next = MAX_EXT; /* maximum supported extensions */
	do {
		next--;
		ext_func_send = _gnutls_ext_func_send(next);
		if (ext_func_send == NULL) continue;
		size = ext_func_send( state, &sdata);
		if (size > 0) {
			(*data) = gnutls_realloc( (*data), pos+size+3);
			(*data)[pos++] = (uint8) next; /* set type */

			WRITEuint16( size, &(*data)[pos]);
			pos+=2;
			
			memcpy( &(*data)[pos], sdata, size);
			pos+=size;
			gnutls_free(sdata);
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

/**
  * gnutls_ext_get_dnsname - Used to get the dnsname a client connected to
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function is to be used by servers that support virtual hosting.
  * The client may give the server the dnsname they connected to.
  * if no name was given this function returns NULL.
  *
  **/
const char* gnutls_ext_get_dnsname( GNUTLS_STATE state) {
	if (state->security_parameters.entity==GNUTLS_CLIENT) return NULL;

	if ( state->security_parameters.extensions.dnsname[0] == 0) return NULL;

	return state->security_parameters.extensions.dnsname;
}

/**
  * gnutls_ext_set_dnsname - Used to set the dnsname as an extension
  * @state: is a &GNUTLS_STATE structure.
  * @dnsname: is a null terminated string that contains the dns name.
  *
  * This function is to be used by clients that want to inform 
  * ( via a TLS extension mechanism) the server of the name they
  * connected to. This should be used by clients that connect
  * to servers that do virtual hosting.
  **/
int gnutls_ext_set_dnsname( GNUTLS_STATE state, const char* dnsname) {

	if (state->security_parameters.entity==GNUTLS_SERVER) return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	
	if (strlen( dnsname) >= MAX_DNSNAME_SIZE) return GNUTLS_E_MEMORY_ERROR;

	strcpy( state->security_parameters.extensions.dnsname, dnsname);

	return 0;
}
