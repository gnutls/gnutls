/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
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
#include "gnutls_errors.h"
#include "gnutls_num.h"

/* 
 * In case of a server: if a NAME_DNS extension type is received then it stores
 * into the session the value of NAME_DNS. The server may use gnutls_ext_get_server_name(),
 * in order to access it.
 *
 * In case of a client: If a proper NAME_DNS extension type is found in the session then
 * it sends the extension to the peer.
 *
 */

int _gnutls_server_name_recv_params(gnutls_session session,
				    const opaque * data, int data_size)
{
   int i;
   const char *p;
   uint16 len;
   int server_names = 0;

   if (session->security_parameters.entity == GNUTLS_SERVER) {
      DECR_LEN(data_size, 2);
      len = _gnutls_read_uint16(data);

      i = data_size;
      p = data + 2;

      /* Count all server_names in the packet. */
      while (i > 0) {
	 DECR_LEN(data_size, 2);
	 len = _gnutls_read_uint16(p);
	 p += 2;

	 DECR_LEN(data_size, len);
	 server_names++;

	 p += len;
	 i -= len + 2;

      }

      session->security_parameters.extensions.server_names_size =
	  server_names;
      if (server_names == 0)
	 return 0;		/* no names found */

      if (session->security_parameters.extensions.server_names)
	 free(session->security_parameters.extensions.server_names);

      session->security_parameters.extensions.server_names =
	  gnutls_malloc(server_names * sizeof(server_name_st));

      p = data + 2;
      for (i = 0; i < server_names; i++) {
	 len = _gnutls_read_uint16(p);
	 p += 2;

	 switch (*p) {
	 case 0: /* NAME_DNS */
	    if (len - 1 <= MAX_SERVER_NAME_SIZE) {
	       memcpy(session->security_parameters.extensions.
		      server_names[i].name, &p[1], len - 1);
	       session->security_parameters.extensions.server_names[i].
		   name_length = len - 1;
	       session->security_parameters.extensions.server_names[i].
		   type = GNUTLS_NAME_DNS;
	       break;
	    }
	 }

	 /* move to next record */
	 p += len;
      }
   }
   return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated localy
 */
int _gnutls_server_name_send_params(gnutls_session session, opaque * data,
				    int data_size)
{
   uint16 len;
   char *p;
   int i;
   int total_size = 0;

   /* this function sends the client extension data (dnsname) */
   if (session->security_parameters.entity == GNUTLS_CLIENT) {

      for (i = 0;
	   i < session->security_parameters.extensions.server_names_size;
	   i++) {
	 switch (session->security_parameters.extensions.server_names[i].
		 type) {
	 case GNUTLS_NAME_DNS:
	    if (session->security_parameters.extensions.server_names != NULL && (len = session->security_parameters.extensions.server_names[0].name_length) > 0) {	/* send dnsname */

	       /* UINT16: total size of all names
	        * UINT16: size of the first name
	        * UINT8: type of this extension
	        * REST of the data ( we only send one name);
	        */
	       if (data_size < len + 5) {
		  gnutls_assert();
		  return GNUTLS_E_INVALID_REQUEST;
	       }

	       p = data;

	       _gnutls_write_uint16(len + 3, p);
	       p += 2;

	       _gnutls_write_uint16(len + 1, p);
	       p += 2;

	       *p = 0;		/* NAME_DNS type */
	       p++;

	       memcpy(p,
		      session->security_parameters.extensions.
		      server_names[0].name, len);
	       len = len + 5;
	    }
	    break;
	 default:
	    return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	 }
	 data += len;
	 total_size += len;
      }
   }
   if (total_size == 0)
      return GNUTLS_E_INVALID_REQUEST;
   return total_size;
}

/**
  * gnutls_get_server_name - Used to get the server name indicator send by a client
  * @session: is a &gnutls_session structure.
  * @data: will hold the data
  * @data_length: will hold the data length. Must hold the maximum size of data.
  * @type: will hold the server name indicator type
  * @index: is the index of the server_name
  *
  * This function will allow you to get the name indication (if any),
  * a client has sent. The name indication may be any of the enumeration
  * gnutls_server_name_type.
  *
  * If 'type' is GNUTLS_NAME_DNS, then this function is to be used by servers
  * that support virtual hosting, and the data will be null terminated.
  * The client may give the server the dnsname they connected to.
  *
  * If data has not enough size to hold the server name GNUTLS_E_INVALID_REQUEST
  * is returned, and data_length will hold the required size.
  *
  * 'index' is used to retrieve more than one server names (if sent by the client).
  * The first server name has an index of 0, the second 1 and so on. If no name with the given
  * index exists GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
  *
  **/
int gnutls_get_server_name(gnutls_session session, void *data,
			   int *data_length,
			   int * type, int index)
{
   char *_data = data;
   
   if (session->security_parameters.entity == GNUTLS_CLIENT)
      return GNUTLS_E_INVALID_REQUEST;

   if (index >
       session->security_parameters.extensions.server_names_size - 1)
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

   *type =
       session->security_parameters.extensions.server_names[index].type;

   if (*data_length > /* greater since we need one extra byte for the null */
       session->security_parameters.extensions.server_names[index].
       name_length) {
      *data_length =
	  session->security_parameters.extensions.server_names[index].
	  name_length;
      memcpy(data,
	     session->security_parameters.extensions.server_names[index].
	     name, *data_length);

      if (*type == GNUTLS_NAME_DNS)	/* null terminate */
	 _data[(*data_length)] = 0;

   } else {
      *data_length =
	  session->security_parameters.extensions.server_names[index].
	  name_length;
      return GNUTLS_E_INVALID_REQUEST;
   }

   return 0;
}

/**
  * gnutls_set_server_name - Used to set a name indicator to be sent as an extension
  * @session: is a &gnutls_session structure.
  * @name: is a string that contains the server name.
  * @name_length: holds the length of name
  * @type: specifies the indicator type
  *
  * This function is to be used by clients that want to inform 
  * ( via a TLS extension mechanism) the server of the name they
  * connected to. This should be used by clients that connect
  * to servers that do virtual hosting.
  *
  * The value of 'name' depends on the 'ind' type. In case of GNUTLS_NAME_DNS,
  * a null terminated string is expected. 
  *
  **/
int gnutls_set_server_name(gnutls_session session,
			   gnutls_server_name_type type,
			   const void *name, int name_length)
{
   const char *dnsname;
   int server_names;

   if (session->security_parameters.entity == GNUTLS_SERVER)
      return GNUTLS_E_INVALID_REQUEST;

   if (name_length > MAX_SERVER_NAME_SIZE)
      return GNUTLS_E_INVALID_REQUEST;

   server_names =
       session->security_parameters.extensions.server_names_size + 1;

   session->security_parameters.extensions.server_names =
       gnutls_realloc(session->security_parameters.extensions.server_names,
		      server_names * sizeof(server_name_st));

   if (session->security_parameters.extensions.server_names == NULL)
      return GNUTLS_E_MEMORY_ERROR;

   session->security_parameters.extensions.server_names[server_names -
							1].type = type;
   memcpy(session->security_parameters.extensions.
	  server_names[server_names - 1].name, name, name_length);
   session->security_parameters.extensions.server_names[server_names -
							1].name_length =
       name_length;

   session->security_parameters.extensions.server_names_size++;

   return 0;
}
