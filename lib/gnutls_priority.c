/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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

/* Here lies the code of the gnutls_*_set_priority() functions.
 */

#include "gnutls_int.h"
#include "gnutls_algorithms.h"
#include "gnutls_errors.h"
#include <gnutls_num.h>

/**
  * gnutls_cipher_set_priority - Sets the priority on the ciphers supported by gnutls.
  * @session: is a &gnutls_session structure.
  * @list: is a 0 terminated list of gnutls_cipher_algorithm elements.
  *
  * Sets the priority on the ciphers supported by gnutls.
  * Priority is higher for ciphers specified before others.
  * After specifying the ciphers you want, you should add 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  **/
int gnutls_cipher_set_priority( gnutls_session session, gnutls_list list) {
gnutls_list _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 

	num = GMIN( MAX_ALGOS, num);
	session->internals.cipher_algorithm_priority.algorithms = num;
	
	for (i=0;i<num;i++) {
		session->internals.cipher_algorithm_priority.priority[i] = list[i];
	}
	
	return 0;
}

/**
  * gnutls_kx_set_priority - Sets the priority on the key exchange algorithms supported by gnutls.
  * @session: is a &gnutls_session structure.
  * @list: is a 0 terminated list of gnutls_kx_algorithm elements.
  *
  * Sets the priority on the key exchange algorithms supported by gnutls.
  * Priority is higher for algorithms specified before others.
  * After specifying the algorithms you want, you should add 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
 **/
int gnutls_kx_set_priority( gnutls_session session, gnutls_list list) {
gnutls_list _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 


	num = GMIN( MAX_ALGOS, num);
	session->internals.kx_algorithm_priority.algorithms = num;

	for (i=0;i<num;i++) {
		session->internals.kx_algorithm_priority.priority[i] = list[i];
	}

	return 0;
}

/**
  * gnutls_mac_set_priority - Sets the priority on the mac algorithms supported by gnutls.
  * @session: is a &gnutls_session structure.
  * @list: is a 0 terminated list of gnutls_mac_algorithm elements.
  *
  * Sets the priority on the mac algorithms supported by gnutls.
  * Priority is higher for algorithms specified before others.
  * After specifying the algorithms you want, you should add 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  **/
int gnutls_mac_set_priority( gnutls_session session, gnutls_list list) {
gnutls_list _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 

	
	num = GMIN( MAX_ALGOS, num);
	session->internals.mac_algorithm_priority.algorithms = num;

	for (i=0;i<num;i++) {
		session->internals.mac_algorithm_priority.priority[i] = list[i];
	}

	return 0;
}

/**
  * gnutls_compression_set_priority - Sets the priority on the compression algorithms supported by gnutls.
  * @session: is a &gnutls_session structure.
  * @list: is a 0 terminated list of gnutls_compression_method elements.
  *
  * Sets the priority on the compression algorithms supported by gnutls.
  * Priority is higher for algorithms specified before others.
  * After specifying the algorithms you want, you should add 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  *
  * TLS 1.0 does not define any compression algorithms except
  * NULL. Other compression algorithms are to be considered
  * as gnutls extensions.
  *
  **/
int gnutls_compression_set_priority( gnutls_session session, gnutls_list list) {
gnutls_list _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 
	
	num = GMIN( MAX_ALGOS, num);
	session->internals.compression_method_priority.algorithms = num;

	for (i=0;i<num;i++) {
		session->internals.compression_method_priority.priority[i] = list[i];
	}
	return 0;
}

/**
  * gnutls_protocol_set_priority - Sets the priority on the protocol versions supported by gnutls.
  * @session: is a &gnutls_session structure.
  * @list: is a 0 terminated list of gnutls_protocol_version elements.
  *
  * Sets the priority on the protocol versions supported by gnutls.
  * This function actually enables or disables protocols. Newer protocol
  * versions always have highest priority.
  *
  **/
int gnutls_protocol_set_priority( gnutls_session session, gnutls_list list) {
gnutls_list _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 

	
	num = GMIN( MAX_ALGOS, num);
	session->internals.protocol_priority.algorithms = num;

	for (i=0;i<num;i++) {
		session->internals.protocol_priority.priority[i] = list[i];
	}

	/* set the current version to the first in the chain.
	 * This will be overriden later.
	 */
	if (num > 0)
		_gnutls_set_current_version( session, session->internals.protocol_priority.priority[0]);

	return 0;
}

/**
  * gnutls_certificate_type_set_priority - Sets the priority on the certificate types supported by gnutls.
  * @session: is a &gnutls_session structure.
  * @list: is a 0 terminated list of gnutls_certificate_type elements.
  *
  * Sets the priority on the certificate types supported by gnutls.
  * Priority is higher for types specified before others.
  * After specifying the types you want, you should add 0.
  * Note that the certificate type priority is set on the client. 
  * The server does not use the cert type priority except for disabling
  * types that were not specified.
  **/
int gnutls_certificate_type_set_priority( gnutls_session session, gnutls_list list) {
#ifdef HAVE_LIBOPENCDK
gnutls_list _list = list;
int num=0, i;


	while( *_list != 0) {
		num++;
		++_list;
	} 

	num = GMIN( MAX_ALGOS, num);
	session->internals.cert_type_priority.algorithms = num;

	for (i=0;i<num;i++) {
		session->internals.cert_type_priority.priority[i] = list[i];
	}

	return 0;

#endif

	return GNUTLS_E_UNIMPLEMENTED_FEATURE;

}
