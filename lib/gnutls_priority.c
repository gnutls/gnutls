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

#include "gnutls_int.h"
#include "gnutls_algorithms.h"
#include "gnutls_errors.h"
#include <gnutls_num.h>

/**
  * gnutls_cipher_set_priority - Sets the priority on the ciphers supported by gnutls.
  * @state: is a &GNUTLS_STATE structure.
  * @list: is a 0 terminated list of BulkCipherAlgorithm elements.
  *
  * Sets the priority on the ciphers supported by gnutls.
  * Priority is higher for ciphers specified before others.
  * After specifying the ciphers you want, you should add 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  **/
int gnutls_cipher_set_priority( GNUTLS_STATE state, GNUTLS_LIST list) {
GNUTLS_LIST _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 

	num = GMIN( MAX_ALGOS, num);
	state->gnutls_internals.BulkCipherAlgorithmPriority.algorithms = num;
	
	for (i=0;i<num;i++) {
		state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority[i] = list[i];
	}
	
	return 0;
}

/**
  * gnutls_kx_set_priority - Sets the priority on the key exchange algorithms supported by gnutls.
  * @state: is a &GNUTLS_STATE structure.
  * @list: is a 0 terminated list of KXAlgorithm elements.
  *
  * Sets the priority on the key exchange algorithms supported by gnutls.
  * Priority is higher for algorithms specified before others.
  * After specifying the algorithms you want, you should add 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
 **/
int gnutls_kx_set_priority( GNUTLS_STATE state, GNUTLS_LIST list) {
GNUTLS_LIST _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 


	num = GMIN( MAX_ALGOS, num);
	state->gnutls_internals.KXAlgorithmPriority.algorithms = num;

	for (i=0;i<num;i++) {
		state->gnutls_internals.KXAlgorithmPriority.algorithm_priority[i] = list[i];
	}

	return 0;
}

/**
  * gnutls_mac_set_priority - Sets the priority on the mac algorithms supported by gnutls.
  * @state: is a &GNUTLS_STATE structure.
  * @list: is a 0 terminated list of MACAlgorithm elements.
  *
  * Sets the priority on the mac algorithms supported by gnutls.
  * Priority is higher for algorithms specified before others.
  * After specifying the algorithms you want, you should add 0.
  * Note that the priority is set on the client. The server does
  * not use the algorithm's priority except for disabling
  * algorithms that were not specified.
  **/
int gnutls_mac_set_priority( GNUTLS_STATE state, GNUTLS_LIST list) {
GNUTLS_LIST _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 

	
	num = GMIN( MAX_ALGOS, num);
	state->gnutls_internals.MACAlgorithmPriority.algorithms = num;

	for (i=0;i<num;i++) {
		state->gnutls_internals.MACAlgorithmPriority.algorithm_priority[i] = list[i];
	}

	return 0;
}

/**
  * gnutls_compression_set_priority - Sets the priority on the compression algorithms supported by gnutls.
  * @state: is a &GNUTLS_STATE structure.
  * @list: is a 0 terminated list of CompressionMethod elements.
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
int gnutls_compression_set_priority( GNUTLS_STATE state, GNUTLS_LIST list) {
GNUTLS_LIST _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 
	
	num = GMIN( MAX_ALGOS, num);
	state->gnutls_internals.CompressionMethodPriority.algorithms = num;

	for (i=0;i<num;i++) {
		state->gnutls_internals.CompressionMethodPriority.algorithm_priority[i] = list[i];
	}
	return 0;
}

/**
  * gnutls_protocol_set_priority - Sets the priority on the protocol versions supported by gnutls.
  * @state: is a &GNUTLS_STATE structure.
  * @list: is a 0 terminated list of GNUTLS_Version elements.
  *
  * Sets the priority on the protocol versions supported by gnutls.
  * This function actually enables or disables protocols. Newer protocol
  * versions always have highest priority.
  *
  **/
int gnutls_protocol_set_priority( GNUTLS_STATE state, GNUTLS_LIST list) {
GNUTLS_LIST _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 

	
	num = GMIN( MAX_ALGOS, num);
	state->gnutls_internals.ProtocolPriority.algorithms = num;

	for (i=0;i<num;i++) {
		state->gnutls_internals.ProtocolPriority.algorithm_priority[i] = list[i];
	}

	/* set the current version to the first in the chain.
	 * This will be overriden later.
	 */
	if (num > 0)
		_gnutls_set_current_version( state, state->gnutls_internals.ProtocolPriority.algorithm_priority[0]);

	return 0;
}

/**
  * gnutls_cert_type_set_priority - Sets the priority on the certificate types supported by gnutls.
  * @state: is a &GNUTLS_STATE structure.
  * @list: is a 0 terminated list of GNUTLS_CertificateType elements.
  *
  * Sets the priority on the certificate types supported by gnutls.
  * Priority is higher for types specified before others.
  * After specifying the types you want, you should add 0.
  * Note that the certificate type priority is set on the client. 
  * The server does not use the cert type priority except for disabling
  * types that were not specified.
  **/
int gnutls_cert_type_set_priority( GNUTLS_STATE state, GNUTLS_LIST list) {
GNUTLS_LIST _list = list;
int num=0, i;

#ifdef HAVE_LIBOPENCDK

	while( *_list != 0) {
		num++;
		++_list;
	} 

	num = GMIN( MAX_ALGOS, num);
	state->gnutls_internals.cert_type_priority.algorithms = num;

	for (i=0;i<num;i++) {
		state->gnutls_internals.cert_type_priority.algorithm_priority[i] = list[i];
	}

	return 0;

#endif

	return GNUTLS_E_UNIMPLEMENTED_FEATURE;

}
