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

/* the prototypes for these are in gnutls.h */

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

	if (state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority!=NULL)
		gnutls_free(state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority);

	state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority = gnutls_malloc(sizeof(int)*num);
	if (state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority == NULL)
		return GNUTLS_E_MEMORY_ERROR;
		
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


	if (state->gnutls_internals.KXAlgorithmPriority.algorithm_priority!=NULL)
		gnutls_free(state->gnutls_internals.KXAlgorithmPriority.algorithm_priority);
	state->gnutls_internals.KXAlgorithmPriority.algorithm_priority = gnutls_malloc(sizeof(int)*num);
	if (state->gnutls_internals.KXAlgorithmPriority.algorithm_priority==NULL)
		return GNUTLS_E_MEMORY_ERROR;
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

	
	if (state->gnutls_internals.MACAlgorithmPriority.algorithm_priority!=NULL)
		gnutls_free(state->gnutls_internals.MACAlgorithmPriority.algorithm_priority);	
	state->gnutls_internals.MACAlgorithmPriority.algorithm_priority = gnutls_malloc(sizeof(int)*num);
	if (state->gnutls_internals.MACAlgorithmPriority.algorithm_priority ==NULL)
		return GNUTLS_E_MEMORY_ERROR;
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
  **/
int gnutls_compression_set_priority( GNUTLS_STATE state, GNUTLS_LIST list) {
GNUTLS_LIST _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 
	
	if (state->gnutls_internals.CompressionMethodPriority.algorithm_priority!=NULL)
		gnutls_free(state->gnutls_internals.CompressionMethodPriority.algorithm_priority);	
	state->gnutls_internals.CompressionMethodPriority.algorithm_priority = gnutls_malloc(sizeof(int)*num);
	if (state->gnutls_internals.CompressionMethodPriority.algorithm_priority == NULL)
		return GNUTLS_E_MEMORY_ERROR;

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
  * Priority is higher for protocols specified before others.
  * After specifying the protocols you want, you should add 0.
  * Note that the priority is set on the client. The server does
  * not use the protocols's priority except for disabling
  * protocols that were not specified.
  **/
int gnutls_protocol_set_priority( GNUTLS_STATE state, GNUTLS_LIST list) {
GNUTLS_LIST _list = list;
int num=0, i;

	while( *_list != 0) {
		num++;
		++_list;
	} 

	
	if (state->gnutls_internals.ProtocolPriority.algorithm_priority!=NULL)
		gnutls_free(state->gnutls_internals.ProtocolPriority.algorithm_priority);

	state->gnutls_internals.ProtocolPriority.algorithm_priority = gnutls_malloc(sizeof(int)*num);

	if (state->gnutls_internals.ProtocolPriority.algorithm_priority == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
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
