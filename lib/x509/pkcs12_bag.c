/*
 *  Copyright (C) 2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS.
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

/* Functions that relate on PKCS12 Bag packet parsing.
 */

#include <gnutls_int.h>

#ifdef ENABLE_PKI

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <pkcs12.h>


/**
  * gnutls_pkcs12_bag_init - This function initializes a gnutls_pkcs12_bag structure
  * @bag: The structure to be initialized
  *
  * This function will initialize a PKCS12 bag structure. PKCS12 Bags
  * usually contain private keys, lists of X.509 Certificates and X.509 Certificate
  * revocation lists.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_pkcs12_bag_init(gnutls_pkcs12_bag * bag)
{
	*bag = gnutls_calloc( 1, sizeof(gnutls_pkcs12_bag_int));

	if (*bag) {
		return 0;		/* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_pkcs12_bag_deinit - This function deinitializes memory used by a gnutls_pkcs12 structure
  * @bag: The structure to be initialized
  *
  * This function will deinitialize a PKCS12 Bag structure. 
  *
  **/
void gnutls_pkcs12_bag_deinit(gnutls_pkcs12_bag bag)
{
int i;

	for (i=0;i<bag->bag_elements;i++)
		_gnutls_free_datum( &bag->data[i]);

	gnutls_free(bag);
}

/**
  * gnutls_pkcs12_bag_get_type - This function returns the bag's type
  * @bag: The bag
  * @indx: The element of the bag to get the type
  *
  * This function will return the bag's type. One of the gnutls_pkcs12_bag_type
  * enumerations.
  *
  **/
gnutls_pkcs12_bag_type gnutls_pkcs12_bag_get_type(gnutls_pkcs12_bag bag, int indx)
{
	if (indx >= bag->bag_elements) 
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	return bag->type[indx];
}

/**
  * gnutls_pkcs12_bag_get_count - This function returns the bag's elements count
  * @bag: The bag
  *
  * This function will return the number of the elements withing the bag. 
  *
  **/
int gnutls_pkcs12_bag_get_count(gnutls_pkcs12_bag bag)
{
	return bag->bag_elements;
}

/**
  * gnutls_pkcs12_bag_get_data - This function returns the bag's data
  * @bag: The bag
  * @indx: The element of the bag to get the data from
  * @data: where the data will be copied to. Should be treated as constant.
  *
  * This function will return the bag's data. 
  *
  **/
int gnutls_pkcs12_bag_get_data(gnutls_pkcs12_bag bag, int indx, gnutls_datum* data)
{
	if (indx >= bag->bag_elements) 
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

	data->data = bag->data[indx].data;
	data->size = bag->data[indx].size;

	return 0;
}

/**
  * gnutls_pkcs12_bag_set_data - This function inserts data into the bag
  * @bag: The bag
  * @type: The data's type
  * @data: the data to be copied.
  *
  * This function will insert the given data of the given type into the
  * bag.
  *
  **/
int gnutls_pkcs12_bag_set_data(gnutls_pkcs12_bag bag, gnutls_pkcs12_bag_type type,
	const gnutls_datum* data)
{
int ret;

	if (bag->bag_elements == MAX_BAG_ELEMENTS-1) {
		gnutls_assert();
		/* bag is full */
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret = _gnutls_set_datum( &bag->data[bag->bag_elements], data->data, data->size);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	bag->type[bag->bag_elements] = type;

	bag->bag_elements++;

	return 0;
}

/**
  * gnutls_pkcs12_bag_decrypt - This function will decrypt an encrypted bag
  * @bag: The bag
  * @pass: The password used for encryption
  *
  * This function will return 0 on success.
  *
  **/
int gnutls_pkcs12_bag_decrypt(gnutls_pkcs12_bag bag, const char* pass)
{
int ret;
gnutls_datum dec;
	
	if (bag->type[0] != GNUTLS_BAG_ENCRYPTED) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	ret = _gnutls_x509_decrypt_pkcs7_encrypted_data( 
		&bag->data[0], pass, &dec);

        if (ret < 0) {
		gnutls_assert();
        	return ret;
        }

        /* decryption succeeded. Now decode the SafeContents
         * stuff, and parse it.
         */

        _gnutls_free_datum( &bag->data[0]);

	ret = _pkcs12_decode_safe_contents( &dec, bag);

        _gnutls_free_datum( &dec);

        if (ret < 0) {
		gnutls_assert();
        	return ret;
        }
	                

	return 0;
}


#endif /* ENABLE_PKI */
