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

#include <gnutls_int.h>
#include <auth_srp.h>
#include <auth_anon.h>
#include <auth_x509.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>

/* SRP */

#define CHECK_AUTH(auth, ret) if (gnutls_auth_get_type(state) != auth) { \
	gnutls_assert(); \
	return ret; \
	}
/**
  * gnutls_srp_server_get_username - This function returns the username of the peer
  * @state: is a gnutls state
  *
  * This function will return the username of the peer. This should only be
  * called in case of SRP authentication and in case of a server.
  * Returns NULL in case of an error.
  *
  **/
const char *gnutls_srp_server_get_username(GNUTLS_STATE state)
{
	SRP_SERVER_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_SRP, NULL);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return NULL;
	return info->username;
}

/* ANON */

/**
  * gnutls_anon_server_get_dh_bits - This function returns the bits used in DH authentication
  * @state: is a gnutls state
  *
  * This function will return the bits used in the Diffie Hellman authentication
  * with the peer. This should only be called in case of a server.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_anon_server_get_dh_bits(GNUTLS_STATE state)
{
	ANON_SERVER_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_ANON, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;
	return info->dh_bits;
}

/**
  * gnutls_anon_client_get_dh_bits - This function returns the bits used in DH authentication
  * @state: is a gnutls state
  *
  * This function will return the bits used in the Diffie Hellman authentication
  * with the peer. This should only be called in case of a client.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_anon_client_get_dh_bits(GNUTLS_STATE state)
{
	ANON_CLIENT_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_ANON, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;
	return info->dh_bits;
}


/* X509PKI */

/**
  * gnutls_x509pki_get_peer_certificate_list - This function returns the peer's raw (DER encoded) certificate
  * @state: is a gnutls state
  * @list_size: is the length of the certificate list
  *
  * This function will return the peer's raw certificate list as sent by the peer.
  * These certificates are DER encoded. The first certificate in the list is the peer's certificate,
  * following the issuer's certificate, then the issuer's issuer etc.
  * Returns NULL in case of an error, or if no certificate was sent.
  *
  **/
const gnutls_datum *gnutls_x509pki_get_peer_certificate_list(GNUTLS_STATE state, int *list_size)
{
	X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, NULL);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return NULL;

	*list_size = info->ncerts;
	return info->raw_certificate_list;
}


/**
  * gnutls_x509pki_get_dh_bits - This function returns the number of bits used in a DHE handshake
  * @state: is a gnutls state
  *
  * This function will return the number of bits used in a Diffie Hellman Handshake. This will only
  * occur in case of DHE_* ciphersuites. The return value may be zero if no applicable ciphersuite was
  * used.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_x509pki_get_dh_bits(GNUTLS_STATE state)
{
	X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;
	return info->dh_bits;
}



/**
  * gnutls_x509pki_get_certificate_request_status - This function returns the certificate request status
  * @state: is a gnutls state
  *
  * This function will return 0 if the peer (server) did not request client
  * authentication or 1 otherwise.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_x509pki_get_certificate_request_status(GNUTLS_STATE state)
{
	X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, 0);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;
	return info->certificate_requested;
}


/**
  * gnutls_fingerprint - This function calculates the fingerprint of the given data
  * @algo: is a digest algorithm
  * @data: is the data
  * @result: is the place where the result will be copied. 
  * @result_size: should hold the size of the result. The actual size
  * of the returned result will also be copied there.
  *
  * This function will calculate a fingerprint (actually a hash), of the
  * given data. The result is not printable data. You should convert it
  * to hex, or to something else printable.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_fingerprint(DigestAlgorithm algo, const gnutls_datum* data, char* result, int* result_size)
{
	GNUTLS_HASH_HANDLE td;
	int hash_len = gnutls_hash_get_algo_len(algo);
	
	if (hash_len > *result_size || hash_len < 0) {
		*result_size = hash_len;
		return GNUTLS_E_INVALID_REQUEST;
	}
	*result_size = hash_len;
	
	td = gnutls_hash_init( algo);
	if (td==NULL) return GNUTLS_E_HASH_FAILED;
	
	gnutls_hash( td, data->data, data->size);
	
	gnutls_hash_deinit( td, result);
		
	return 0;
}

