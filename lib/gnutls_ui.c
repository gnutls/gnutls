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
#include <auth_cert.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>
#include <gnutls_state.h>

/* SRP */

#ifdef ENABLE_SRP

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

	CHECK_AUTH(GNUTLS_CRD_SRP, NULL);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return NULL;
	return info->username;
}

#endif

/* ANON & DHE */

/**
  * gnutls_dh_set_prime_bits - Used to set the bits for a DH ciphersuite
  * @state: is a &GNUTLS_STATE structure.
  * @bits: is the number of bits
  *
  * This function sets the number of bits, for use in an 
  * Diffie Hellman key exchange. This is used both in DH ephemeral and
  * DH anonymous cipher suites. This will set the
  * minimum size of the prime that will be used for the handshake.
  *
  **/
void gnutls_dh_set_prime_bits(GNUTLS_STATE state, int bits)
{
	state->gnutls_internals.dh_prime_bits = bits;
}

/**
  * gnutls_dh_get_prime_bits - This function returns the bits used in DH authentication
  * @state: is a gnutls state
  *
  * This function will return the bits used in the last Diffie Hellman authentication
  * with the peer. Should be used for both anonymous and ephemeral diffie Hellman.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_dh_get_prime_bits(GNUTLS_STATE state)
{
	switch( gnutls_auth_get_type( state)) {
		case GNUTLS_CRD_ANON: {
			ANON_SERVER_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;
			return info->dh_prime_bits;
		}
		case GNUTLS_CRD_CERTIFICATE: {
			CERTIFICATE_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;

			return info->dh_prime_bits;
		}
		default:
			gnutls_assert();
			return GNUTLS_E_INVALID_REQUEST;
	}
}

/**
  * gnutls_dh_get_secret_bits - This function returns the bits used in DH authentication
  * @state: is a gnutls state
  *
  * This function will return the bits used in the last Diffie Hellman authentication
  * with the peer. Should be used for both anonymous and ephemeral diffie Hellman.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_dh_get_secret_bits(GNUTLS_STATE state)
{
	switch( gnutls_auth_get_type( state)) {
		case GNUTLS_CRD_ANON: {
			ANON_SERVER_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;
			return info->dh_secret_bits;
		}
		case GNUTLS_CRD_CERTIFICATE: {
			CERTIFICATE_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;

			return info->dh_secret_bits;
		}
		default:
			gnutls_assert();
			return GNUTLS_E_INVALID_REQUEST;
	}
}

/**
  * gnutls_dh_get_peers_public_bits - This function returns the bits used in DH authentication
  * @state: is a gnutls state
  *
  * This function will return the bits used in the last Diffie Hellman authentication
  * with the peer. Should be used for both anonymous and ephemeral diffie Hellman.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_dh_get_peers_public_bits(GNUTLS_STATE state)
{
	switch( gnutls_auth_get_type( state)) {
		case GNUTLS_CRD_ANON: {
			ANON_SERVER_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;
			return info->dh_peer_public_bits;
		}
		case GNUTLS_CRD_CERTIFICATE: {
			CERTIFICATE_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;

			return info->dh_peer_public_bits;
		}
		default:
			gnutls_assert();
			return GNUTLS_E_INVALID_REQUEST;
	}
}

/* CERTIFICATE STUFF */

/**
  * gnutls_certificate_get_ours - This function returns the raw certificate sent in the last handshake
  * @state: is a gnutls state
  *
  * This function will return the raw certificate list as sent to the peer,
  * in the last handshake. These certificates are in raw format. 
  * In X.509 this is a certificate list. In OpenPGP this is a single
  * certificate.
  * Returns NULL in case of an error, or if no certificate was used.
  *
  **/
const gnutls_datum *gnutls_certificate_get_ours(GNUTLS_STATE state)
{
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	int index;

	CHECK_AUTH(GNUTLS_CRD_CERTIFICATE, NULL);

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return NULL;
	}

	index = state->gnutls_internals.selected_cert_index;
	if (index < 0) return NULL; /* no certificate */
	
	return &cred->cert_list[index]->raw;
}

/**
  * gnutls_certificate_get_peers - This function returns the peer's raw certificate
  * @state: is a gnutls state
  * @list_size: is the length of the certificate list
  *
  * This function will return the peer's raw certificate (list) as sent by the peer.
  * These certificates are in raw format (DER encoded for X509). 
  * In case of a X509 then a certificate list may be present. 
  * The first certificate in the list is the peer's certificate,
  * following the issuer's certificate, then the issuer's issuer etc.
  * Returns NULL in case of an error, or if no certificate was sent.
  *
  **/
const gnutls_datum *gnutls_certificate_get_peers(GNUTLS_STATE state, int *list_size)
{
	CERTIFICATE_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_CRD_CERTIFICATE, NULL);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return NULL;

	*list_size = info->ncerts;
	return info->raw_certificate_list;
}


/**
  * gnutls_certificate_client_get_request_status - This function returns the certificate request status
  * @state: is a gnutls state
  *
  * This function will return 0 if the peer (server) did not request client
  * authentication or 1 otherwise.
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_certificate_client_get_request_status(GNUTLS_STATE state)
{
	CERTIFICATE_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_CRD_CERTIFICATE, 0);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return GNUTLS_E_UNKNOWN_ERROR;
	return info->certificate_requested;
}


typedef MACAlgorithm GNUTLS_DigestAlgorithm;
/**
  * gnutls_x509_fingerprint - This function calculates the fingerprint of the given data
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
int gnutls_x509_fingerprint(GNUTLS_DigestAlgorithm algo, const gnutls_datum* data, char* result, size_t* result_size)
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

/**
  * gnutls_anon_set_server_dh_params - This function will set the DH parameters for a server to use
  * @res: is a GNUTLS_ANON_SERVER_CREDENTIALS structure
  * @dh_params: is a structure that holds diffie hellman parameters.
  *
  * This function will set the diffie hellman parameters for an anonymous
  * server to use. These parameters will be used in Anonymous Diffie Hellman 
  * cipher suites.
  *
  **/
void gnutls_anon_set_server_dh_params( GNUTLS_ANON_SERVER_CREDENTIALS res, GNUTLS_DH_PARAMS dh_params) {
	res->dh_params = dh_params;
}

/**
  * gnutls_certificate_set_server_dh_params - This function will set the DH parameters for a server to use
  * @res: is a GNUTLS_CERTIFICATE_CREDENTIALS structure
  * @dh_params: is a structure that holds diffie hellman parameters.
  *
  * This function will set the diffie hellman parameters for a certificate
  * server to use. These parameters will be used in Ephemeral Diffie Hellman 
  * cipher suites.
  *
  **/
int gnutls_certificate_set_dh_params(GNUTLS_CERTIFICATE_CREDENTIALS res, GNUTLS_DH_PARAMS dh_params) {
	res->dh_params = dh_params;
	return 0;
}
