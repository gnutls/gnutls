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

#define CHECK_AUTH(auth, ret) if (gnutls_get_auth_type(state) != auth) { \
	gnutls_assert(); \
	return ret; \
	}
/**
  * gnutls_srp_server_get_username - This function returns the username of the peer
  * @state: is a gnutls state
  *
  * This function will return the username of the peer. This should only be
  * called in case of SRP authentication and in case of a server.
  *
  **/
const char* gnutls_srp_server_get_username(  GNUTLS_STATE state) {
SRP_SERVER_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_SRP, NULL);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return NULL;
	return info->username;
}

/* ANON */

/**
  * gnutls_anon_server_get_dh_bits - This function returns the bits used in DH authentication
  * @state: is a gnutls state
  *
  * This function will return the bits used in the Diffie Hellman authentication
  * with the peer. This should only be called in case of a server.
  *
  **/
int gnutls_anon_server_get_dh_bits( GNUTLS_STATE state) {
ANON_SERVER_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_ANON, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->dh_bits;
}

/**
  * gnutls_anon_client_get_dh_bits - This function returns the bits used in DH authentication
  * @state: is a gnutls state
  *
  * This function will return the bits used in the Diffie Hellman authentication
  * with the peer. This should only be called in case of a client.
  *
  **/
int gnutls_anon_client_get_dh_bits(  GNUTLS_STATE state) {
ANON_CLIENT_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_ANON, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->dh_bits;
}


/* X509PKI */
/**
  * gnutls_x509pki_get_peer_dn - This function returns the peer's distinguished name
  * @state: is a gnutls state
  *
  * This function will return the name of the peer. The name is gnutls_DN structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns NULL.
  *
  **/
const gnutls_DN* gnutls_x509pki_get_peer_dn(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, NULL);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return NULL;
	return &info->peer_dn;
}

/**
  * gnutls_x509pki_get_issuer_dn - This function returns the peer's certificate issuer distinguished name
  * @state: is a gnutls state
  *
  * This function will return the name of the peer's certificate issuer. The name is gnutls_DN structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns NULL.
  *
  **/
const gnutls_DN* gnutls_x509pki_get_issuer_dn(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, NULL);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return NULL;
	return &info->issuer_dn;
}

/**
  * gnutls_x509pki_get_peer_certificate_status - This function returns the peer's certificate status
  * @state: is a gnutls state
  *
  * This function will return the peer's certificate status (TRUSTED, EXPIRED etc.). This is the output
  * of the certificate verification function. However you must also check the peer's name in order
  * to check if the verified certificate belongs to the actual peer.
  *
  **/
CertificateStatus gnutls_x509pki_get_peer_certificate_status(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->peer_certificate_status;
}

/**
  * gnutls_x509pki_get_peer_certificate_version - This function returns the peer's certificate version
  * @state: is a gnutls state
  *
  * This function will return the peer's certificate version (1, 2, 3). This is obtained by the X509 Certificate
  * Version field. If the certificate is invalid then version will be zero.
  *
  **/
int gnutls_x509pki_get_peer_certificate_version(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->peer_certificate_version;
}

/**
  * gnutls_x509pki_get_dh_bits - This function returns the number of bits used in a DHE handshake
  * @state: is a gnutls state
  *
  * This function will return the number of bits used in a Diffie Hellman Handshake. This will only
  * occur in case of DHE_* ciphersuites. The return value may be zero if no applicable ciphersuite was
  * used.
  *
  **/
int gnutls_x509pki_get_dh_bits(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->dh_bits;
}

/**
  * gnutls_x509pki_get_peer_certificate_activation_time - This function returns the peer's certificate activation time
  * @state: is a gnutls state
  *
  * This function will return the peer's certificate activation time in UNIX time (ie seconds since
  * 00:00:00 UTC January 1, 1970).
  *
  **/
time_t gnutls_x509pki_get_peer_certificate_activation_time(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, -1);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return -1;
	return info->peer_certificate_activation_time;
}

/**
  * gnutls_x509pki_get_peer_certificate_expiration_time - This function returns the peer's certificate expiration time
  * @state: is a gnutls state
  *
  * This function will return the peer's certificate expiration time in UNIX time (ie seconds since
  * 00:00:00 UTC January 1, 1970).
  *
  **/
time_t gnutls_x509pki_get_peer_certificate_expiration_time(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, -1);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return -1;
	return info->peer_certificate_expiration_time;
}


/**
  * gnutls_x509pki_get_key_usage - This function returns the peer's certificate key usage
  * @state: is a gnutls state
  *
  * This function will return the peer's certificate key usage. This is specified in X509v3 Certificate
  * Extensions and is an 8bit string.
  *
  **/
unsigned char gnutls_x509pki_get_key_usage(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, 0);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return 0;
	return info->keyUsage;
}

/**
  * gnutls_x509pki_get_certificate_request_status - This function returns the certificate request status
  * @state: is a gnutls state
  *
  * This function will return 0 if the peer (server) did not requested client
  * authentication or 1 otherwise.
  *
  **/
unsigned char gnutls_x509pki_get_certificate_request_status(  GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, 0);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->certificate_requested;
}


/**
  * gnutls_x509pki_get_subject_dns_name - This function returns the peer's dns name, if any
  * @state: is a gnutls state
  *
  * This function will return the peer's alternative name (the dns part of it). 
  * This is specified in X509v3 Certificate Extensions. 
  * GNUTLS will only return the dnsName of the Alternative name, or a null 
  * string.
  *
  **/
const char* gnutls_x509pki_get_subject_dns_name( GNUTLS_STATE state) {
X509PKI_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_X509PKI, NULL);

	info = _gnutls_get_auth_info(state);	
	if (info==NULL) return NULL;
	return info->subjectAltDNSName;
}

