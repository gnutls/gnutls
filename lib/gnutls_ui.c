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

/* SRP */

/**
  * gnutls_srp_server_get_username - This function returns the username of the peer
  * @info: is a SRP_SERVER_AUTH_INFO structure
  *
  * This function will return the username of the peer. This should only be
  * called in case of SRP authentication and in case of a server.
  *
  **/
const char* gnutls_srp_server_get_username(  SRP_SERVER_AUTH_INFO info) {
	if (info==NULL) return NULL;
	return info->username;
}

/* ANON */

/**
  * gnutls_anon_server_get_dh_bits - This function returns the bits used in DH authentication
  * @info: is an ANON_SERVER_AUTH_INFO structure
  *
  * This function will return the bits used in the Diffie Hellman authentication
  * with the peer. This should only be called in case of a server.
  *
  **/
int gnutls_anon_server_get_dh_bits(  ANON_SERVER_AUTH_INFO info) {
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->dh_bits;
}

/**
  * gnutls_anon_client_get_dh_bits - This function returns the bits used in DH authentication
  * @info: is an ANON_CLIENT_AUTH_INFO structure
  *
  * This function will return the bits used in the Diffie Hellman authentication
  * with the peer. This should only be called in case of a client.
  *
  **/
int gnutls_anon_client_get_dh_bits(  ANON_CLIENT_AUTH_INFO info) {
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->dh_bits;
}


/* X509PKI */
/**
  * gnutls_x509pki_get_peer_dn - This function returns the peer's distinguished name
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return the name of the peer. The name is gnutls_DN structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns NULL.
  *
  **/
const gnutls_DN* gnutls_x509pki_get_peer_dn(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return NULL;
	return &info->peer_dn;
}

/**
  * gnutls_x509pki_get_issuer_dn - This function returns the peer's certificate issuer distinguished name
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return the name of the peer's certificate issuer. The name is gnutls_DN structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns NULL.
  *
  **/
const gnutls_DN* gnutls_x509pki_get_issuer_dn(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return NULL;
	return &info->issuer_dn;
}

/**
  * gnutls_x509pki_get_peer_certificate_status - This function returns the peer's certificate status
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return the peer's certificate status (TRUSTED, EXPIRED etc.). This is the output
  * of the certificate verification function. However you must also check the peer's name in order
  * to check if the verified certificate belongs to the actual peer.
  *
  **/
CertificateStatus gnutls_x509pki_get_peer_certificate_status(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->peer_certificate_status;
}

/**
  * gnutls_x509pki_get_peer_certificate_version - This function returns the peer's certificate version
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return the peer's certificate version (1, 2, 3). This is obtained by the X509 Certificate
  * Version field. If the certificate is invalid then version will be zero.
  *
  **/
int gnutls_x509pki_get_peer_certificate_version(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->peer_certificate_version;
}

/**
  * gnutls_x509pki_get_peer_certificate_activation_time - This function returns the peer's certificate activation time
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return the peer's certificate activation time in UNIX time (ie seconds since
  * 00:00:00 UTC January 1, 1970).
  *
  **/
time_t gnutls_x509pki_get_peer_certificate_activation_time(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->peer_certificate_activation_time;
}

/**
  * gnutls_x509pki_get_peer_certificate_expiration_time - This function returns the peer's certificate expiration time
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return the peer's certificate expiration time in UNIX time (ie seconds since
  * 00:00:00 UTC January 1, 1970).
  *
  **/
time_t gnutls_x509pki_get_peer_certificate_expiration_time(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->peer_certificate_expiration_time;
}


/**
  * gnutls_x509pki_get_key_usage - This function returns the peer's certificate key usage
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return the peer's certificate key usage. This is specified in X509v3 Certificate
  * Extensions and is an 8bit string.
  *
  **/
unsigned char gnutls_x509pki_get_key_usage(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->keyUsage;
}

/**
  * gnutls_x509pki_get_certificate_request_status - This function returns the certificate request status
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return 0 if the peer (server) did not requested client
  * authentication or 1 otherwise.
  *
  **/
unsigned char gnutls_x509pki_get_certificate_request_status(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return GNUTLS_E_UNKNOWN_ERROR;
	return info->certificate_requested;
}


/**
  * gnutls_x509pki_get_subject_alt_name - This function returns the peer's alternative name
  * @info: is an X509PKI_CLIENT_AUTH_INFO structure
  *
  * This function will return the peer's alternative namee. This is specified in X509v3 Certificate
  * Extensions. GNUTLS will only return the dnsName of the Alternative name, or a null string.
  *
  **/
const char* gnutls_x509pki_get_subject_alt_name(  X509PKI_CLIENT_AUTH_INFO info) {
	if (info==NULL) return NULL;
	return info->subjectAltName;
}

