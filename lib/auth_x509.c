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
#include <gnutls_cert.h>
#include <auth_x509.h>


/* Copies data from a internal certificate struct (gnutls_cert) to 
 * exported certificate struct (X509PKI_CLIENT_AUTH_INFO)
 */
void _gnutls_copy_x509_client_auth_info( X509PKI_CLIENT_AUTH_INFO info, gnutls_cert* cert, CertificateStatus verify) {
 /* Copy peer's information to AUTH_INFO
  */
  	memcpy( &info->peer_dn, &cert->cert_info, sizeof(gnutls_DN));
  	memcpy( &info->issuer_dn, &cert->issuer_info, sizeof(gnutls_DN));
  	

	info->peer_certificate_status = verify;

	info->peer_certificate_version = cert->version;
	
	if ( cert->subjectAltDNSName[0]!=0)
		strcpy( info->subjectAltDNSName, cert->subjectAltDNSName);

	info->keyUsage = cert->keyUsage;

	info->peer_certificate_expiration_time = cert->expiration_time;
	info->peer_certificate_activation_time = cert->activation_time;

	return;
}
