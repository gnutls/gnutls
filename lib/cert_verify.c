/*
 * Copyright (C) 2001 Nikos Mavroyanopoulos <nmav@hellug.gr>
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
#include "gnutls_errors.h"
#include "gnutls_cert.h"

int gnutls_verify_certificate2( gnutls_cert* cert, gnutls_cert* trusted_cas, int tcas_size,
	void* CRLs, int crls_size) {
/* CRL is ignored for now */
	
	gnutls_cert* issuer;
	CertificateStatus ret;
	
	issuer = find_issuer( cert, trusted_cas, tcas_size);
	/* issuer is not in trusted certificate
	 * authorities.
	 */
	if (issuer==NULL) return GNUTLS_NOT_VERIFIED;
	
	ret = verify_signature( cert, issuer);
	if (ret!=GNUTLS_VERIFIED)
		return ret;
	
	/* Check CRL 
	 */
	 
	 
	 ret = check_if_expired( cert);

	 if (ret==GNUTLS_EXPIRED) 
	 	return ret;
	 
	 return GNUTLS_VERIFIED;
}

int gnutls_verify_certificate( gnutls_cert* certificate_list, 
	int clist_size, gnutls_cert* trusted_cas, int tcas_size, void* CRLs, 
	int crls_size) 
{
	int i=0;
	CertificateStatus ret;
		
	for( i=0;i<clist_size;i++) {
		if (i+1 > clist_size) break;
		
		/* FIXME: expired problem
		 */
		if ( (ret=gnutls_verify_certificate2( certificate_list[i], certificate_list[i+1], 1, NULL, 0)) != GNUTLS_VERIFIED)
			return ret;
	}
	
	return gnutls_verify_certificate2( certificate_list[i], trysted_cas, tcas_size, CRLs, crls_size);
}
