/*
 * Copyright (C) 2001,2002 Nikos Mavroyanopoulos <nmav@hellug.gr>
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
#include "x509_asn1.h"
#include "x509_der.h"
#include "gnutls_global.h"
#include "gnutls_num.h"		/* GMAX */
#include <gnutls_sig.h>
#include <gnutls_str.h>

/* TIME functions */

time_t _gnutls_utcTime2gtime(char *ttime)
{
	char xx[3];
	struct tm etime;
	time_t ret;

	xx[2] = 0;

/* get the year
 */
	memcpy(xx, ttime, 2);	/* year */
	etime.tm_year = atoi(xx);
	ttime+=2;

	if (etime.tm_year > 49)
		etime.tm_year += 1900;
	else
		etime.tm_year += 2000;

	etime.tm_year-=1900; /* well we need to find something
	                      * better than mktime();
	                      */

/* get the month
 */
	memcpy(xx, ttime, 2);	/* month */
	etime.tm_mon = atoi(xx) - 1;
	ttime+=2;
	
/* get the day
 */
	memcpy(xx, ttime, 2);	/* day */
	etime.tm_mday = atoi(xx);
	ttime+=2;
	
/* get the hour
 */
	memcpy(xx, ttime, 2);	/* hour */
	etime.tm_hour = atoi(xx);
	ttime+=2;
	
/* get the minutes
 */
	memcpy(xx, ttime, 2);	/* minutes */
	etime.tm_min = atoi(xx);
	ttime+=2;
	
	etime.tm_isdst = -1;
	etime.tm_sec = 0;
	
	ret = mktime(&etime);

	return ret;
}

time_t _gnutls_generalTime2gtime(char *ttime)
{
	char xx[5];
	struct tm etime;
	time_t ret;

	if (strchr(ttime, 'Z') == 0) {
		gnutls_assert();
		/* sorry we don't support it yet
		 */
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	xx[4] = 0;

/* get the year
 */
	memcpy(xx, ttime, 4);	/* year */
	etime.tm_year = atoi(xx);
	ttime+=2;

	etime.tm_year-=1900;

	xx[2] = 0;

/* get the month
 */
	memcpy(xx, ttime, 2);	/* month */
	etime.tm_mon = atoi(xx) - 1;
	ttime+=2;
	
/* get the day
 */
	memcpy(xx, ttime, 2);	/* day */
	etime.tm_mday = atoi(xx);
	ttime+=2;
	
/* get the hour
 */
	memcpy(xx, ttime, 2);	/* hour */
	etime.tm_hour = atoi(xx);
	ttime+=2;
	
/* get the minutes
 */
	memcpy(xx, ttime, 2);	/* minutes */
	etime.tm_min = atoi(xx);
	ttime+=2;
	
	ret = mktime(&etime);

	etime.tm_isdst = -1;
	etime.tm_sec = 0;

	return ret;
}

/* Returns 0 or EXPIRED. 
 */
static int check_if_expired(gnutls_cert * cert)
{
	CertificateStatus ret = GNUTLS_CERT_EXPIRED;

	/* get the issuer of 'cert'
	 */

	if (time(NULL) < cert->expiration_time)
		ret = 0;

	return ret;
}

/* Return 0 or INVALID, if the issuer is a CA,
 * or not.
 */
static int check_if_ca(const gnutls_cert * cert, const gnutls_cert* issuer)
{
	CertificateStatus ret = GNUTLS_CERT_INVALID;
	
	/* Check if the issuer is the same with the
	 * certificate. This is added in order for trusted
	 * certificates to be able to verify themselves.
	 */
	if (cert->raw.size == issuer->raw.size) {
		if ( memcmp( cert->raw.data, issuer->raw.data, cert->raw.size)==0) {
			return 0;
		}
	}

	if (issuer->CA==1) {
		ret = 0;
	} else
		gnutls_assert();

	return ret;
}



void _gnutls_int2str(int k, char* data);

#define MAX_DN_ELEM 1024

/* This function checks if 'certs' issuer is 'issuer_cert'.
 * This does a straight (DER) compare of the issuer/subject fields in
 * the given certificates.
 *
 * FIXME: use a real DN comparison algorithm.
 */
static
int compare_dn(gnutls_cert * cert, gnutls_cert * issuer_cert)
{
	node_asn *c2, *c3;
	int result, len1;
	int len2;
	char tmpstr[512];
	int start1, start2, end1, end2;

	/* get the issuer of 'cert'
	 */
	if (asn1_create_structure(_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2, "certificate2") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}
	
	result = asn1_get_der(c2, cert->raw.data, cert->raw.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	


	/* get the 'subject' info of 'issuer_cert'
	 */
	if (asn1_create_structure(_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c3, "certificate2") != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_ERROR;
	}
	
	result = asn1_get_der(c3, issuer_cert->raw.data, issuer_cert->raw.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

		
	_gnutls_str_cpy( tmpstr, sizeof(tmpstr), "certificate2.tbsCertificate.issuer"); 
	result = asn1_get_start_end_der( c2, cert->raw.data, cert->raw.size,
	                tmpstr, &start1, &end1);
	asn1_delete_structure( c2);
	
	if (result!=ASN_OK) {
		gnutls_assert();
		asn1_delete_structure( c3);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
		
	len1 = end1 - start1 + 1;
		
	_gnutls_str_cpy( tmpstr, sizeof(tmpstr), "certificate2.tbsCertificate.subject"); 
	result = asn1_get_start_end_der( c3, issuer_cert->raw.data, issuer_cert->raw.size,
	                tmpstr, &start2, &end2);
	asn1_delete_structure( c3);
	
	if (result!=ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	
	len2 = end2 - start2 + 1;

	/* The error code returned does not really matter
	 * here.
	 */		
	if (len1!=len2) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}
	if (memcmp( &issuer_cert->raw.data[start2], 
		&cert->raw.data[start1], len1) != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}
		
	/* they match */
	return 0;

}

static gnutls_cert *find_issuer(gnutls_cert * cert, gnutls_cert * trusted_cas, int tcas_size)
{
	int i;

	/* this is serial search. 
	 */

	for (i = 0; i < tcas_size; i++) {
		if (compare_dn(cert, &trusted_cas[i]) == 0)
			return &trusted_cas[i];
	}

	gnutls_assert();
	return NULL;
}

/* ret_trust is the value to return when the certificate chain is ok
 * ret_else is the value to return otherwise.
 */
int gnutls_verify_certificate2(gnutls_cert * cert, gnutls_cert * trusted_cas, int tcas_size,
			       void *CRLs, int crls_size, int ret_trust, int ret_else)
{
/* CRL is ignored for now */

	gnutls_cert *issuer;
	int ret;

	if (tcas_size >= 1)
		issuer = find_issuer(cert, trusted_cas, tcas_size);
	else {
		gnutls_assert();
		return ret_else;
	}

	/* issuer is not in trusted certificate
	 * authorities.
	 */
	if (issuer == NULL) {
		gnutls_assert();
		return ret_else;
	}

	ret = check_if_ca( cert, issuer);
	if (ret != 0) {
		gnutls_assert();
		return ret_else|GNUTLS_CERT_INVALID;
	}

	ret = check_if_expired( issuer);
	if (ret != 0) {
		gnutls_assert();
		return ret_else|GNUTLS_CERT_EXPIRED;
	}
	
        ret = gnutls_x509_verify_signature(cert, issuer);
        if (ret != 0) {
	      gnutls_assert();
              return ret_else|GNUTLS_CERT_INVALID;
	}

	/* FIXME: Check CRL --not done yet.
	 */


	return ret_trust;
}

/* The algorithm used is:
 * 1. Check the certificate chain given by the peer, if it is ok.
 * 2. If any certificate in the chain are expired, revoked, not
 *    valid, or they are not CAs then the certificate is invalid.
 * 3. If 1 is ok, then find a certificate in the trusted CAs file
 *    that has the DN of the issuer field in the last certificate
 *    in the peer's certificate chain.
 * 4. If it does exist then verify it. If verification is ok then
 *    it is trusted. Otherwise it is just valid (but not trusted).
 */
/* This function verifies a X.509 certificate list. The certificate list should
 * lead to a trusted CA in order to be trusted.
 */
int _gnutls_x509_verify_certificate( gnutls_cert * certificate_list,
    int clist_size, gnutls_cert * trusted_cas, int tcas_size, void *CRLs,
			      int crls_size)
{
	int i = 0, ret;
	CertificateStatus status=0;
	
	if (tcas_size == 0 || clist_size == 0) {
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	ret = check_if_expired( &certificate_list[0]);
	if (ret != 0) {
		gnutls_assert();
		status |= GNUTLS_CERT_EXPIRED;
	}

	/* Verify the certificate path */
	for (i = 0; i < clist_size; i++) {
		if (i + 1 >= clist_size)
			break;

		if ((ret = gnutls_verify_certificate2(&certificate_list[i], &certificate_list[i + 1], 
			1, NULL, 0, 0, GNUTLS_CERT_INVALID)) != 0) {
			 /*
			 * We only accept the first certificate to be
			 * expired, revoked etc. If any of the certificates in the
			 * certificate chain is expired then the certificate
			 * is not valid.
			 */
			if (ret > 0) {
				gnutls_assert();
				status |= ret;
			} else {
				gnutls_assert();
				return ret;
			}
		}
	}

	/* Now verify the last certificate in the certificate path
	 * against the trusted CA certificate list.
	 */
	ret = gnutls_verify_certificate2(&certificate_list[i], trusted_cas, tcas_size, 
		CRLs, crls_size, GNUTLS_CERT_TRUSTED, GNUTLS_CERT_NOT_TRUSTED);

	if (ret > 0) {
		/* if the last certificate in the certificate
		 * list is expired, then the certificate is not
		 * trusted.
		 */
		gnutls_assert();
		status |= ret;
	}

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	/* if we got here, then it's trusted.
	 */
	return status;
}
