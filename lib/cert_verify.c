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
#include "cert_asn1.h"
#include "cert_der.h"
#include "gnutls_global.h"
#include "gnutls_num.h"		/* GMAX */
#include <gnutls_sig.h>

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

static int check_if_expired(gnutls_cert * cert)
{
	CertificateStatus ret = GNUTLS_CERT_EXPIRED;

	/* get the issuer of 'cert'
	 */

	if (time(NULL) < cert->expiration_time)
		ret = GNUTLS_CERT_TRUSTED;

	return ret;
}




#define MAX_DN 10*1024

/* This function checks if 'certs' issuer is 'issuer_cert'.
 * This does a straight compare of the DER rdnSequence. 
 */
static
int compare_dn(gnutls_cert * cert, gnutls_cert * issuer_cert)
{
	node_asn *c2;
	int result, len;
	int issuer_len;
	opaque issuer_dn[MAX_DN];
	opaque dn[MAX_DN];

fprintf(stderr, "XXX: %s\nIII: %s\n", cert->issuer_info.common_name, issuer_cert->cert_info.common_name);
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
	
	issuer_len = sizeof(issuer_dn) - 1;
	if ((result =
	     asn1_read_value(c2, "certificate2.tbsCertificate.issuer.rdnSequence", issuer_dn, &issuer_len)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	asn1_delete_structure(c2);


	/* get the 'subject' info of 'issuer_cert'
	 */
	if (asn1_create_structure(_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2, "certificate2") != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}
	
	result = asn1_get_der(c2, issuer_cert->raw.data, issuer_cert->raw.size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	
	len = sizeof(dn) - 1;
	if ((result =
	     asn1_read_value(c2, "certificate2.tbsCertificate.subject.rdnSequence", dn, &len)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	asn1_delete_structure(c2);

fprintf(stderr, "len: %d\nisslen: %d\n", len,issuer_len);

	if (memcmp(dn, issuer_dn, GMAX(len, issuer_len)) == 0)
		return 0;

	gnutls_assert();
	return GNUTLS_E_UNKNOWN_ERROR;	/* do not match */

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


int gnutls_verify_certificate2(gnutls_cert * cert, gnutls_cert * trusted_cas, int tcas_size,
			       void *CRLs, int crls_size)
{
/* CRL is ignored for now */

	gnutls_cert *issuer;
	CertificateStatus ret = GNUTLS_CERT_NOT_TRUSTED;

	if (tcas_size >= 1)
		issuer = find_issuer(cert, trusted_cas, tcas_size);
	else {
		gnutls_assert();
		return ret;
	}

	/* issuer is not in trusted certificate
	 * authorities.
	 */
	if (issuer == NULL) {
		gnutls_assert();
		return GNUTLS_CERT_NOT_TRUSTED;
	}
fprintf(stderr, "XXXissuer: %d\n", issuer->subject_pk_algorithm);
	
        ret = gnutls_verify_signature(cert, issuer);
        if (ret != GNUTLS_CERT_TRUSTED)
              return ret;

	/* Check CRL --not done yet.
	 */

	ret = check_if_expired( cert);

	if (ret == GNUTLS_CERT_EXPIRED)
		return ret;

	return GNUTLS_CERT_TRUSTED;
}

int gnutls_verify_certificate(gnutls_cert * certificate_list,
    int clist_size, gnutls_cert * trusted_cas, int tcas_size, void *CRLs,
			      int crls_size)
{
	int i = 0;
	int expired = 0;
	CertificateStatus ret=GNUTLS_CERT_NOT_TRUSTED;

	if (tcas_size == 0) {
		return ret;
	}

	for (i = 0; i < clist_size; i++) {
		if (i + 1 >= clist_size)
			break;

		if ((ret = gnutls_verify_certificate2(&certificate_list[i], &certificate_list[i + 1], 1, NULL, 0)) != GNUTLS_CERT_TRUSTED) {
			/* we do that because expired means that
			 * it was verified but it was also expired.
			 */
			if (ret == GNUTLS_CERT_EXPIRED)
				expired = 1;
			else
				return ret;
		}
	}

	ret = gnutls_verify_certificate2(&certificate_list[i], trusted_cas, tcas_size, CRLs, crls_size);

	if (ret != GNUTLS_CERT_TRUSTED)
		return ret;

	if (expired != 0)
		return GNUTLS_CERT_EXPIRED;
	return GNUTLS_CERT_TRUSTED;
}
