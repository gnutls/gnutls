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

/* This file contains the types and prototypes for the X.509
 * certificate and CRL parsing functions.
 */

#ifndef GNUTLS_X509_H
# define GNUTLS_X509_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gnutls/gnutls.h>

/* Some OIDs usually found in Distinguished names
 */
#define X520_COUNTRY_NAME		"2 5 4 6"
#define X520_ORGANIZATION_NAME 		"2 5 4 10"
#define X520_ORGANIZATIONAL_UNIT_NAME 	"2 5 4 11"
#define X520_COMMON_NAME 		"2 5 4 3"
#define X520_LOCALITY_NAME 		"2 5 4 7"
#define X520_STATE_OR_PROVINCE_NAME 	"2 5 4 8"
#define LDAP_DC				"0 9 2342 19200300 100 1 25"
#define LDAP_UID			"0 9 2342 19200300 100 1 1"
#define PKCS9_EMAIL 			"1 2 840 113549 1 9 1"
                                                                        

struct gnutls_crl_int;
typedef struct gnutls_crl_int* gnutls_crl;

int gnutls_x509_crl_init(gnutls_crl * crl);
void gnutls_x509_crl_deinit(gnutls_crl crl);

int gnutls_x509_crl_import(gnutls_crl crl, const gnutls_datum * data, 
	gnutls_x509_certificate_format format);

int gnutls_x509_crl_get_issuer_dn(const gnutls_crl crl, 
	char *buf, int *sizeof_buf);
int gnutls_x509_crl_get_issuer_dn_by_oid(gnutls_crl crl, const char* oid, 
	char *buf, int *sizeof_buf);


int gnutls_x509_crl_get_signed_data(gnutls_crl crl, gnutls_datum *data);

int gnutls_x509_crl_get_signature(gnutls_crl crl, gnutls_datum *data);
int gnutls_x509_crl_get_signature_algorithm(gnutls_crl crl);
int gnutls_x509_crl_get_version(gnutls_crl crl);

time_t gnutls_x509_crl_get_this_update(gnutls_crl crl);
time_t gnutls_x509_crl_get_next_update(gnutls_crl crl);

int gnutls_x509_crl_get_certificate_count(gnutls_crl crl);
int gnutls_x509_crl_get_certificate(gnutls_crl crl, int index, unsigned char* serial,
        int* serial_size, time_t* time);

#ifdef __cplusplus
}
#endif
#endif /* GNUTLS_X509_H */

