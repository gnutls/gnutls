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

struct gnutls_crl_int;
typedef struct gnutls_crl_int* gnutls_crl;

int gnutls_x509_crl_init(gnutls_crl * crl);
void gnutls_x509_crl_deinit(gnutls_crl crl);

int gnutls_x509_crl_import(gnutls_crl crl, const gnutls_datum * data, 
	gnutls_x509_certificate_format format);

int gnutls_x509_crl_get_issuer_dn(const gnutls_crl crl, 
	char *buf, int *sizeof_buf);
int gnutls_x509_crl_get_signed_data(gnutls_crl crl, gnutls_datum *data);


#ifdef __cplusplus
}
#endif
#endif /* GNUTLS_X509_H */

