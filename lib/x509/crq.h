/*
 * Copyright (C) 2003, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#ifndef CRQ_H
# define CRQ_H

typedef struct gnutls_x509_crq_int {
    ASN1_TYPE crq;
} gnutls_x509_crq_int;

typedef struct gnutls_x509_crq_int *gnutls_x509_crq_t;

int gnutls_x509_crq_get_dn_by_oid(gnutls_x509_crq_t crq, const char *oid,
				  int indx, unsigned int raw_flag,
				  void *buf, size_t * sizeof_buf);

int gnutls_x509_crq_init(gnutls_x509_crq_t * crq);
void gnutls_x509_crq_deinit(gnutls_x509_crq_t crq);

int gnutls_x509_crq_import(gnutls_x509_crq_t crq,
			   const gnutls_datum_t * data,
			   gnutls_x509_crt_fmt_t format);

int gnutls_x509_crq_get_pk_algorithm(gnutls_x509_crq_t crq,
				     unsigned int *bits);

#endif
