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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

typedef struct gnutls_pkcs7_int {
    ASN1_TYPE pkcs7;
} gnutls_pkcs7_int;

typedef struct gnutls_pkcs7_int *gnutls_pkcs7_t;

int gnutls_pkcs7_init(gnutls_pkcs7_t * pkcs7);
void gnutls_pkcs7_deinit(gnutls_pkcs7_t pkcs7);
int gnutls_pkcs7_import(gnutls_pkcs7_t pkcs7, const gnutls_datum_t * data,
			gnutls_x509_crt_fmt_t format);
int gnutls_pkcs7_get_crt_raw(gnutls_pkcs7_t pkcs7,
			     int indx, void *certificate,
			     size_t * certificate_size);
int gnutls_pkcs7_get_crt_count(gnutls_pkcs7_t pkcs7);
