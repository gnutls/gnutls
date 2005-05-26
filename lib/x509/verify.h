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

#include "x509.h"

typedef enum gnutls_certificate_verify_flags {
    GNUTLS_VERIFY_DISABLE_CA_SIGN = 1,
    GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT = 2,
    GNUTLS_VERIFY_DO_NOT_ALLOW_SAME = 4,
    GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT = 8
} gnutls_certificate_verify_flags;

int gnutls_x509_crt_is_issuer(gnutls_x509_crt_t cert,
    gnutls_x509_crt_t issuer);
int gnutls_x509_crt_verify(gnutls_x509_crt_t cert,
    const gnutls_x509_crt_t * CA_list,
    int CA_list_length, unsigned int flags,
    unsigned int *verify);
int gnutls_x509_crl_verify(gnutls_x509_crl_t crl,
    const gnutls_x509_crt_t * CA_list, int CA_list_length, 
    unsigned int flags, unsigned int *verify);

int gnutls_x509_crt_list_verify(const gnutls_x509_crt_t * cert_list,
    int cert_list_length, const gnutls_x509_crt_t * CA_list,
    int CA_list_length, const gnutls_x509_crl_t * CRL_list,
    int CRL_list_length, unsigned int flags, unsigned int *verify);

int _gnutls_x509_verify_signature(const gnutls_datum_t * tbs,
    const gnutls_datum_t * signature, gnutls_x509_crt_t issuer);
int _gnutls_x509_privkey_verify_signature(const gnutls_datum_t * tbs,
    const gnutls_datum_t * signature, gnutls_x509_privkey_t issuer);
