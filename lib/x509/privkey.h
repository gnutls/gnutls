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

typedef enum gnutls_pkcs_encrypt_flags_t {
    GNUTLS_PKCS_PLAIN = 1,	/* if set the private key will not
				 * be encrypted.
				 */
    GNUTLS_PKCS_USE_PKCS12_3DES = 2,
    GNUTLS_PKCS_USE_PKCS12_ARCFOUR = 4,
    GNUTLS_PKCS_USE_PKCS12_RC2_40 = 8,
    GNUTLS_PKCS_USE_PBES2_3DES = 16
} gnutls_pkcs_encrypt_flags_t;

int gnutls_x509_privkey_import(gnutls_x509_privkey_t key,
			       const gnutls_datum_t * data,
			       gnutls_x509_crt_fmt_t format);
ASN1_TYPE _gnutls_privkey_decode_pkcs1_rsa_key(const gnutls_datum_t *
					       raw_key,
					       gnutls_x509_privkey_t pkey);
int gnutls_x509_privkey_cpy(gnutls_x509_privkey_t dst,
			    gnutls_x509_privkey_t src);
