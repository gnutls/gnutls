/*
 * Copyright (C) 2018 ARPA2 project
 *
 * Author: Tom Vrancken (dev@tomvrancken.nl)
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * This file provides common functionality for certificate type
 * handling during TLS hello extensions.
 *
 */

/* Maps IANA TLS Certificate Types identifiers to internal
 * certificate type representation.
 */
static inline gnutls_certificate_type_t _gnutls_IANA2cert_type(int num)
{
	switch (num) {
		case 0:
			return GNUTLS_CRT_X509;
		default:
			return GNUTLS_CRT_UNKNOWN;
	}
}

/* Maps internal certificate type representation to
 * IANA TLS Certificate Types identifiers.
 */
static inline int _gnutls_cert_type2IANA(gnutls_certificate_type_t cert_type)
{
	switch (cert_type) {
		case GNUTLS_CRT_X509:
			return 0;
		default:
			return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
	}
}
