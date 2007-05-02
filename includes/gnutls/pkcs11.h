/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS-PKCS11.
 *
 * GNUTLS-PKCS11 is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * GNUTLS-PKCS11 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS-PKCS11; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/* Note the libgnutls-extra is not a standalone library. It requires
 * to link also against libgnutls.
 */

#ifndef GNUTLS_PKCS11_H
# define GNUTLS_PKCS11_H

# include <gnutls/gnutls.h>

# ifdef __cplusplus
extern "C"
{
# endif

# define LIBGNUTLS_PKCS11_VERSION LIBGNUTLS_VERSION

  int gnutls_pkcs11_get_ca_certificates (gnutls_x509_crt_t ** cert_list,
					 unsigned int *ncerts);

# ifdef __cplusplus
}
# endif
#endif
