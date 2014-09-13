/*
 * GnuTLS PKCS#11 support
 * Copyright (C) 2014 Red Hat
 * 
 * Authors: Nikos Mavrogiannopoulos
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
 */

#ifndef PKCS11X_H
#define PKCS11X_H

#ifdef HAVE_PKCS11X_H
# include <p11-kit/pkcs11x.h>
#else

# include <p11-kit/pkcs11.h>

# ifndef CKA_X_VENDOR
#  define CKA_X_VENDOR (CKA_VENDOR_DEFINED | 0x58444700UL)
# endif

# ifndef CKO_X_VENDOR
#  define CKO_X_VENDOR   (CKA_VENDOR_DEFINED | 0x58444700UL)
# endif

# ifndef CKA_X_DISTRUSTED
#  define CKA_X_DISTRUSTED (CKA_X_VENDOR + 100)
# endif

# ifndef CKO_X_CERTIFICATE_EXTENSION
#  define CKO_X_CERTIFICATE_EXTENSION                  (CKO_X_VENDOR + 200)
# endif

# ifndef CKA_PUBLIC_KEY_INFO
#  define CKA_PUBLIC_KEY_INFO                          0x00000129UL
# endif

#endif

#endif
