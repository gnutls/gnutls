/* pkcs5.h	header file for pkcs5 functions                       -*- c -*-
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef PKCS5_H
#define PKCS5_H

/* This should be discarded as soon as this functionality moved
 * to libgcrypt.
 */

/* PRF types */
enum
{
  /* XXX must be synchronized with libgcrypt */
  PKCS5_PRF_MD5 = 1,
  PKCS5_PRF_SHA1 = 2,
  PKCS5_PRF_RMD160 = 3,
  PKCS5_PRF_MD2 = 5,
  PKCS5_PRF_TIGER = 6,
  PKCS5_PRF_HAVAL = 7,
  PKCS5_PRF_SHA256 = 8,
  PKCS5_PRF_SHA384 = 9,
  PKCS5_PRF_SHA512 = 10,
  PKCS5_PRF_MD4 = 11
};

/* Error codes */
enum
{
  PKCS5_OK = 0,
  PKCS5_INVALID_PRF,
  PKCS5_INVALID_ITERATION_COUNT,
  PKCS5_INVALID_DERIVED_KEY_LENGTH,
  PKCS5_DERIVED_KEY_TOO_LONG
};

extern int
_gnutls_pkcs5_pbkdf2 (int PRF,
	const char *P,
	size_t Plen,
	const char *S,
	size_t Slen, unsigned int c, unsigned int dkLen, char *DK);

#endif /* PKCS5_H */
