/* arctwo-meta.c */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2004 Simon Josefsson
 * Copyright (C) 2002 Niels Möller
 *
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "nettle-meta.h"

#include "arctwo.h"

const struct nettle_cipher nettle_arctwo128
= _NETTLE_CIPHER(arctwo, ARCTWO, 128);

const struct nettle_cipher nettle_pkcs12_arctwo40
= _NETTLE_CIPHER(pkcs12_arctwo, ARCTWO, 40);
