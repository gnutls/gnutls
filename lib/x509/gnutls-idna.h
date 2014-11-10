/*
 * Copyright (C) 2014 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
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
 */

#ifndef _GNUTLS_IDNA_H
# define _GNUTLS_IDNA_H

#include <config.h>

#ifdef HAVE_LIBIDN
# include <idna.h>
# include <idn-free.h>

#else /* #ifndef HAVE_LIBIDN */

#define IDNA_SUCCESS 0

static inline
int idna_to_ascii_8z(const char * input, char ** output, int flags)
{
	*output = (char*)input;
	return 0;
}

#define idn_free(x)

static inline
const char *idna_strerror(int ret)
{
	return "";
}
#endif

#endif
