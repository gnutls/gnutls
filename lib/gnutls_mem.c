/*
 *      Copyright (C) 2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>

void* (*gnutls_secure_malloc)(size_t) = malloc;
void* (*gnutls_malloc)(size_t) = malloc;
void (*gnutls_free)(void*) = free;
char* (*gnutls_strdup)(const char*) = strdup;

int _gnutls_is_secure_mem_null( const void* ign) { return 0; }

int (*_gnutls_is_secure_memory)(const void*) = _gnutls_is_secure_mem_null;
void* (*gnutls_realloc)(void*, size_t) = realloc;


void *gnutls_calloc(size_t nmemb, size_t size)
{
	void *ret;
	ret = gnutls_malloc(size);
	if (ret == NULL)
		return ret;

	memset(ret, 0, size);

	return ret;
}

svoid *gnutls_secure_calloc(size_t nmemb, size_t size)
{
	svoid *ret;
	ret = gnutls_secure_malloc(size);
	if (ret == NULL)
		return ret;

	memset(ret, 0, size);

	return ret;
}

