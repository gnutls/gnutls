/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>

#ifdef USE_DMALLOC

int _gnutls_is_secure_memory(const void *ign)
{
	return 0;
}

#else

/* #define MALLOC_DEBUG */
# define EXTRA_SIZE sizeof(size_t)+1

int _gnutls_is_secure_memory(const svoid * mem)
{
	return *((opaque *) mem - 1);
}

void *gnutls_malloc(size_t size)
{
	opaque *ret;
	if (size == 0)
		return NULL;

	ret = malloc(size + EXTRA_SIZE);
	if (ret == NULL)
		return ret;

	*((int *) ret) = size;
	ret[sizeof(size_t)] = 0;	/* not secure */

	ret += EXTRA_SIZE;

#ifdef MALLOC_DEBUG
	_gnutls_log("Allocated: %x with %d bytes\n", ret,
		    _gnutls_malloc_ptr_size(ret));
#endif

	return ret;

}

void *gnutls_calloc(size_t nmemb, size_t size)
{
	void *ret;
	ret = gnutls_malloc(size);
	if (ret == NULL)
		return ret;

	memset(ret, 0, size);

	return ret;
}

size_t _gnutls_malloc_ptr_size(void *_ptr)
{
	opaque *ptr = _ptr;

	if (_ptr == NULL)
		return 0;

	return *((int *) ((opaque *) ptr - sizeof(size_t) - 1));
}

void *gnutls_realloc(void *_ptr, size_t size)
{
	opaque *ret;
	opaque* ptr = _ptr;
	
	if (ptr!=NULL)
		ptr -= EXTRA_SIZE;

	ret = realloc(ptr, size + EXTRA_SIZE);
	if (ret == NULL)
		return ret;

	*((int *) ret) = size;
	ret[sizeof(size_t)] = 0;	/* not secure */

	ret += EXTRA_SIZE;

	return ret;
}

void *gnutls_realloc_fast(void *ptr, size_t size)
{

	if (ptr != NULL && size <= _gnutls_malloc_ptr_size(ptr)) {
		/* do nothing, just return the pointer.
		   * It's much faster.
		 */
		return ptr;
	}
	return gnutls_realloc(ptr, size);
}


void gnutls_free(void *_ptr)
{
	opaque *ptr = _ptr;

	if (_ptr == NULL)
		return;

	ptr -= EXTRA_SIZE;

#ifdef MALLOC_DEBUG
	_gnutls_log("Freed: %x with %d bytes\n", _ptr,
		    _gnutls_malloc_ptr_size(_ptr));
#endif
	free(ptr);
}

svoid *secure_malloc(size_t size)
{
	opaque *ret;
	ret = gnutls_malloc(size);
	if (ret == NULL)
		return ret;

	*((opaque *) ret - 1) = 1;	/* secure mem */

	return ret;

}

svoid *secure_calloc(size_t nmemb, size_t size)
{
	svoid *ret;
	ret = secure_malloc(size);
	if (ret == NULL)
		return ret;

	memset(ret, 0, size);

	return ret;
}

size_t _secure_ptr_size(svoid * ptr)
{
	return _gnutls_malloc_ptr_size(ptr);
}

svoid *secure_realloc(svoid * ptr, size_t size)
{
	svoid *ret;
	if (ptr != NULL && size <= _secure_ptr_size(ptr)) {
		/* do not do realloc.
		 * return the previous pointer.
		 */
		return ptr;
	}
	ret = secure_malloc(size);
	if (ret == NULL)
		return ret;

	if (ptr != NULL) {
		memcpy(ret, ptr, GMIN(_secure_ptr_size(ptr), size));
		secure_free(ptr);
	}

	return ret;
}

void secure_free(svoid * ptr)
{
	memset(ptr, 0, _secure_ptr_size(ptr));
	gnutls_free(ptr);
}

char *gnutls_strdup(const char *s)
{
	int size = strlen(s);
	char *ret;

	ret = gnutls_malloc(size + 1);	/* hold null */
	if (ret == NULL)
		return ret;

	strcpy(ret, s); /* Flawfinder: ignore */

	return ret;
}
#endif				/* USE_DMALLOC */
