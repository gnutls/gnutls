/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
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
#include <gnutls_str.h>

/* These function are like strcat, strcpy. They only
 * do bound checking (they shouldn't cause buffer overruns),
 * and they always produce null terminated strings.
 *
 * They should be used only with null terminated strings.
 */
void _gnutls_str_cat( char* dest, size_t dest_tot_size, const char* src) {
size_t str_size = strlen(src);
size_t dest_size = strlen(dest);

	if ( dest_tot_size - dest_size > str_size) {
		strcat( dest, src);
	} else {
		if ( dest_tot_size - dest_size > 0) {
			strncat( dest, src, (dest_tot_size - dest_size) -1);
			dest[dest_tot_size-1] = 0;
		}
	}
}

void _gnutls_str_cpy( char* dest, size_t dest_tot_size, const char* src) {
size_t str_size = strlen(src);

	if ( dest_tot_size > str_size) {
		strcpy( dest, src);
	} else {
		if ( dest_tot_size > 0) {
			strncpy( dest, src, (dest_tot_size) -1);
			dest[dest_tot_size-1] = 0;
		}
	}
}

void _gnutls_mem_cpy( char* dest, size_t dest_tot_size, const char* src, size_t src_size) 
{

	if ( dest_tot_size >= src_size) {
		memcpy( dest, src, src_size);
	} else {
		if ( dest_tot_size > 0) {
			memcpy( dest, src, dest_tot_size);
		}
	}
}

void _gnutls_string_init( gnutls_string* str, ALLOC_FUNC alloc_func, 
	REALLOC_FUNC realloc_func,
	FREE_FUNC free_func) 
{
	str->string = NULL;
	str->max_length = 0;
	str->length = 0;
	
	str->alloc_func = alloc_func;
	str->free_func = free_func;
	str->realloc_func = realloc_func;
}

void _gnutls_string_clear( gnutls_string* str)
{
	str->free_func( str->string);
	memset( str, 0, sizeof( gnutls_string));
}

/* This one does not copy the string.
 */
gnutls_datum _gnutls_string2datum( gnutls_string* str)
{
	gnutls_datum ret;
	
	ret.data = str->string;
	ret.size = str->length;
	
	return ret;
}

#define MIN_CHUNK 256

int _gnutls_string_copy_str( gnutls_string* dest, const char * src)
{
	size_t src_len = strlen( src);
	
	if (dest->max_length >= src_len) {
		memcpy( dest->string, src, src_len);
		dest->length = src_len;
		
		return src_len;
	} else {
		dest->string = dest->realloc_func( dest->string, GMAX(src_len, MIN_CHUNK));
		if (dest->string == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		dest->max_length = GMAX( MIN_CHUNK, src_len);

		memcpy( dest->string, src, src_len);
		dest->length = src_len;
		
		return src_len;
	}
}

int _gnutls_string_append_str( gnutls_string* dest, const char * src)
{
	size_t src_len = strlen( src);
	size_t tot_len = src_len + dest->length;
	
	if (dest->max_length >= tot_len) {
		memcpy( &dest->string[dest->length], src, src_len);
		dest->length = tot_len;
		
		return tot_len;
	} else {
		dest->string = dest->realloc_func( dest->string, GMAX(tot_len, MIN_CHUNK));
		if (dest->string == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		dest->max_length = GMAX( MIN_CHUNK, tot_len);

		memcpy( &dest->string[dest->length], src, src_len);
		dest->length = tot_len;
		
		return tot_len;
	}
}

int _gnutls_string_append_data( gnutls_string* dest, const void * data, size_t data_size)
{
	size_t tot_len = data_size + dest->length;
	
	if (dest->max_length >= tot_len) {
		memcpy( &dest->string[dest->length], data, data_size);
		dest->length = tot_len;
		
		return tot_len;
	} else {
		dest->string = dest->realloc_func( dest->string, GMAX(tot_len, MIN_CHUNK));
		if (dest->string == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		dest->max_length = GMAX( MIN_CHUNK, tot_len);

		memcpy( &dest->string[dest->length], data, data_size);
		dest->length = tot_len;
		
		return tot_len;
	}
}
