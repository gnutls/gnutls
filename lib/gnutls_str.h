#ifndef GNUTLS_STR_H
# define GNUTLS_STR_H

#include <gnutls_int.h>

void _gnutls_str_cpy( char* dest, size_t dest_tot_size, const char* src);
void _gnutls_mem_cpy( char* dest, size_t dest_tot_size, const char* src, size_t src_size);
void _gnutls_str_cat( char* dest, size_t dest_tot_size, const char* src);

typedef struct {
	opaque * data;
	size_t max_length;
	size_t length;
	gnutls_realloc_function realloc_func;
	gnutls_alloc_function alloc_func;
	gnutls_free_function free_func;
} gnutls_string;

void _gnutls_string_init( gnutls_string*, gnutls_alloc_function, gnutls_realloc_function, gnutls_free_function);
void _gnutls_string_clear( gnutls_string*);

/* Beware, do not clear the string, after calling this
 * function
 */
gnutls_datum _gnutls_string2datum( gnutls_string* str);

int _gnutls_string_copy_str( gnutls_string* dest, const char* src);
int _gnutls_string_append_str( gnutls_string*, const char* str);
int _gnutls_string_append_data( gnutls_string*, const void* data, size_t data_size);

char * _gnutls_bin2hex(const void *old, size_t oldlen, char* buffer,
	size_t buffer_size);

#endif
