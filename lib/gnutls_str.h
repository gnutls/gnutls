#include <gnutls_int.h>

void _gnutls_str_cpy( char* dest, size_t dest_tot_size, const char* src);
void _gnutls_mem_cpy( char* dest, size_t dest_tot_size, const char* src, size_t src_size);
void _gnutls_str_cat( char* dest, size_t dest_tot_size, const char* src);

typedef struct {
	char * string;
	size_t max_length;
	size_t length;
	REALLOC_FUNC realloc_func;
	ALLOC_FUNC alloc_func;
	FREE_FUNC free_func;
} gnutls_string;

void _gnutls_string_init( gnutls_string*, ALLOC_FUNC, REALLOC_FUNC, FREE_FUNC);
void _gnutls_string_clear( gnutls_string*);
gnutls_datum _gnutls_string2datum( gnutls_string* str);
int _gnutls_string_copy_str( gnutls_string* dest, const char* src);
int _gnutls_string_append_str( gnutls_string*, const char* str);
int _gnutls_string_append_data( gnutls_string*, const void* data, size_t data_size);
