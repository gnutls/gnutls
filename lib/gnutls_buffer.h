#include <gnutls_str.h>

typedef gnutls_string gnutls_buffer;

#define _gnutls_buffer_init(buf) _gnutls_string_init(buf, gnutls_malloc, gnutls_realloc, gnutls_free);
#define _gnutls_buffer_clear _gnutls_string_clear
#define _gnutls_buffer_append _gnutls_string_append_data

