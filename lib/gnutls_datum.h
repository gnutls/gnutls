void _gnutls_write_datum16( opaque* dest, gnutls_datum dat);
void _gnutls_write_datum24( opaque* dest, gnutls_datum dat);
void _gnutls_write_datum32( opaque* dest, gnutls_datum dat);
void _gnutls_write_datum8( opaque* dest, gnutls_datum dat);

int _gnutls_set_datum_m( gnutls_datum* dat, const void* data, int data_size, 
	ALLOC_FUNC);
#define _gnutls_set_datum( x, y, z) _gnutls_set_datum_m(x,y,z, gnutls_malloc)
#define _gnutls_sset_datum( x, y, z) _gnutls_set_datum_m(x,y,z, gnutls_secure_malloc)

int _gnutls_datum_append_m( gnutls_datum* dat, const void* data, int data_size,
	REALLOC_FUNC);
#define _gnutls_datum_append(x,y,z) _gnutls_datum_append_m(x,y,z, gnutls_realloc)

void _gnutls_free_datum_m( gnutls_datum* dat, 
	FREE_FUNC);
#define _gnutls_free_datum(x) _gnutls_free_datum_m(x, gnutls_free)
