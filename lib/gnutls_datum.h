void _gnutls_write_datum16( opaque* dest, gnutls_datum dat);
void _gnutls_write_datum24( opaque* dest, gnutls_datum dat);
void _gnutls_write_datum32( opaque* dest, gnutls_datum dat);
void _gnutls_write_datum8( opaque* dest, gnutls_datum dat);

int gnutls_set_datum( gnutls_datum* dat, const void* data, int data_size);
int gnutls_datum_append( gnutls_datum* dat, const void* data, int data_size);
/* uses secure_malloc */
int gnutls_sset_datum( gnutls_sdatum* dat, const void* data, int data_size);
void gnutls_free_datum( gnutls_datum* dat);
void gnutls_sfree_datum( gnutls_sdatum* dat);
