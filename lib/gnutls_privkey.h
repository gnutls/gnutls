int _gnutls_PKCS1key2gnutlsKey(gnutls_private_key * pkey, gnutls_datum raw_key);
int _gnutls_DSAkey2gnutlsKey(gnutls_private_key * pkey, gnutls_datum raw_key);
void _gnutls_free_private_key( gnutls_private_key pkey);
