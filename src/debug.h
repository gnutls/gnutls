void _print_state(GNUTLS_STATE state);
void _print_TLSCompressed(GNUTLSCompressed * compressed);
void _print_TLSPlaintext(GNUTLSPlaintext * plaintext);
void _print_TLSCiphertext( GNUTLSCiphertext *);
char * bin2hex(const unsigned char *old, const size_t oldlen);
