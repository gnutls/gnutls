int _gnutls_text2TLSPlaintext(GNUTLS_STATE state, ContentType type, GNUTLSPlaintext**, char *text, uint16 length);
int _gnutls_freeTLSPlaintext(GNUTLSPlaintext* plaintext);
int _gnutls_TLSPlaintext2text( char**, GNUTLSPlaintext* plaintext);
