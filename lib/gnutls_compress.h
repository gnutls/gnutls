int _gnutls_freeTLSCompressed(GNUTLSCompressed * compressed);
int _gnutls_TLSPlaintext2TLSCompressed(GNUTLS_STATE state,
						     GNUTLSCompressed **
						     compress,
						     GNUTLSPlaintext *
						     plaintext);
int _gnutls_TLSCompressed2TLSPlaintext(GNUTLS_STATE state,
						     GNUTLSPlaintext**
						     plain,
						     GNUTLSCompressed *
						     compressed);
