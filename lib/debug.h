#ifdef DEBUG
void _gnutls_print_state(GNUTLS_STATE state);
void _gnutls_print_TLSCompressed(GNUTLSCompressed * compressed);
void _gnutls_print_TLSPlaintext(GNUTLSPlaintext * plaintext);
void _gnutls_print_TLSCiphertext( GNUTLSCiphertext *);
char * _gnutls_bin2hex(const unsigned char *old, const size_t oldlen);
void _gnutls_dump_mpi(char* prefix,MPI a);
char* _gnutls_packet2str( int packet);
char* _gnutls_alert2str( int alert);
#endif
