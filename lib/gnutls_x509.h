int _gnutls_x509_cert_verify_peers(GNUTLS_STATE state);
int _gnutls_x509_cert2gnutls_cert(gnutls_cert * gCert, gnutls_datum derCert);

#define MAX_INT_DIGITS 4
void _gnutls_int2str(int k, char *data);

int _gnutls_check_x509_key_usage( const gnutls_cert * cert, KXAlgorithm alg);
