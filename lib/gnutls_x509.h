#include <libtasn1.h>

int _gnutls_x509_cert_verify_peers(GNUTLS_STATE state);
int _gnutls_x509_cert2gnutls_cert(gnutls_cert * gCert, gnutls_datum derCert);

#define MAX_INT_DIGITS 4
void _gnutls_int2str(unsigned int k, char *data);

#define PEM_CERT_SEP "-----BEGIN"

int _gnutls_check_x509_key_usage( const gnutls_cert * cert, KXAlgorithm alg);
time_t gnutls_x509_extract_certificate_activation_time( const gnutls_datum*);
time_t gnutls_x509_extract_certificate_expiration_time( const gnutls_datum*);

time_t _gnutls_x509_utcTime2gtime(char *ttime);
time_t _gnutls_x509_generalTime2gtime(char *ttime);

