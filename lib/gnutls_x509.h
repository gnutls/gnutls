#include <libtasn1.h>

int _gnutls_x509_cert_verify_peers(GNUTLS_STATE state);

typedef enum ConvFlags { 
	CERT_NO_COPY=2, 
	CERT_ONLY_PUBKEY=4,
	CERT_ONLY_EXTENSIONS=16
} ConvFlags;

int _gnutls_x509_cert2gnutls_cert(gnutls_cert * gCert, gnutls_datum derCert, ConvFlags flags);

#define MAX_INT_DIGITS 4
void _gnutls_int2str(unsigned int k, char *data);

#define PEM_CERT_SEP "-----BEGIN"

int _gnutls_check_x509_key_usage( const gnutls_cert * cert, KXAlgorithm alg);
time_t gnutls_x509_extract_certificate_activation_time( const gnutls_datum*);
time_t gnutls_x509_extract_certificate_expiration_time( const gnutls_datum*);

time_t _gnutls_x509_utcTime2gtime(char *ttime);
time_t _gnutls_x509_generalTime2gtime(char *ttime);

int _gnutls_x509_oid_data2string( const char* OID, void* value, 
	int value_size, char * res, int res_size);

const char* _gnutls_x509_oid2string( const char* OID);
int _gnutls_x509_oid_data_printable( const char* OID);

