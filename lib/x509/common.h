/* for int2str */
#define MAX_INT_DIGITS 4
void _gnutls_int2str(unsigned int k, char *data);

#define PEM_CRL "X509 CRL"
#define PEM_X509_CERT "X509 CERTIFICATE"
#define PEM_X509_CERT2 "CERTIFICATE"
#define PEM_PKCS7 "PKCS7"

time_t _gnutls_x509_utcTime2gtime(char *ttime);
time_t _gnutls_x509_generalTime2gtime(char *ttime);

int _gnutls_x509_oid_data2string( const char* OID, void* value, 
	int value_size, char * res, int *res_size);

const char* _gnutls_x509_oid2string( const char* OID);
const char* _gnutls_x509_oid2ldap_string( const char* OID);

int _gnutls_x509_oid_data_choice( const char* OID);
int _gnutls_x509_oid_data_printable( const char* OID);
gnutls_pk_algorithm _gnutls_x509_oid2pk_algorithm( const char* oid);

time_t _gnutls_x509_get_time(ASN1_TYPE c2, const char *when);

gnutls_x509_subject_alt_name _gnutls_x509_san_find_type( char* str_type);
