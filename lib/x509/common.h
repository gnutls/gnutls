/* for int2str */
#define MAX_INT_DIGITS 4
void _gnutls_int2str(unsigned int k, char *data);

#define GNUTLS_XML_SHOW_ALL 1

#define PEM_CRL "X509 CRL"
#define PEM_X509_CERT "X509 CERTIFICATE"
#define PEM_X509_CERT2 "CERTIFICATE"
#define PEM_PKCS7 "PKCS7"
#define PEM_PKCS12 "PKCS12"

#define PKIX1_RSA_OID "1.2.840.113549.1.1.1"
#define DSA_OID "1.2.840.10040.4.1"

#define DSA_SHA1_OID "1.2.840.10040.4.3"
#define RSA_MD5_OID "1.2.840.113549.1.1.4"
#define RSA_SHA1_OID "1.2.840.113549.1.1.5"

time_t _gnutls_x509_utcTime2gtime(char *ttime);
time_t _gnutls_x509_generalTime2gtime(char *ttime);

int _gnutls_x509_oid_data2string( const char* OID, void* value, 
	int value_size, char * res, int *res_size);

const char* _gnutls_x509_oid2ldap_string( const char* OID);

int _gnutls_x509_oid_data_choice( const char* OID);
int _gnutls_x509_oid_data_printable( const char* OID);

gnutls_pk_algorithm _gnutls_x509_oid2pk_algorithm( const char* oid);
gnutls_mac_algorithm _gnutls_x509_oid2mac_algorithm( const char* oid);
gnutls_pk_algorithm _gnutls_x509_oid2sign_algorithm( const char* oid, 
	gnutls_mac_algorithm * mac);

const char* _gnutls_x509_pk2oid( gnutls_pk_algorithm pk);
const char* _gnutls_x509_sign2oid( gnutls_pk_algorithm pk, gnutls_mac_algorithm mac);
const char* _gnutls_x509_mac2oid( gnutls_mac_algorithm mac);

time_t _gnutls_x509_get_time(ASN1_TYPE c2, const char *when);

gnutls_x509_subject_alt_name _gnutls_x509_san_find_type( char* str_type);

int _gnutls_x509_der_encode_and_copy( ASN1_TYPE src, const char* src_name,
	ASN1_TYPE dest, const char* dest_name, int str);
int _gnutls_x509_der_encode( ASN1_TYPE src, const char* src_name,
        gnutls_datum *res, int str);

int _gnutls_x509_export_int( ASN1_TYPE asn1_data,
	gnutls_x509_crt_fmt format, char* pem_header,
	int tmp_buf_size, unsigned char* output_data, int* output_data_size);

int _gnutls_x509_read_value( ASN1_TYPE c, const char* root, gnutls_datum *ret, int str);
int _gnutls_x509_write_value( ASN1_TYPE c, const char* root, const gnutls_datum* data, int str);
