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

/* signature OIDs
 */
#define DSA_SHA1_OID "1.2.840.10040.4.3"
#define RSA_MD5_OID "1.2.840.113549.1.1.4"
#define RSA_MD2_OID "1.2.840.113549.1.1.2"
#define RSA_SHA1_OID "1.2.840.113549.1.1.5"

time_t _gnutls_x509_utcTime2gtime(const char *ttime);
time_t _gnutls_x509_generalTime2gtime(const char *ttime);
int _gnutls_x509_set_time(ASN1_TYPE c2, const char *where, time_t tim);

int _gnutls_x509_oid_data2string( const char* OID, void* value, 
	int value_size, char * res, size_t *res_size);

const char* _gnutls_x509_oid2ldap_string( const char* OID);

int _gnutls_x509_oid_data_choice( const char* OID);
int _gnutls_x509_oid_data_printable( const char* OID);

gnutls_pk_algorithm_t _gnutls_x509_oid2pk_algorithm( const char* oid);
gnutls_mac_algorithm_t _gnutls_x509_oid2mac_algorithm( const char* oid);
gnutls_sign_algorithm_t _gnutls_x509_oid2sign_algorithm( const char* oid);

const char* _gnutls_x509_pk_to_oid( gnutls_pk_algorithm_t pk);

gnutls_sign_algorithm_t _gnutls_x509_pk_to_sign(
        gnutls_pk_algorithm_t pk, gnutls_mac_algorithm_t mac);
const char* _gnutls_x509_sign_to_oid( gnutls_pk_algorithm_t, gnutls_mac_algorithm_t mac);
const char* _gnutls_x509_mac_to_oid( gnutls_mac_algorithm_t mac);

time_t _gnutls_x509_get_time(ASN1_TYPE c2, const char *when);

gnutls_x509_subject_alt_name_t _gnutls_x509_san_find_type( char* str_type);

int _gnutls_x509_der_encode_and_copy( ASN1_TYPE src, const char* src_name,
	ASN1_TYPE dest, const char* dest_name, int str);
int _gnutls_x509_der_encode( ASN1_TYPE src, const char* src_name,
        gnutls_datum_t *res, int str);

int _gnutls_x509_export_int( ASN1_TYPE asn1_data,
	gnutls_x509_crt_fmt_t format, char* pem_header,
	int tmp_buf_size, unsigned char* output_data, size_t* output_data_size);

int _gnutls_x509_read_value( ASN1_TYPE c, const char* root, gnutls_datum_t *ret, int str);
int _gnutls_x509_write_value( ASN1_TYPE c, const char* root, const gnutls_datum_t* data, int str);

int _gnutls_x509_encode_and_write_attribute( const char* given_oid, ASN1_TYPE asn1_struct, 
	const char* where, const void* data, int sizeof_data, int multi);
int _gnutls_x509_decode_and_read_attribute(ASN1_TYPE asn1_struct, const char* where,
        char* oid, int oid_size, gnutls_datum_t* value, int multi);

int _gnutls_x509_get_pk_algorithm( ASN1_TYPE src, const char* src_name, unsigned int* bits);

int _gnutls_x509_encode_and_copy_PKI_params( ASN1_TYPE dst, const char* dst_name,
	gnutls_pk_algorithm_t pk_algorithm, mpi_t* params, int params_size);
int _gnutls_asn1_copy_node( ASN1_TYPE *dst, const char* dst_name,
	ASN1_TYPE src, const char* src_name);

int _gnutls_x509_get_signed_data( ASN1_TYPE src, const char* src_name, gnutls_datum_t * signed_data);
int _gnutls_x509_get_signature( ASN1_TYPE src, const char* src_name, gnutls_datum_t * signature);
