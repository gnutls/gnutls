#ifndef GNUTLS_UI_H
# define GNUTLS_UI_H


/* Extra definitions */

#define GNUTLS_X509_CN_SIZE 256
#define GNUTLS_X509_C_SIZE 3
#define GNUTLS_X509_O_SIZE 256
#define GNUTLS_X509_OU_SIZE 256
#define GNUTLS_X509_L_SIZE 256
#define GNUTLS_X509_S_SIZE 256
#define GNUTLS_X509_EMAIL_SIZE 256

typedef struct {
	char common_name[GNUTLS_X509_CN_SIZE];
	char country[GNUTLS_X509_C_SIZE];
	char organization[GNUTLS_X509_O_SIZE];
	char organizational_unit_name[GNUTLS_X509_OU_SIZE];
	char locality_name[GNUTLS_X509_L_SIZE];
	char state_or_province_name[GNUTLS_X509_S_SIZE];
	char email[GNUTLS_X509_EMAIL_SIZE];
} gnutls_x509_dn;
#define gnutls_DN gnutls_x509_dn

typedef struct {
	char name[GNUTLS_X509_CN_SIZE];
	char email[GNUTLS_X509_CN_SIZE];
} gnutls_openpgp_name;	

typedef enum gnutls_x509_subject_alt_name {
	GNUTLS_SAN_DNSNAME=1, GNUTLS_SAN_RFC822NAME,
	GNUTLS_SAN_URI, GNUTLS_SAN_IPADDRESS
} gnutls_x509_subject_alt_name;
#define GNUTLS_X509_SUBJECT_ALT_NAME gnutls_x509_subject_alt_name

/* For key Usage, test as:
 * if (st.keyUsage & X509KEY_DIGITAL_SIGNATURE) ...
 */
#define GNUTLS_X509KEY_DIGITAL_SIGNATURE 	256
#define GNUTLS_X509KEY_NON_REPUDIATION		128
#define GNUTLS_X509KEY_KEY_ENCIPHERMENT		64
#define GNUTLS_X509KEY_DATA_ENCIPHERMENT	32
#define GNUTLS_X509KEY_KEY_AGREEMENT		16
#define GNUTLS_X509KEY_KEY_CERT_SIGN		8
#define GNUTLS_X509KEY_CRL_SIGN			4
#define GNUTLS_X509KEY_ENCIPHER_ONLY		2
#define GNUTLS_X509KEY_DECIPHER_ONLY		1


# ifdef LIBGNUTLS_VERSION /* These are defined only in gnutls.h */

typedef int gnutls_certificate_client_select_function(gnutls_session, const gnutls_datum *, int, const gnutls_datum *, int);
typedef int gnutls_certificate_server_select_function(gnutls_session, const gnutls_datum *, int);
#define gnutls_certificate_client_select_func gnutls_certificate_client_select_function
#define gnutls_certificate_server_select_func gnutls_certificate_server_select_function

/* Functions that allow AUTH_INFO structures handling
 */

gnutls_credentials_type gnutls_auth_get_type( gnutls_session session);

/* DH */

void gnutls_dh_set_prime_bits( gnutls_session session, int bits);
int gnutls_dh_get_prime_bits( gnutls_session);
int gnutls_dh_get_secret_bits( gnutls_session);
int gnutls_dh_get_peers_public_bits( gnutls_session);

/* RSA */
int gnutls_rsa_export_get_modulus_bits(gnutls_session session);

/* X509PKI */

void gnutls_certificate_client_set_select_function( gnutls_session, gnutls_certificate_client_select_function *);
void gnutls_certificate_server_set_select_function( gnutls_session, gnutls_certificate_server_select_function *);
#define gnutls_certificate_client_set_select_func gnutls_certificate_client_set_select_function
#define gnutls_certificate_server_set_select_func gnutls_certificate_server_set_select_function

void gnutls_certificate_server_set_request( gnutls_session, gnutls_certificate_request);

/* X.509 certificate handling functions */
int gnutls_x509_certificate_to_xml(const gnutls_datum * cert, gnutls_datum* res, int detail);

int gnutls_x509_extract_dn( const gnutls_datum*, gnutls_x509_dn*);
int gnutls_x509_extract_certificate_dn( const gnutls_datum*, gnutls_x509_dn*);
int gnutls_x509_extract_certificate_issuer_dn(  const gnutls_datum*, gnutls_x509_dn *);
int gnutls_x509_extract_certificate_version( const gnutls_datum*);
int gnutls_x509_extract_certificate_serial(const gnutls_datum * cert, char* result, int* result_size);
time_t gnutls_x509_extract_certificate_activation_time( const gnutls_datum*);
time_t gnutls_x509_extract_certificate_expiration_time( const gnutls_datum*);
int gnutls_x509_extract_certificate_subject_alt_name( const gnutls_datum*, int seq, char*, int*);
int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size);
int gnutls_x509_extract_certificate_pk_algorithm( const gnutls_datum * cert, int* bits);
int gnutls_x509_extract_key_pk_algorithm( const gnutls_datum * key);

int gnutls_x509_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, const gnutls_datum * CA_list, int CA_list_length, const gnutls_datum* CRL_list, int CRL_list_length);


/* get data from the session */
const gnutls_datum* gnutls_certificate_get_peers( gnutls_session, int* list_size);
const gnutls_datum *gnutls_certificate_get_ours( gnutls_session session);
const gnutls_datum *gnutls_certificate_get_our_issuer(gnutls_session session);

time_t gnutls_certificate_activation_time_peers(gnutls_session session);
time_t gnutls_certificate_expiration_time_peers(gnutls_session session);

int gnutls_certificate_client_get_request_status(  gnutls_session);
int gnutls_certificate_verify_peers( gnutls_session);

int gnutls_pem_base64_encode( const char* header, const gnutls_datum *data, char* result, int* result_size);
int gnutls_pem_base64_decode( const char* header, const gnutls_datum *b64_data, char* result, int* result_size);

int gnutls_pem_base64_encode_alloc( const char* header, const gnutls_datum *data, gnutls_datum * result);
int gnutls_pem_base64_decode_alloc( const char* header, const gnutls_datum *b64_data, gnutls_datum* result);

# endif /* LIBGNUTLS_VERSION */

#endif /* GNUTLS_UI_H */
