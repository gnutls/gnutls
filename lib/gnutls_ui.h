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

typedef enum GNUTLS_X509_SUBJECT_ALT_NAME {
	GNUTLS_SAN_DNSNAME=1, GNUTLS_SAN_RFC822NAME,
	GNUTLS_SAN_URI, GNUTLS_SAN_IPADDRESS
} GNUTLS_X509_SUBJECT_ALT_NAME;

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

typedef int gnutls_certificate_client_select_func(GNUTLS_STATE, const gnutls_datum *, int, const gnutls_datum *, int);
typedef int gnutls_certificate_server_select_func(GNUTLS_STATE, const gnutls_datum *, int);

/* Functions that allow AUTH_INFO structures handling
 */

GNUTLS_CredType gnutls_auth_get_type( GNUTLS_STATE state);

/* DH */

void gnutls_dh_set_prime_bits( GNUTLS_STATE state, int bits);
int gnutls_dh_get_prime_bits( GNUTLS_STATE);
int gnutls_dh_get_secret_bits( GNUTLS_STATE);
int gnutls_dh_get_peers_public_bits( GNUTLS_STATE);

/* X509PKI */

void gnutls_certificate_client_set_select_func( GNUTLS_STATE, gnutls_certificate_client_select_func *);
void gnutls_certificate_server_set_select_func( GNUTLS_STATE, gnutls_certificate_server_select_func *);

void gnutls_certificate_server_set_request( GNUTLS_STATE, GNUTLS_CertificateRequest);

/* X.509 certificate handling functions */
int gnutls_x509_get_certificate_xml(const gnutls_datum * cert,  gnutls_datum* res);

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

int gnutls_x509_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, const gnutls_datum * CA_list, int CA_list_length, const gnutls_datum* CRL_list, int CRL_list_length);


/* get data from the state */
const gnutls_datum* gnutls_certificate_get_peers( GNUTLS_STATE, int* list_size);
const gnutls_datum *gnutls_certificate_get_ours( GNUTLS_STATE state);

time_t gnutls_certificate_activation_time_peers(GNUTLS_STATE state);
time_t gnutls_certificate_expiration_time_peers(GNUTLS_STATE state);

int gnutls_certificate_client_get_request_status(  GNUTLS_STATE);
int gnutls_certificate_verify_peers( GNUTLS_STATE);

int gnutls_b64_encode_fmt( const char* msg, const gnutls_datum *data, char* result, int* result_size);
int gnutls_b64_decode_fmt( const gnutls_datum *b64_data, char* result, int* result_size);

int gnutls_b64_encode_fmt2( const char* msg, const gnutls_datum *data, const gnutls_datum * result);
int gnutls_b64_decode_fmt2( const gnutls_datum *b64_data, const gnutls_datum* result);

# endif /* LIBGNUTLS_VERSION */

#endif /* GNUTLS_UI_H */
