#ifndef GNUTLS_UI_H
# define GNUTLS_UI_H


/* Extra definitions */

#define X509_CN_SIZE 256
#define X509_C_SIZE 3
#define X509_O_SIZE 256
#define X509_OU_SIZE 256
#define X509_L_SIZE 256
#define X509_S_SIZE 256
#define X509_EMAIL_SIZE 256

typedef struct {
	char common_name[X509_CN_SIZE];
	char country[X509_C_SIZE];
	char organization[X509_O_SIZE];
	char organizational_unit_name[X509_OU_SIZE];
	char locality_name[X509_L_SIZE];
	char state_or_province_name[X509_S_SIZE];
	char email[X509_EMAIL_SIZE];
} gnutls_DN;

/* For key Usage, test as:
 * if (st.keyUsage & X509KEY_DIGITAL_SIGNATURE) ...
 */
#define X509KEY_DIGITAL_SIGNATURE 	256
#define X509KEY_NON_REPUDIATION		128
#define X509KEY_KEY_ENCIPHERMENT	64
#define X509KEY_DATA_ENCIPHERMENT	32
#define X509KEY_KEY_AGREEMENT		16
#define X509KEY_KEY_CERT_SIGN		8
#define X509KEY_CRL_SIGN		4
#define X509KEY_ENCIPHER_ONLY		2
#define X509KEY_DECIPHER_ONLY		1


# ifdef LIBGNUTLS_VERSION /* These are defined only in gnutls.h */

typedef int x509pki_client_cert_callback_func(GNUTLS_STATE, const gnutls_datum *, int, const gnutls_datum *, int);
typedef int x509pki_server_cert_callback_func(GNUTLS_STATE, const gnutls_datum *, int);

/* Functions that allow AUTH_INFO structures handling
 */

CredType gnutls_auth_get_type( GNUTLS_STATE state);

/* SRP */

const char* gnutls_srp_server_get_username( GNUTLS_STATE state);

/* ANON */

int gnutls_anon_server_get_dh_bits( GNUTLS_STATE state);
int gnutls_anon_client_get_dh_bits( GNUTLS_STATE state);

/* X509PKI */

void gnutls_x509pki_set_client_cert_callback( X509PKI_CREDENTIALS, x509pki_client_cert_callback_func *);

void gnutls_x509pki_set_server_cert_callback( X509PKI_CREDENTIALS, x509pki_server_cert_callback_func *);
void gnutls_x509pki_server_set_cert_request( GNUTLS_STATE, CertificateRequest);

void gnutls_x509pki_set_dh_bits( GNUTLS_STATE state, int bits);

/* X.509 certificate handling functions */
int gnutls_x509pki_extract_dn( const gnutls_datum*, gnutls_DN*);
int gnutls_x509pki_extract_certificate_dn( const gnutls_datum*, gnutls_DN*);
int gnutls_x509pki_extract_certificate_issuer_dn(  const gnutls_datum*, gnutls_DN *);
int gnutls_x509pki_extract_certificate_version( const gnutls_datum*);
time_t gnutls_x509pki_extract_certificate_activation_time( const gnutls_datum*);
time_t gnutls_x509pki_extract_certificate_expiration_time( const gnutls_datum*);
int gnutls_x509pki_extract_subject_dns_name( const gnutls_datum*, char*, int*);

/* get data from the state */
const gnutls_datum* gnutls_x509pki_get_peer_certificate_list( GNUTLS_STATE, int* list_size);
int gnutls_x509pki_get_dh_bits( GNUTLS_STATE);
int gnutls_x509pki_get_certificate_request_status(  GNUTLS_STATE);
int gnutls_x509pki_get_peer_certificate_status( GNUTLS_STATE);

#define gnutls_x509pki_server_get_dh_bits gnutls_x509pki_get_dh_bits
#define gnutls_x509pki_client_get_dh_bits gnutls_x509pki_get_dh_bits

#define gnutls_x509pki_server_get_peer_certificate_status gnutls_x509pki_get_peer_certificate_status
#define gnutls_x509pki_server_get_peer_certificate_list gnutls_x509pki_get_peer_certificate_list

#define gnutls_x509pki_client_get_peer_certificate_status gnutls_x509pki_get_peer_certificate_status
#define gnutls_x509pki_client_get_peer_certificate_list gnutls_x509pki_get_peer_certificate_list

# endif /* LIBGNUTLS_VERSION */

#endif /* GNUTLS_UI_H */
