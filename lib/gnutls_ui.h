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

typedef int x509_cert_callback_func(gnutls_DN *, gnutls_DN *, int, gnutls_DN *, int);


# ifdef LIBGNUTLS_VERSION /* defined only in gnutls.h */

/* Functions that allow AUTH_INFO structures handling
 */

CredType gnutls_get_auth_type( GNUTLS_STATE state);

/* SRP */

const char* gnutls_srp_server_get_username( GNUTLS_STATE state);

/* ANON */

int gnutls_anon_server_get_dh_bits( GNUTLS_STATE state);
int gnutls_anon_client_get_dh_bits( GNUTLS_STATE state);

/* X509PKI */

int gnutls_set_x509_cert_callback( X509PKI_CREDENTIALS, x509_cert_callback_func *);
int gnutls_x509pki_set_cert_request( GNUTLS_STATE, CertificateRequest);

int gnutls_x509pki_get_certificate_request_status(  GNUTLS_STATE);
const gnutls_DN* gnutls_x509pki_get_peer_dn( GNUTLS_STATE);
const gnutls_datum* gnutls_x509pki_get_peer_certificate( GNUTLS_STATE);
const gnutls_DN* gnutls_x509pki_get_issuer_dn(  GNUTLS_STATE);
CertificateStatus gnutls_x509pki_get_peer_certificate_status( GNUTLS_STATE);
int gnutls_x509pki_get_peer_certificate_version( GNUTLS_STATE);
time_t gnutls_x509pki_get_peer_certificate_activation_time( GNUTLS_STATE);
time_t gnutls_x509pki_get_peer_certificate_expiration_time( GNUTLS_STATE);
unsigned char gnutls_x509pki_get_key_usage( GNUTLS_STATE);
const char* gnutls_x509pki_get_subject_dns_name( GNUTLS_STATE);
int gnutls_x509pki_get_dh_bits( GNUTLS_STATE);

#define gnutls_x509pki_server_get_dh_bits gnutls_x509pki_get_dh_bits
#define gnutls_x509pki_client_get_dh_bits gnutls_x509pki_get_dh_bits

#define gnutls_x509pki_server_get_peer_dn gnutls_x509pki_get_peer_dn
#define gnutls_x509pki_server_get_issuer_dn gnutls_x509pki_get_issuer_dn
#define gnutls_x509pki_server_get_peer_certificate_status gnutls_x509pki_get_peer_certificate_status
#define gnutls_x509pki_server_get_peer_certificate gnutls_x509pki_get_peer_certificate
#define gnutls_x509pki_server_get_peer_certificate_version gnutls_x509pki_get_peer_certificate_version
#define gnutls_x509pki_server_get_peer_certificate_activation_time gnutls_x509pki_get_peer_certificate_activation_time
#define gnutls_x509pki_server_get_peer_certificate_expiration_time gnutls_x509pki_get_peer_certificate_expiration_time
#define gnutls_x509pki_server_get_key_usage gnutls_x509pki_get_key_usage
#define gnutls_x509pki_server_get_subject_dns_name gnutls_x509pki_get_subject_dns_name

#define gnutls_x509pki_client_get_peer_dn gnutls_x509pki_get_peer_dn
#define gnutls_x509pki_client_get_issuer_dn gnutls_x509pki_get_issuer_dn
#define gnutls_x509pki_client_get_peer_certificate_status gnutls_x509pki_get_peer_certificate_status
#define gnutls_x509pki_client_get_peer_certificate gnutls_x509pki_get_peer_certificate
#define gnutls_x509pki_client_get_peer_certificate_version gnutls_x509pki_get_peer_certificate_version
#define gnutls_x509pki_client_get_peer_certificate_activation_time gnutls_x509pki_get_peer_certificate_activation_time
#define gnutls_x509pki_client_get_peer_certificate_expiration_time gnutls_x509pki_get_peer_certificate_expiration_time
#define gnutls_x509pki_client_get_key_usage gnutls_x509pki_get_key_usage
#define gnutls_x509pki_client_get_subject_dns_name gnutls_x509pki_get_subject_dns_name

# endif /* LIBGNUTLS_VERSION */

#endif /* GNUTLS_UI_H */
