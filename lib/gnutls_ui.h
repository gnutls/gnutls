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

/* SRP */

const char* gnutls_srp_server_get_username( const SRP_SERVER_AUTH_INFO info);

/* ANON */

int gnutls_anon_server_get_dh_bits(  ANON_SERVER_AUTH_INFO info);
int gnutls_anon_client_get_dh_bits(  ANON_CLIENT_AUTH_INFO info);

/* X509PKI */

int gnutls_set_x509_cert_callback( X509PKI_CREDENTIALS, x509_cert_callback_func *);
int gnutls_x509pki_set_cert_request( GNUTLS_STATE, CertificateRequest);

const gnutls_DN* gnutls_x509pki_get_peer_dn(  X509PKI_CLIENT_AUTH_INFO info);
const gnutls_DN* gnutls_x509pki_get_issuer_dn(  X509PKI_CLIENT_AUTH_INFO info);
CertificateStatus gnutls_x509pki_get_peer_certificate_status(  X509PKI_CLIENT_AUTH_INFO info);
int gnutls_x509pki_get_peer_certificate_version(  X509PKI_CLIENT_AUTH_INFO info);
time_t gnutls_x509pki_get_peer_certificate_activation_time(  X509PKI_CLIENT_AUTH_INFO info);
time_t gnutls_x509pki_get_peer_certificate_expiration_time(  X509PKI_CLIENT_AUTH_INFO info);
unsigned char gnutls_x509pki_get_key_usage(  X509PKI_CLIENT_AUTH_INFO info);
const char* gnutls_x509pki_get_subject_dns_name(  X509PKI_CLIENT_AUTH_INFO info);
int gnutls_x509pki_get_dh_bits(  X509PKI_CLIENT_AUTH_INFO info);

#define gnutls_x509pki_server_get_dh_bits gnutls_x509pki_get_dh_bits
#define gnutls_x509pki_client_get_dh_bits gnutls_x509pki_get_dh_bits

#define gnutls_x509pki_server_get_peer_dn gnutls_x509pki_get_peer_dn
#define gnutls_x509pki_server_get_issuer_dn gnutls_x509pki_get_issuer_dn
#define gnutls_x509pki_server_get_peer_certificate_status gnutls_x509pki_get_peer_certificate_status
#define gnutls_x509pki_server_get_peer_certificate_version gnutls_x509pki_get_peer_certificate_version
#define gnutls_x509pki_server_get_peer_certificate_activation_time gnutls_x509pki_get_peer_certificate_activation_time
#define gnutls_x509pki_server_get_peer_certificate_expiration_time gnutls_x509pki_get_peer_certificate_expiration_time
#define gnutls_x509pki_server_get_key_usage gnutls_x509pki_get_key_usage
#define gnutls_x509pki_server_get_subject_dns_name gnutls_x509pki_get_subject_dns_name

#define gnutls_x509pki_client_get_peer_dn gnutls_x509pki_get_peer_dn
#define gnutls_x509pki_client_get_issuer_dn gnutls_x509pki_get_issuer_dn
#define gnutls_x509pki_client_get_peer_certificate_status gnutls_x509pki_get_peer_certificate_status
#define gnutls_x509pki_client_get_peer_certificate_version gnutls_x509pki_get_peer_certificate_version
#define gnutls_x509pki_client_get_peer_certificate_activation_time gnutls_x509pki_get_peer_certificate_activation_time
#define gnutls_x509pki_client_get_peer_certificate_expiration_time gnutls_x509pki_get_peer_certificate_expiration_time
#define gnutls_x509pki_client_get_key_usage gnutls_x509pki_get_key_usage
#define gnutls_x509pki_client_get_subject_dns_name gnutls_x509pki_get_subject_dns_name

# endif /* LIBGNUTLS_VERSION */

#endif
