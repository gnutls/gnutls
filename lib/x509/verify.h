#include "x509.h"

typedef enum gnutls_certificate_verify_flags {
	GNUTLS_VERIFY_DISABLE_CA_SIGN=1,
	GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT=2
} gnutls_certificate_verify_flags;

int gnutls_x509_crt_is_issuer( gnutls_x509_crt cert,
	gnutls_x509_crt issuer);
int gnutls_x509_crt_verify( gnutls_x509_crt cert,
	gnutls_x509_crt *CA_list, int CA_list_length,
	unsigned int flags, unsigned int *verify);
int gnutls_x509_crl_verify( gnutls_x509_crl crl,
	gnutls_x509_crt *CA_list, int CA_list_length,
	unsigned int flags, unsigned int *verify);

int gnutls_x509_crt_list_verify( gnutls_x509_crt* cert_list, int cert_list_length, 
	gnutls_x509_crt * CA_list, int CA_list_length, 
	gnutls_x509_crl* CRL_list, int CRL_list_length, 
	unsigned int flags, unsigned int *verify);

int _gnutls_x509_verify_signature( const gnutls_datum* tbs,
	const gnutls_datum* signature, gnutls_x509_crt issuer);
int _gnutls_x509_privkey_verify_signature( const gnutls_datum* tbs,
	const gnutls_datum* signature, gnutls_x509_privkey issuer);
