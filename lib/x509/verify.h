#include "x509.h"

typedef enum gnutls_certificate_verify_flags {
	GNUTLS_VERIFY_DISABLE_CA_SIGN=1
} gnutls_certificate_verify_flags;

int gnutls_x509_certificate_is_issuer( gnutls_x509_certificate cert,
	gnutls_x509_certificate issuer);
int gnutls_x509_certificate_verify( gnutls_x509_certificate cert,
	gnutls_x509_certificate *CA_list, int CA_list_length,
	unsigned int flags, unsigned int *verify);
int gnutls_x509_crl_verify( gnutls_x509_crl crl,
	gnutls_x509_certificate *CA_list, int CA_list_length,
	unsigned int flags, unsigned int *verify);

int gnutls_x509_certificate_list_verify( gnutls_x509_certificate* cert_list, int cert_list_length, 
	gnutls_x509_certificate * CA_list, int CA_list_length, 
	gnutls_x509_crl* CRL_list, int CRL_list_length, 
	unsigned int flags, unsigned int *verify);

