#include "x509.h"

typedef enum gnutls_certificate_verify_flags {
    GNUTLS_VERIFY_DISABLE_CA_SIGN=1,
    GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT=2,
    GNUTLS_VERIFY_DO_NOT_ALLOW_SAME=4
} gnutls_certificate_verify_flags;

int gnutls_x509_crt_is_issuer( gnutls_x509_crt_t cert,
    gnutls_x509_crt_t issuer);
int gnutls_x509_crt_verify( gnutls_x509_crt_t cert,
    const gnutls_x509_crt_t *CA_list, int CA_list_length,
    unsigned int flags, unsigned int *verify);
int gnutls_x509_crl_verify( gnutls_x509_crl_t crl,
    const gnutls_x509_crt_t *CA_list, int CA_list_length,
    unsigned int flags, unsigned int *verify);

int gnutls_x509_crt_list_verify( 
    const gnutls_x509_crt_t* cert_list, int cert_list_length, 
    const gnutls_x509_crt_t * CA_list, int CA_list_length, 
    const gnutls_x509_crl_t* CRL_list, int CRL_list_length, 
    unsigned int flags, unsigned int *verify);

int _gnutls_x509_verify_signature( const gnutls_datum_t* tbs,
    const gnutls_datum_t* signature, gnutls_x509_crt_t issuer);
int _gnutls_x509_privkey_verify_signature( const gnutls_datum_t* tbs,
    const gnutls_datum_t* signature, gnutls_x509_privkey_t issuer);
