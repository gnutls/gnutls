#include <libtasn1.h>

int _gnutls_x509_cert_verify_peers(gnutls_session session);

#define PEM_CERT_SEP2 "-----BEGIN X509 CERTIFICATE"
#define PEM_CERT_SEP "-----BEGIN CERTIFICATE"
#define PEM_PKCS7_SEP "-----BEGIN PKCS7"

#define PEM_CRL_SEP "-----BEGIN X509 CRL"

#define PEM_KEY_RSA_SEP "-----BEGIN RSA"
#define PEM_KEY_DSA_SEP "-----BEGIN DSA"

int _gnutls_check_key_usage( const gnutls_cert* cert, gnutls_kx_algorithm alg);

int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize, GNUTLS_MPI * params);

int _gnutls_x509_raw_privkey_to_gkey( gnutls_privkey* privkey, const gnutls_datum* raw_key,
        gnutls_x509_crt_fmt type);
int _gnutls_x509_privkey_to_gkey( gnutls_privkey* privkey, gnutls_x509_privkey);
