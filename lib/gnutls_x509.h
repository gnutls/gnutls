#include <libtasn1.h>

int _gnutls_x509_cert_verify_peers(gnutls_session session);

typedef enum ConvFlags { 
	CERT_NO_COPY=2, 
	CERT_ONLY_PUBKEY=4,
	CERT_ONLY_EXTENSIONS=16
} ConvFlags;

int _gnutls_x509_cert2gnutls_cert(gnutls_cert * gCert, gnutls_datum derCert, ConvFlags flags);

#define PEM_CERT_SEP2 "-----BEGIN X509 CERTIFICATE"
#define PEM_CERT_SEP "-----BEGIN CERTIFICATE"
#define PEM_PKCS7_SEP "-----BEGIN PKCS7"

#define PEM_KEY_RSA_SEP "-----BEGIN RSA"
#define PEM_KEY_DSA_SEP "-----BEGIN DSA"

int _gnutls_check_x509_key_usage( const gnutls_cert * cert, gnutls_kx_algorithm alg);

int _gnutls_x509_read_rsa_params(opaque * der, int dersize, GNUTLS_MPI * params);
int _gnutls_x509_read_dsa_pubkey(opaque * der, int dersize, GNUTLS_MPI * params);
