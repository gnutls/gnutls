#include <stdio.h>

#define SUCCEED 1
#define FAILED 0
#define UNSURE -1

int test_srp( GNUTLS_STATE state);
int test_hello_extension( GNUTLS_STATE state);
int test_dhe( GNUTLS_STATE state);
int test_ssl3( GNUTLS_STATE state);
int test_aes( GNUTLS_STATE state);
int test_md5( GNUTLS_STATE state);
int test_sha( GNUTLS_STATE state);
int test_3des( GNUTLS_STATE state);
int test_arcfour( GNUTLS_STATE state);
int test_tls1( GNUTLS_STATE state);
int test_tls1_2( GNUTLS_STATE state);
int test_rsa_pms( GNUTLS_STATE state);
int test_max_record_size( GNUTLS_STATE state);
int test_version_rollback( GNUTLS_STATE state);
int test_anonymous( GNUTLS_STATE state);
int test_unknown_ciphersuites( GNUTLS_STATE state);
int test_openpgp1( GNUTLS_STATE state);
int test_bye( GNUTLS_STATE state);
int test_session_resume2( GNUTLS_STATE state);

#define GERR(ret) fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret))

