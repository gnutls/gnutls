#ifndef GNUTLS_UI_H
# define GNUTLS_UI_H

typedef enum gnutls_x509_subject_alt_name {
	GNUTLS_SAN_DNSNAME=1, GNUTLS_SAN_RFC822NAME,
	GNUTLS_SAN_URI, GNUTLS_SAN_IPADDRESS
} gnutls_x509_subject_alt_name;

# ifdef LIBGNUTLS_VERSION /* These are defined only in gnutls.h */

/* Callback prototypes for the certificate authentication
 * callbacks.
 */
typedef int gnutls_certificate_client_select_function(
   gnutls_session, const gnutls_datum *client_cert, int ncerts, 
   const gnutls_datum* req_ca_cert, int nreqs);
typedef int gnutls_certificate_server_select_function(
   gnutls_session, const gnutls_datum *server_certs, int ncerts);

typedef int gnutls_certificate_client_retrieve_function(
   gnutls_session, const gnutls_datum* req_ca_cert, int nreqs,
   gnutls_datum** certs, unsigned int* ncerts, gnutls_datum* key);
typedef int gnutls_certificate_server_retrieve_function(
   gnutls_session, gnutls_datum **server_certs, unsigned int* ncerts
   gnutls_datum* key);


/* Functions that allow AUTH_INFO structures handling
 */

gnutls_credentials_type gnutls_auth_get_type( gnutls_session session);

/* DH */

void gnutls_dh_set_prime_bits( gnutls_session session, int bits);
int gnutls_dh_get_prime_bits( gnutls_session);
int gnutls_dh_get_secret_bits( gnutls_session);
int gnutls_dh_get_peers_public_bits( gnutls_session);

/* RSA */
int gnutls_rsa_export_get_modulus_bits(gnutls_session session);

/* X509PKI */

#include <gnutls/compat8.h>

void gnutls_certificate_client_set_select_function( gnutls_session, gnutls_certificate_client_select_function *);
void gnutls_certificate_server_set_select_function( gnutls_session, gnutls_certificate_server_select_function *);

void gnutls_certificate_client_set_retrieve_function( gnutls_session, gnutls_certificate_client_retrieve_function *);
void gnutls_certificate_server_set_retrieve_function( gnutls_session, gnutls_certificate_server_retrieve_function *);

void gnutls_certificate_server_set_request( gnutls_session, gnutls_certificate_request);

/* X.509 certificate handling functions 
 */

int gnutls_pkcs3_extract_dh_params(const gnutls_datum * params,
	gnutls_x509_crt_fmt format, gnutls_datum * prime,
	gnutls_datum * generator, int* prime_bits);
int gnutls_pkcs3_export_dh_params( const gnutls_datum * prime,
	const gnutls_datum * generator, gnutls_x509_crt_fmt format,
	unsigned char* params_data, int* params_data_size);

/* get data from the session 
 */
const gnutls_datum* gnutls_certificate_get_peers( gnutls_session, unsigned int* list_size);
const gnutls_datum *gnutls_certificate_get_ours( gnutls_session session);

time_t gnutls_certificate_activation_time_peers(gnutls_session session);
time_t gnutls_certificate_expiration_time_peers(gnutls_session session);

int gnutls_certificate_client_get_request_status(  gnutls_session);
int gnutls_certificate_verify_peers( gnutls_session);

int gnutls_pem_base64_encode( const char* header, const gnutls_datum *data, 
	char* result, size_t* result_size);
int gnutls_pem_base64_decode( const char* header, const gnutls_datum *b64_data, 
	unsigned char* result, size_t* result_size);

int gnutls_pem_base64_encode_alloc( const char* header, const gnutls_datum *data, 
	gnutls_datum * result);
int gnutls_pem_base64_decode_alloc( const char* header, const gnutls_datum *b64_data, 
	gnutls_datum* result);

# endif /* LIBGNUTLS_VERSION */

#endif /* GNUTLS_UI_H */
