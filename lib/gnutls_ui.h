#ifndef GNUTLS_UI_H
# define GNUTLS_UI_H

typedef enum gnutls_x509_subject_alt_name_t {
    GNUTLS_SAN_DNSNAME = 1, GNUTLS_SAN_RFC822NAME,
    GNUTLS_SAN_URI, GNUTLS_SAN_IPADDRESS
} gnutls_x509_subject_alt_name_t;

# ifdef LIBGNUTLS_VERSION	/* These are defined only in gnutls.h */

struct gnutls_openpgp_key_int;
typedef struct gnutls_openpgp_key_int *gnutls_openpgp_key_t;

struct gnutls_openpgp_privkey_int;
typedef struct gnutls_openpgp_privkey_int *gnutls_openpgp_privkey_t;

typedef struct gnutls_retr_st {
    gnutls_certificate_type_t type;
    union cert {
	gnutls_x509_crt_t *x509;
	gnutls_openpgp_key_t pgp;
    } cert;
    unsigned int ncerts;	/* one for pgp keys */

    union key {
	gnutls_x509_privkey_t x509;
	gnutls_openpgp_privkey_t pgp;
    } key;

    unsigned int deinit_all;	/* if non zero all keys will be deinited */
} gnutls_retr_st;

typedef int gnutls_certificate_client_retrieve_function(gnutls_session_t,
    const gnutls_datum_t* req_ca_rdn, int nreqs,
    const gnutls_pk_algorithm_t* pk_algos, int pk_algos_length, gnutls_retr_st *);
typedef int gnutls_certificate_server_retrieve_function(gnutls_session_t,
    gnutls_retr_st *);


/* Functions that allow auth_info_t structures handling
 */

gnutls_credentials_type_t gnutls_auth_get_type(gnutls_session_t session);
gnutls_credentials_type_t gnutls_auth_server_get_type(gnutls_session_t session);
gnutls_credentials_type_t gnutls_auth_client_get_type(gnutls_session_t session);

/* DH */

void gnutls_dh_set_prime_bits(gnutls_session_t session, int bits);
int gnutls_dh_get_secret_bits(gnutls_session_t);
int gnutls_dh_get_peers_public_bits(gnutls_session_t);
int gnutls_dh_get_prime_bits(gnutls_session_t);

int gnutls_dh_get_group(gnutls_session_t, gnutls_datum_t * gen,
    gnutls_datum_t * prime);
int gnutls_dh_get_pubkey(gnutls_session_t, gnutls_datum_t * pub);

/* RSA */
int gnutls_rsa_export_get_pubkey(gnutls_session_t session,
				 gnutls_datum_t * exp, gnutls_datum_t * mod);
int gnutls_rsa_export_get_modulus_bits(gnutls_session_t session);

/* X509PKI */

/* These are set on the credentials structure.
 */
void
gnutls_certificate_client_set_retrieve_function( gnutls_certificate_credentials_t,
    gnutls_certificate_client_retrieve_function *);
void gnutls_certificate_server_set_retrieve_function(gnutls_certificate_credentials_t,
    gnutls_certificate_server_retrieve_function *);

void gnutls_certificate_server_set_request(gnutls_session_t session,
    gnutls_certificate_request_t req);

/* X.509 certificate handling functions 
 */

int gnutls_pkcs3_extract_dh_params(const gnutls_datum_t * params,
    gnutls_x509_crt_fmt_t format,
    gnutls_datum_t * prime, gnutls_datum_t * generator, int *prime_bits);
int gnutls_pkcs3_export_dh_params(const gnutls_datum_t * prime,
    const gnutls_datum_t * generator, gnutls_x509_crt_fmt_t format,
    unsigned char *params_data, int *params_data_size);

/* get data from the session 
 */
const gnutls_datum_t *gnutls_certificate_get_peers(gnutls_session_t,
    unsigned int *list_size);
const gnutls_datum_t *gnutls_certificate_get_ours(gnutls_session_t session);

time_t gnutls_certificate_activation_time_peers(gnutls_session_t session);
time_t gnutls_certificate_expiration_time_peers(gnutls_session_t session);

int gnutls_certificate_client_get_request_status(gnutls_session_t);
int gnutls_certificate_verify_peers2(gnutls_session_t, unsigned int* status);

int gnutls_pem_base64_encode(const char *header, const gnutls_datum_t * data,
    char *result, size_t * result_size);
int gnutls_pem_base64_decode(const char *header,
    const gnutls_datum_t * b64_data,
    unsigned char *result, size_t * result_size);

int gnutls_pem_base64_encode_alloc(const char *header,
    const gnutls_datum_t * data, gnutls_datum_t * result);
int gnutls_pem_base64_decode_alloc(const char *header,
    const gnutls_datum_t * b64_data, gnutls_datum_t * result);

/* key_usage will be an OR of the following values:
 */
#define GNUTLS_KEY_DIGITAL_SIGNATURE            128	/* when the key is to be
							 * used for signing.
							 */
#define GNUTLS_KEY_NON_REPUDIATION              64
#define GNUTLS_KEY_KEY_ENCIPHERMENT             32	/* when the key is to be
							 * used for encryption.
							 */
#define GNUTLS_KEY_DATA_ENCIPHERMENT            16
#define GNUTLS_KEY_KEY_AGREEMENT                8
#define GNUTLS_KEY_KEY_CERT_SIGN                4
#define GNUTLS_KEY_CRL_SIGN                     2
#define GNUTLS_KEY_ENCIPHER_ONLY                1
#define GNUTLS_KEY_DECIPHER_ONLY                32768

typedef struct gnutls_params_st {
    gnutls_params_type_t type;
    union params {
	gnutls_dh_params_t dh;
	gnutls_rsa_params_t rsa_export;
    } params;
    int deinit;
} gnutls_params_st;

typedef int gnutls_params_function(gnutls_session_t, gnutls_params_type_t,
				   gnutls_params_st *);

void gnutls_certificate_set_params_function(gnutls_certificate_credentials_t
					    res,
					    gnutls_params_function * func);
void gnutls_anon_set_params_function(gnutls_certificate_credentials_t res,
				     gnutls_params_function * func);



# endif				/* LIBGNUTLS_VERSION */

#endif				/* GNUTLS_UI_H */
