#ifndef X509_H
# define X509_H

#define OID_SHA1 "1.3.14.3.2.26"
#define OID_MD5 "1.2.840.113549.2.5"

typedef struct gnutls_x509_crl_int {
	ASN1_TYPE crl;
} gnutls_x509_crl_int;

typedef struct gnutls_x509_crt_int {
	ASN1_TYPE cert;
	int use_extensions;
} gnutls_x509_crt_int;


#define MAX_PRIV_PARAMS_SIZE 6 /* ok for RSA and DSA */

/* parameters should not be larger than this limit */
#define DSA_PRIVATE_PARAMS 5
#define DSA_PUBLIC_PARAMS 4
#define RSA_PRIVATE_PARAMS 6
#define RSA_PUBLIC_PARAMS 2

#if MAX_PRIV_PARAMS_SIZE - RSA_PRIVATE_PARAMS < 0
# error INCREASE MAX_PRIV_PARAMS
#endif

#if MAX_PRIV_PARAMS_SIZE - DSA_PRIVATE_PARAMS < 0
# error INCREASE MAX_PRIV_PARAMS
#endif

typedef struct gnutls_x509_privkey_int {
	GNUTLS_MPI params[MAX_PRIV_PARAMS_SIZE];/* the size of params depends on the public 
				 * key algorithm 
				 */
				/*
				 * RSA: [0] is modulus
				 *      [1] is public exponent
				 *	[2] is private exponent
				 *	[3] is prime1 (p)
				 *	[4] is prime2 (q)
				 *	[5] is coefficient (u == inverse of p mod q)
				 * DSA: [0] is p
				 *      [1] is q
				 *      [2] is g
				 *      [3] is y (public key)
				 *      [4] is x (private key)
				 */
	int params_size; /* holds the number of params */

	gnutls_pk_algorithm pk_algorithm;

	ASN1_TYPE key;
} gnutls_x509_privkey_int;

typedef struct gnutls_x509_crt_int *gnutls_x509_crt;
typedef struct gnutls_x509_crl_int *gnutls_x509_crl;
typedef struct gnutls_x509_privkey_int *gnutls_x509_privkey;

int gnutls_x509_crt_get_issuer_dn_by_oid(gnutls_x509_crt cert, const char* oid, 
	int indx, unsigned int raw_flag, void *buf, size_t *sizeof_buf);
int gnutls_x509_crt_get_subject_alt_name(gnutls_x509_crt cert, 
	unsigned int seq, void *ret, size_t *ret_size, unsigned int* critical);
int gnutls_x509_crt_get_dn_by_oid(gnutls_x509_crt cert, const char* oid, 
	int indx, unsigned int raw_flag, void *buf, size_t *sizeof_buf);
int gnutls_x509_crt_get_dn(gnutls_x509_crt cert, char *buf,
					 size_t *sizeof_buf);
int gnutls_x509_crt_get_issuer_dn(gnutls_x509_crt cert, char *buf,
					 size_t *sizeof_buf);

int gnutls_x509_crt_get_ca_status(gnutls_x509_crt cert, unsigned int* critical);
int gnutls_x509_crt_get_pk_algorithm( gnutls_x509_crt cert, unsigned int* bits);

int _gnutls_x509_crt_cpy(gnutls_x509_crt dest, gnutls_x509_crt src);
int _gnutls_x509_crt_get_raw_issuer_dn( gnutls_x509_crt cert,
	gnutls_datum* start);
int _gnutls_x509_crt_get_raw_dn( gnutls_x509_crt cert,
	gnutls_datum* start);

int gnutls_x509_crt_get_serial(gnutls_x509_crt cert, void* result, size_t* result_size);

int _gnutls_x509_compare_raw_dn(const gnutls_datum * dn1,
	const gnutls_datum * dn2);

int gnutls_x509_crt_check_revocation(gnutls_x509_crt cert, gnutls_x509_crl * crl_list, int crl_list_length);


int _gnutls_x509_crl_cpy(gnutls_x509_crl dest, gnutls_x509_crl src);
int _gnutls_x509_crl_get_raw_issuer_dn( gnutls_x509_crl crl,
	gnutls_datum* dn);
int gnutls_x509_crl_get_crt_count(gnutls_x509_crl crl);
int gnutls_x509_crl_get_crt_serial(gnutls_x509_crl crl, int index,
	    unsigned char *serial,
	    size_t *serial_size, time_t * time);

void gnutls_x509_crl_deinit(gnutls_x509_crl crl);
int gnutls_x509_crl_init(gnutls_x509_crl * crl);
int gnutls_x509_crl_import(gnutls_x509_crl crl, const gnutls_datum * data,
			   gnutls_x509_crt_fmt format);
int gnutls_x509_crl_export( gnutls_x509_crl crl,
	gnutls_x509_crt_fmt format, void* output_data, size_t* output_data_size);

int gnutls_x509_crt_init(gnutls_x509_crt * cert);
void gnutls_x509_crt_deinit(gnutls_x509_crt cert);
int gnutls_x509_crt_import(gnutls_x509_crt cert, const gnutls_datum * data,
	gnutls_x509_crt_fmt format);
int gnutls_x509_crt_export( gnutls_x509_crt cert,
	gnutls_x509_crt_fmt format, void* output_data, size_t* output_data_size);

int gnutls_x509_crt_get_key_usage(gnutls_x509_crt cert, unsigned int *key_usage,
	unsigned int *critical);
int gnutls_x509_crt_get_version(gnutls_x509_crt cert);

int gnutls_x509_privkey_init(gnutls_x509_privkey * key);
void gnutls_x509_privkey_deinit(gnutls_x509_privkey key);

int gnutls_x509_privkey_generate( gnutls_x509_privkey key, gnutls_pk_algorithm algo,
	unsigned int bits, unsigned int flags);

int gnutls_x509_privkey_import(gnutls_x509_privkey key, const gnutls_datum * data,
	gnutls_x509_crt_fmt format);
int gnutls_x509_privkey_get_pk_algorithm( gnutls_x509_privkey key);
int gnutls_x509_privkey_import_rsa_raw(gnutls_x509_privkey key, 
	const gnutls_datum* m, const gnutls_datum* e,
	const gnutls_datum* d, const gnutls_datum* p, 
	const gnutls_datum* q, const gnutls_datum* u);
int gnutls_x509_privkey_export_rsa_raw(gnutls_x509_privkey key,
	gnutls_datum * m, gnutls_datum *e,
	gnutls_datum *d, gnutls_datum *p, gnutls_datum* q, 
	gnutls_datum* u);
int gnutls_x509_privkey_export( gnutls_x509_privkey key,
	gnutls_x509_crt_fmt format, void* output_data, size_t* output_data_size);

#define GNUTLS_CRL_REASON_UNUSED 128
#define GNUTLS_CRL_REASON_KEY_COMPROMISE 64
#define GNUTLS_CRL_REASON_CA_COMPROMISE 32
#define GNUTLS_CRL_REASON_AFFILIATION_CHANGED 16
#define GNUTLS_CRL_REASON_SUPERSEEDED 8
#define GNUTLS_CRL_REASON_CESSATION_OF_OPERATION 4
#define GNUTLS_CRL_REASON_CERTIFICATE_HOLD 2
#define GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN 1
#define GNUTLS_CRL_REASON_AA_COMPROMISE 32768

time_t gnutls_x509_crt_get_activation_time(gnutls_x509_crt cert);
time_t gnutls_x509_crt_get_expiration_time(gnutls_x509_crt cert);

#endif
