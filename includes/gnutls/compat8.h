#ifndef GNUTLS_COMPAT8_H
# define GNUTLS_COMPAT8_H

#ifdef __GNUC__

#define _GT_GCC_VERSION (__GNUC__ * 10000 \
                             + __GNUC_MINOR__ * 100 \
                             + __GNUC_PATCHLEVEL__)

#if _GT_GCC_VERSION >= 30100
# ifndef DEPRECATED
#  define DEPRECATED __attribute__ ((__deprecated__))
# endif
#endif

#endif

#ifndef DEPRECATED
# define DEPRECATED
#endif


/* Extra definitions */

#define GNUTLS_X509_CN_SIZE 256
#define GNUTLS_X509_C_SIZE 3
#define GNUTLS_X509_O_SIZE 256
#define GNUTLS_X509_OU_SIZE 256
#define GNUTLS_X509_L_SIZE 256
#define GNUTLS_X509_S_SIZE 256
#define GNUTLS_X509_EMAIL_SIZE 256

typedef struct {
	char common_name[GNUTLS_X509_CN_SIZE];
	char country[GNUTLS_X509_C_SIZE];
	char organization[GNUTLS_X509_O_SIZE];
	char organizational_unit_name[GNUTLS_X509_OU_SIZE];
	char locality_name[GNUTLS_X509_L_SIZE];
	char state_or_province_name[GNUTLS_X509_S_SIZE];
	char email[GNUTLS_X509_EMAIL_SIZE];
} gnutls_x509_dn;

typedef struct {
	char name[GNUTLS_X509_CN_SIZE];
	char email[GNUTLS_X509_CN_SIZE];
} gnutls_openpgp_name;

int gnutls_x509_extract_dn( const gnutls_datum*, gnutls_x509_dn*) DEPRECATED;
int gnutls_x509_extract_dn_string(const gnutls_datum * idn,
        char *buf, unsigned int sizeof_buf) DEPRECATED;
int gnutls_x509_extract_certificate_dn( const gnutls_datum*, gnutls_x509_dn*) DEPRECATED;
int gnutls_x509_extract_certificate_dn_string(char *buf, unsigned int sizeof_buf,
   const gnutls_datum * cert, int issuer) DEPRECATED;
int gnutls_x509_extract_certificate_issuer_dn(  const gnutls_datum*, gnutls_x509_dn *) DEPRECATED;
int gnutls_x509_extract_certificate_version( const gnutls_datum*) DEPRECATED;
int gnutls_x509_extract_certificate_serial(const gnutls_datum * cert, char* result, int* result_size) DEPRECATED;
time_t gnutls_x509_extract_certificate_activation_time( const gnutls_datum*) DEPRECATED;
time_t gnutls_x509_extract_certificate_expiration_time( const gnutls_datum*) DEPRECATED;
int gnutls_x509_extract_certificate_subject_alt_name( const gnutls_datum*, int seq, char*, int*) DEPRECATED;
int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size) DEPRECATED;
int gnutls_x509_extract_certificate_pk_algorithm( const gnutls_datum * cert, int* bits) DEPRECATED;
int gnutls_x509_extract_certificate_ca_status(const gnutls_datum * cert) DEPRECATED;
int gnutls_x509_extract_key_pk_algorithm( const gnutls_datum * key) DEPRECATED;

int gnutls_x509_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, const gnutls_datum * CA_list, int CA_list_length, const gnutls_datum* CRL_list, int CRL_list_length) DEPRECATED;
int gnutls_x509_check_certificates_hostname(const gnutls_datum * cert,
                                const char *hostname) DEPRECATED;

#define gnutls_x509_fingerprint gnutls_fingerprint
#define gnutls_x509_certificate_format gnutls_x509_crt_fmt

int gnutls_x509_extract_key_pk_algorithm( const gnutls_datum * key) DEPRECATED;

int gnutls_rsa_params_set(gnutls_rsa_params rsa_params, 
	gnutls_datum m, gnutls_datum e, gnutls_datum d, 
	gnutls_datum p, gnutls_datum q, gnutls_datum u,
	int bits) DEPRECATED;
int gnutls_rsa_params_generate(gnutls_datum * m, gnutls_datum *e,
	gnutls_datum *d, gnutls_datum *p, gnutls_datum* q, 
	gnutls_datum* u, int bits) DEPRECATED;

int gnutls_dh_params_set( gnutls_dh_params, gnutls_datum prime, gnutls_datum generator, int bits) DEPRECATED;
int gnutls_dh_params_generate( gnutls_datum* prime, gnutls_datum* generator, int bits) DEPRECATED;

#define gnutls_certificate_set_rsa_params gnutls_certificate_set_rsa_export_params

#define GNUTLS_CERT_NOT_TRUSTED GNUTLS_CERT_INVALID

#endif
