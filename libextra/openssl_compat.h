#ifndef GNUTLS_COMPAT8_H
# define GNUTLS_COMPAT8_H

/* Extra definitions */
#include <gnutls/openssl.h>

int gnutls_x509_extract_dn( const gnutls_datum*, gnutls_x509_dn*);
int gnutls_x509_extract_dn_string(const gnutls_datum * idn,
        char *buf, unsigned int sizeof_buf);
int gnutls_x509_extract_certificate_dn( const gnutls_datum*, gnutls_x509_dn*);
int gnutls_x509_extract_certificate_dn_string(char *buf, unsigned int sizeof_buf,
   const gnutls_datum * cert, int issuer);
int gnutls_x509_extract_certificate_issuer_dn(  const gnutls_datum*, gnutls_x509_dn *);
int gnutls_x509_extract_certificate_version( const gnutls_datum*);
int gnutls_x509_extract_certificate_serial(const gnutls_datum * cert, char* result, int* result_size);
time_t gnutls_x509_extract_certificate_activation_time( const gnutls_datum*);
time_t gnutls_x509_extract_certificate_expiration_time( const gnutls_datum*);
int gnutls_x509_extract_certificate_subject_alt_name( const gnutls_datum*, int seq, char*, int*);
int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size);
int gnutls_x509_extract_certificate_pk_algorithm( const gnutls_datum * cert, int* bits);
int gnutls_x509_extract_certificate_ca_status(const gnutls_datum * cert);
int gnutls_x509_extract_key_pk_algorithm( const gnutls_datum * key);

int gnutls_x509_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, const gnutls_datum * CA_list, int CA_list_length, const gnutls_datum* CRL_list, int CRL_list_length);

#define gnutls_x509_fingerprint gnutls_fingerprint
#define gnutls_x509_certificate_format gnutls_x509_crt_fmt

int gnutls_x509_extract_key_pk_algorithm( const gnutls_datum * key);

#define gnutls_certificate_set_rsa_params gnutls_certificate_set_rsa_export_params

#endif
