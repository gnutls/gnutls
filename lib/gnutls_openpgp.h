#ifndef GNUTLS_OPENPGP_H
#define GNUTLS_OPENPGP_H

/* OpenCDK compatible */
typedef enum {
  KEY_ATTR_NONE = 0,
  KEY_ATTR_SHORT_KEYID = 3,
  KEY_ATTR_KEYID = 4,
  KEY_ATTR_FPR = 5
} key_attr_t;

int gnutls_certificate_set_openpgp_key_file(
                                            GNUTLS_CERTIFICATE_CREDENTIALS res,
                                            char* CERTFILE,
                                            char* KEYFILE);

int gnutls_openpgp_count_key_names( const gnutls_datum *cert );
     
int gnutls_openpgp_extract_key_name( const gnutls_datum *cert,
                                     int idx,
                                     gnutls_openpgp_name *dn );

int gnutls_openpgp_extract_key_pk_algorithm(const gnutls_datum *cert,
                                            int *r_bits);

int gnutls_openpgp_extract_key_version( const gnutls_datum *cert );

time_t gnutls_openpgp_extract_key_creation_time( const gnutls_datum *cert );

time_t gnutls_openpgp_extract_key_expiration_time( const gnutls_datum  *cert );

int gnutls_openpgp_verify_key( const char *trustdb,
                               const gnutls_datum *keyring,
                               const gnutls_datum* cert_list,
                               int cert_list_length );

int gnutls_openpgp_fingerprint( const gnutls_datum *cert, opaque *fpr,
                                size_t *fprlen );

int gnutls_openpgp_keyid( const gnutls_datum *cert, uint32 *keyid );

int gnutls_openpgp_add_keyring_mem(gnutls_datum *keyring,
                                   const char *data, size_t len);

int gnutls_openpgp_add_keyring_file(gnutls_datum *keyring, const char *name);

int gnutls_certificate_set_openpgp_keyring_file(
                                             GNUTLS_CERTIFICATE_CREDENTIALS c,
                                             const char *file);
int gnutls_certificate_set_openpgp_keyring_mem(
                                            GNUTLS_CERTIFICATE_CREDENTIALS c,
                                            const char *file);

int gnutls_openpgp_get_key(gnutls_datum *key, const gnutls_datum *keyring,
                           key_attr_t by, opaque *pattern);

int gnutls_openpgp_get_key_trust(const char *trustdb, gnutls_datum *key);
     

int gnutls_openpgp_recv_key(const char *host, short port, uint32 keyid,
                            gnutls_datum *key);
     
/* internal */
int _gnutls_openpgp_cert2gnutls_cert(gnutls_cert *cert, gnutls_datum raw);

int
_gnutls_openpgp_request_key( gnutls_datum* ret, 
	const GNUTLS_CERTIFICATE_CREDENTIALS cred, opaque* key_fpr,
	int key_fpr_size);

#endif /*GNUTLS_OPENPGP_H*/
