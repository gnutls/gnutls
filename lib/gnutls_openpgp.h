#ifndef GNUTLS_OPENPGP_H
#define GNUTLS_OPENPGP_H

int gnutls_certificate_set_openpgp_key_file(
                                            GNUTLS_CERTIFICATE_CREDENTIALS res,
                                            char* CERTFILE,
                                            char* KEYFILE);

int gnutls_openpgp_extract_key_name( const gnutls_datum *cert,
                                     gnutls_openpgp_name *dn );

int gnutls_openpgp_extract_key_version( const gnutls_datum *cert );

time_t gnutls_openpgp_extract_key_creation_time( const gnutls_datum *cert );

time_t gnutls_openpgp_extract_key_expiration_time( const gnutls_datum  *cert );

int gnutls_openpgp_verify_key( const gnutls_datum *keyring,
                               const gnutls_datum* cert_list,
                               int cert_list_length );

int gnutls_openpgp_fingerprint( const gnutls_datum *cert, opaque *fpr,
                                size_t *fprlen );

int gnutls_openpgp_keyid( const gnutls_datum *cert, uint32 *keyid );

int gnutls_openpgp_add_keyring_mem(gnutls_datum *keyring,
                                   const char *data, size_t len);

int gnutls_openpgp_add_keyring_file(gnutls_datum *keyring, const char *name);

/* internal */
int _gnutls_openpgp_cert2gnutls_cert(gnutls_cert *cert, gnutls_datum raw);

#endif /*GNUTLS_OPENPGP_H*/









