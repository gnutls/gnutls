#ifndef GNUTLS_SIG_H
# define GNUTLS_SIG_H
# include <auth_cert.h>

gnutls_certificate_status gnutls_x509_verify_signature(gnutls_cert* cert, gnutls_cert* issuer);
int _gnutls_pkcs1_rsa_generate_sig( gnutls_cert* cert, gnutls_private_key *pkey, const gnutls_datum* hash_concat, gnutls_datum *signature);
int _gnutls_generate_sig_from_hdata( gnutls_session session, gnutls_cert* cert, gnutls_private_key *pkey, gnutls_datum *signature);
int _gnutls_generate_sig_params( gnutls_session session, gnutls_cert* cert, gnutls_private_key *pkey, gnutls_datum* params, gnutls_datum *signature);
int _gnutls_verify_sig_hdata( gnutls_session session, gnutls_cert *cert, gnutls_datum* signature);
int _gnutls_verify_sig_params( gnutls_session session, gnutls_cert *cert, const gnutls_datum* params, gnutls_datum* signature);

#endif
