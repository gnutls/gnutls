int _gnutls_pkcs1_rsa_verify_sig( gnutls_datum* signature, gnutls_datum *text, MPI m, MPI e);
CertificateStatus gnutls_verify_signature(gnutls_cert* cert, gnutls_cert* issuer);
int _gnutls_pkcs1_rsa_generate_sig( MACAlgorithm hash_algo, gnutls_private_key *pkey, const gnutls_datum *data, gnutls_datum *signature);
int _gnutls_generate_sig( GNUTLS_STATE state, gnutls_private_key *pkey, gnutls_datum *signature);
