int _gnutls_x509_sign( const gnutls_datum* tbs, gnutls_mac_algorithm hash,
	gnutls_x509_privkey signer, gnutls_datum* signature);
int _gnutls_x509_sign_tbs( ASN1_TYPE cert, const char* tbs_name,
	gnutls_mac_algorithm hash, gnutls_x509_privkey signer, gnutls_datum* signature);
int _gnutls_x509_pkix_sign(ASN1_TYPE src, const char* src_name, 
	gnutls_x509_crt issuer, gnutls_x509_privkey issuer_key);
