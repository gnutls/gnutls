int _gnutls_x509_sign( const gnutls_datum_t* tbs, gnutls_mac_algorithm_t hash,
	gnutls_x509_privkey_t signer, gnutls_datum_t* signature);
int _gnutls_x509_sign_tbs( ASN1_TYPE cert, const char* tbs_name,
	gnutls_mac_algorithm_t hash, gnutls_x509_privkey_t signer, gnutls_datum_t* signature);
int _gnutls_x509_pkix_sign(ASN1_TYPE src, const char* src_name, 
	gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key);
