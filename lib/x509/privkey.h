typedef enum gnutls_privkey_pkcs8_flags {
	GNUTLS_PKCS8_PLAIN=1,  /* if set the private key will not
			        * be encrypted.
				*/
} gnutls_privkey_pkcs8_flags;

int gnutls_x509_privkey_import(gnutls_x509_privkey key, const gnutls_datum * data,
	gnutls_x509_crt_fmt format);
ASN1_TYPE _gnutls_privkey_decode_pkcs1_rsa_key( const gnutls_datum *raw_key,
        gnutls_x509_privkey pkey);
