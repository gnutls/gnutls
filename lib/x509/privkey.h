typedef enum gnutls_pkcs_encrypt_flags_t {
    GNUTLS_PKCS_PLAIN = 1,	/* if set the private key will not
				 * be encrypted.
				 */
    GNUTLS_PKCS_USE_PKCS12_3DES = 2,
    GNUTLS_PKCS_USE_PKCS12_ARCFOUR = 4,
    GNUTLS_PKCS_USE_PKCS12_RC2_40 = 8,
    GNUTLS_PKCS_USE_PBES2_3DES = 16
} gnutls_pkcs_encrypt_flags_t;

int gnutls_x509_privkey_import(gnutls_x509_privkey_t key,
			       const gnutls_datum_t * data,
			       gnutls_x509_crt_fmt_t format);
ASN1_TYPE _gnutls_privkey_decode_pkcs1_rsa_key(const gnutls_datum_t *
					       raw_key,
					       gnutls_x509_privkey_t pkey);
int gnutls_x509_privkey_cpy(gnutls_x509_privkey_t dst,
			    gnutls_x509_privkey_t src);
