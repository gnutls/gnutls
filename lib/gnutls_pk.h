int _gnutls_pk_encrypt(int algo, MPI * resarr, MPI data, MPI ** pkey);
int _gnutls_pkcs1_rsa_encrypt(gnutls_datum * ciphertext, gnutls_datum plaintext,
		      MPI pkey, MPI n);
int _gnutls_pkcs1_rsa_decrypt(gnutls_datum * plaintext, gnutls_datum ciphertext,
		      MPI pkey, MPI n);
