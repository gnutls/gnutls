#ifndef GNUTLS_PK_H
# define GNUTLS_PK_H

typedef enum PKAlgorithm { GNUTLS_PK_RSA = 1, GNUTLS_PK_DSA,	/* sign only */
	GNUTLS_PK_DH, GNUTLS_PK_UNKNOWN 
} PKAlgorithm;

int _gnutls_pk_encrypt(int algo, MPI * resarr, MPI data, MPI ** pkey);
int _gnutls_pkcs1_rsa_encrypt(gnutls_datum * ciphertext, gnutls_datum plaintext,
		      MPI pkey, MPI n, int btype);
int _gnutls_pkcs1_rsa_decrypt(gnutls_datum * plaintext, gnutls_datum ciphertext,
		      MPI pkey, MPI n, int btype);

#endif /* GNUTLS_PK_H */
