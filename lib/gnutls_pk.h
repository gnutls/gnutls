#ifndef GNUTLS_PK_H
# define GNUTLS_PK_H

int _gnutls_pk_encrypt(int algo, MPI * resarr, MPI data, MPI * pkey);
int _gnutls_pkcs1_rsa_encrypt(gnutls_datum * ciphertext, gnutls_datum plaintext,
		      MPI * params, int btype);
int _gnutls_dsa_sign(gnutls_datum * signature, const gnutls_datum *plaintext,
		      MPI *params);
int _gnutls_pkcs1_rsa_decrypt(gnutls_datum * plaintext, gnutls_datum ciphertext,
		      MPI * params, int btype);
int _gnutls_rsa_verify( const gnutls_datum* vdata, const gnutls_datum *ciphertext, 
	MPI* params, int btype);
int _gnutls_dsa_verify( const gnutls_datum* vdata, const gnutls_datum *sig_value, 
	MPI * params);

#endif /* GNUTLS_PK_H */
