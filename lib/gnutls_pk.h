#ifndef GNUTLS_PK_H
# define GNUTLS_PK_H

int _gnutls_pkcs1_rsa_encrypt(gnutls_datum_t * ciphertext,
			      const gnutls_datum_t * plaintext,
			      mpi_t * params, uint params_len, uint btype);
int _gnutls_dsa_sign(gnutls_datum_t * signature,
		     const gnutls_datum_t * plaintext, mpi_t * params,
		     uint params_len);
int _gnutls_pkcs1_rsa_decrypt(gnutls_datum_t * plaintext,
			      const gnutls_datum_t * ciphertext,
			      mpi_t * params, uint params_len, uint btype);
int _gnutls_rsa_verify(const gnutls_datum_t * vdata,
		       const gnutls_datum_t * ciphertext, mpi_t * params,
		       int params_len, int btype);
int _gnutls_dsa_verify(const gnutls_datum_t * vdata,
     const gnutls_datum_t * sig_value, mpi_t * params, int params_len);

#endif				/* GNUTLS_PK_H */
