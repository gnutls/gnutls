char *_gnutls_crypt_srpsha1_wrapper(const char* username, const char *pass_new, int salt, MPI g, MPI n);
char *_gnutls_crypt_srpsha1(const char *username, const char *passwd,
		    const char *salt, GNUTLS_MPI g, GNUTLS_MPI n);
