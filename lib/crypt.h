/* crypt functions */

char * gnutls_crypt(const char* username, const char *passwd, crypt_algo algo, int salt, MPI g, MPI n);
int gnutls_crypt_vrfy(const char* username, const char *passwd, char* salt, MPI g, MPI n);
