/* crypt functions */

char * _gnutls_srp_crypt(const char* username, const char *passwd, int salt, MPI g, MPI n);
int _gnutls_srp_crypt_vrfy(const char* username, const char *passwd, char* salt, MPI g, MPI n);
