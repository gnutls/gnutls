char * crypt_bcrypt (const char* username, const char *passwd, const char *salt, MPI g, MPI n);
char *crypt_bcrypt_wrapper(const char* username, const char *pass_new, int cost, MPI g, MPI n);
int _gnutls_calc_srp_bcrypt( const char* username, const char *passwd, opaque *salt, int salt_size, int* size, void* digest);
