char * crypt_bcrypt (const char *passwd, const char *salt, MPI g, MPI n);
char *crypt_bcrypt_wrapper(const char *pass_new, int cost, MPI g, MPI n);
void * _gnutls_calc_srp_bcrypt( char *passwd, opaque *salt, int salt_size, int* size);
