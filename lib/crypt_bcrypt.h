char * crypt_bcrypt (const char *passwd, const char *salt);
char *crypt_bcrypt_wrapper(const char *pass_new, int cost);
void * _gnutls_calc_srp_bcrypt( char *passwd, opaque *salt, int salt_size);
