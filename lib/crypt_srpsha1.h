char * crypt_srpsha1(const char* username, const char *passwd, const char *salt, MPI g, MPI n);
char *crypt_srpsha1_wrapper(const char* username, const char *pass_new, int salt, MPI g, MPI n);
