typedef struct {
	char* username;
	int algorithm;
	
	opaque* salt;
	int salt_size;
	
	MPI v;
	MPI g;
	MPI n;
} GNUTLS_SRP_PWD_ENTRY;

/* this is localy alocated. It should be freed */
GNUTLS_SRP_PWD_ENTRY *_gnutls_srp_pwd_read_entry( GNUTLS_KEY key, char* username);

