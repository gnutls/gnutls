#ifdef ENABLE_SRP

typedef struct {
	char* username;
	
	gnutls_datum salt;
	gnutls_datum v;
	gnutls_datum g;
	gnutls_datum n;
	
	int malloced; /* if non zero, use free() instead of gnutls_free()
		       */

} SRP_PWD_ENTRY;

/* this is localy alocated. It should be freed using the provided function */
SRP_PWD_ENTRY *_gnutls_srp_pwd_read_entry( gnutls_session state, char* username, int* err);
void _gnutls_srp_entry_free( SRP_PWD_ENTRY * entry);
SRP_PWD_ENTRY* _gnutls_randomize_pwd_entry(void);
int _gnutls_sbase64_encode(uint8 * data, size_t data_size, uint8 ** result);
int _gnutls_sbase64_decode(uint8 * data, size_t data_size, uint8 ** result);

#endif /* ENABLE_SRP */
