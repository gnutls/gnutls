#ifdef ENABLE_SRP

typedef struct {
    char *username;

    gnutls_datum_t salt;
    gnutls_datum_t v;
    gnutls_datum_t g;
    gnutls_datum_t n;
} SRP_PWD_ENTRY;

/* this is locally allocated. It should be freed using the provided function */
int _gnutls_srp_pwd_read_entry(gnutls_session_t state, char *username,
			       SRP_PWD_ENTRY **);
void _gnutls_srp_entry_free(SRP_PWD_ENTRY * entry);
int _gnutls_sbase64_encode(uint8 * data, size_t data_size,
			   uint8 ** result);
int _gnutls_sbase64_decode(uint8 * data, size_t data_size,
			   uint8 ** result);

#endif				/* ENABLE_SRP */
