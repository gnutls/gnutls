#define GNUTLS_CIPHER_ENTRY(name, blksize, keysize, block) \
	{ #name, name, blksize, keysize, block }

struct gnutls_cipher_entry {
	char *name;
	BulkCipherAlgorithm id;
	size_t blocksize;
	size_t keysize;
	int block;
};
typedef struct gnutls_cipher_entry gnutls_cipher_entry;

static gnutls_cipher_entry algorithms[] = {
	GNUTLS_CIPHER_ENTRY(CIPHER_3DES, 8, 24, 1),
	GNUTLS_CIPHER_ENTRY(CIPHER_NULL, 0, 1, 0),
	{0}
};

#define GNUTLS_LOOP(b) \
        gnutls_cipher_entry *p; \
                for(p = algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_ALG_LOOP(a) \
                        GNUTLS_LOOP( if(p->id == algorithm) { a; break; } )


int _gnutls_get_block_size(BulkCipherAlgorithm algorithm);
int _gnutls_is_block_algorithm(BulkCipherAlgorithm algorithm);
int _gnutls_get_key_size(BulkCipherAlgorithm algorithm);
char *_gnutls_get_algorithms_name(BulkCipherAlgorithm algorithm);
