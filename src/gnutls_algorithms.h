#define GNUTLS_CIPHER_ENTRY(name, blksize, keysize, block, iv) \
	{ #name, name, blksize, keysize, block, iv }

struct gnutls_cipher_entry {
	char *name;
	BulkCipherAlgorithm id;
	size_t blocksize;
	size_t keysize;
	size_t block;
	size_t iv;
};
typedef struct gnutls_cipher_entry gnutls_cipher_entry;

static gnutls_cipher_entry algorithms[] = {
	GNUTLS_CIPHER_ENTRY(CIPHER_3DES, 8, 24, 1, 8),
	GNUTLS_CIPHER_ENTRY(CIPHER_NULL, 1, 0, 0, 0),
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
int _gnutls_get_iv_size(BulkCipherAlgorithm algorithm);
char *_gnutls_get_algorithms_name(BulkCipherAlgorithm algorithm);
