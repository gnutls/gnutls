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




#define GNUTLS_KX_ALGO_ENTRY(name, server_cert, server_kx, client_cert, RSA_premaster, DH_public_value) \
	{ #name, name, server_cert, server_kx, client_cert, RSA_premaster, DH_public_value }

struct gnutls_kx_algo_entry {
	char *name;
	KX_Algorithm algorithm;
	int server_cert;
	int server_kx;
	int client_cert;
	int RSA_premaster;
	int DH_public_value;
};
typedef struct gnutls_kx_algo_entry gnutls_kx_algo_entry;

static gnutls_kx_algo_entry kx_algorithms[] = {
	GNUTLS_KX_ALGO_ENTRY( KX_ANON_DH, 0, 1, 0, 0, 1),
	GNUTLS_KX_ALGO_ENTRY( KX_RSA    , 1, 0, 1, 1, 0),
	GNUTLS_KX_ALGO_ENTRY( KX_DHE_DSS, 1, 1, 1, 0, 0),
	GNUTLS_KX_ALGO_ENTRY( KX_DHE_RSA, 1, 1, 1, 0, 0),
	GNUTLS_KX_ALGO_ENTRY( KX_DH_DSS , 1, 0, 1, 0, 0),
	GNUTLS_KX_ALGO_ENTRY( KX_DH_RSA , 1, 0, 1, 0, 0),
	{0}
};

#define GNUTLS_KX_LOOP(b) \
        gnutls_kx_algo_entry *p; \
                for(p = kx_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_KX_ALG_LOOP(a) \
                        GNUTLS_KX_LOOP( if(p->algorithm == algorithm) { a; break; } )


int _gnutls_cipher_get_block_size(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_is_block(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_is_ok(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_key_size(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_iv_size(BulkCipherAlgorithm algorithm);
char *_gnutls_cipher_get_name(BulkCipherAlgorithm algorithm);


int _gnutls_kx_get_block_size(KX_Algorithm algorithm);
int _gnutls_kx_is_block(KX_Algorithm algorithm);
int _gnutls_kx_is_ok(KX_Algorithm algorithm);
int _gnutls_kx_get_key_size(KX_Algorithm algorithm);
int _gnutls_kx_get_iv_size(KX_Algorithm algorithm);
char *_gnutls_kx_get_name(KX_Algorithm algorithm);

