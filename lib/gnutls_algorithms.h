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
	GNUTLS_CIPHER_ENTRY(GNUTLS_3DES, 8, 24, 1, 8),
	GNUTLS_CIPHER_ENTRY(GNUTLS_NULL, 1, 0, 0, 0),
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

#define GNUTLS_CIPHER_SUITE_ENTRY(suite, kx_algorithm, cipher_algorithm, mac_algorithm) \
	{ #suite, suite, kx_algorithm, cipher_algorithm, mac_algorithm }

struct gnutls_cipher_suite_entry {
	char*			name;
	GNUTLS_CipherSuite 	suite;
	KX_Algorithm		kx_algorithm;
	BulkCipherAlgorithm	cipher_algorithm;
	MACAlgorithm		mac_algorithm;
};
typedef struct gnutls_cipher_suite_entry gnutls_cipher_suite_entry;

#define GNUTLS_DH_anon_WITH_3DES_EDE_CBC_SHA { 0x00, 0x1B }
 
static gnutls_cipher_suite_entry cipher_suite_algorithms[] = {
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DH_anon_WITH_3DES_EDE_CBC_SHA, KX_ANON_DH, GNUTLS_3DES, MAC_SHA),
	{0}
};

#define GNUTLS_CIPHER_SUITE_LOOP(b) \
        gnutls_cipher_suite_entry *p; \
                for(p = cipher_suite_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_CIPHER_SUITE_ALG_LOOP(a) \
                        GNUTLS_CIPHER_SUITE_LOOP( if( p->suite.CipherSuite[0] == suite.CipherSuite[0] && p->suite.CipherSuite[1] == suite.CipherSuite[1]) { a; break; } )





int _gnutls_cipher_suite_is_ok(GNUTLS_CipherSuite algorithm);
int _gnutls_cipher_suite_count();

char *_gnutls_cipher_suite_get_name(GNUTLS_CipherSuite algorithm);
BulkCipherAlgorithm _gnutls_cipher_suite_get_cipher_algo(GNUTLS_CipherSuite algorithm);
KX_Algorithm _gnutls_cipher_suite_get_kx_algo(GNUTLS_CipherSuite algorithm);
MACAlgorithm _gnutls_cipher_suite_get_mac_algo(GNUTLS_CipherSuite algorithm);
GNUTLS_CipherSuite _gnutls_cipher_suite_get_suite_name(GNUTLS_CipherSuite algorithm);


int _gnutls_cipher_get_block_size(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_is_block(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_is_ok(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_key_size(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_iv_size(BulkCipherAlgorithm algorithm);
char *_gnutls_cipher_get_name(BulkCipherAlgorithm algorithm);


int _gnutls_kx_algo_server_certificate(KX_Algorithm algorithm);
int _gnutls_kx_algo_server_key_exchange(KX_Algorithm algorithm);
int _gnutls_kx_algo_client_certificate(KX_Algorithm algorithm);
int _gnutls_kx_algo_RSA_premaster(KX_Algorithm algorithm);
int _gnutls_kx_algo_DH_public_value(KX_Algorithm algorithm);
char *_gnutls_kx_algo_get_name(KX_Algorithm algorithm);
int _gnutls_kx_algo_is_ok(KX_Algorithm algorithm);
