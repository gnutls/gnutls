int _gnutls_hash_get_digest_size(MACAlgorithm algorithm);
char *_gnutls_hash_get_name(MACAlgorithm algorithm);
int _gnutls_hash_is_ok(MACAlgorithm algorithm);
int _gnutls_is_hash_selected(MACAlgorithm algorithm);

int _gnutls_cipher_suite_is_ok(GNUTLS_CipherSuite algorithm);
int _gnutls_supported_ciphersuites(GNUTLS_CipherSuite **ciphers);
int _gnutls_cipher_suite_count();
char *_gnutls_cipher_suite_get_name(GNUTLS_CipherSuite algorithm);
BulkCipherAlgorithm _gnutls_cipher_suite_get_cipher_algo(const GNUTLS_CipherSuite algorithm);
KX_Algorithm _gnutls_cipher_suite_get_kx_algo(const GNUTLS_CipherSuite algorithm);
MACAlgorithm _gnutls_cipher_suite_get_mac_algo(const GNUTLS_CipherSuite algorithm);
GNUTLS_CipherSuite _gnutls_cipher_suite_get_suite_name(GNUTLS_CipherSuite algorithm);

int _gnutls_is_cipher_selected(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_block_size(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_is_block(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_is_ok(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_key_size(BulkCipherAlgorithm algorithm);
int _gnutls_cipher_get_iv_size(BulkCipherAlgorithm algorithm);
char *_gnutls_cipher_get_name(BulkCipherAlgorithm algorithm);

int _gnutls_is_kx_algo_selected(KX_Algorithm algorithm);
int _gnutls_kx_algo_server_certificate(KX_Algorithm algorithm);
int _gnutls_kx_algo_server_key_exchange(KX_Algorithm algorithm);
int _gnutls_kx_algo_client_certificate(KX_Algorithm algorithm);
int _gnutls_kx_algo_RSA_premaster(KX_Algorithm algorithm);
int _gnutls_kx_algo_DH_public_value(KX_Algorithm algorithm);
char *_gnutls_kx_algo_get_name(KX_Algorithm algorithm);
int _gnutls_kx_algo_is_ok(KX_Algorithm algorithm);


/*
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
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DH_anon_WITH_3DES_EDE_CBC_SHA, KX_ANON_DH, GNUTLS_3DES, GNUTLS_MAC_SHA),
	{0}
};

#define GNUTLS_CIPHER_SUITE_LOOP(b) \
        gnutls_cipher_suite_entry *p; \
                for(p = cipher_suite_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_CIPHER_SUITE_ALG_LOOP(a) \
                        GNUTLS_CIPHER_SUITE_LOOP( if( p->suite.CipherSuite[0] == suite.CipherSuite[0] && p->suite.CipherSuite[1] == suite.CipherSuite[1]) { a; break; } )




*/
