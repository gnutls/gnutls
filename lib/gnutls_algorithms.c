#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_algorithms.h"

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


#define GNUTLS_HASH_ENTRY(name, hashsize) \
	{ #name, name, hashsize }

struct gnutls_hash_entry {
	char *name;
	MACAlgorithm id;
	size_t digestsize;
};
typedef struct gnutls_hash_entry gnutls_hash_entry;

static gnutls_hash_entry hash_algorithms[] = {
	GNUTLS_HASH_ENTRY(GNUTLS_MAC_SHA, 20),
	GNUTLS_HASH_ENTRY(GNUTLS_MAC_MD5, 16),
	GNUTLS_HASH_ENTRY(GNUTLS_MAC_NULL, 0),
	{0}
};

#define GNUTLS_HASH_LOOP(b) \
        gnutls_hash_entry *p; \
                for(p = hash_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_HASH_ALG_LOOP(a) \
                        GNUTLS_HASH_LOOP( if(p->id == algorithm) { a; break; } )




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




void tolow(char *str, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		str[i] = tolower(str[i]);
	}
}

/* HASHES */
int _gnutls_hash_get_digest_size(MACAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_HASH_ALG_LOOP(ret = p->digestsize);
	return ret;

}

char *_gnutls_hash_get_name(MACAlgorithm algorithm)
{
	char *ret = NULL;
	char *pointerTo_;

	/* avoid prefix */
	GNUTLS_HASH_ALG_LOOP(ret = strdup(p->name + sizeof("GNUTLS_") - 1));


	if (ret != NULL) {
		tolow(ret, strlen(ret));
		pointerTo_ = strchr(ret, '_');

		while (pointerTo_ != NULL) {
			*pointerTo_ = '-';
			pointerTo_ = strchr(ret, '_');
		}
	}
	return ret;
}


int _gnutls_hash_is_ok(MACAlgorithm algorithm)
{
	char *y = _gnutls_hash_get_name(algorithm);

	if (y != NULL) {
		free(y);
		return 0;
	} else {
		return 1;
	}

}



/* CIPHER */
int _gnutls_cipher_get_block_size(BulkCipherAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->blocksize);
	return ret;

}

int _gnutls_cipher_is_block(BulkCipherAlgorithm algorithm)
{
	size_t ret = 0;

	GNUTLS_ALG_LOOP(ret = p->block);
	return ret;

}

int _gnutls_cipher_get_key_size(BulkCipherAlgorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->keysize);
	return ret;

}

int _gnutls_cipher_get_iv_size(BulkCipherAlgorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->iv);
	return ret;

}

char *_gnutls_cipher_get_name(BulkCipherAlgorithm algorithm)
{
	char *ret = NULL;
	char *pointerTo_;

	/* avoid prefix */
	GNUTLS_ALG_LOOP(ret = strdup(p->name + sizeof("GNUTLS_") - 1));


	if (ret != NULL) {
		tolow(ret, strlen(ret));
		pointerTo_ = strchr(ret, '_');

		while (pointerTo_ != NULL) {
			*pointerTo_ = '-';
			pointerTo_ = strchr(ret, '_');
		}
	}
	return ret;
}


int _gnutls_cipher_is_ok(BulkCipherAlgorithm algorithm)
{
	char *y = _gnutls_cipher_get_name(algorithm);

	if (y != NULL) {
		free(y);
		return 0;
	} else {
		return 1;
	}

}


/* Key EXCHANGE */
int _gnutls_kx_algo_server_certificate(KX_Algorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->server_cert);
	return ret;

}

int _gnutls_kx_algo_server_key_exchange(KX_Algorithm algorithm)
{
	size_t ret = 0;

	GNUTLS_KX_ALG_LOOP(ret = p->server_kx);
	return ret;

}

int _gnutls_kx_algo_client_certificate(KX_Algorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->client_cert);
	return ret;

}

int _gnutls_kx_algo_RSA_premaster(KX_Algorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->RSA_premaster);
	return ret;

}

int _gnutls_kx_algo_DH_public_value(KX_Algorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->DH_public_value);
	return ret;

}

char *_gnutls_kx_algo_get_name(KX_Algorithm algorithm)
{
	char *ret = NULL;
	char *pointerTo_;

	/* avoid prefix */
	GNUTLS_KX_ALG_LOOP(ret = strdup(p->name + sizeof("KX_") - 1));


	if (ret != NULL) {
		tolow(ret, strlen(ret));
		pointerTo_ = strchr(ret, '_');

		while (pointerTo_ != NULL) {
			*pointerTo_ = '-';
			pointerTo_ = strchr(ret, '_');
		}
	}
	return ret;
}


int _gnutls_kx_algo_is_ok(KX_Algorithm algorithm)
{
	char *y = _gnutls_kx_algo_get_name(algorithm);

	if (y != NULL) {
		free(y);
		return 0;
	} else {
		return 1;
	}

}

/* Cipher Suites */
BulkCipherAlgorithm _gnutls_cipher_suite_get_cipher_algo(GNUTLS_CipherSuite suite)
{
	size_t ret = 0;
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->cipher_algorithm);
	return ret;
}

KX_Algorithm _gnutls_cipher_suite_get_kx_algo(GNUTLS_CipherSuite suite)
{
	size_t ret = 0;

	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->kx_algorithm);
	return ret;

}

MACAlgorithm _gnutls_cipher_suite_get_mac_algo(GNUTLS_CipherSuite suite)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->mac_algorithm);
	return ret;

}

char *_gnutls_cipher_suite_get_name(GNUTLS_CipherSuite suite)
{
	char *ret = NULL;
	char *pointerTo_;

	/* avoid prefix */
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = strdup(p->name + sizeof("GNUTLS_") - 1));


	if (ret != NULL) {
		tolow(ret, strlen(ret));
		pointerTo_ = strchr(ret, '_');

		while (pointerTo_ != NULL) {
			*pointerTo_ = '-';
			pointerTo_ = strchr(ret, '_');
		}
	}
	return ret;
}


int _gnutls_cipher_suite_is_ok(GNUTLS_CipherSuite suite)
{
	char *y = _gnutls_cipher_suite_get_name(suite);

	if (y != NULL) {
		free(y);
		return 0;
	} else {
		return 1;
	}

}

int _gnutls_cipher_suite_count()
{
GNUTLS_CipherSuite suite;
uint8 i, counter=0;
char* y;
	suite.CipherSuite[0] = 0x00;
	
	for (i=0;i<255;i++) {
		suite.CipherSuite[1] = i;
		y = _gnutls_cipher_suite_get_name(suite);

		if (y != NULL) {
			free(y);
			counter++;
		}
	}

	return counter;
}

