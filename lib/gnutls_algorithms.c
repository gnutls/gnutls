#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_algorithms.h"


void tolow(char *str, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		str[i] = tolower(str[i]);
	}
}


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

