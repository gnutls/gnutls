#include <defines.h>
#include <mhash.h>
#include "gnutls_int.h"
#include "gnutls_algorithms.h"


void tolow(char *str, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		str[i] = tolower(str[i]);
	}
}


int _gnutls_get_block_size(BulkCipherAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->blocksize);
	return ret;

}

int _gnutls_is_block_algorithm(BulkCipherAlgorithm algorithm)
{
	size_t ret = 0;

	GNUTLS_ALG_LOOP(ret = p->block);
	return ret;

}

int _gnutls_get_key_size(BulkCipherAlgorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->keysize);
	return ret;

}

int _gnutls_get_iv_size(BulkCipherAlgorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->iv);
	return ret;

}

char *_gnutls_get_algorithms_name(BulkCipherAlgorithm algorithm)
{
	char *ret = NULL;
	char *pointerTo_;

	/* avoid prefix */
	GNUTLS_ALG_LOOP(ret = strdup(p->name + sizeof("CIPHER_") - 1));


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


int _gnutls_is_algorithm(BulkCipherAlgorithm algorithm)
{
	char *y = _gnutls_get_algorithms_name(algorithm);

	if (y != NULL) {
		free(y);
		return 0;
	} else {
		return 1;
	}

}
