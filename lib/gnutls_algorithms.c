/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_algorithms.h"

#define GNUTLS_CIPHER_ENTRY(name, blksize, keysize, block, iv, priority) \
	{ #name, name, blksize, keysize, block, iv, priority }

struct gnutls_cipher_entry {
	char *name;
	BulkCipherAlgorithm id;
	size_t blocksize;
	size_t keysize;
	size_t block;
	size_t iv;
	int priority;
};
typedef struct gnutls_cipher_entry gnutls_cipher_entry;

static gnutls_cipher_entry algorithms[] = {
	GNUTLS_CIPHER_ENTRY(GNUTLS_3DES, 8, 24, 1, 8, 10),
	GNUTLS_CIPHER_ENTRY(GNUTLS_ARCFOUR, 1, 16, 0, 0, -1),
	GNUTLS_CIPHER_ENTRY(GNUTLS_NULL, 1, 0, 0, 0, -1),
	{0}
};

#define GNUTLS_LOOP(b) \
        gnutls_cipher_entry *p; \
                for(p = algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_ALG_LOOP(a) \
                        GNUTLS_LOOP( if(p->id == algorithm) { a; break; } )


#define GNUTLS_HASH_ENTRY(name, hashsize, priority) \
	{ #name, name, hashsize, priority }

struct gnutls_hash_entry {
	char *name;
	MACAlgorithm id;
	size_t digestsize;
	int priority;
};
typedef struct gnutls_hash_entry gnutls_hash_entry;

static gnutls_hash_entry hash_algorithms[] = {
	GNUTLS_HASH_ENTRY(GNUTLS_MAC_SHA, 20, 20),
	GNUTLS_HASH_ENTRY(GNUTLS_MAC_MD5, 16, 10),
	GNUTLS_HASH_ENTRY(GNUTLS_MAC_NULL, 0, -1),
	{0}
};

#define GNUTLS_HASH_LOOP(b) \
        gnutls_hash_entry *p; \
                for(p = hash_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_HASH_ALG_LOOP(a) \
                        GNUTLS_HASH_LOOP( if(p->id == algorithm) { a; break; } )




#define GNUTLS_KX_ALGO_ENTRY(name, server_cert, server_kx, client_cert, RSA_premaster, DH_public_value, priority) \
	{ #name, name, server_cert, server_kx, client_cert, RSA_premaster, DH_public_value, priority }

struct gnutls_kx_algo_entry {
	char *name;
	KX_Algorithm algorithm;
	int server_cert;
	int server_kx;
	int client_cert;
	int RSA_premaster;
	int DH_public_value;
	int priority;
};
typedef struct gnutls_kx_algo_entry gnutls_kx_algo_entry;

static gnutls_kx_algo_entry kx_algorithms[] = {
	GNUTLS_KX_ALGO_ENTRY(KX_ANON_DH, 0, 1, 0, 0, 1, 5),
	GNUTLS_KX_ALGO_ENTRY(KX_RSA, 1, 0, 1, 1, 0, -1),
	GNUTLS_KX_ALGO_ENTRY(KX_DHE_DSS, 1, 1, 1, 0, 0, -1),
	GNUTLS_KX_ALGO_ENTRY(KX_DHE_RSA, 1, 1, 1, 0, 0, -1),
	GNUTLS_KX_ALGO_ENTRY(KX_DH_DSS, 1, 0, 1, 0, 0, -1),
	GNUTLS_KX_ALGO_ENTRY(KX_DH_RSA, 1, 0, 1, 0, 0, -1),
	{0}
};

#define GNUTLS_KX_LOOP(b) \
        gnutls_kx_algo_entry *p; \
                for(p = kx_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_KX_ALG_LOOP(a) \
                        GNUTLS_KX_LOOP( if(p->algorithm == algorithm) { a; break; } )



/* Cipher SUITES */
#define GNUTLS_CIPHER_SUITE_ENTRY(name, block_algorithm, kx_algorithm, mac_algorithm) \
	{ #name, name, block_algorithm, kx_algorithm, mac_algorithm }

typedef struct {
	char *name;
	GNUTLS_CipherSuite id;
	BulkCipherAlgorithm block_algorithm;
	KX_Algorithm kx_algorithm;
	MACAlgorithm mac_algorithm;
} gnutls_cipher_suite_entry;

#define GNUTLS_DH_anon_WITH_3DES_EDE_CBC_SHA { 0x00, 0x1B }
#define GNUTLS_DH_anon_WITH_ARCFOUR_MD5 { 0x00, 0x18 }

static gnutls_cipher_suite_entry cs_algorithms[] = {
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_anon_WITH_ARCFOUR_MD5,   GNUTLS_ARCFOUR, KX_ANON_DH, GNUTLS_MAC_MD5),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_anon_WITH_3DES_EDE_CBC_SHA, GNUTLS_3DES, KX_ANON_DH, GNUTLS_MAC_SHA),
	{0}
};

#define GNUTLS_CIPHER_SUITE_LOOP(b) \
        gnutls_cipher_suite_entry *p; \
                for(p = cs_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_CIPHER_SUITE_ALG_LOOP(a) \
                        GNUTLS_CIPHER_SUITE_LOOP( if( memcmp( &p->id, &suite, 2)==0) { a; break; } )





/* Generic Functions */

/* this function makes the whole string lowercase */
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

int _gnutls_is_hash_selected(MACAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_HASH_ALG_LOOP(ret = p->priority);
	return ret;

}


char *_gnutls_hash_get_name(MACAlgorithm algorithm)
{
	char *ret = NULL;
	char *pointerTo_;

	/* avoid prefix */
	GNUTLS_HASH_ALG_LOOP(ret =
			     strdup(p->name + sizeof("GNUTLS_") - 1));


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

int _gnutls_hash_algo_count()
{
	uint8 i, counter = 0;
	char *y;

	for (i = 0; i < 255; i++) {
		y = _gnutls_hash_get_name(i);

		if (y != NULL) {
			free(y);
			counter++;
		}
	}
	return counter;
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



/* CIPHER functions */
int _gnutls_cipher_get_block_size(BulkCipherAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->blocksize);
	return ret;

}

int _gnutls_is_cipher_selected(BulkCipherAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->priority);
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

int _gnutls_cipher_algo_count()
{
	uint8 i, counter = 0;
	char *y;

	for (i = 0; i < 255; i++) {
		y = _gnutls_cipher_get_name(i);

		if (y != NULL) {
			free(y);
			counter++;
		}
	}
	return counter;
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


/* Key EXCHANGE functions */
int _gnutls_kx_algo_server_certificate(KX_Algorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->server_cert);
	return ret;

}

int _gnutls_is_kx_algo_selected(KX_Algorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->priority);
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

int _gnutls_kx_algo_count()
{
	uint8 i, counter = 0;
	char *y;

	for (i = 0; i < 255; i++) {
		y = _gnutls_kx_algo_get_name(i);

		if (y != NULL) {
			free(y);
			counter++;
		}
	}
	return counter;
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

/* Cipher Suite's functions */
BulkCipherAlgorithm _gnutls_cipher_suite_get_cipher_algo(const GNUTLS_CipherSuite
							 suite)
{
	size_t ret = 0;
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->block_algorithm);
	return ret;
}

KX_Algorithm _gnutls_cipher_suite_get_kx_algo(const GNUTLS_CipherSuite suite)
{
	size_t ret = 0;

	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->kx_algorithm);
	return ret;

}

MACAlgorithm _gnutls_cipher_suite_get_mac_algo(const GNUTLS_CipherSuite suite)
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
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret =
				     strdup(p->name + sizeof("GNUTLS_") -
					    1));


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
	uint8 i, counter = 0;
	char *y;
	suite.CipherSuite[0] = 0x00;	/* FIXME */

	for (i = 0; i < 255; i++) {
		suite.CipherSuite[1] = i;
		y = _gnutls_cipher_suite_get_name(suite);

		if (y != NULL) {
			free(y);
			counter++;
		}
	}

	return counter;
}

/* a compare function for hash(mac) algorithms (using priorities). For use with qsort */
int _gnutls_compare_mac_algo(const void* i_A1, const void* i_A2)
{
	MACAlgorithm A1 = _gnutls_cipher_suite_get_mac_algo( *(GNUTLS_CipherSuite*)i_A1);
	MACAlgorithm A2 = _gnutls_cipher_suite_get_mac_algo( *(GNUTLS_CipherSuite*)i_A2);
	int p1 = _gnutls_is_hash_selected(A1);
	int p2 = _gnutls_is_hash_selected(A2);

	if (p1 > p2) {
		return -1;
	} else {
		if (p1 == p2) {
			/* compare the addresses */
			/* since it is in a list... if A1 is before A2 then it is greater */
			if ( (int)A1 < (int)A2) return 1; else return -1;
		}
		return 1;
	}
}


/* a compare function for block algorithms (using priorities). For use with qsort */
int _gnutls_compare_cipher_algo(const void* i_A1, const void* i_A2)
{
	BulkCipherAlgorithm A1 = _gnutls_cipher_suite_get_cipher_algo( *(GNUTLS_CipherSuite*)i_A1);
	BulkCipherAlgorithm A2 = _gnutls_cipher_suite_get_cipher_algo( *(GNUTLS_CipherSuite*)i_A2);
	int p1 = _gnutls_is_cipher_selected(A1);
	int p2 = _gnutls_is_cipher_selected(A2);

	if (p1 > p2) {
		return -1; /* we actually want descending order */
	} else {
		if (p1 == p2) {
			/* compare the addresses */
			/* since it is in a list... if A1 is before A2 then it is greater */
			if ( (int)A1 < (int)A2) return 1; else return -1;
		}
		return 1;
	}
}


/* a compare function for KX algorithms (using priorities). For use with qsort */
int _gnutls_compare_kx_algo(const void* i_A1, const void* i_A2)
{
	KX_Algorithm A1 = _gnutls_cipher_suite_get_kx_algo(*(GNUTLS_CipherSuite*)i_A1);
	KX_Algorithm A2 = _gnutls_cipher_suite_get_kx_algo(*(GNUTLS_CipherSuite*)i_A2);
	int p1 = _gnutls_is_kx_algo_selected(A1);
	int p2 = _gnutls_is_kx_algo_selected(A2);

	if (p1 > p2) {
		return -1;
	} else {
		if (p1 == p2) {
			/* compare the addresses */
			/* since it is in a list... if A1 is before A2 then it is greater */
			if ( (int)A1 < (int)A2) return 1; else return -1;
		}
		return 1;
	}
}

int _gnutls_supported_ciphersuites(GNUTLS_CipherSuite ** ciphers)
{

	int i, ret_count;
	int count = _gnutls_cipher_suite_count();
	GNUTLS_CipherSuite *tmp_ciphers;

	if (count == 0) {
		*ciphers = NULL;
		return 0;
	}

	tmp_ciphers = gnutls_malloc(count * sizeof(GNUTLS_CipherSuite));
	*ciphers = gnutls_malloc(count * sizeof(GNUTLS_CipherSuite)); 


	for (i = 0; i < count; i++) {
		tmp_ciphers[i].CipherSuite[0] =
		    cs_algorithms[i].id.CipherSuite[0];
		tmp_ciphers[i].CipherSuite[1] =
		    cs_algorithms[i].id.CipherSuite[1];
	}

/* First sort using MAC priority (lowest) */
	qsort(tmp_ciphers, count, sizeof(GNUTLS_CipherSuite), _gnutls_compare_mac_algo);

/* then sort using block algorithm's priorities */
	qsort(tmp_ciphers, count, sizeof(GNUTLS_CipherSuite), _gnutls_compare_cipher_algo);

/* Last try KX algorithms priority */
	qsort(tmp_ciphers, count, sizeof(GNUTLS_CipherSuite), _gnutls_compare_kx_algo);

	for (i = 0; i < count; i++) {
		fprintf(stderr, "**** %s\n", _gnutls_cipher_get_name(_gnutls_cipher_suite_get_cipher_algo(tmp_ciphers[i])));
		if (_gnutls_is_kx_algo_selected( _gnutls_cipher_suite_get_kx_algo(tmp_ciphers[i])) < 0) break;
		if (_gnutls_is_hash_selected( _gnutls_cipher_suite_get_mac_algo(tmp_ciphers[i])) < 0) break;
		if (_gnutls_is_cipher_selected( _gnutls_cipher_suite_get_cipher_algo(tmp_ciphers[i])) < 0) break;

		(*ciphers)[i].CipherSuite[0] = tmp_ciphers[i].CipherSuite[0];
		(*ciphers)[i].CipherSuite[1] = tmp_ciphers[i].CipherSuite[1];
	}
	ret_count=i;

	if (ret_count > 0 && ret_count != count) {
		 *ciphers = gnutls_realloc(*ciphers, ret_count * sizeof(GNUTLS_CipherSuite)); 
	}
	else {
		if (ret_count!=count) {
			gnutls_free(*ciphers);
			*ciphers=NULL;
		}
	}

	gnutls_free(tmp_ciphers);
	return ret_count;
}
