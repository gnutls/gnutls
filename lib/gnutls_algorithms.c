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

/* TLS Versions */

typedef struct {
	char *name;
	GNUTLS_Version *id;
	int supported; /* 0 not supported, > 0 is supported */
} gnutls_version_entry;

GNUTLS_Version GNUTLS_TLS1 = {0, 3, 1};
GNUTLS_Version GNUTLS_SSL3 = {0, 3, 0};

static gnutls_version_entry sup_versions[] = {
	{ "SSL3", &GNUTLS_SSL3,  1 },
	{ "TLS1", &GNUTLS_TLS1,  1 },
	{0}
};

#define GNUTLS_VERSION_LOOP(b) \
        gnutls_version_entry *p; \
                for(p = sup_versions; p->name != NULL; p++) { b ; }

#define GNUTLS_VERSION_ALG_LOOP(a) \
                        GNUTLS_VERSION_LOOP( if( (p->id->local == version.local)&&(p->id->major == version.major)&&(p->id->minor == version.minor) ) { a; break; } )


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
	GNUTLS_CIPHER_ENTRY(GNUTLS_RIJNDAEL, 16, 16, 1, 16),
#ifdef USE_MCRYPT
	GNUTLS_CIPHER_ENTRY(GNUTLS_ARCFOUR, 1, 16, 0, 0,),
#else
	GNUTLS_CIPHER_ENTRY(GNUTLS_ARCFOUR, 1, 16, 0, 0),
#endif
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
	KXAlgorithm algorithm;
	int server_cert;
	int server_kx;
	int client_cert;
	int RSA_premaster;
	int DH_public_value;
};
typedef struct gnutls_kx_algo_entry gnutls_kx_algo_entry;

static gnutls_kx_algo_entry kx_algorithms[] = {
	GNUTLS_KX_ALGO_ENTRY(GNUTLS_KX_ANON_DH, 0, 1, 0, 0, 1),
	GNUTLS_KX_ALGO_ENTRY(GNUTLS_KX_RSA, 1, 0, 1, 1, 0),
	GNUTLS_KX_ALGO_ENTRY(GNUTLS_KX_DHE_DSS, 1, 1, 1, 0, 0),
	GNUTLS_KX_ALGO_ENTRY(GNUTLS_KX_DHE_RSA, 1, 1, 1, 0, 0),
	GNUTLS_KX_ALGO_ENTRY(GNUTLS_KX_DH_DSS, 1, 0, 1, 0, 0),
	GNUTLS_KX_ALGO_ENTRY(GNUTLS_KX_DH_RSA, 1, 0, 1, 0, 0),
	{0}
};

#define GNUTLS_KX_LOOP(b) \
        gnutls_kx_algo_entry *p; \
                for(p = kx_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_KX_ALG_LOOP(a) \
                        GNUTLS_KX_LOOP( if(p->algorithm == algorithm) { a; break; } )



/* Cipher SUITES */
#define GNUTLS_CIPHER_SUITE_ENTRY( name, block_algorithm, kx_algorithm, mac_algorithm) \
	{ #name, {name}, block_algorithm, kx_algorithm, mac_algorithm }

typedef struct {
	char *name;
	GNUTLS_CipherSuite id;
	BulkCipherAlgorithm block_algorithm;
	KXAlgorithm kx_algorithm;
	MACAlgorithm mac_algorithm;
} gnutls_cipher_suite_entry;

#define GNUTLS_DH_anon_WITH_3DES_EDE_CBC_SHA { 0x00, 0x1B }
#define GNUTLS_DH_anon_WITH_ARCFOUR_MD5 { 0x00, 0x18 }
#define GNUTLS_DH_anon_WITH_RIJNDAEL_SHA { 0x00, 0x34 }

#define GNUTLS_DH_DSS_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0D }
#define GNUTLS_DH_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x10 }
#define GNUTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA { 0x00, 0x13 }
#define GNUTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x16 }
#define GNUTLS_RSA_WITH_ARCFOUR_SHA { 0x00, 0x05 }
#define GNUTLS_RSA_WITH_ARCFOUR_MD5 { 0x00, 0x04 }
#define GNUTLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
#define GNUTLS_RSA_WITH_DES_CBC_SHA { 0x00, 0x09 }
#define GNUTLS_DH_DSS_WITH_DES_CBC_SHA { 0x00, 0x0C }
#define GNUTLS_DH_RSA_WITH_DES_CBC_SHA { 0x00, 0x0F }
#define GNUTLS_DHE_DSS_WITH_DES_CBC_SHA { 0x00, 0x12 }
#define GNUTLS_DHE_RSA_WITH_DES_CBC_SHA { 0x00, 0x15 }

#define GNUTLS_RSA_WITH_RIJNDAEL_128_CBC_SHA { 0x00, 0x2F }
#define GNUTLS_DH_DSS_WITH_RIJNDAEL_128_CBC_SHA { 0x00, 0x30 }
#define GNUTLS_DH_RSA_WITH_RIJNDAEL_128_CBC_SHA { 0x00, 0x31 }
#define GNUTLS_DHE_DSS_WITH_RIJNDAEL_128_CBC_SHA { 0x00, 0x32 }
#define GNUTLS_DHE_RSA_WITH_RIJNDAEL_128_CBC_SHA { 0x00, 0x33 }
     	               
     	               
static gnutls_cipher_suite_entry cs_algorithms[] = {
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_anon_WITH_ARCFOUR_MD5,   GNUTLS_ARCFOUR, GNUTLS_KX_ANON_DH, GNUTLS_MAC_MD5),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_anon_WITH_3DES_EDE_CBC_SHA, GNUTLS_3DES, GNUTLS_KX_ANON_DH, GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, GNUTLS_3DES, GNUTLS_KX_DH_DSS,  GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, GNUTLS_3DES, GNUTLS_KX_DH_RSA,  GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,GNUTLS_3DES, GNUTLS_KX_DHE_DSS, GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,GNUTLS_3DES, GNUTLS_KX_DHE_RSA, GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_RSA_WITH_ARCFOUR_SHA,         GNUTLS_ARCFOUR, GNUTLS_KX_RSA,  GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_RSA_WITH_ARCFOUR_MD5,         GNUTLS_ARCFOUR, GNUTLS_KX_RSA,  GNUTLS_MAC_MD5),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_RSA_WITH_3DES_EDE_CBC_SHA,    GNUTLS_3DES, GNUTLS_KX_RSA,     GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_RSA_WITH_RIJNDAEL_128_CBC_SHA,	GNUTLS_RIJNDAEL,  GNUTLS_KX_RSA,	GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DH_DSS_WITH_RIJNDAEL_128_CBC_SHA,	GNUTLS_RIJNDAEL,  GNUTLS_KX_DH_DSS,  GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DH_RSA_WITH_RIJNDAEL_128_CBC_SHA,	GNUTLS_RIJNDAEL,  GNUTLS_KX_DH_RSA,	GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DHE_DSS_WITH_RIJNDAEL_128_CBC_SHA,	GNUTLS_RIJNDAEL,  GNUTLS_KX_DHE_DSS,	GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY( GNUTLS_DHE_RSA_WITH_RIJNDAEL_128_CBC_SHA,	GNUTLS_RIJNDAEL,  GNUTLS_KX_DHE_RSA,	GNUTLS_MAC_SHA),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_anon_WITH_RIJNDAEL_SHA,   GNUTLS_RIJNDAEL, GNUTLS_KX_ANON_DH, GNUTLS_MAC_SHA),
	{0}
};

#define GNUTLS_CIPHER_SUITE_LOOP(b) \
        gnutls_cipher_suite_entry *p; \
                for(p = cs_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_CIPHER_SUITE_ALG_LOOP(a) \
                        GNUTLS_CIPHER_SUITE_LOOP( if( (p->id.CipherSuite[0] == suite.CipherSuite[0]) && (p->id.CipherSuite[1] == suite.CipherSuite[1])) { a; break; } )



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
int _gnutls_mac_get_digest_size(MACAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_HASH_ALG_LOOP(ret = p->digestsize);
	return ret;

}

int _gnutls_mac_priority(GNUTLS_STATE state, MACAlgorithm algorithm) /* actually returns the priority */
{
	int i, num = state->gnutls_internals.MACAlgorithmPriority.algorithms;
	for (i=0;i<num;i++) {
		if (state->gnutls_internals.MACAlgorithmPriority.algorithm_priority[i]==algorithm) return i;
	}
	return -1;
}


char *_gnutls_mac_get_name(MACAlgorithm algorithm)
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

int _gnutls_mac_count()
{
	uint8 i, counter = 0;
	char *y;

	for (i = 0; i < 255; i++) {
		y = _gnutls_mac_get_name(i);

		if (y != NULL) {
			free(y);
			counter++;
		}
	}
	return counter;
}

int _gnutls_mac_is_ok(MACAlgorithm algorithm)
{
	char *y = _gnutls_mac_get_name(algorithm);

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

 /* returns the priority */
int _gnutls_cipher_priority(GNUTLS_STATE state, BulkCipherAlgorithm algorithm)
{
	int i, num = state->gnutls_internals.BulkCipherAlgorithmPriority.algorithms;
	for (i=0;i<num;i++) {
		if (state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority[i]==algorithm) return i;
	}
	return -1;
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

int _gnutls_cipher_count()
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
int _gnutls_kx_server_certificate(KXAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->server_cert);
	return ret;

}

int _gnutls_kx_priority(GNUTLS_STATE state, KXAlgorithm algorithm)
{
	int i, num = state->gnutls_internals.KXAlgorithmPriority.algorithms;
	for (i=0;i<num;i++) {
		if (state->gnutls_internals.KXAlgorithmPriority.algorithm_priority[i]==algorithm) return i;
	}
	return -1;
}

int _gnutls_kx_server_key_exchange(KXAlgorithm algorithm)
{
	size_t ret = 0;

	GNUTLS_KX_ALG_LOOP(ret = p->server_kx);
	return ret;

}

int _gnutls_kx_client_certificate(KXAlgorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->client_cert);
	return ret;

}

int _gnutls_kx_RSA_premaster(KXAlgorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->RSA_premaster);
	return ret;

}

int _gnutls_kx_DH_public_value(KXAlgorithm algorithm)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->DH_public_value);
	return ret;

}

char *_gnutls_kx_get_name(KXAlgorithm algorithm)
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

int _gnutls_kx_count()
{
	uint8 i, counter = 0;
	char *y;

	for (i = 0; i < 255; i++) {
		y = _gnutls_kx_get_name(i);

		if (y != NULL) {
			free(y);
			counter++;
		}
	}
	return counter;
}


int _gnutls_kx_is_ok(KXAlgorithm algorithm)
{
	char *y = _gnutls_kx_get_name(algorithm);

	if (y != NULL) {
		free(y);
		return 0;
	} else {
		return 1;
	}

}

/* Version Functions */
int _gnutls_version_cmp(GNUTLS_Version ver1, GNUTLS_Version ver2) {
	if (ver1.major!=ver2.major) return 1;
	if (ver1.minor!=ver2.minor) return 1;
	if (ver1.local!=ver2.local) return 1;
	return 0;
}

int _gnutls_version_is_supported(GNUTLS_STATE state, const GNUTLS_Version version)
{
	size_t ret = 0;
	/* FIXME: make it to read it from the state */
	GNUTLS_VERSION_ALG_LOOP(ret = p->supported);
	return ret;
}


/* Cipher Suite's functions */
BulkCipherAlgorithm _gnutls_cipher_suite_get_cipher_algo(const GNUTLS_CipherSuite
							 suite)
{
	size_t ret = 0;
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->block_algorithm);
	return ret;
}

KXAlgorithm _gnutls_cipher_suite_get_kx_algo(const GNUTLS_CipherSuite suite)
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

static void bsort(GNUTLS_STATE state, void *_base, size_t nmemb, size_t size, int (*compar)(GNUTLS_STATE, const void *, const void *)) {
int i,j;
int full=nmemb*size;
char* base=_base;
char* tmp=gnutls_malloc(size);

	for (i=0;i<full;i+=size) {
		for (j=0;j<full;j+=size) {
			if (compar(state, &base[i], &base[j]) < 0) {
				memcpy(tmp, &base[i], size);
				memcpy(&base[i], &base[j], size);
				memcpy(&base[j], tmp, size);
			}			
		}
	}
	free(tmp);

}


/* a compare function for hash(mac) algorithms (using priorities). For use with qsort */
static int _gnutls_compare_mac_algo(GNUTLS_STATE state, const void* i_A1, const void* i_A2)
{
	MACAlgorithm A1 = _gnutls_cipher_suite_get_mac_algo( *(GNUTLS_CipherSuite*)i_A1);
	MACAlgorithm A2 = _gnutls_cipher_suite_get_mac_algo( *(GNUTLS_CipherSuite*)i_A2);
	int p1 = _gnutls_mac_priority(state, A1);
	int p2 = _gnutls_mac_priority(state, A2);

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
static int _gnutls_compare_cipher_algo(GNUTLS_STATE state, const void* i_A1, const void* i_A2)
{
	BulkCipherAlgorithm A1 = _gnutls_cipher_suite_get_cipher_algo( *(GNUTLS_CipherSuite*)i_A1);
	BulkCipherAlgorithm A2 = _gnutls_cipher_suite_get_cipher_algo( *(GNUTLS_CipherSuite*)i_A2);
	int p1 = _gnutls_cipher_priority(state, A1);
	int p2 = _gnutls_cipher_priority(state, A2);

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
static int _gnutls_compare_kx_algo(GNUTLS_STATE state, const void* i_A1, const void* i_A2)
{
	KXAlgorithm A1 = _gnutls_cipher_suite_get_kx_algo(*(GNUTLS_CipherSuite*)i_A1);
	KXAlgorithm A2 = _gnutls_cipher_suite_get_kx_algo(*(GNUTLS_CipherSuite*)i_A2);
	int p1 = _gnutls_kx_priority(state, A1);
	int p2 = _gnutls_kx_priority(state, A2);

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

int _gnutls_supported_ciphersuites(GNUTLS_STATE state, GNUTLS_CipherSuite ** ciphers)
{

	int i, ret_count, j=0;
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
	bsort(state, tmp_ciphers, count, sizeof(GNUTLS_CipherSuite), _gnutls_compare_mac_algo);

/* then sort using block algorithm's priorities */
	bsort(state, tmp_ciphers, count, sizeof(GNUTLS_CipherSuite), _gnutls_compare_cipher_algo);

/* Last try KX algorithms priority */
	bsort(state, tmp_ciphers, count, sizeof(GNUTLS_CipherSuite), _gnutls_compare_kx_algo);

	for (i = 0; i < count; i++) {

		if (_gnutls_kx_priority( state, _gnutls_cipher_suite_get_kx_algo(tmp_ciphers[i])) < 0) continue;
		if (_gnutls_mac_priority( state, _gnutls_cipher_suite_get_mac_algo(tmp_ciphers[i])) < 0) continue;
		if (_gnutls_cipher_priority( state, _gnutls_cipher_suite_get_cipher_algo(tmp_ciphers[i])) < 0) continue;

		(*ciphers)[j].CipherSuite[0] = tmp_ciphers[i].CipherSuite[0];
		(*ciphers)[j].CipherSuite[1] = tmp_ciphers[i].CipherSuite[1];
/*		fprintf(stderr, "%d: %s\n", j, _gnutls_cipher_suite_get_name((*ciphers)[j])); */
		j++;
	}
	ret_count=j;

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

/* For compression - FIXME!!! */
#define SUPPORTED_COMPRESSION_METHODS 1
int _gnutls_supported_compression_methods(GNUTLS_STATE state, CompressionMethod ** comp)
{

 	*comp =
            gnutls_malloc(SUPPORTED_COMPRESSION_METHODS *
                          sizeof(CompressionMethod));

/* NULL Compression */
	(*comp)[0] = COMPRESSION_NULL;

	return SUPPORTED_COMPRESSION_METHODS;
}
