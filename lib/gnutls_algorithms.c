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
#include "gnutls_errors.h"

/* TLS Versions */

typedef struct {
	char *name;
	GNUTLS_Version *id;
	int supported;		/* 0 not supported, > 0 is supported */
} gnutls_version_entry;

GNUTLS_Version GNUTLS_TLS1 = { 0, 3, 1 };
GNUTLS_Version GNUTLS_SSL3 = { 0, 3, 0 };

static gnutls_version_entry sup_versions[] = {
	{"SSL3", &GNUTLS_SSL3, 1},
	{"TLS1", &GNUTLS_TLS1, 1},
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
	GNUTLS_CIPHER_ENTRY(GNUTLS_ARCFOUR, 1, 16, 0, 0),
#else
	GNUTLS_CIPHER_ENTRY(GNUTLS_ARCFOUR, 1, 16, 0, 0),
#endif
	GNUTLS_CIPHER_ENTRY(GNUTLS_NULL_CIPHER, 1, 0, 0, 0),
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
	GNUTLS_HASH_ENTRY(GNUTLS_NULL_MAC, 0),
	{0}
};

#define GNUTLS_HASH_LOOP(b) \
        gnutls_hash_entry *p; \
                for(p = hash_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_HASH_ALG_LOOP(a) \
                        GNUTLS_HASH_LOOP( if(p->id == algorithm) { a; break; } )


/* Compression Section */
#define GNUTLS_COMPRESSION_ENTRY(name) \
	{ #name, name }

struct gnutls_compression_entry {
	char *name;
	CompressionMethod id;
};

typedef struct gnutls_compression_entry gnutls_compression_entry;
static gnutls_compression_entry compression_algorithms[] = {
	GNUTLS_COMPRESSION_ENTRY(GNUTLS_NULL_COMPRESSION),
#ifdef HAVE_LIBZ
	GNUTLS_COMPRESSION_ENTRY(GNUTLS_ZLIB),
#endif
	{0}
};

#define GNUTLS_COMPRESSION_LOOP(b) \
        gnutls_compression_entry *p; \
                for(p = compression_algorithms; p->name != NULL; p++) { b ; }
#define GNUTLS_COMPRESSION_ALG_LOOP(a) \
                        GNUTLS_COMPRESSION_LOOP( if(p->id == algorithm) { a; break; } )


/* Key Exchange Section */
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
#define GNUTLS_CIPHER_SUITE_ENTRY( name, block_algorithm, kx_algorithm, mac_algorithm, compression_algorithm) \
	{ #name, {name}, block_algorithm, kx_algorithm, mac_algorithm, compression_algorithm }

typedef struct {
	char *name;
	GNUTLS_CipherSuite id;
	BulkCipherAlgorithm block_algorithm;
	KXAlgorithm kx_algorithm;
	MACAlgorithm mac_algorithm;
	CompressionMethod compression_algorithm;
} gnutls_cipher_suite_entry;

#define GNUTLS_DH_anon_3DES_EDE_CBC_SHA { 0x00, 0x1B }
#define GNUTLS_DH_anon_ARCFOUR_MD5 { 0x00, 0x18 }
#define GNUTLS_DH_anon_RIJNDAEL_128_CBC_SHA { 0x00, 0x34 }

#define GNUTLS_DH_DSS_3DES_EDE_CBC_SHA { 0x00, 0x0D }
#define GNUTLS_DH_RSA_3DES_EDE_CBC_SHA { 0x00, 0x10 }
#define GNUTLS_DHE_DSS_3DES_EDE_CBC_SHA { 0x00, 0x13 }
#define GNUTLS_DHE_RSA_3DES_EDE_CBC_SHA { 0x00, 0x16 }
#define GNUTLS_RSA_ARCFOUR_SHA { 0x00, 0x05 }
#define GNUTLS_RSA_ARCFOUR_MD5 { 0x00, 0x04 }
#define GNUTLS_RSA_3DES_EDE_CBC_SHA { 0x00, 0x0A }
#define GNUTLS_RSA_DES_CBC_SHA { 0x00, 0x09 }
#define GNUTLS_DH_DSS_DES_CBC_SHA { 0x00, 0x0C }
#define GNUTLS_DH_RSA_DES_CBC_SHA { 0x00, 0x0F }
#define GNUTLS_DHE_DSS_DES_CBC_SHA { 0x00, 0x12 }
#define GNUTLS_DHE_RSA_DES_CBC_SHA { 0x00, 0x15 }

#define GNUTLS_RSA_RIJNDAEL_128_CBC_SHA { 0x00, 0x2F }
#define GNUTLS_DH_DSS_RIJNDAEL_128_CBC_SHA { 0x00, 0x30 }
#define GNUTLS_DH_RSA_RIJNDAEL_128_CBC_SHA { 0x00, 0x31 }
#define GNUTLS_DHE_DSS_RIJNDAEL_128_CBC_SHA { 0x00, 0x32 }
#define GNUTLS_DHE_RSA_RIJNDAEL_128_CBC_SHA { 0x00, 0x33 }


static gnutls_cipher_suite_entry cs_algorithms[] = {
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_anon_ARCFOUR_MD5,
				  GNUTLS_ARCFOUR,
				  GNUTLS_KX_ANON_DH, GNUTLS_MAC_MD5,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_anon_3DES_EDE_CBC_SHA,
				  GNUTLS_3DES, GNUTLS_KX_ANON_DH,
				  GNUTLS_MAC_SHA,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_DSS_3DES_EDE_CBC_SHA,
				  GNUTLS_3DES,
				  GNUTLS_KX_DH_DSS, GNUTLS_MAC_SHA,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_RSA_3DES_EDE_CBC_SHA,
				  GNUTLS_3DES,
				  GNUTLS_KX_DH_RSA, GNUTLS_MAC_SHA,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DHE_DSS_3DES_EDE_CBC_SHA,
				  GNUTLS_3DES, GNUTLS_KX_DHE_DSS,
				  GNUTLS_MAC_SHA,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DHE_RSA_3DES_EDE_CBC_SHA,
				  GNUTLS_3DES, GNUTLS_KX_DHE_RSA,
				  GNUTLS_MAC_SHA,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_RSA_ARCFOUR_SHA,
				  GNUTLS_ARCFOUR,
				  GNUTLS_KX_RSA, GNUTLS_MAC_SHA,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_RSA_ARCFOUR_MD5,
				  GNUTLS_ARCFOUR,
				  GNUTLS_KX_RSA, GNUTLS_MAC_MD5,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_RSA_3DES_EDE_CBC_SHA,
				  GNUTLS_3DES,
				  GNUTLS_KX_RSA, GNUTLS_MAC_SHA,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_RSA_RIJNDAEL_128_CBC_SHA,
				  GNUTLS_RIJNDAEL, GNUTLS_KX_RSA,
				  GNUTLS_MAC_SHA,
				  GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_DSS_RIJNDAEL_128_CBC_SHA,
				  GNUTLS_RIJNDAEL, GNUTLS_KX_DH_DSS,
				  GNUTLS_MAC_SHA, GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_RSA_RIJNDAEL_128_CBC_SHA,
				  GNUTLS_RIJNDAEL, GNUTLS_KX_DH_RSA,
				  GNUTLS_MAC_SHA, GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DHE_DSS_RIJNDAEL_128_CBC_SHA,
				  GNUTLS_RIJNDAEL, GNUTLS_KX_DHE_DSS,
				  GNUTLS_MAC_SHA, GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DHE_RSA_RIJNDAEL_128_CBC_SHA,
				  GNUTLS_RIJNDAEL, GNUTLS_KX_DHE_RSA,
				  GNUTLS_MAC_SHA, GNUTLS_NULL_COMPRESSION),
	GNUTLS_CIPHER_SUITE_ENTRY(GNUTLS_DH_anon_RIJNDAEL_128_CBC_SHA,
				  GNUTLS_RIJNDAEL, GNUTLS_KX_ANON_DH,
				  GNUTLS_MAC_SHA, GNUTLS_NULL_COMPRESSION),
	{0}
};

#define GNUTLS_CIPHER_SUITE_LOOP(b) \
        gnutls_cipher_suite_entry *p; \
                for(p = cs_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_CIPHER_SUITE_ALG_LOOP(a) \
                        GNUTLS_CIPHER_SUITE_LOOP( if( (p->id.CipherSuite[0] == suite.CipherSuite[0]) && (p->id.CipherSuite[1] == suite.CipherSuite[1])) { a; break; } )



/* Generic Functions */

/* this function makes the whole string lowercase */
void _gnutls_tolow(char *str, int size)
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

inline int _gnutls_mac_priority(GNUTLS_STATE state, MACAlgorithm algorithm)
{				/* actually returns the priority */
	int i;
	for (i = 0;
	     i < state->gnutls_internals.MACAlgorithmPriority.algorithms;
	     i++) {
		if (state->gnutls_internals.
		    MACAlgorithmPriority.algorithm_priority[i] ==
		    algorithm) return i;
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
		_gnutls_tolow(ret, strlen(ret));
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
	for (i = 0; i < 255; i++) {
		if (_gnutls_mac_is_ok(i) == 0)
			counter++;
	}
	return counter;
}

int _gnutls_mac_is_ok(MACAlgorithm algorithm)
{
	size_t ret = -1;
	GNUTLS_HASH_ALG_LOOP(ret = p->id);
	if (ret >= 0)
		ret = 0;
	else
		ret = 1;
	return ret;
}

/* Compression Functions */
inline
    int _gnutls_compression_priority(GNUTLS_STATE state,
				     CompressionMethod algorithm)
{				/* actually returns the priority */
	int i;
	for (i = 0;
	     i <
	     state->gnutls_internals.CompressionMethodPriority.algorithms;
	     i++) {
		if (state->gnutls_internals.
		    CompressionMethodPriority.algorithm_priority[i] ==
		    algorithm) return i;
	}
	return -1;
}

char *_gnutls_compression_get_name(CompressionMethod algorithm)
{
	char *ret = NULL;
	char *pointerTo_;

	/* avoid prefix */
	GNUTLS_COMPRESSION_ALG_LOOP(ret =
				    strdup(p->name + sizeof("GNUTLS_") -
					   1));


	if (ret != NULL) {
		_gnutls_tolow(ret, strlen(ret));
		pointerTo_ = strchr(ret, '_');

		while (pointerTo_ != NULL) {
			*pointerTo_ = '-';
			pointerTo_ = strchr(ret, '_');
		}
	}
	return ret;
}

int _gnutls_compression_count()
{
	uint8 i, counter = 0;
	for (i = 0; i < 255; i++) {
		if (_gnutls_compression_is_ok(i) == 0)
			counter++;
	}
	return counter;
}

int _gnutls_compression_is_ok(CompressionMethod algorithm)
{
	size_t ret = -1;
	GNUTLS_COMPRESSION_ALG_LOOP(ret = p->id);
	if (ret >= 0)
		ret = 0;
	else
		ret = 1;
	return ret;
}



/* CIPHER functions */
int _gnutls_cipher_get_block_size(BulkCipherAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_ALG_LOOP(ret = p->blocksize);
	return ret;

}

 /* returns the priority */
inline
    int
_gnutls_cipher_priority(GNUTLS_STATE state, BulkCipherAlgorithm algorithm)
{
	int i;
	for (i = 0;
	     i <
	     state->gnutls_internals.
	     BulkCipherAlgorithmPriority.algorithms; i++) {
		if (state->gnutls_internals.
		    BulkCipherAlgorithmPriority.algorithm_priority[i] ==
		    algorithm) return i;
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
		_gnutls_tolow(ret, strlen(ret));
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
	for (i = 0; i < 255; i++) {
		if (_gnutls_cipher_is_ok(i) == 0)
			counter++;
	}
	return counter;
}


int _gnutls_cipher_is_ok(BulkCipherAlgorithm algorithm)
{
	size_t ret = -1;
	GNUTLS_ALG_LOOP(ret = p->id);
	if (ret >= 0)
		ret = 0;
	else
		ret = 1;
	return ret;
}


/* Key EXCHANGE functions */
int _gnutls_kx_server_certificate(KXAlgorithm algorithm)
{
	size_t ret = 0;
	GNUTLS_KX_ALG_LOOP(ret = p->server_cert);
	return ret;

}

inline int _gnutls_kx_priority(GNUTLS_STATE state, KXAlgorithm algorithm)
{
	int i;
	for (i = 0;
	     i < state->gnutls_internals.KXAlgorithmPriority.algorithms;
	     i++) {
		if (state->gnutls_internals.
		    KXAlgorithmPriority.algorithm_priority[i] == algorithm)
			return i;
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
		_gnutls_tolow(ret, strlen(ret));
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
	for (i = 0; i < 255; i++) {
		if (_gnutls_kx_is_ok(i) == 0)
			counter++;
	}
	return counter;
}


int _gnutls_kx_is_ok(KXAlgorithm algorithm)
{
	size_t ret = -1;
	GNUTLS_KX_ALG_LOOP(ret = p->algorithm);
	if (ret >= 0)
		ret = 0;
	else
		ret = 1;
	return ret;

}

/* Version Functions */
int _gnutls_version_cmp(GNUTLS_Version ver1, GNUTLS_Version ver2)
{
	if (ver1.major != ver2.major)
		return 1;
	if (ver1.minor != ver2.minor)
		return 1;
	if (ver1.local != ver2.local)
		return 1;
	return 0;
}

int
_gnutls_version_is_supported(GNUTLS_STATE state,
			     const GNUTLS_Version version)
{
	size_t ret = 0;
	/* FIXME: make it to read it from the state */
	GNUTLS_VERSION_ALG_LOOP(ret = p->supported);
	return ret;
}


/* Cipher Suite's functions */
BulkCipherAlgorithm
_gnutls_cipher_suite_get_cipher_algo(const GNUTLS_CipherSuite suite)
{
	size_t ret = 0;
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->block_algorithm);
	return ret;
}

KXAlgorithm _gnutls_cipher_suite_get_kx_algo(const GNUTLS_CipherSuite
					     suite)
{
	size_t ret = 0;

	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->kx_algorithm);
	return ret;

}

MACAlgorithm
_gnutls_cipher_suite_get_mac_algo(const GNUTLS_CipherSuite suite)
{				/* In bytes */
	size_t ret = 0;
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->mac_algorithm);
	return ret;

}

CompressionMethod
_gnutls_cipher_suite_get_compression_algo(const GNUTLS_CipherSuite suite)
{
	size_t ret = 0;
	GNUTLS_CIPHER_SUITE_ALG_LOOP(ret = p->compression_algorithm);
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
		_gnutls_tolow(ret, strlen(ret));
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
	size_t ret;
	char *name = NULL;

	GNUTLS_CIPHER_SUITE_ALG_LOOP(name = p->name);
	if (name != NULL)
		ret = 0;
	else
		ret = 1;
	return ret;

}

/* quite expensive */
int _gnutls_cipher_suite_count()
{
	GNUTLS_CipherSuite suite;
	uint8 i, counter = 0, j;
	for (j = 0; j < 255; j++) {
		suite.CipherSuite[0] = j;
		if (j != 0 && j != 255)
			continue;	/* these are the only suites we support */
		for (i = 0; i < 255; i++) {
			suite.CipherSuite[1] = i;
			if (_gnutls_cipher_suite_is_ok(suite) == 0)
				counter++;
		}
	}
	return counter;
}

#define SWAP(x, y) memcpy(tmp,x,size); \
		   memcpy(x,y,size); \
		   memcpy(y,tmp,size)

#define MAX_ELEM_SIZE 4
inline
    static int _gnutls_partition(GNUTLS_STATE state, void *_base, size_t nmemb,
			 size_t size, int (*compar) (GNUTLS_STATE,
						     const void *,
						     const void *))
{
	uint8 *base = _base;
	uint8 tmp[MAX_ELEM_SIZE];
	uint8 ptmp[MAX_ELEM_SIZE];
	int pivot;
	int i, j;
	int full;

	i = pivot = 0;
	j = full = (nmemb - 1) * size;

	memcpy(ptmp, &base[pivot], size);	/* set pivot item */

	while (i < j) {
		while ((compar(state, &base[i], ptmp) <= 0) && (i < full))
			i += size;
		while ((compar(state, &base[j], ptmp) >= 0) && (j > 0))
			j -= size;

		if (i < j) {
			SWAP(&base[j], &base[i]);
		}
	}

	if (j > pivot) {
		SWAP(&base[pivot], &base[j]);
		pivot = j;
	} else if (i < pivot) {
		fprintf(stderr, "HERE!");
		SWAP(&base[pivot], &base[i]);
		pivot = i;
	}
	return pivot / size;
}

static void
_gnutls_qsort(GNUTLS_STATE state, void *_base, size_t nmemb, size_t size,
	      int (*compar) (GNUTLS_STATE, const void *, const void *))
{
	int pivot;
	char *base = _base;
	int snmemb = nmemb;

#ifdef DEBUG
	if (size > MAX_ELEM_SIZE) {
		gnutls_assert();
		exit(1);
	}
#endif

	if (snmemb <= 1)
		return;
	pivot = _gnutls_partition(state, _base, nmemb, size, compar);
#ifdef SORT_DEBUG
	fprintf(stderr, "pivot: %d\n", pivot);
#endif

	_gnutls_qsort(state, base, pivot+1, size, compar);
	_gnutls_qsort(state, &base[(pivot + 1) * size], nmemb - pivot - 1,
		      size, compar);
}


/* a compare function for KX algorithms (using priorities). For use with qsort */
static int
_gnutls_compare_algo(GNUTLS_STATE state, const void *i_A1,
			const void *i_A2)
{
	KXAlgorithm kA1 =
	    _gnutls_cipher_suite_get_kx_algo(*(GNUTLS_CipherSuite *) i_A1);
	KXAlgorithm kA2 =
	    _gnutls_cipher_suite_get_kx_algo(*(GNUTLS_CipherSuite *) i_A2);
	BulkCipherAlgorithm cA1 =
	    _gnutls_cipher_suite_get_cipher_algo(*(GNUTLS_CipherSuite *)
						 i_A1);
	BulkCipherAlgorithm cA2 =
	    _gnutls_cipher_suite_get_cipher_algo(*(GNUTLS_CipherSuite *)
						 i_A2);
	MACAlgorithm mA1 =
	    _gnutls_cipher_suite_get_mac_algo(*(GNUTLS_CipherSuite *)
					      i_A1);
	MACAlgorithm mA2 =
	    _gnutls_cipher_suite_get_mac_algo(*(GNUTLS_CipherSuite *)
					      i_A2);

	int p1 = _gnutls_kx_priority(state, kA1)*100;
	int p2 = _gnutls_kx_priority(state, kA2)*100;
	p1 += _gnutls_cipher_priority(state, cA1)*10;
	p2 += _gnutls_cipher_priority(state, cA2)*10;
	p1 += _gnutls_mac_priority(state, mA1);
	p2 += _gnutls_mac_priority(state, mA2);

	if (p1 > p2) {
		return 1;
	} else {
		if (p1 == p2) {
			/* compare the addresses */
			/* since it is in a list... if A1 is before A2 then it is greater */
			if ((uint32) i_A1 < (uint32) i_A2)
				return 1;
			return -1;
		}
		return -1;
	}
}

#if 0
static void 
_gnutls_bsort(GNUTLS_STATE state, void *_base, size_t nmemb,
		  size_t size, int (*compar) (GNUTLS_STATE, const void *,
					      const void *))
{
	int i, j;
	int full = nmemb * size;
	char *base = _base;
	char *tmp = gnutls_malloc(size);

	for (i = 0; i < full; i += size) {
		for (j = 0; j < full; j += size) {
			if (compar(state, &base[i], &base[j]) < 0) {
				memcpy(tmp, &base[i], size);
				memcpy(&base[i], &base[j], size);
				memcpy(&base[j], tmp, size);
			}
		}
	}
	free(tmp);

}
#endif

int
_gnutls_supported_ciphersuites_sorted(GNUTLS_STATE state,
				      GNUTLS_CipherSuite ** ciphers)
{

	int i, ret_count, j = 0;
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

#ifdef SORT_DEBUG
	fprintf(stderr, "Unsorted: \n");
	for (i = 0; i < count; i++)
		fprintf(stderr, "\t%d: %s\n", i,
			_gnutls_cipher_suite_get_name((tmp_ciphers)[i]));
#endif

	_gnutls_qsort(state, tmp_ciphers, count,
		      sizeof(GNUTLS_CipherSuite), _gnutls_compare_algo);

	for (i = 0; i < count; i++) {
		if (_gnutls_kx_priority
		    (state,
		     _gnutls_cipher_suite_get_kx_algo(tmp_ciphers[i])) < 0)
			continue;
		if (_gnutls_mac_priority
		    (state,
		     _gnutls_cipher_suite_get_mac_algo(tmp_ciphers[i])) <
		    0) continue;
		if (_gnutls_cipher_priority
		    (state,
		     _gnutls_cipher_suite_get_cipher_algo(tmp_ciphers[i]))
		    < 0)
			continue;

		(*ciphers)[j].CipherSuite[0] = tmp_ciphers[i].CipherSuite[0];
		(*ciphers)[j].CipherSuite[1] = tmp_ciphers[i].CipherSuite[1];
		j++;
	}

#ifdef SORT_DEBUG
	fprintf(stderr, "Sorted: \n");
	for (i = 0; i < j; i++)
		fprintf(stderr, "\t%d: %s\n", i,
			_gnutls_cipher_suite_get_name((*ciphers)[i]));
#endif

	ret_count = j;

	if (ret_count > 0 && ret_count != count) {
		*ciphers =
		    gnutls_realloc(*ciphers,
				   ret_count * sizeof(GNUTLS_CipherSuite));
	} else {
		if (ret_count != count) {
			gnutls_free(*ciphers);
			*ciphers = NULL;
		}
	}

	gnutls_free(tmp_ciphers);
	return ret_count;
}

int
_gnutls_supported_ciphersuites(GNUTLS_STATE state,
			       GNUTLS_CipherSuite ** ciphers)
{

	int i, ret_count, j = 0;
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

	for (i = 0; i < count; i++) {
		if (_gnutls_kx_priority
		    (state,
		     _gnutls_cipher_suite_get_kx_algo(tmp_ciphers[i])) < 0)
			continue;
		if (_gnutls_mac_priority
		    (state,
		     _gnutls_cipher_suite_get_mac_algo(tmp_ciphers[i])) <
		    0) continue;
		if (_gnutls_cipher_priority
		    (state,
		     _gnutls_cipher_suite_get_cipher_algo(tmp_ciphers[i]))
		    < 0)
			continue;

		(*ciphers)[j].CipherSuite[0] = tmp_ciphers[i].CipherSuite[0];
		(*ciphers)[j].CipherSuite[1] = tmp_ciphers[i].CipherSuite[1];
		j++;
	}

	ret_count = j;

	if (ret_count > 0 && ret_count != count) {
		*ciphers =
		    gnutls_realloc(*ciphers,
				   ret_count * sizeof(GNUTLS_CipherSuite));
	} else {
		if (ret_count != count) {
			gnutls_free(*ciphers);
			*ciphers = NULL;
		}
	}

	gnutls_free(tmp_ciphers);
	return ret_count;
}


/* For compression  */
#define SUPPORTED_COMPRESSION_METHODS state->gnutls_internals.CompressionMethodPriority.algorithms
int
_gnutls_supported_compression_methods(GNUTLS_STATE state,
				      CompressionMethod ** comp)
{
	int i;
	*comp = gnutls_malloc(SUPPORTED_COMPRESSION_METHODS * 1);

	for (i = 0; i < SUPPORTED_COMPRESSION_METHODS; i++) {

		(*comp)[i] =
		    state->gnutls_internals.
		    CompressionMethodPriority.algorithm_priority[i];
	}

	return SUPPORTED_COMPRESSION_METHODS;
}
