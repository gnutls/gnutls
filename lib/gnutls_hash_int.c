/*
 * Copyright (C) 2000 Nikos Mavroyanopoulos
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
#include <gnutls_int.h>

#include <gnutls_hash_int.h>

/* This file handles all the internal functions that cope with hashes
 * and hmacs. Currently it uses the functions provided by
 * the gcrypt library that this can be easily changed.
 */

GNUTLS_MAC_HANDLE gnutls_hash_init(MACAlgorithm algorithm)
{
	GNUTLS_MAC_HANDLE ret =
	    gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));

	ret->algorithm = algorithm;
	switch (algorithm) {
	case GNUTLS_MAC_NULL:
		ret = GNUTLS_HASH_FAILED;
		break;
	case GNUTLS_MAC_SHA:
#ifdef USE_MHASH
		ret->handle = mhash_init(MHASH_SHA1);
#else
		ret->handle = gcry_md_open(GCRY_MD_SHA1, 0);
#endif
		if (!ret->handle)
			return GNUTLS_HASH_FAILED;
		break;
	case GNUTLS_MAC_MD5:
#ifdef USE_MHASH
		ret->handle = mhash_init(MHASH_MD5);
#else
		ret->handle = gcry_md_open(GCRY_MD_MD5, 0);
#endif
		if (!ret->handle)
			return GNUTLS_HASH_FAILED;
		break;
	default:
		ret = GNUTLS_HASH_FAILED;
	}

	return ret;
}

int gnutls_hash_get_algo_len(MACAlgorithm algorithm)
{
	int ret;

	switch (algorithm) {
	case GNUTLS_MAC_NULL:
		ret = 0;
		break;
	case GNUTLS_MAC_SHA:
#ifdef USE_MHASH
		ret = mhash_get_block_size(MHASH_SHA1);
#else
		ret = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
#endif
		break;
	case GNUTLS_MAC_MD5:
#ifdef USE_MHASH
		ret = mhash_get_block_size(MHASH_MD5);
#else
		ret = gcry_md_get_algo_dlen(GCRY_MD_MD5);
#endif
		break;
	default:
		ret = 0;
	}

	return ret;

}

int gnutls_hash(GNUTLS_MAC_HANDLE handle, void *text, int textlen)
{
#ifdef USE_MHASH
	mhash(handle->handle, text, textlen);
#else
	gcry_md_write(handle->handle, text, textlen);
#endif
	return 0;
}

void *gnutls_hash_deinit(GNUTLS_MAC_HANDLE handle)
{
	char *mac;
	int maclen;
	char *ret;

#ifdef USE_MHASH
	ret = mhash_end(handle->handle);
#else
	maclen = gcry_md_get_algo_dlen(gcry_md_get_algo(handle->handle));
	ret = gnutls_malloc(maclen);

	gcry_md_final(handle->handle);
	mac = gcry_md_read(handle->handle, 0);
	memmove(ret, mac, maclen);
	gcry_md_close(handle->handle);
#endif
	gnutls_free(handle);
	return ret;
}


GNUTLS_MAC_HANDLE gnutls_hmac_init(MACAlgorithm algorithm, char *key,
				   int keylen)
{
	GNUTLS_MAC_HANDLE ret =
	    gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));
	ret->algorithm = algorithm;
	ret->key = key;
	ret->keysize = keylen;

	switch (algorithm) {
	case GNUTLS_MAC_NULL:
		ret = GNUTLS_MAC_FAILED;
		break;
	case GNUTLS_MAC_SHA:
#ifdef USE_MHASH
		ret->handle = mhash_hmac_init(MHASH_SHA1, key, keylen, 0);
#else
		ret->handle =
		    gcry_md_open(GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
#endif
		if (!ret->handle)
			ret = GNUTLS_MAC_FAILED;
		break;
	case GNUTLS_MAC_MD5:
#ifdef USE_MHASH
		ret->handle = mhash_hmac_init(MHASH_MD5, key, keylen, 0);
#else
		ret->handle = gcry_md_open(GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
#endif
		if (!ret->handle)
			ret = GNUTLS_MAC_FAILED;
		break;
	default:
		ret = GNUTLS_MAC_FAILED;
	}
#ifndef USE_MHASH
	if (ret != GNUTLS_MAC_FAILED)
		gcry_md_setkey(ret->handle, key, keylen);
#endif

	return ret;
}


int gnutls_hmac_get_algo_len(MACAlgorithm algorithm)
{
	int ret;

	switch (algorithm) {
	case GNUTLS_MAC_NULL:
		ret = 0;
		break;
	case GNUTLS_MAC_SHA:
#ifdef USE_MHASH
		ret = mhash_get_block_size(MHASH_SHA1);
#else
		ret = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
#endif
		break;
	case GNUTLS_MAC_MD5:
#ifdef USE_MHASH
		ret = mhash_get_block_size(MHASH_MD5);
#else
		ret = gcry_md_get_algo_dlen(GCRY_MD_MD5);
#endif
		break;
	default:
		ret = 0;
	}

	return ret;

}

int gnutls_hmac(GNUTLS_MAC_HANDLE handle, void *text, int textlen)
{

#ifdef USE_MHASH
	mhash(handle->handle, text, textlen);
#else
	gcry_md_write(handle->handle, text, textlen);
#endif
	return 0;

}

void *gnutls_hmac_deinit(GNUTLS_MAC_HANDLE handle)
{
	char *mac;
	int maclen;
	char *ret;

#ifdef USE_MHASH
	ret = mhash_hmac_end(handle->handle);
#else
	maclen = gcry_md_get_algo_dlen(gcry_md_get_algo(handle->handle));
	ret = gnutls_malloc(maclen);

	gcry_md_final(handle->handle);
	mac = gcry_md_read(handle->handle, 0);
	memmove(ret, mac, maclen);
	gcry_md_close(handle->handle);
#endif
	gnutls_free(handle);
	return ret;
}

GNUTLS_MAC_HANDLE gnutls_hash_init_ssl3(MACAlgorithm algorithm, char *key,
					int keylen)
{
	GNUTLS_MAC_HANDLE ret;
	char *ipad;
	char *digest;
	int padsize;

	switch (algorithm) {
	case GNUTLS_MAC_MD5:
		padsize = 48;
		break;
	case GNUTLS_MAC_SHA:
		padsize = 40;
		break;
	default:
		padsize = 0;
	}
	if (padsize>0) {
		ipad = gnutls_malloc(padsize);
		memset(ipad, 0x36, padsize);
	}
	ret = gnutls_hash_init(algorithm);
	if (ret!=GNUTLS_MAC_FAILED) {
		ret->key = key;
		ret->keysize = keylen;

		if (keylen>0) gnutls_hash(ret, key, keylen);
		gnutls_hash(ret, ipad, padsize);
	}
	if (padsize>0) gnutls_free(ipad);

	return ret;
}

void *gnutls_hash_deinit_ssl3(GNUTLS_MAC_HANDLE handle)
{
	void *ret=NULL;
	GNUTLS_MAC_HANDLE td;
	char *opad;
	int padsize;
	
	switch (handle->algorithm) {
	case GNUTLS_MAC_MD5:
		padsize = 48;
		break;
	case GNUTLS_MAC_SHA:
		padsize = 40;
		break;
	default:
		padsize=0;
	}
	if (padsize>0) {
		opad = gnutls_malloc(padsize);
		memset(opad, 0x5C, padsize);
	}

	td = gnutls_hash_init(handle->algorithm);
	if (td!=GNUTLS_MAC_FAILED) {
		if (handle->keysize) gnutls_hash(td, handle->key, handle->keysize);

		gnutls_hash(td, opad, padsize);
		gnutls_free(opad);

		ret = gnutls_hash_deinit(handle);	/* get the previous hash */
		gnutls_hash(td, ret, gnutls_hmac_get_algo_len(handle->algorithm));
		gnutls_free(ret);

		ret = gnutls_hash_deinit(handle);
	}
	return ret;
}

void *ssl3_sha(int i, char *secret, int secret_len, char *random,
	       int random_len)
{
	int j;
	char text1[26];

	GNUTLS_MAC_HANDLE td;

	for (j = 0; j < i + 1; j++) {
		text1[j] = 65 + i;	/* A==65 */
	}

	td = gnutls_hash_init(GNUTLS_MAC_SHA);
	gnutls_hash(td, text1, i + 1);
	gnutls_hash(td, secret, secret_len);
	gnutls_hash(td, random, random_len);
	return gnutls_hash_deinit(td);
}
void *ssl3_md5(int i, char *secret, int secret_len, char *random,
	       int random_len)
{
	int j;
	void *digest;
	GNUTLS_MAC_HANDLE td;

	td = gnutls_hash_init(GNUTLS_MAC_MD5);
	gnutls_hash(td, secret, secret_len);

	digest = ssl3_sha(i, secret, secret_len, random, random_len);

	gnutls_hash(td, secret, secret_len);
	gnutls_hash(td, digest, gnutls_hash_get_algo_len(GNUTLS_MAC_SHA));
	gnutls_free(digest);

	return gnutls_hash_deinit(td);

}

void *ssl3_generate_random(void *secret, int secret_len, void *random,
			   int random_len, int bytes)
{
	int size = 0, i = 0;
	char *digest;
	char *ret = gnutls_malloc(bytes);
	int block = gnutls_hash_get_algo_len(GNUTLS_MAC_SHA);

	while (size < bytes) {
		digest =
		    ssl3_md5(i, secret, secret_len, random, random_len);


		size += block;
		memmove(&ret[size - block], digest,
			size > bytes ? (block - bytes % block) : block);
		i++;
	}

}
