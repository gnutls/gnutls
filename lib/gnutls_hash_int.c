/*
 * Copyright (C) 2000,2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

/* This file handles all the internal functions that cope with hashes
 * and HMACs. Currently it uses the functions provided by
 * the gcrypt library that this can be easily changed.
 */

#include <gnutls_int.h>
#include <gnutls_hash_int.h>
#include <gnutls_errors.h>

GNUTLS_HASH_HANDLE _gnutls_hash_init(gnutls_mac_algorithm algorithm)
{
	GNUTLS_MAC_HANDLE ret;

	switch (algorithm) {
	case GNUTLS_MAC_SHA:
		ret = gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));
		if (ret == NULL)
			return GNUTLS_HASH_FAILED;
		ret->handle = gcry_md_open(GCRY_MD_SHA1, 0);
		if (!ret->handle) {
			gnutls_free(ret);
			ret = GNUTLS_HASH_FAILED;
		}
		break;

	case GNUTLS_MAC_MD5:
		ret = gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));
		if (ret == NULL)
			return GNUTLS_HASH_FAILED;
		ret->handle = gcry_md_open(GCRY_MD_MD5, 0);
		if (!ret->handle) {
			gnutls_free(ret);
			ret = GNUTLS_HASH_FAILED;
		}
		break;

	case GNUTLS_MAC_MD2:
		ret = gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));
		if (ret == NULL)
			return GNUTLS_HASH_FAILED;
		ret->handle = gcry_md_open(GCRY_MD_MD2, 0);
		if (!ret->handle) {
			gnutls_free(ret);
			ret = GNUTLS_HASH_FAILED;
		}
		break;

	default:
		ret = GNUTLS_HASH_FAILED;
	}

	if (ret != GNUTLS_HASH_FAILED)
		ret->algorithm = algorithm;

	return ret;
}

int _gnutls_hash_get_algo_len(gnutls_mac_algorithm algorithm)
{
	int ret;

	switch (algorithm) {
	case GNUTLS_MAC_SHA:
		ret = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
		break;
	case GNUTLS_MAC_MD5:
		ret = gcry_md_get_algo_dlen(GCRY_MD_MD5);
		break;
	case GNUTLS_MAC_MD2:
		ret = gcry_md_get_algo_dlen(GCRY_MD_MD2);
		break;
	default:
		ret = 0;
	}

	return ret;

}

int _gnutls_hash(GNUTLS_HASH_HANDLE handle, const void *text, size_t textlen)
{
	if (textlen > 0)
		gcry_md_write(handle->handle, text, textlen);
	return 0;
}

GNUTLS_HASH_HANDLE _gnutls_hash_copy(GNUTLS_HASH_HANDLE handle)
{
	GNUTLS_HASH_HANDLE ret;

	ret = gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));

	if (ret == NULL)
		return GNUTLS_HASH_FAILED;

	ret->algorithm = handle->algorithm;
	ret->key = NULL;	/* it's a hash anyway */
	ret->keysize = 0;

	ret->handle = gcry_md_copy(handle->handle);

	if (ret->handle == NULL) {
		gnutls_free(ret);
		return GNUTLS_HASH_FAILED;
	}

	return ret;
}

void _gnutls_hash_deinit(GNUTLS_HASH_HANDLE handle, void *digest)
{
	char *mac;
	int maclen;

	maclen = gcry_md_get_algo_dlen(gcry_md_get_algo(handle->handle));
	gcry_md_final(handle->handle);
	mac = gcry_md_read(handle->handle, 0);
	if (digest != NULL)
		memcpy(digest, mac,
		       _gnutls_hash_get_algo_len(handle->algorithm));

	gcry_md_close(handle->handle);

	gnutls_free(handle);
	return;
}


GNUTLS_MAC_HANDLE _gnutls_hmac_init(gnutls_mac_algorithm algorithm,
				    const void *key, int keylen)
{
	GNUTLS_MAC_HANDLE ret;

	switch (algorithm) {
	case GNUTLS_MAC_NULL:
		ret = GNUTLS_MAC_FAILED;
		break;
	case GNUTLS_MAC_SHA:
		ret = gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));
		if (ret == NULL)
			return GNUTLS_MAC_FAILED;

		ret->handle =
		    gcry_md_open(GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);

		if (!ret->handle)
			ret = GNUTLS_MAC_FAILED;
		break;
	case GNUTLS_MAC_MD5:
		ret = gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));
		if (ret == NULL)
			return GNUTLS_MAC_FAILED;

		ret->handle = gcry_md_open(GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);

		if (!ret->handle)
			ret = GNUTLS_MAC_FAILED;
		break;
	case GNUTLS_MAC_MD2:
		ret = gnutls_malloc(sizeof(GNUTLS_MAC_HANDLE_INT));
		if (ret == NULL)
			return GNUTLS_MAC_FAILED;

		ret->handle = gcry_md_open(GCRY_MD_MD2, GCRY_MD_FLAG_HMAC);

		if (!ret->handle)
			ret = GNUTLS_MAC_FAILED;
		break;
	default:
		ret = GNUTLS_MAC_FAILED;
	}

	if (ret != GNUTLS_MAC_FAILED) {
		gcry_md_setkey(ret->handle, key, keylen);

		ret->algorithm = algorithm;
		ret->key = key;
		ret->keysize = keylen;
	}



	return ret;
}


int _gnutls_hmac_get_algo_len(gnutls_mac_algorithm algorithm)
{
	return _gnutls_hash_get_algo_len( algorithm);
}

int _gnutls_hmac(GNUTLS_MAC_HANDLE handle, const void *text, size_t textlen)
{

	gcry_md_write(handle->handle, text, textlen);
	return 0;

}

void _gnutls_hmac_deinit(GNUTLS_MAC_HANDLE handle, void *digest)
{
	char *mac;
	int maclen;

	maclen = gcry_md_get_algo_dlen(gcry_md_get_algo(handle->handle));

	gcry_md_final(handle->handle);
	mac = gcry_md_read(handle->handle, 0);

	if (digest != NULL)
		memcpy(digest, mac, maclen);

	gcry_md_close(handle->handle);

	gnutls_free(handle);
	return;
}

GNUTLS_MAC_HANDLE _gnutls_mac_init_ssl3(gnutls_mac_algorithm algorithm, void *key,
					int keylen)
{
	GNUTLS_MAC_HANDLE ret;
	char ipad[48];
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
	if (padsize > 0) {
		memset(ipad, 0x36, padsize);
	}
	ret = _gnutls_hash_init(algorithm);
	if (ret != GNUTLS_HASH_FAILED) {
		ret->key = key;
		ret->keysize = keylen;

		if (keylen > 0)
			_gnutls_hash(ret, key, keylen);
		_gnutls_hash(ret, ipad, padsize);
	}

	return ret;
}

void _gnutls_mac_deinit_ssl3(GNUTLS_MAC_HANDLE handle, void *digest)
{
	opaque ret[MAX_HASH_SIZE];
	GNUTLS_MAC_HANDLE td;
	char opad[48];
	int padsize;
	int block;

	switch (handle->algorithm) {
	case GNUTLS_MAC_MD5:
		padsize = 48;
		break;
	case GNUTLS_MAC_SHA:
		padsize = 40;
		break;
	default:
		padsize = 0;
	}
	if (padsize > 0) {
		memset(opad, 0x5C, padsize);
	}

	td = _gnutls_hash_init(handle->algorithm);
	if (td != GNUTLS_MAC_FAILED) {
		if (handle->keysize > 0)
			_gnutls_hash(td, handle->key, handle->keysize);

		_gnutls_hash(td, opad, padsize);
		block = _gnutls_hmac_get_algo_len(handle->algorithm);
		_gnutls_hash_deinit(handle, ret);	/* get the previous hash */
		_gnutls_hash(td, ret, block);

		_gnutls_hash_deinit(td, digest);
	}
	return;
}

void _gnutls_mac_deinit_ssl3_handshake(GNUTLS_MAC_HANDLE handle,
				       void *digest, opaque * key,
				       uint32 key_size)
{
	opaque ret[MAX_HASH_SIZE];
	GNUTLS_MAC_HANDLE td;
	char opad[48];
	char ipad[48];
	int padsize;
	int block;

	switch (handle->algorithm) {
	case GNUTLS_MAC_MD5:
		padsize = 48;
		break;
	case GNUTLS_MAC_SHA:
		padsize = 40;
		break;
	default:
		padsize = 0;
	}
	if (padsize > 0) {
		memset(opad, 0x5C, padsize);
		memset(ipad, 0x36, padsize);
	}

	td = _gnutls_hash_init(handle->algorithm);
	if (td != GNUTLS_HASH_FAILED) {
		if (key_size > 0)
			_gnutls_hash(td, key, key_size);

		_gnutls_hash(td, opad, padsize);
		block = _gnutls_hmac_get_algo_len(handle->algorithm);

		if (key_size > 0)
			_gnutls_hash(handle, key, key_size);
		_gnutls_hash(handle, ipad, padsize);
		_gnutls_hash_deinit(handle, ret);	/* get the previous hash */

		_gnutls_hash(td, ret, block);

		_gnutls_hash_deinit(td, digest);
	}
	return;
}

static int ssl3_sha(int i, char *secret, int secret_len, char *random,
		    int random_len, void *digest)
{
	int j;
	char text1[26];

	GNUTLS_HASH_HANDLE td;

	for (j = 0; j < i + 1; j++) {
		text1[j] = 65 + i;	/* A==65 */
	}

	td = _gnutls_hash_init(GNUTLS_MAC_SHA);
	if (td == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	_gnutls_hash(td, text1, i + 1);
	_gnutls_hash(td, secret, secret_len);
	_gnutls_hash(td, random, random_len);

	_gnutls_hash_deinit(td, digest);
	return 0;
}

static int ssl3_md5(int i, char *secret, int secret_len, char *random,
		    int random_len, void *digest)
{
	opaque tmp[MAX_HASH_SIZE];
	GNUTLS_MAC_HANDLE td;
	int ret;

	td = _gnutls_hash_init(GNUTLS_MAC_MD5);
	if (td == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	_gnutls_hash(td, secret, secret_len);

	ret = ssl3_sha(i, secret, secret_len, random, random_len, tmp);
	if (ret < 0) {
		gnutls_assert();
		_gnutls_hash_deinit(td, digest);
		return ret;
	}

	_gnutls_hash(td, tmp, _gnutls_hash_get_algo_len(GNUTLS_MAC_SHA));

	_gnutls_hash_deinit(td, digest);
	return 0;
}

int _gnutls_ssl3_hash_md5(void *first, int first_len,
			  void *second, int second_len, int ret_len,
			  opaque * ret)
{
	opaque digest[MAX_HASH_SIZE];
	GNUTLS_MAC_HANDLE td;
	int block = _gnutls_hash_get_algo_len(GNUTLS_MAC_MD5);

	td = _gnutls_hash_init(GNUTLS_MAC_MD5);
	if (td == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	_gnutls_hash(td, first, first_len);
	_gnutls_hash(td, second, second_len);

	_gnutls_hash_deinit(td, digest);

	if (ret_len > block) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	memcpy(ret, digest, ret_len);

	return 0;

}

int _gnutls_ssl3_generate_random(void *secret, int secret_len,
				 void *random, int random_len,
				 int ret_bytes, opaque * ret)
{
	int i = 0, copy, output_bytes;
	char digest[MAX_HASH_SIZE];
	int block = _gnutls_hash_get_algo_len(GNUTLS_MAC_MD5);
	int result, times;

	output_bytes = 0;
	do {
		output_bytes += block;
	} while (output_bytes < ret_bytes);

	times = output_bytes / block;

	for (i = 0; i < times; i++) {

		result =
		    ssl3_md5(i, secret, secret_len, random, random_len,
			     digest);
		if (result < 0) {
			gnutls_assert();
			return result;
		}

		if ((1 + i) * block < ret_bytes) {
			copy = block;
		} else {
			copy = ret_bytes - (i) * block;
		}

		memcpy(&ret[i * block], digest, copy);
	}

	return 0;
}
