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

GNUTLS_HASH_HANDLE gnutls_hash_init(MACAlgorithm algorithm) {
GNUTLS_HASH_HANDLE ret;

	switch (algorithm) {
		case GNUTLS_MAC_NULL:
			ret = GNUTLS_HASH_FAILED;
			break;
		case GNUTLS_MAC_SHA:
#ifdef USE_MHASH
			ret = mhash_init( MHASH_SHA1);
#else
			ret = gcry_md_open( GCRY_MD_SHA1, 0);
#endif
			if (!ret) return GNUTLS_HASH_FAILED;
			break;
		case GNUTLS_MAC_MD5:
#ifdef USE_MHASH
			ret = mhash_init( MHASH_MD5);
#else
			ret = gcry_md_open( GCRY_MD_MD5, 0);
#endif
			if (!ret) return GNUTLS_HASH_FAILED;
			break;
		default:
			ret = GNUTLS_HASH_FAILED;
	}
	
	return ret;
}

int gnutls_hash_get_algo_len(MACAlgorithm algorithm) {
int ret;

	switch (algorithm) {
		case GNUTLS_MAC_NULL:
			ret = 0;
			break;
		case GNUTLS_MAC_SHA:
#ifdef USE_MHASH
			ret = mhash_get_block_size(MHASH_SHA1);
#else			 
			ret = gcry_md_get_algo_dlen( GCRY_MD_SHA1);
#endif
			break;
		case GNUTLS_MAC_MD5:
#ifdef USE_MHASH
			ret = mhash_get_block_size(MHASH_MD5);
#else			 
			ret = gcry_md_get_algo_dlen( GCRY_MD_MD5);
#endif
			break;
		default:
			ret = 0;
	}

return ret;

}

int gnutls_hash(GNUTLS_HASH_HANDLE handle, void* text, int textlen) {
#ifdef USE_MHASH
	mhash( handle, text, textlen);
#else
	gcry_md_write( handle, text, textlen);
#endif
	return 0;
}

void* gnutls_hash_deinit( GNUTLS_HASH_HANDLE handle) {
char* mac;
int maclen;
char* ret;

#ifdef USE_MHASH
    ret = mhash_end(handle);
#else
    maclen = gcry_md_get_algo_dlen(gcry_md_get_algo(handle));
    ret = gnutls_malloc(maclen);
    
    gcry_md_final(handle);
    mac = gcry_md_read(handle,0);
    memmove( ret, mac, maclen);
    gcry_md_close(handle);
#endif    
    return ret;
}


GNUTLS_MAC_HANDLE _gnutls_hmac_init( MACAlgorithm algorithm, char* key, int keylen, int dp) {
GNUTLS_MAC_HANDLE ret;

	switch (algorithm) {
		case GNUTLS_MAC_NULL:
			ret = GNUTLS_MAC_FAILED;
			break;
		case GNUTLS_MAC_SHA:
#ifdef USE_MHASH
			if (dp==0) {
				ret = mhash_hmac_init( MHASH_SHA1, key, keylen, 0);
			} else {
				ret = mhash_hmac_init_dp( MHASH_SHA1, key, keylen, 0);
			}
#else
			ret = gcry_md_open( GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
#endif
			if (!ret) ret = GNUTLS_MAC_FAILED;
			break;
		case GNUTLS_MAC_MD5:
#ifdef USE_MHASH
			if (dp==0) {
				ret = mhash_hmac_init( MHASH_MD5, key, keylen, 0);
			} else {
				ret = mhash_hmac_init_dp( MHASH_MD5, key, keylen, 0);
			}
#else
			ret = gcry_md_open( GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
#endif
			if (!ret) ret = GNUTLS_MAC_FAILED;
			break;
		default:
			ret = GNUTLS_MAC_FAILED;
	}
#ifndef USE_MHASH
	if (ret!=GNUTLS_MAC_FAILED) gcry_md_setkey(ret, key, keylen);
#endif
	
	return ret;
}

int gnutls_hmac_get_algo_len(MACAlgorithm algorithm) {
int ret;

	switch (algorithm) {
		case GNUTLS_MAC_NULL:
			ret = 0;
			break;
		case GNUTLS_MAC_SHA:
#ifdef USE_MHASH
			ret = mhash_get_block_size(MHASH_SHA1);
#else			
			ret = gcry_md_get_algo_dlen( GCRY_MD_SHA1);
#endif
			break;
		case GNUTLS_MAC_MD5:
#ifdef USE_MHASH
			ret = mhash_get_block_size(MHASH_MD5);
#else			
			ret = gcry_md_get_algo_dlen( GCRY_MD_MD5);
#endif
			break;
		default:
			ret = 0;
	}

return ret;

}

int gnutls_hmac(GNUTLS_MAC_HANDLE handle, void* text, int textlen) {

#ifdef USE_MHASH
	mhash( handle, text, textlen);
#else
	gcry_md_write( handle, text, textlen);
#endif
	return 0;

}

void* _gnutls_hmac_deinit( GNUTLS_MAC_HANDLE handle, int dp) {
char* mac;
int maclen;
char* ret;

#ifdef USE_MHASH
    if (dp==0) {
	    ret = mhash_hmac_end(handle);
    } else {
    	    ret = mhash_hmac_end_dp(handle);
    }
#else
    maclen = gcry_md_get_algo_dlen(gcry_md_get_algo(handle));
    ret = gnutls_malloc( maclen);
    
    gcry_md_final(handle);
    mac = gcry_md_read(handle,0);
    memmove( ret, mac, maclen);
    gcry_md_close(handle);
#endif

    return ret;
}

