/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_extensions.h>
#include <ext_srp.h>
#include <gnutls_openpgp.h>
#include <gnutls_extra.h>
#include <gnutls_algorithms.h>
#include <minilzo.h>

extern gnutls_extension_entry _gnutls_extensions[];
extern const int _gnutls_extensions_size;

#define TOSTR(x) #x

static int _gnutls_add_srp_extension(void) {
int i;

	/* find the last element */
	for(i=0;i<_gnutls_extensions_size;i++) {
		if (_gnutls_extensions[i].name==NULL) break;
	}

	if (_gnutls_extensions[i].name==NULL && (i < _gnutls_extensions_size-1)) {
		_gnutls_extensions[i].name = TOSTR(GNUTLS_EXTENSION_SRP);
		_gnutls_extensions[i].type = GNUTLS_EXTENSION_SRP;
		_gnutls_extensions[i].gnutls_ext_func_recv = _gnutls_srp_recv_params;
		_gnutls_extensions[i].gnutls_ext_func_send = _gnutls_srp_send_params;
		
		_gnutls_extensions[i+1].name = 0;
	
		return 0; /* ok */
	}

	return GNUTLS_E_MEMORY_ERROR;
}

extern const int _gnutls_kx_algorithms_size;
extern gnutls_kx_algo_entry _gnutls_kx_algorithms[];
extern MOD_AUTH_STRUCT srp_auth_struct;

static int _gnutls_add_srp_auth_struct(void) {
int i;

	/* find the last element */
	for(i=0;i<_gnutls_kx_algorithms_size;i++) {
		if (_gnutls_kx_algorithms[i].name==NULL) break;
	}

	if (_gnutls_kx_algorithms[i].name==NULL && (i < _gnutls_kx_algorithms_size-1)) {
		_gnutls_kx_algorithms[i].name = "SRP";
		_gnutls_kx_algorithms[i].algorithm = GNUTLS_KX_SRP;
		_gnutls_kx_algorithms[i].auth_struct = &srp_auth_struct;

		_gnutls_kx_algorithms[i+1].name = 0;
	
		return 0; /* ok */
	}

	return GNUTLS_E_MEMORY_ERROR;
}

/* the number of the compression algorithms available in the compression
 * structure.
 */
extern int _gnutls_comp_algorithms_size;

/* Functions in gnutls that have not been initialized.
 */
typedef int (*LZO_FUNC)();
extern LZO_FUNC _gnutls_lzo1x_decompress_safe;
extern LZO_FUNC _gnutls_lzo1x_1_compress;

extern gnutls_compression_entry _gnutls_compression_algorithms[];

static int _gnutls_add_lzo_comp(void) 
{
int i;

	/* find the last element */
	for(i=0;i<_gnutls_comp_algorithms_size;i++) {
		if (_gnutls_compression_algorithms[i].name==NULL) break;
	}

	if (_gnutls_compression_algorithms[i].name==NULL && (i < _gnutls_comp_algorithms_size-1)) {
		_gnutls_compression_algorithms[i].name = "GNUTLS_COMP_LZO";
		_gnutls_compression_algorithms[i].id = GNUTLS_COMP_LZO;
		_gnutls_compression_algorithms[i].num = 0xf2;

		_gnutls_compression_algorithms[i+1].name = 0;

		/* Now enable the lzo functions: */
		_gnutls_lzo1x_decompress_safe = lzo1x_decompress_safe;
		_gnutls_lzo1x_1_compress = lzo1x_1_compress;
	
		return 0; /* ok */
	}
	

	return GNUTLS_E_MEMORY_ERROR;
}


extern OPENPGP_KEY_CREATION_TIME_FUNC _E_gnutls_openpgp_extract_key_creation_time;
extern OPENPGP_KEY_EXPIRATION_TIME_FUNC _E_gnutls_openpgp_extract_key_expiration_time;
extern OPENPGP_VERIFY_KEY_FUNC _E_gnutls_openpgp_verify_key;
extern OPENPGP_CERT2GNUTLS_CERT _E_gnutls_openpgp_cert2gnutls_cert;
extern OPENPGP_FINGERPRINT _E_gnutls_openpgp_fingerprint;
extern OPENPGP_KEY_REQUEST _E_gnutls_openpgp_request_key;

static void _gnutls_add_openpgp_functions(void) {
	_E_gnutls_openpgp_verify_key = gnutls_openpgp_verify_key;
	_E_gnutls_openpgp_extract_key_expiration_time = gnutls_openpgp_extract_key_expiration_time;
	_E_gnutls_openpgp_extract_key_creation_time = gnutls_openpgp_extract_key_creation_time;
	_E_gnutls_openpgp_fingerprint = gnutls_openpgp_fingerprint;
	_E_gnutls_openpgp_request_key = _gnutls_openpgp_request_key;
	_E_gnutls_openpgp_cert2gnutls_cert = _gnutls_openpgp_cert2gnutls_cert;
	
	return;
}

const char* gnutls_check_version( const char*);
static int _gnutls_init_extra = 0;

/**
  * gnutls_global_init_extra - This function initializes the global state of gnutls-extra 
  *
  * This function initializes the global state of gnutls-extra library to defaults.
  * Returns zero on success.
  *
  * Note that gnutls_global_init() has to be called before this function.
  * If this function is not called then the gnutls-extra library will not
  * be usable.
  *
  **/
int gnutls_global_init_extra(void) {
int ret;
	
	/* If the version of libgnutls != version of
	 * libextra, then do not initialize the library.
	 * This is because it may break things.
	 */
	if (strcmp( gnutls_check_version(NULL), GNUTLS_VERSION)!=0) {
		return GNUTLS_E_LIBRARY_VERSION_MISMATCH;
	}

	_gnutls_init_extra++;

	if (_gnutls_init_extra!=1) {
		return 0;
	}

	/* Initialize the LZO library
	 */
	if (lzo_init() != LZO_E_OK) {
		return GNUTLS_E_LZO_INIT_FAILED;
	}

	/* Add the LZO compression method in the list of compression
	 * methods.
	 */
	ret = _gnutls_add_lzo_comp();
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* Add the SRP authentication to the list of authentication
	 * methods.
	 */
	ret = _gnutls_add_srp_auth_struct();
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* Do the same of the extension
	 */
	ret = _gnutls_add_srp_extension();
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* Register the openpgp functions. This is because some
	 * of them are defined to be NULL in the main library.
	 */
	_gnutls_add_openpgp_functions();

	return 0;
}
