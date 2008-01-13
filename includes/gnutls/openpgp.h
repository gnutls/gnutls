/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 *
 */

/* This file contains the types and prototypes for the OpenPGP
 * key and private key parsing functions.
 */

#ifndef GNUTLS_OPENPGP_H
# define GNUTLS_OPENPGP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>

  typedef struct 
  {
    unsigned char keyid[8];
  } gnutls_openpgp_keyid_t;
    
/* gnutls_openpgp_cert_t should be defined in gnutls.h
 */

  /* initializes the memory for gnutls_openpgp_crt_t struct */
  int gnutls_openpgp_crt_init (gnutls_openpgp_crt_t * key);
  /* frees all memory */
  void gnutls_openpgp_crt_deinit (gnutls_openpgp_crt_t key);

  int gnutls_openpgp_crt_import (gnutls_openpgp_crt_t key,
				 const gnutls_datum_t * data,
				 gnutls_openpgp_crt_fmt_t format);
  int gnutls_openpgp_crt_export (gnutls_openpgp_crt_t key,
				 gnutls_openpgp_crt_fmt_t format,
				 void *output_data,
				 size_t * output_data_size);

  int gnutls_openpgp_crt_print (gnutls_openpgp_crt_t cert,
		       gnutls_certificate_print_formats_t format,
		       gnutls_datum_t *out);

/* The key_usage flags are defined in gnutls.h. They are
 * the GNUTLS_KEY_* definitions.
 */
  int gnutls_openpgp_crt_get_key_usage (gnutls_openpgp_crt_t cert,
					unsigned int *key_usage);
  int gnutls_openpgp_crt_get_fingerprint (gnutls_openpgp_crt_t key, void *fpr,
					  size_t * fprlen);

  int gnutls_openpgp_crt_get_name (gnutls_openpgp_crt_t key,
				   int idx, char *buf, size_t * sizeof_buf);

  gnutls_pk_algorithm_t
  gnutls_openpgp_crt_get_pk_algorithm (gnutls_openpgp_crt_t key,
				       unsigned int *bits);

  int gnutls_openpgp_crt_get_version (gnutls_openpgp_crt_t key);

  time_t gnutls_openpgp_crt_get_creation_time (gnutls_openpgp_crt_t key);
  time_t gnutls_openpgp_crt_get_expiration_time (gnutls_openpgp_crt_t key);

  int gnutls_openpgp_crt_get_id (gnutls_openpgp_crt_t key,
				 gnutls_openpgp_keyid_t* keyid);

  int gnutls_openpgp_crt_check_hostname (gnutls_openpgp_crt_t key,
					 const char *hostname);

  int gnutls_openpgp_crt_get_revoked_status (gnutls_openpgp_crt_t key);

  int gnutls_openpgp_crt_get_subkey_count (gnutls_openpgp_crt_t key);
  int gnutls_openpgp_crt_get_subkey_idx (gnutls_openpgp_crt_t key, gnutls_openpgp_keyid_t keyid);
  int gnutls_openpgp_crt_get_subkey_revoked_status (gnutls_openpgp_crt_t key, unsigned int idx);
  gnutls_pk_algorithm_t gnutls_openpgp_crt_get_subkey_pk_algorithm (gnutls_openpgp_crt_t key,
    unsigned int idx, unsigned int *bits);
  time_t gnutls_openpgp_crt_get_subkey_creation_time (gnutls_openpgp_crt_t key, unsigned int idx);
  time_t gnutls_openpgp_crt_get_subkey_expiration_time (gnutls_openpgp_crt_t key, unsigned int idx);
  int gnutls_openpgp_crt_get_subkey_id (gnutls_openpgp_crt_t key, unsigned int idx, gnutls_openpgp_keyid_t* keyid);
  int gnutls_openpgp_crt_get_subkey_usage (gnutls_openpgp_crt_t key, unsigned int idx,
				  unsigned int *key_usage);

/* privkey stuff.
 */
  int gnutls_openpgp_privkey_init (gnutls_openpgp_privkey_t * key);
  void gnutls_openpgp_privkey_deinit (gnutls_openpgp_privkey_t key);
  gnutls_pk_algorithm_t
  gnutls_openpgp_privkey_get_pk_algorithm (gnutls_openpgp_privkey_t key,
					   unsigned int *bits);
  int gnutls_openpgp_privkey_import (gnutls_openpgp_privkey_t key,
				     const gnutls_datum_t * data,
				     gnutls_openpgp_crt_fmt_t format,
				     const char *pass, unsigned int flags);
  int gnutls_openpgp_privkey_sign_hash (gnutls_openpgp_privkey_t key,
                                  gnutls_openpgp_keyid_t subkeyid,
				  const gnutls_datum_t * hash,
				  gnutls_datum_t * signature);
  int gnutls_openpgp_privkey_get_fingerprint (gnutls_openpgp_privkey_t key,
				    void *fpr, size_t * fprlen);
  int gnutls_openpgp_privkey_get_key_id (gnutls_openpgp_privkey_t key, gnutls_openpgp_keyid_t* keyid);
  int gnutls_openpgp_privkey_get_subkey_count (gnutls_openpgp_privkey_t key);
  int gnutls_openpgp_privkey_get_subkey_idx (gnutls_openpgp_privkey_t key, gnutls_openpgp_keyid_t keyid);

  int gnutls_openpgp_privkey_get_subkey_revoked_status (gnutls_openpgp_privkey_t key, unsigned int idx);

  int gnutls_openpgp_privkey_get_revoked_status (gnutls_openpgp_privkey_t key);

  gnutls_pk_algorithm_t gnutls_openpgp_privkey_get_subkey_pk_algorithm (gnutls_openpgp_privkey_t key,
    unsigned int idx, unsigned int *bits);

  time_t gnutls_openpgp_privkey_get_subkey_expiration_time (gnutls_openpgp_privkey_t key, unsigned int idx);

  int gnutls_openpgp_privkey_get_subkey_id (gnutls_openpgp_privkey_t key, unsigned int idx, gnutls_openpgp_keyid_t* keyid);

  time_t gnutls_openpgp_privkey_get_subkey_creation_time (gnutls_openpgp_privkey_t key, unsigned int idx);

/* Keyring stuff.
 */
  struct gnutls_openpgp_keyring_int;	/* object to hold (parsed) openpgp keyrings */
  typedef struct gnutls_openpgp_keyring_int *gnutls_openpgp_keyring_t;
  
  int gnutls_openpgp_keyring_init (gnutls_openpgp_keyring_t * keyring);
  void gnutls_openpgp_keyring_deinit (gnutls_openpgp_keyring_t keyring);

  int gnutls_openpgp_keyring_import (gnutls_openpgp_keyring_t keyring,
				     const gnutls_datum_t * data,
				     gnutls_openpgp_crt_fmt_t format);

  int gnutls_openpgp_keyring_check_id (gnutls_openpgp_keyring_t ring,
				       gnutls_openpgp_keyid_t keyid,
				       unsigned int flags);


  int gnutls_openpgp_crt_verify_ring (gnutls_openpgp_crt_t key,
				      gnutls_openpgp_keyring_t keyring,
				      unsigned int flags, unsigned int *verify
				      /* the output of the verification */ );

  int gnutls_openpgp_crt_verify_self (gnutls_openpgp_crt_t key,
				      unsigned int flags,
				      unsigned int *verify);


/* certificate authentication stuff.
 */
  int gnutls_certificate_set_openpgp_key (gnutls_certificate_credentials_t
					  res, gnutls_openpgp_crt_t key,
					  gnutls_openpgp_privkey_t pkey);

#ifdef __cplusplus
}
#endif
#endif				/* GNUTLS_OPENPGP_H */
