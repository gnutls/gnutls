/*
 * Copyright (C) 2003-2012 Free Software Foundation, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef CERTTOOL_COMMON_H
#define CERTTOOL_COMMON_H

#include <gnutls/x509.h>
#include <stdio.h>

#define TYPE_CRT 1
#define TYPE_CRQ 2

void certtool_version (void);

#include <gnutls/x509.h>
#include <gnutls/abstract.h>

typedef struct common_info
{
  const char *secret_key;
  const char *privkey;
  const char *pubkey;
  int pkcs8;
  int incert_format;
  const char *cert;

  const char *request;
  const char *ca;
  const char *ca_privkey;
  int bits;
  const char* sec_param;
  const char* pkcs_cipher;
  const char* password;
  unsigned int crq_extensions;
  unsigned int v1_cert;
} common_info_st;

gnutls_pubkey_t load_public_key_or_import(int mand, gnutls_privkey_t privkey, common_info_st * info);
gnutls_privkey_t load_private_key (int mand, common_info_st * info);
gnutls_x509_privkey_t load_x509_private_key (int mand, common_info_st * info);
gnutls_x509_crq_t load_request (common_info_st * info);
gnutls_privkey_t load_ca_private_key (common_info_st * info);
gnutls_x509_crt_t load_ca_cert (common_info_st * info);
gnutls_x509_crt_t load_cert (int mand, common_info_st * info);
gnutls_datum_t *load_secret_key (int mand, common_info_st * info);
gnutls_pubkey_t load_pubkey (int mand, common_info_st * info);
gnutls_x509_crt_t *load_cert_list (int mand, size_t * size,
                                   common_info_st * info);
int get_bits (gnutls_pk_algorithm_t key_type, int info_bits, const char* info_sec_param);
gnutls_sec_param_t str_to_sec_param (const char *str);

/* prime.c */
int generate_prime (int how, common_info_st * info);
void dh_info (common_info_st * ci);

FILE *safe_open_rw (const char *file, int privkey_op);

extern unsigned char buffer[];
extern const int buffer_size;


#endif
