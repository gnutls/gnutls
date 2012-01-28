/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <libtasn1.h>
#include <gnutls_global.h>
#include <gnutls_num.h>         /* MAX */
#include <gnutls_sig.h>
#include <gnutls_str.h>
#include <gnutls_datum.h>
#include <hash.h>
#include "x509_int.h"
#include <common.h>
#include <base64.h>
#include <gnutls/abstract.h>
#include <system.h>

static int raw_pubkey_to_base64(gnutls_datum_t* pubkey);
static int x509_crt_to_raw_pubkey(const gnutls_datum_t * cert, gnutls_datum_t *rpubkey);
static int pgp_crt_to_raw_pubkey(const gnutls_datum_t * cert, gnutls_datum_t *rpubkey);
static int find_stored_pubkey(const char* file, const char* application,
                              const char* host, const char* service, 
                              const gnutls_datum_t* skey);
static int find_config_file(char* file, size_t max_size);
#define MAX_FILENAME 512

/**
 * gnutls_verify_stored_pubkey:
 * @file: A file specifying the stored keys (use NULL for the default)
 * @application: non-NULL with an application name if this key is application-specific
 * @host: The peer's name
 * @service: non-NULL if this key is specific to a service (e.g. http)
 * @cert_type: The type of the certificate
 * @cert: The raw (der) data of the certificate
 * @flags: should be 0.
 *
 * This function will try to verify the provided certificate using
 * a list of stored public keys.  The @service field if non-NULL should
 * be a port number.
 *
 * Returns: If no associated public key is found
 * then %GNUTLS_E_NO_CERTIFICATE_FOUND will be returned. If a key
 * is found but does not match %GNUTLS_E_CERTIFICATE_KEY_MISMATCH
 * is returned. On success, %GNUTLS_E_SUCCESS (0) is returned, 
 * or a negative error value on other errors.
 *
 * Since: 3.0.0
 **/
int
gnutls_verify_stored_pubkey(const char* file, 
                            const char* application,
                            const char* host,
                            const char* service,
                            gnutls_certificate_type_t cert_type,
                            const gnutls_datum_t * cert, unsigned int flags)
{
gnutls_datum_t pubkey = { NULL, 0 };
int ret;
char local_file[MAX_FILENAME];

  if (cert_type != GNUTLS_CRT_X509 && cert_type != GNUTLS_CRT_OPENPGP)
    return gnutls_assert_val(GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE);

  if (file == NULL)
    {
      ret = find_config_file(local_file, sizeof(local_file));
      if (ret < 0)
        return gnutls_assert_val(ret);
      file = local_file;
    }

  if (cert_type == GNUTLS_CRT_X509)
    ret = x509_crt_to_raw_pubkey(cert, &pubkey);
  else
    ret = pgp_crt_to_raw_pubkey(cert, &pubkey);

  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }
  
  ret = raw_pubkey_to_base64(&pubkey);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }

  ret = find_stored_pubkey(file, application, host, service, &pubkey);
  if (ret < 0)
    return gnutls_assert_val(GNUTLS_E_NO_CERTIFICATE_FOUND);
  

cleanup:
  gnutls_free(pubkey.data);
  return ret;
}

static int parse_line(char* line, const char* application,
                      size_t application_len,
                      const char* host, size_t host_len,
                      const char* service, size_t service_len,
                      const gnutls_datum_t *skey)
{
char* p, *kp;
char* savep = NULL;
size_t kp_len;

  /* read version */
  p = strtok_r(line, "|", &savep);
  if (p == NULL)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);

  if (strncmp(p, "g0", 2) != 0)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);

  /* read application */
  p = strtok_r(NULL, "|", &savep);
  if (p == NULL)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
    
  if (p[0] != '*' && strcmp(p, application)!=0)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);

  /* read host */
  p = strtok_r(NULL, "|", &savep);
  if (p == NULL)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
    
  if (p[0] != '*' && strcmp(p, host) != 0)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);

  /* read service */
  p = strtok_r(NULL, "|", &savep);
  if (p == NULL)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
    
  if (p[0] != '*' && strcmp(p, service) != 0)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);

  /* read service */
  kp = strtok_r(NULL, "|", &savep);
  if (kp == NULL)
    return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
  
  p = strpbrk(kp, "\n \r\t|");
  if (p != NULL) *p = 0;

  kp_len = strlen(kp);
  if (kp_len != skey->size)
    return gnutls_assert_val(GNUTLS_E_CERTIFICATE_KEY_MISMATCH);
    
  if (memcmp(kp, skey->data, skey->size) != 0)
    return gnutls_assert_val(GNUTLS_E_CERTIFICATE_KEY_MISMATCH);
  
  /* key found and matches */
  return 0;
}

/* Returns the base64 key if found 
 */
static int find_stored_pubkey(const char* file, const char* application,
                             const char* host, const char* service, 
                             const gnutls_datum_t* skey)
{
FILE* fd;
char* line = NULL;
size_t line_size = 0;
int ret, l2, mismatch = 0;
size_t application_len = 0, host_len = 0, service_len = 0;

  if (host != NULL) host_len = strlen(host);
  if (service != NULL) service_len = strlen(service);
  if (application != NULL) application_len = strlen(application);

  fd = fopen(file, "rb");
  if (fd == NULL)
    return gnutls_assert_val(GNUTLS_E_FILE_ERROR);
  
  do 
    {
      l2 = getline(&line, &line_size, fd);
      if (l2 > 0)
        {
          ret = parse_line(line, application, application_len,
                          host, host_len, service, service_len, skey);
          if (ret == 0) /* found */
            {
              goto cleanup;
            }
          else if (ret == GNUTLS_E_CERTIFICATE_KEY_MISMATCH)
            mismatch = 1;
        }
    }
  while(l2 >= 0);

  if (mismatch)
    ret = GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
  else
    ret = GNUTLS_E_NO_CERTIFICATE_FOUND;
  
cleanup:
  free(line);
  fclose(fd);
  
  return ret;
}

static int raw_pubkey_to_base64(gnutls_datum_t* pubkey)
{
  int ret;
  char* out;
  
  ret = base64_encode_alloc((void*)pubkey->data, pubkey->size, &out);
  if (ret == 0)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
  
  gnutls_free(pubkey->data);
  pubkey->data = (void*)out;
  pubkey->size = ret;
  
  return 0;
}

static int x509_crt_to_raw_pubkey(const gnutls_datum_t * cert, gnutls_datum_t *rpubkey)
{
gnutls_x509_crt_t crt = NULL;
gnutls_pubkey_t pubkey = NULL;
size_t size;
int ret;

  ret = gnutls_x509_crt_init(&crt);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ret = gnutls_pubkey_init(&pubkey);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }
  
  ret = gnutls_x509_crt_import(crt, cert, GNUTLS_X509_FMT_DER);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }

  ret = gnutls_pubkey_import_x509 (pubkey, crt, 0);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }
  
  size = 0;
  ret = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER, NULL, &size);
  if (ret < 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      gnutls_assert();
      goto cleanup;
    }

  rpubkey->data = gnutls_malloc(size);
  if (rpubkey->data == NULL)
  if (ret < 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      ret = GNUTLS_E_MEMORY_ERROR;
      gnutls_assert();
      goto cleanup;
    }
  
  ret = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER, rpubkey->data, &size);
  if (ret < 0)
    {
      gnutls_free(rpubkey->data);
      gnutls_assert();
      goto cleanup;
    }

  rpubkey->size = size;
  ret = 0;

cleanup:
  gnutls_x509_crt_deinit(crt);
  gnutls_pubkey_deinit(pubkey);

  return ret;
}

static int pgp_crt_to_raw_pubkey(const gnutls_datum_t * cert, gnutls_datum_t *rpubkey)
{
gnutls_openpgp_crt_t crt = NULL;
gnutls_pubkey_t pubkey = NULL;
size_t size;
int ret;

  ret = gnutls_openpgp_crt_init(&crt);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ret = gnutls_pubkey_init(&pubkey);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }
  
  ret = gnutls_openpgp_crt_import(crt, cert, GNUTLS_OPENPGP_FMT_RAW);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }

  ret = gnutls_pubkey_import_openpgp (pubkey, crt, 0);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }
  
  size = 0;
  ret = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER, NULL, &size);
  if (ret < 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      gnutls_assert();
      goto cleanup;
    }

  rpubkey->data = gnutls_malloc(size);
  if (rpubkey->data == NULL)
  if (ret < 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      ret = GNUTLS_E_MEMORY_ERROR;
      gnutls_assert();
      goto cleanup;
    }
  
  ret = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER, rpubkey->data, &size);
  if (ret < 0)
    {
      gnutls_free(rpubkey->data);
      gnutls_assert();
      goto cleanup;
    }

  rpubkey->size = size;
  ret = 0;

cleanup:
  gnutls_openpgp_crt_deinit(crt);
  gnutls_pubkey_deinit(pubkey);

  return ret;
}

/**
 * gnutls_store_pubkey:
 * @file: A file specifying the stored keys (use NULL for the default)
 * @application: non-NULL with an application name if this key is application-specific
 * @host: The peer's name
 * @service: non-NULL if this key is specific to a service (e.g. http)
 * @cert_type: The type of the certificate
 * @cert: The data of the certificate
 * @flags: should be 0.
 *
 * This function will store to verify the provided certificate to 
 * the list of stored public keys. 
 *
 * Note that this function is not thread safe.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_store_pubkey(const char* file, 
                    const char* application,
                    const char* host,
                    const char* service,
                    gnutls_certificate_type_t cert_type,
                    const gnutls_datum_t * cert, unsigned int flags)
{
FILE* fd = NULL;
gnutls_datum_t pubkey = { NULL, 0 };
int ret;
char local_file[MAX_FILENAME];

  if (cert_type != GNUTLS_CRT_X509 && cert_type != GNUTLS_CRT_OPENPGP)
    return gnutls_assert_val(GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE);
  
  if (file == NULL)
    {
      ret = _gnutls_find_config_path(local_file, sizeof(local_file));
      if (ret < 0)
        return gnutls_assert_val(ret);
      
      _gnutls_debug_log("Configuration path: %s\n", local_file);
      mkdir(local_file, 0700);
      
      ret = find_config_file(local_file, sizeof(local_file));
      if (ret < 0)
        return gnutls_assert_val(ret);
      file = local_file;
    }
    
  if (cert_type == GNUTLS_CRT_X509)
    ret = x509_crt_to_raw_pubkey(cert, &pubkey);
  else
    ret = pgp_crt_to_raw_pubkey(cert, &pubkey);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }
  
  ret = raw_pubkey_to_base64(&pubkey);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }

  _gnutls_debug_log("Configuration file: %s\n", file);

  fd = fopen(file, "ab+");
  if (fd == NULL)
    {
      ret = gnutls_assert_val(GNUTLS_E_FILE_ERROR);
      goto cleanup;
    }

  if (application == NULL) application = "*";
  if (service == NULL) service = "*";
  if (host == NULL) host = "*";

  fprintf(fd, "|g0|%s|%s|%s|%.*s\n", application, host, service, pubkey.size, pubkey.data);

  ret = 0;

cleanup:
  gnutls_free(pubkey.data);
  if (fd != NULL) fclose(fd);
  
  return ret;
}

#define CONFIG_FILE "known_hosts"

static int find_config_file(char* file, size_t max_size)
{
char path[MAX_FILENAME];
int ret;

  ret = _gnutls_find_config_path(path, sizeof(path));
  if (ret < 0)
    return gnutls_assert_val(ret);

  if (path[0] == 0)
    snprintf(file, max_size, "%s", CONFIG_FILE);
  else
    snprintf(file, max_size, "%s/%s", path, CONFIG_FILE);
      
  return 0;
}
