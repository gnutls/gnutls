/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
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
#include <gnutls_num.h>
#include <gnutls_sig.h>
#include <gnutls_str.h>
#include <gnutls_datum.h>
#include "x509_int.h"
#include <common.h>
#include "verify-high.h"
#include "read-file.h"

/* Convenience functions for verify-high functionality 
 */

/**
 * gnutls_x509_trust_list_add_trust_mem:
 * @list: The structure of the list
 * @cas: A buffer containing a list of CAs (optional)
 * @crls: A buffer containing a list of CRLs (optional)
 * @type: The format of the certificates
 * @tl_flags: GNUTLS_TL_*
 * @tl_vflags: gnutls_certificate_verify_flags if flags specifies GNUTLS_TL_VERIFY_CRL
 *
 * This function will add the given certificate authorities
 * to the trusted list. 
 *
 * Returns: The number of added elements is returned.
 *
 * Since: 3.1
 **/
int
gnutls_x509_trust_list_add_trust_mem(gnutls_x509_trust_list_t list,
                                     const gnutls_datum_t * cas, 
                                     const gnutls_datum_t * crls,
                                     gnutls_x509_crt_fmt_t type,
                                     unsigned int tl_flags,
                                     unsigned int tl_vflags)
{
  int ret;
  gnutls_x509_crt_t *x509_ca_list = NULL;
  gnutls_x509_crl_t *x509_crl_list = NULL;
  unsigned int x509_ncas, x509_ncrls;
  unsigned int r = 0;
  
  if (cas != NULL && cas->data != NULL)
    {
      ret = gnutls_x509_crt_list_import2( &x509_ca_list, &x509_ncas, cas, type, 0);
      if (ret < 0)
        return gnutls_assert_val(ret);

      ret = gnutls_x509_trust_list_add_cas(list, x509_ca_list, x509_ncas, tl_flags);
      gnutls_free(x509_ca_list);

      if (ret < 0)
        return gnutls_assert_val(ret);
      else
        r += ret;
    }

  if (crls != NULL && crls->data != NULL)
    {
      ret = gnutls_x509_crl_list_import2( &x509_crl_list, &x509_ncrls, crls, type, 0);
      if (ret < 0)
        return gnutls_assert_val(ret);

      ret = gnutls_x509_trust_list_add_crls(list, x509_crl_list, x509_ncrls, tl_flags, tl_vflags);
      gnutls_free(x509_crl_list);

      if (ret < 0)
        return gnutls_assert_val(ret);
      else
        r += ret;
    }

  return r;
}

/**
 * gnutls_x509_trust_list_remove_trust_mem:
 * @list: The structure of the list
 * @cas: A buffer containing a list of CAs (optional)
 * @type: The format of the certificates
 *
 * This function will add the given certificate authorities
 * to the trusted list. 
 *
 * Returns: The number of added elements is returned.
 *
 * Since: 3.1.10
 **/
int
gnutls_x509_trust_list_remove_trust_mem(gnutls_x509_trust_list_t list,
                                     const gnutls_datum_t * cas, 
                                     gnutls_x509_crt_fmt_t type)
{
  int ret;
  gnutls_x509_crt_t *x509_ca_list = NULL;
  unsigned int x509_ncas;
  unsigned int r = 0, i;
  
  if (cas != NULL && cas->data != NULL)
    {
      ret = gnutls_x509_crt_list_import2( &x509_ca_list, &x509_ncas, cas, type, 0);
      if (ret < 0)
        return gnutls_assert_val(ret);

      ret = gnutls_x509_trust_list_remove_cas(list, x509_ca_list, x509_ncas);
      
      for (i=0;i<x509_ncas;i++)
        gnutls_x509_crt_deinit(x509_ca_list[i]);
      gnutls_free(x509_ca_list);

      if (ret < 0)
        return gnutls_assert_val(ret);
      else
        r += ret;
    }

  return r;
}

#ifdef ENABLE_PKCS11
static 
int import_pkcs11_url(gnutls_x509_trust_list_t list, const char* ca_file, unsigned int flags)
{
gnutls_x509_crt_t *xcrt_list = NULL;
gnutls_pkcs11_obj_t *pcrt_list = NULL;
unsigned int pcrt_list_size = 0, i;
int ret;
      
  ret = gnutls_pkcs11_obj_list_import_url2(&pcrt_list, &pcrt_list_size, ca_file, 
                                           GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED_CA, 0);
  if (ret < 0)
    return gnutls_assert_val(ret);
     
  if (pcrt_list_size == 0)
    {
      ret = 0;
      goto cleanup;
    }
      
  xcrt_list = gnutls_malloc(sizeof(gnutls_x509_crt_t)*pcrt_list_size);
  if (xcrt_list == NULL)
    {
      ret = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }
      
  ret = gnutls_x509_crt_list_import_pkcs11( xcrt_list, pcrt_list_size, pcrt_list, 0);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }
  
  ret = gnutls_x509_trust_list_add_cas(list, xcrt_list, pcrt_list_size, flags);
  
cleanup:
  for (i=0;i<pcrt_list_size;i++)
    gnutls_pkcs11_obj_deinit(pcrt_list[i]);
  gnutls_free(pcrt_list);
  gnutls_free(xcrt_list);

  return ret;
}

static 
int remove_pkcs11_url(gnutls_x509_trust_list_t list, const char* ca_file)
{
gnutls_x509_crt_t *xcrt_list = NULL;
gnutls_pkcs11_obj_t *pcrt_list = NULL;
unsigned int pcrt_list_size = 0, i;
int ret;
      
  ret = gnutls_pkcs11_obj_list_import_url2(&pcrt_list, &pcrt_list_size, ca_file, 
                                           GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED_CA, 0);
  if (ret < 0)
    return gnutls_assert_val(ret);
     
  if (pcrt_list_size == 0)
    {
      ret = 0;
      goto cleanup;
    }
      
  xcrt_list = gnutls_malloc(sizeof(gnutls_x509_crt_t)*pcrt_list_size);
  if (xcrt_list == NULL)
    {
      ret = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }
      
  ret = gnutls_x509_crt_list_import_pkcs11( xcrt_list, pcrt_list_size, pcrt_list, 0);
  if (ret < 0)
    {
      gnutls_assert();
      goto cleanup;
    }
  
  ret = gnutls_x509_trust_list_remove_cas(list, xcrt_list, pcrt_list_size);
  
cleanup:
  for (i=0;i<pcrt_list_size;i++)
    {
      gnutls_pkcs11_obj_deinit(pcrt_list[i]);
      gnutls_x509_crt_deinit(xcrt_list[i]);
    }
  gnutls_free(pcrt_list);
  gnutls_free(xcrt_list);

  return ret;
}
#endif


/**
 * gnutls_x509_trust_list_add_trust_file:
 * @list: The structure of the list
 * @ca_file: A file containing a list of CAs (optional)
 * @crl_file: A file containing a list of CRLs (optional)
 * @type: The format of the certificates
 * @tl_flags: GNUTLS_TL_*
 * @tl_vflags: gnutls_certificate_verify_flags if flags specifies GNUTLS_TL_VERIFY_CRL
 *
 * This function will add the given certificate authorities
 * to the trusted list. pkcs11 URLs are also accepted, instead
 * of files, by this function.
 *
 * Returns: The number of added elements is returned.
 *
 * Since: 3.1
 **/
int
gnutls_x509_trust_list_add_trust_file(gnutls_x509_trust_list_t list,
                                      const char* ca_file, 
                                      const char* crl_file,
                                      gnutls_x509_crt_fmt_t type,
                                      unsigned int tl_flags,
                                      unsigned int tl_vflags)
{
  gnutls_datum_t cas = { NULL, 0 };
  gnutls_datum_t crls = { NULL, 0 };
  size_t size;
  int ret;

#ifdef ENABLE_PKCS11
  if (strncmp (ca_file, "pkcs11:", 7) == 0)
    {
      ret = import_pkcs11_url(list, ca_file, tl_flags);
      if (ret < 0)
        return gnutls_assert_val(ret);
    }
  else
#endif
    {
      cas.data = (void*)read_binary_file (ca_file, &size);
      if (cas.data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_FILE_ERROR;
        }
      cas.size = size;
    }

  if (crl_file)
    {
      crls.data = (void*)read_binary_file (crl_file, &size);
      if (crls.data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_FILE_ERROR;
        }
      crls.size = size;
    }
  
  ret = gnutls_x509_trust_list_add_trust_mem(list, &cas, &crls, type, tl_flags, tl_vflags);
  free(crls.data);
  free(cas.data);

  return ret;
}

/**
 * gnutls_x509_trust_list_remove_trust_file:
 * @list: The structure of the list
 * @ca_file: A file containing a list of CAs
 * @type: The format of the certificates
 *
 * This function will add the given certificate authorities
 * to the trusted list. pkcs11 URLs are also accepted, instead
 * of files, by this function.
 *
 * Returns: The number of added elements is returned.
 *
 * Since: 3.1.10
 **/
int
gnutls_x509_trust_list_remove_trust_file(gnutls_x509_trust_list_t list,
                                      const char* ca_file, 
                                      gnutls_x509_crt_fmt_t type)
{
  gnutls_datum_t cas = { NULL, 0 };
  size_t size;
  int ret;

#ifdef ENABLE_PKCS11
  if (strncmp (ca_file, "pkcs11:", 7) == 0)
    {
      ret = remove_pkcs11_url(list, ca_file);
      if (ret < 0)
        return gnutls_assert_val(ret);
    }
  else
#endif
    {
      cas.data = (void*)read_binary_file (ca_file, &size);
      if (cas.data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_FILE_ERROR;
        }
      cas.size = size;
    }

  ret = gnutls_x509_trust_list_remove_trust_mem(list, &cas, type);
  free(cas.data);

  return ret;
}

