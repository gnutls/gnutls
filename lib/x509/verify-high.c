/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
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

#define DEFAULT_SIZE 503
#define INIT_HASH 0x33a1
struct node_st {
  /* The trusted certificates */
  gnutls_x509_crt_t * trusted_crts;
  unsigned int trusted_crt_size;

  /* The trusted CRLs */
  gnutls_x509_crl_t * crls;
  unsigned int crl_size;
};

struct gnutls_x509_trust_list_st {
  int size;
  struct node_st *node;
};

/**
 * gnutls_x509_trust_list_init:
 * @list: The structure to be initialized
 * @size: The size of the internal hash table. Use zero for default size.
 *
 * This function will initialize an X.509 trust list structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_trust_list_init (gnutls_x509_trust_list_t * list, unsigned int size)
{
  gnutls_x509_trust_list_t tmp = gnutls_calloc (1, sizeof (struct gnutls_x509_trust_list_st));

  if (!tmp)
    return GNUTLS_E_MEMORY_ERROR;

  if (size == 0) size = DEFAULT_SIZE;
  tmp->size = size;
  
  tmp->node = gnutls_calloc(1, tmp->size * sizeof(tmp->node[0]));
  if (tmp->node == NULL)
    {
      gnutls_assert();
      gnutls_free(tmp);
      return GNUTLS_E_MEMORY_ERROR;
    }

  *list = tmp;

  return 0;                     /* success */
}

/**
 * gnutls_x509_trust_list_deinit:
 * @list: The structure to be deinitialized
 * @all: if non-zero it will deinitialize all the certificates and CRLs contained in the structure.
 *
 * This function will deinitialize a trust list.
 **/
void
gnutls_x509_trust_list_deinit (gnutls_x509_trust_list_t list, unsigned int all)
{
int i, j;

  if (!list)
    return;

  if (all)
    {
      for (i=0;i<list->size;i++)
        {
          for (j=0;j<list->node[i].trusted_crt_size;j++)
            {
              gnutls_x509_crt_deinit(list->node[i].trusted_crts[j]);
            }
          gnutls_free(list->node[i].trusted_crts);
          for (j=0;j<list->node[i].crl_size;j++)
            {
              gnutls_x509_crl_deinit(list->node[i].crls[j]);
            }
          gnutls_free(list->node[i].crls);
        }
    }

  gnutls_free (list->node);
  gnutls_free (list);
}

/**
 * gnutls_x509_trust_list_add_cas:
 * @list: The structure of the list
 * @clist: A list of CAs
 * @clist_size: The length of the CA list
 * @flags: should be 0.
 *
 * This function will add the given certificate authorities
 * to the trusted list. The list of CAs must not be deinitialized
 * during this structure's lifetime.
 *
 * Returns: The number of added elements is returned.
 *
 **/
int
gnutls_x509_trust_list_add_cas (gnutls_x509_trust_list_t list, 
  const gnutls_x509_crt_t * clist, int clist_size, unsigned int flags)
{
gnutls_datum_t dn;
int ret, i;
uint32_t hash;

  for (i=0;i<clist_size;i++)
    {
        ret = gnutls_x509_crt_get_raw_dn(clist[i], &dn);
        if (ret < 0)
          {
            gnutls_assert();
            return i;
          }

        hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
        hash %= list->size;

        list->node[hash].trusted_crts = gnutls_realloc_fast( list->node[hash].trusted_crts, (list->node[hash].trusted_crt_size+1)*sizeof(list->node[hash].trusted_crts[0]));
        if (list->node[hash].trusted_crts == NULL)
          {
            gnutls_assert();
            return i;
          }

        list->node[hash].trusted_crts[list->node[hash].trusted_crt_size] = clist[i];
        list->node[hash].trusted_crt_size++;

        _gnutls_free_datum(&dn);
    }

  return i;
}

/**
 * gnutls_x509_trust_list_add_crls:
 * @list: The structure of the list
 * @crl_list: A list of CRLs
 * @crl_size: The length of the CRL list
 * @flags: if GNUTLS_TL_VERIFY_CRL is given the CRLs will be verified before being added.
 * @verification_flags: gnutls_certificate_verify_flags if flags specifies GNUTLS_TL_VERIFY_CRL
 *
 * This function will add the given certificate revocation lists
 * to the trusted list. The list of CRLs must not be deinitialized
 * during this structure's lifetime.
 *
 * This function must be called after gnutls_x509_trust_list_add_cas()
 * to allow verifying the CRLs for validity.
 *
 * Returns: The number of added elements is returned.
 *
 **/

int
gnutls_x509_trust_list_add_crls (gnutls_x509_trust_list_t list, 
  const gnutls_x509_crl_t * crl_list, int crl_size, unsigned int flags,
  unsigned int verification_flags)
{
int ret, i, j = 0;
gnutls_datum_t dn;
unsigned int vret = 0;
uint32_t hash;

  /* Probably we can optimize things such as removing duplicates
   * etc.
   */

  if (crl_size == 0 || crl_list == NULL)
    return 0;

  for (i=0;i<crl_size;i++)
    {
        ret = gnutls_x509_crl_get_raw_issuer_dn(crl_list[i], &dn);
        if (ret < 0)
          {
            gnutls_assert();
            return i;
          }

        hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
        hash %= list->size;

        _gnutls_free_datum(&dn);

        if (flags & GNUTLS_TL_VERIFY_CRL)
          {

            ret = gnutls_x509_crl_verify(crl_list[i], list->node[hash].trusted_crts,
              list->node[hash].trusted_crt_size, verification_flags, &vret);
            if (ret < 0 || vret != 0)
              continue;
          }

        list->node[hash].crls = gnutls_realloc_fast( list->node[hash].crls, (list->node[hash].crl_size+1)*sizeof(list->node[hash].trusted_crts[0]));
        if (list->node[hash].crls == NULL)
          {
            gnutls_assert();
            return i;
          }

        list->node[hash].crls[list->node[hash].crl_size] = crl_list[i];
        list->node[hash].crl_size++;
        j++;
    }

  return j;
}

/* Takes a certificate list and shortens it if there are
 * intermedia certificates already trusted by us.
 *
 * FIXME: This is very similar to _gnutls_x509_verify_certificate().
 *
 * Returns the new size of the list or a negative number on error.
 */
static int shorten_clist(gnutls_x509_trust_list_t list,
  gnutls_x509_crt_t* certificate_list, int clist_size)
{
int i, ret;
uint32_t hash;
gnutls_datum_t dn;

  if (clist_size > 1)
    {
      /* Check if the last certificate in the path is self signed.
       * In that case ignore it (a certificate is trusted only if it
       * leads to a trusted party by us, not the server's).
       *
       * This prevents from verifying self signed certificates against
       * themselves. This (although not bad) caused verification
       * failures on some root self signed certificates that use the
       * MD2 algorithm.
       */
      if (gnutls_x509_crt_check_issuer (certificate_list[clist_size - 1],
                                        certificate_list[clist_size - 1]) > 0)
        {
          clist_size--;
        }
    }

  /* We want to shorten the chain by removing the cert that matches
   * one of the certs we trust and all the certs after that i.e. if
   * cert chain is A signed-by B signed-by C signed-by D (signed-by
   * self-signed E but already removed above), and we trust B, remove
   * B, C and D. */
  for (i=1; i < clist_size; i++)
    {
      int j;

      ret = gnutls_x509_crt_get_raw_issuer_dn(certificate_list[i], &dn);
      if (ret < 0)
        {
          gnutls_assert();
          return ret;
        }

      hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
      hash %= list->size;

      _gnutls_free_datum(&dn);

      for (j = 0; j < list->node[hash].trusted_crt_size; j++)
        {
          if (check_if_same_cert (certificate_list[i], list->node[hash].trusted_crts[j]) == 0)
            {
              /* cut the list at the point of first the trusted certificate */
              clist_size = i+1;
              break;
            }
        }
      /* clist_size may have been changed which gets out of loop */
    }

  return clist_size;
}


/**
 * gnutls_x509_trust_list_verify_crt:
 * @list: The structure of the list
 * @cert_list: is the certificate list to be verified
 * @cert_list_size: is the certificate list size
 * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
 * @verify: will hold the certificate verification output.
 * @func: If non-null will be called on each chain element verification with the output.
 *
 * This function will try to verify the given certificate and return
 * its status.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_trust_list_verify_crt (
  gnutls_x509_trust_list_t list,
  gnutls_x509_crt_t *cert_list,
  unsigned int cert_list_size,
  unsigned int flags,
  unsigned int *verify,
  gnutls_verify_output_function func)
{
gnutls_datum_t dn;
int ret, i;
uint32_t hash;

  if (cert_list == NULL || cert_list_size < 1)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  cert_list_size = shorten_clist(list, cert_list, cert_list_size);
  if (cert_list_size <= 0)
    return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

  ret = gnutls_x509_crt_get_raw_issuer_dn(cert_list[cert_list_size-1], &dn);
  if (ret < 0)
    {
      gnutls_assert();
      return ret;
    }

  hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
  hash %= list->size;

  _gnutls_free_datum(&dn);

  *verify = _gnutls_x509_verify_certificate(cert_list, cert_list_size, 
    list->node[hash].trusted_crts, list->node[hash].trusted_crt_size, 
    flags, func);

  if (*verify != 0) return 0;

  /* Check revocation of individual certificates.
   * start with the last one that we already have its hash
   */
  ret = _gnutls_x509_crt_check_revocation (cert_list[cert_list_size-1],
                                        list->node[hash].crls, 
                                        list->node[hash].crl_size, func);
  if (ret == 1)
    { /* revoked */
      *verify |= GNUTLS_CERT_REVOKED;
      *verify |= GNUTLS_CERT_INVALID;
      return 0;
    }

  for (i=0;i<cert_list_size-1;i++)
    {
      ret = gnutls_x509_crt_get_raw_issuer_dn(cert_list[i], &dn);
      if (ret < 0)
        {
          gnutls_assert();
          return ret;
        }

      hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
      hash %= list->size;

      _gnutls_free_datum(&dn);

      ret = _gnutls_x509_crt_check_revocation (cert_list[i],
                                            list->node[hash].crls, 
                                            list->node[hash].crl_size, func);
      if (ret == 1)
        { /* revoked */
          *verify |= GNUTLS_CERT_REVOKED;
          *verify |= GNUTLS_CERT_INVALID;
          return 0;
        }
    }

  return 0;
}
