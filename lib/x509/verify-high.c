/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include "verify-high.h"

struct named_cert_st {
  gnutls_x509_crt_t cert;
  uint8_t name[MAX_NAME_SIZE];
  unsigned int name_size;
};

struct node_st {
  /* The trusted certificates */
  gnutls_x509_crt_t *trusted_cas;
  unsigned int trusted_ca_size;

  struct named_cert_st *named_certs;
  unsigned int named_cert_size;

  /* The trusted CRLs */
  gnutls_x509_crl_t *crls;
  unsigned int crl_size;
};

struct gnutls_x509_trust_list_st {
  int size;
  struct node_st *node;
};

#define INIT_HASH 0x33a1
#define DEFAULT_SIZE 503

/**
 * gnutls_x509_trust_list_init:
 * @list: The structure to be initialized
 * @size: The size of the internal hash table. Use (0) for default size.
 *
 * This function will initialize an X.509 trust list structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_x509_trust_list_init(gnutls_x509_trust_list_t * list,
                            unsigned int size)
{
    gnutls_x509_trust_list_t tmp =
        gnutls_calloc(1, sizeof(struct gnutls_x509_trust_list_st));

    if (!tmp)
        return GNUTLS_E_MEMORY_ERROR;

    if (size == 0)
        size = DEFAULT_SIZE;
    tmp->size = size;

    tmp->node = gnutls_calloc(1, tmp->size * sizeof(tmp->node[0]));
    if (tmp->node == NULL) {
        gnutls_assert();
        gnutls_free(tmp);
        return GNUTLS_E_MEMORY_ERROR;
    }

    *list = tmp;

    return 0;                   /* success */
}

/**
 * gnutls_x509_trust_list_deinit:
 * @list: The structure to be deinitialized
 * @all: if non-(0) it will deinitialize all the certificates and CRLs contained in the structure.
 *
 * This function will deinitialize a trust list.
 *
 * Since: 3.0.0
 **/
void
gnutls_x509_trust_list_deinit(gnutls_x509_trust_list_t list,
                              unsigned int all)
{
    int i, j;

    if (!list)
        return;

    for (i = 0; i < list->size; i++) {
        if (all)
            for (j = 0; j < list->node[i].trusted_ca_size; j++) {
                gnutls_x509_crt_deinit(list->node[i].trusted_cas[j]);
            }
        gnutls_free(list->node[i].trusted_cas);

        if (all)
            for (j = 0; j < list->node[i].crl_size; j++) {
                gnutls_x509_crl_deinit(list->node[i].crls[j]);
            }
        gnutls_free(list->node[i].crls);
        gnutls_free(list->node[i].named_certs);
    }

    gnutls_free(list->node);
    gnutls_free(list);
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
 * Since: 3.0.0
 **/
int
gnutls_x509_trust_list_add_cas(gnutls_x509_trust_list_t list,
                               const gnutls_x509_crt_t * clist,
                               int clist_size, unsigned int flags)
{
    gnutls_datum_t dn;
    int ret, i;
    uint32_t hash;

    for (i = 0; i < clist_size; i++) {
        ret = gnutls_x509_crt_get_raw_dn(clist[i], &dn);
        if (ret < 0) {
            gnutls_assert();
            return i;
        }

        hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
        hash %= list->size;

        _gnutls_free_datum(&dn);
        list->node[hash].trusted_cas =
            gnutls_realloc_fast(list->node[hash].trusted_cas,
                                (list->node[hash].trusted_ca_size +
                                 1) *
                                sizeof(list->node[hash].trusted_cas[0]));
        if (list->node[hash].trusted_cas == NULL) {
            gnutls_assert();
            return i;
        }

        list->node[hash].trusted_cas[list->node[hash].trusted_ca_size] =
            clist[i];
        list->node[hash].trusted_ca_size++;
    }

    return i;
}

/**
 * gnutls_x509_trust_list_add_named_crt:
 * @list: The structure of the list
 * @cert: A certificate
 * @name: An identifier for the certificate
 * @name_size: The size of the identifier
 * @flags: should be 0.
 *
 * This function will add the given certificate to the trusted
 * list and associate it with a name. The certificate will not be
 * be used for verification with gnutls_x509_trust_list_verify_crt()
 * but only with gnutls_x509_trust_list_verify_named_crt().
 *
 * In principle this function can be used to set individual "server"
 * certificates that are trusted by the user for that specific server
 * but for no other purposes.
 *
 * The certificate must not be deinitialized during the lifetime
 * of the trusted list.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_x509_trust_list_add_named_crt(gnutls_x509_trust_list_t list,
                                     gnutls_x509_crt_t cert,
                                     const void *name, size_t name_size,
                                     unsigned int flags)
{
    gnutls_datum_t dn;
    int ret;
    uint32_t hash;

    if (name_size >= MAX_NAME_SIZE)
        return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

    ret = gnutls_x509_crt_get_raw_issuer_dn(cert, &dn);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
    hash %= list->size;

    _gnutls_free_datum(&dn);

    list->node[hash].named_certs =
        gnutls_realloc_fast(list->node[hash].named_certs,
                            (list->node[hash].named_cert_size +
                             1) * sizeof(list->node[hash].named_certs[0]));
    if (list->node[hash].named_certs == NULL)
        return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

    list->node[hash].named_certs[list->node[hash].named_cert_size].cert =
        cert;
    memcpy(list->node[hash].named_certs[list->node[hash].named_cert_size].
           name, name, name_size);
    list->node[hash].named_certs[list->node[hash].named_cert_size].
        name_size = name_size;

    list->node[hash].named_cert_size++;

    return 0;
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
 * Since: 3.0.0
 **/
int
gnutls_x509_trust_list_add_crls(gnutls_x509_trust_list_t list,
                                const gnutls_x509_crl_t * crl_list,
                                int crl_size, unsigned int flags,
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

    for (i = 0; i < crl_size; i++) {
        ret = gnutls_x509_crl_get_raw_issuer_dn(crl_list[i], &dn);
        if (ret < 0) {
            gnutls_assert();
            return i;
        }

        hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
        hash %= list->size;

        _gnutls_free_datum(&dn);

        if (flags & GNUTLS_TL_VERIFY_CRL) {

            ret =
                gnutls_x509_crl_verify(crl_list[i],
                                       list->node[hash].trusted_cas,
                                       list->node[hash].trusted_ca_size,
                                       verification_flags, &vret);
            if (ret < 0 || vret != 0)
                continue;
        }

        list->node[hash].crls =
            gnutls_realloc_fast(list->node[hash].crls,
                                (list->node[hash].crl_size +
                                 1) *
                                sizeof(list->node[hash].trusted_cas[0]));
        if (list->node[hash].crls == NULL) {
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
                         gnutls_x509_crt_t * certificate_list,
                         int clist_size)
{
    int i, ret;
    uint32_t hash;
    gnutls_datum_t dn;

    if (clist_size > 1) {
        /* Check if the last certificate in the path is self signed.
         * In that case ignore it (a certificate is trusted only if it
         * leads to a trusted party by us, not the server's).
         *
         * This prevents from verifying self signed certificates against
         * themselves. This (although not bad) caused verification
         * failures on some root self signed certificates that use the
         * MD2 algorithm.
         */
        if (gnutls_x509_crt_check_issuer(certificate_list[clist_size - 1],
                                         certificate_list[clist_size -
                                                          1]) > 0) {
            clist_size--;
        }
    }

    /* We want to shorten the chain by removing the cert that matches
     * one of the certs we trust and all the certs after that i.e. if
     * cert chain is A signed-by B signed-by C signed-by D (signed-by
     * self-signed E but already removed above), and we trust B, remove
     * B, C and D. */
    for (i = 1; i < clist_size; i++) {
        int j;

        ret = gnutls_x509_crt_get_raw_issuer_dn(certificate_list[i], &dn);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }

        hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
        hash %= list->size;

        _gnutls_free_datum(&dn);

        for (j = 0; j < list->node[hash].trusted_ca_size; j++) {
            if (check_if_same_cert
                (certificate_list[i],
                 list->node[hash].trusted_cas[j]) == 0) {
                /* cut the list at the point of first the trusted certificate */
                clist_size = i + 1;
                break;
            }
        }
        /* clist_size may have been changed which gets out of loop */
    }

    return clist_size;
}

/**
 * gnutls_x509_trust_list_get_issuer:
 * @list: The structure of the list
 * @cert: is the certificate to find issuer for
 * @issuer: Will hold the issuer if any. Should be treated as constant.
 * @flags: Use (0).
 *
 * This function will attempt to find the issuer of the
 * given certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int gnutls_x509_trust_list_get_issuer(gnutls_x509_trust_list_t list,
                                      gnutls_x509_crt_t cert,
                                      gnutls_x509_crt_t * issuer,
                                      unsigned int flags)
{
    gnutls_datum_t dn;
    int ret, i;
    uint32_t hash;

    ret = gnutls_x509_crt_get_raw_issuer_dn(cert, &dn);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
    hash %= list->size;

    _gnutls_free_datum(&dn);

    for (i = 0; i < list->node[hash].trusted_ca_size; i++) {
        ret =
            gnutls_x509_crt_check_issuer(cert,
                                         list->node[hash].trusted_cas[i]);
        if (ret > 0) {
            *issuer = list->node[hash].trusted_cas[i];
            return 0;
        }
    }

    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
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
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_x509_trust_list_verify_crt(gnutls_x509_trust_list_t list,
                                  gnutls_x509_crt_t * cert_list,
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

    ret =
        gnutls_x509_crt_get_raw_issuer_dn(cert_list[cert_list_size - 1],
                                          &dn);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
    hash %= list->size;

    _gnutls_free_datum(&dn);

    *verify = _gnutls_x509_verify_certificate(cert_list, cert_list_size,
                                              list->node[hash].trusted_cas,
                                              list->node[hash].
                                              trusted_ca_size, flags,
                                              func);

    if (*verify != 0 || (flags & GNUTLS_VERIFY_DISABLE_CRL_CHECKS))
        return 0;

    /* Check revocation of individual certificates.
     * start with the last one that we already have its hash
     */
    ret = _gnutls_x509_crt_check_revocation(cert_list[cert_list_size - 1],
                                            list->node[hash].crls,
                                            list->node[hash].crl_size,
                                            func);
    if (ret == 1) {             /* revoked */
        *verify |= GNUTLS_CERT_REVOKED;
        *verify |= GNUTLS_CERT_INVALID;
        return 0;
    }

    for (i = 0; i < cert_list_size - 1; i++) {
        ret = gnutls_x509_crt_get_raw_issuer_dn(cert_list[i], &dn);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }

        hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
        hash %= list->size;

        _gnutls_free_datum(&dn);

        ret = _gnutls_x509_crt_check_revocation(cert_list[i],
                                                list->node[hash].crls,
                                                list->node[hash].crl_size,
                                                func);
        if (ret == 1) {         /* revoked */
            *verify |= GNUTLS_CERT_REVOKED;
            *verify |= GNUTLS_CERT_INVALID;
            return 0;
        }
    }

    return 0;
}

/**
 * gnutls_x509_trust_list_verify_named_crt:
 * @list: The structure of the list
 * @cert: is the certificate to be verified
 * @name: is the certificate's name
 * @name_size: is the certificate's name size
 * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
 * @verify: will hold the certificate verification output.
 * @func: If non-null will be called on each chain element verification with the output.
 *
 * This function will try to find a matching named certificate. If a
 * match is found the certificate is considered valid. In addition to that
 * this function will also check CRLs.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0.0
 **/
int
gnutls_x509_trust_list_verify_named_crt(gnutls_x509_trust_list_t list,
                                        gnutls_x509_crt_t cert,
                                        const void *name,
                                        size_t name_size,
                                        unsigned int flags,
                                        unsigned int *verify,
                                        gnutls_verify_output_function func)
{
    gnutls_datum_t dn;
    int ret, i;
    uint32_t hash;

    ret = gnutls_x509_crt_get_raw_issuer_dn(cert, &dn);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
    hash %= list->size;

    _gnutls_free_datum(&dn);

    *verify = GNUTLS_CERT_INVALID;

    for (i = 0; i < list->node[hash].named_cert_size; i++) {
        if (check_if_same_cert(cert, list->node[hash].named_certs[i].cert) == 0) {      /* check if name matches */
            if (list->node[hash].named_certs[i].name_size == name_size &&
                memcmp(list->node[hash].named_certs[i].name, name,
                       name_size) == 0) {
                *verify = 0;
                break;
            }
        }
    }

    if (*verify != 0 || (flags & GNUTLS_VERIFY_DISABLE_CRL_CHECKS))
        return 0;

    /* Check revocation of individual certificates.
     * start with the last one that we already have its hash
     */
    ret = _gnutls_x509_crt_check_revocation(cert,
                                            list->node[hash].crls,
                                            list->node[hash].crl_size,
                                            func);
    if (ret == 1) {             /* revoked */
        *verify |= GNUTLS_CERT_REVOKED;
        *verify |= GNUTLS_CERT_INVALID;
        return 0;
    }

    return 0;
}

int
_gnutls_trustlist_inlist_p (gnutls_x509_trust_list_t list,
			    gnutls_x509_crt_t cert)
{
  gnutls_datum_t dn;
  int ret, i;
  uint32_t hash;

  ret = gnutls_x509_crt_get_raw_dn (cert, &dn);
  if (ret < 0)
    {
      gnutls_assert();
      return ret;
    }

  hash = _gnutls_bhash(dn.data, dn.size, INIT_HASH);
  hash %= list->size;

  _gnutls_free_datum (&dn);

  for (i = 0; i < list->node[hash].trusted_ca_size; i++)
    {
      ret = check_if_same_cert (cert, list->node[hash].trusted_cas[i]);
      if (ret < 0)
	{
	  gnutls_assert ();
	  return ret;
	}

      if (ret == 1)
	return 1;
    }

  return 0;
}
