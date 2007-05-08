/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS-PKCS11.
 *
 * GNUTLS-PKCS11 is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * GNUTLS-PKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS-PKCS11; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include <gnutls/pkcs11.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "auth_cert.h"

#include "cryptoki.h"

/* The logic of PKCS#11 support in GnuTLS is as follows, for the
 * gnutls_pkcs11_get_ca_certificates() function.  Enable debug logging
 * to trace the details.
 *
 * 1) Initialize the PKCS#11 provider. (startup_pkcs11())
 *
 * 2) Iterate through certificates, and if the certificate has the
 *    CKA_TRUSTED flag, treat the certificate as a trusted CA
 *    certificate.  (search_certificates())
 *
 * The function gnutls_pkcs11_get_user_certificates will behave as
 * follows.
 *
 * 0) Initialize the PKCS#11 provider. (startup_pkcs11())
 *
 * 1) Enumerate the CKA_ID's of all private keys.  (find_keys())
 *
 * 2) Iterate through certificates, and if the certificate CKA_ID
 *    matches a private key CKA_ID, treat the certificate as a user
 *    certificate.  (search_certificates())
 */

static int
startup_pkcs11 (CK_ULONG *ulSlotCount, CK_SLOT_ID_PTR *pSlotList)
{
  CK_SLOT_INFO slotInfo;
  CK_ULONG i;
  CK_RV rv;
  CK_TOKEN_INFO tokenInfo;

  rv = C_Initialize (NULL);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      return GNUTLS_E_PKCS11_ERROR;
    }

  rv = C_GetSlotList(FALSE, NULL, ulSlotCount);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      return GNUTLS_E_PKCS11_ERROR;
    }

  _gnutls_debug_log("PKCS#11 slot count %d\n", *ulSlotCount);

  *pSlotList = gnutls_malloc(*ulSlotCount * sizeof(CK_SLOT_ID));
  if (!*pSlotList)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  rv = C_GetSlotList(FALSE, *pSlotList, ulSlotCount);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      gnutls_free (*pSlotList);
      return GNUTLS_E_PKCS11_ERROR;
    }

  for (i = 0; i < *ulSlotCount; i++)
    {
      rv = C_GetSlotInfo((*pSlotList)[i], &slotInfo);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  gnutls_free (*pSlotList);
	  return GNUTLS_E_PKCS11_ERROR;
	}

      _gnutls_debug_log("PKCS#11 slot[%d].description: `%s'\n",
			(*pSlotList)[i], slotInfo.slotDescription);
      _gnutls_debug_log("PKCS#11 slot[%d].manufacturer: `%s'\n",
			(*pSlotList)[i], slotInfo.manufacturerID);

      rv = C_GetTokenInfo((*pSlotList)[i], &tokenInfo);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  gnutls_free (*pSlotList);
	  return GNUTLS_E_PKCS11_ERROR;
	}

      _gnutls_debug_log("PKCS#11 slot[%d].token.label: `%s'\n",
			(*pSlotList)[i], tokenInfo.label);
    }

  return 0;
}

/* Used to determine the names of the private keys to use.  *keys is
   allocated as a zero-terminated array of zero-terminated strings
   indicating the private key CKA_ID's. */
static int
find_keys (char ***keys,
	   CK_ULONG ulSlotCount,
	   CK_SLOT_ID_PTR pSlotList)
{
  CK_SESSION_HANDLE shSession;
  CK_RV rv;
  CK_ULONG i;
  size_t nkeys = 0;

  *keys = gnutls_calloc (sizeof (*keys), 1);
  if (!*keys)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  for (i = 0; i < ulSlotCount; i++)
    {
      rv = C_OpenSession (pSlotList[i], CKF_SERIAL_SESSION,
			  NULL, NULL, &shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}

      rv = C_FindObjectsInit(shSession, NULL, 0);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}

      while (1)
	{
	  CK_ULONG ulNumFound = 0;
	  CK_ATTRIBUTE pValueTemplate[1];
	  CK_OBJECT_CLASS ocClass;
	  CK_OBJECT_HANDLE ohObject;

	  rv = C_FindObjects(shSession, &ohObject, 1, &ulNumFound);
	  if (rv != CKR_OK)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_PKCS11_ERROR;
	    }

	  if (ulNumFound == 0)
	    break;

	  pValueTemplate[0].type = CKA_CLASS;
	  pValueTemplate[0].pValue = &ocClass;
	  pValueTemplate[0].ulValueLen = sizeof(ocClass);

	  rv = C_GetAttributeValue(shSession, ohObject, pValueTemplate, 1);
	  if (rv != CKR_OK)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_PKCS11_ERROR;
	    }

	  if (ocClass == CKO_PRIVATE_KEY)
	    {
	      char **tmp;

	      pValueTemplate[0].type = CKA_ID;
	      pValueTemplate[0].pValue = NULL;
	      pValueTemplate[0].ulValueLen = 0;

	      rv = C_GetAttributeValue(shSession, ohObject,
				       pValueTemplate, 1);
	      if (rv != CKR_OK)
		{
		  gnutls_assert ();
		  return GNUTLS_E_PKCS11_ERROR;
		}

	      pValueTemplate[0].pValue =
		gnutls_calloc (1, pValueTemplate[0].ulValueLen + 1);
	      if (!pValueTemplate[0].pValue)
		{
		  gnutls_assert ();
		  return GNUTLS_E_MEMORY_ERROR;
		}

	      rv = C_GetAttributeValue(shSession, ohObject,
				       pValueTemplate, 1);
	      if (rv != CKR_OK)
		{
		  gnutls_assert ();
		  gnutls_free (pValueTemplate[0].pValue);
		  return GNUTLS_E_PKCS11_ERROR;
		}

	      tmp = gnutls_realloc (*keys, (nkeys + 2) * sizeof (**keys));
	      if (!tmp)
		{
		  gnutls_assert ();
		  return GNUTLS_E_MEMORY_ERROR;
		}
	      *keys = tmp;
	      (*keys)[nkeys] = pValueTemplate[0].pValue;
	      nkeys++;
	      (*keys)[nkeys] = NULL;

	      _gnutls_debug_log("Added private key %s from slot %d\n",
				pValueTemplate[0].pValue, pSlotList[i]);
	    }
	}

      rv = C_FindObjectsFinal(shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}

      rv = C_CloseSession(shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}
    }

  return 0;
}

static int
have_key (char *const*keys, const char *key)
{
  char *const*p;
  for (p = keys; *p; p++)
    if (strcmp (*p, key) == 0)
      return 1;
  return 0;
}

/* Add certificates appropriately.  */
static int
search_certificates (char *const *pkcs11_keys,
		     CK_ULONG ulSlotCount,
		     CK_SLOT_ID_PTR pSlotList,
		     gnutls_x509_crt_t ** cert_list,
		     unsigned int *ncerts)
{
  CK_SESSION_HANDLE shSession;
  CK_RV rv;
  CK_ULONG i;

  *cert_list = NULL;
  *ncerts = 0;

  for (i = 0; i < ulSlotCount; i++)
    {
      rv = C_OpenSession (pSlotList[i], CKF_SERIAL_SESSION,
			  NULL, NULL, &shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}

      rv = C_FindObjectsInit(shSession, NULL, 0);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}

      while (1)
	{
	  CK_ULONG ulNumFound = 0;
	  CK_ATTRIBUTE pValueTemplate[1];
	  CK_OBJECT_CLASS ocClass;
	  CK_OBJECT_HANDLE ohObject;

	  rv = C_FindObjects(shSession, &ohObject, 1, &ulNumFound);
	  if (rv != CKR_OK)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_PKCS11_ERROR;
	    }

	  if (ulNumFound == 0)
	    break;

	  pValueTemplate[0].type = CKA_CLASS;
	  pValueTemplate[0].pValue = &ocClass;
	  pValueTemplate[0].ulValueLen = sizeof(ocClass);

	  rv = C_GetAttributeValue(shSession, ohObject, pValueTemplate, 1);
	  if (rv != CKR_OK)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_PKCS11_ERROR;
	    }

	  if (ocClass == CKO_CERTIFICATE)
	    {
	      CK_ATTRIBUTE pValueTemplate[4];
	      CK_BBOOL trusted;
	      CK_ULONG cat;

	      pValueTemplate[0].type = CKA_ID;
	      pValueTemplate[0].pValue = NULL;
	      pValueTemplate[0].ulValueLen = 0;

	      pValueTemplate[1].type = CKA_VALUE;
	      pValueTemplate[1].pValue = NULL;
	      pValueTemplate[1].ulValueLen = 0;

	      pValueTemplate[2].type = CKA_CERTIFICATE_CATEGORY;
	      pValueTemplate[2].pValue = &cat;
	      pValueTemplate[2].ulValueLen = sizeof(cat);

	      pValueTemplate[3].type = CKA_TRUSTED;
	      pValueTemplate[3].pValue = &trusted;
	      pValueTemplate[3].ulValueLen = sizeof(trusted);

	      rv = C_GetAttributeValue(shSession, ohObject,
				       pValueTemplate, 4);
	      if (rv != CKR_OK)
		{
		  gnutls_assert ();
		  return GNUTLS_E_PKCS11_ERROR;
		}

	      pValueTemplate[0].pValue =
		gnutls_calloc (1, pValueTemplate[0].ulValueLen + 1);
	      if (!pValueTemplate[0].pValue)
		{
		  gnutls_assert ();
		  return GNUTLS_E_MEMORY_ERROR;
		}

	      pValueTemplate[1].pValue =
		gnutls_malloc (pValueTemplate[1].ulValueLen);
	      if (!pValueTemplate[1].pValue)
		{
		  gnutls_free (pValueTemplate[0].pValue);
		  gnutls_assert ();
		  return GNUTLS_E_MEMORY_ERROR;
		}

	      rv = C_GetAttributeValue(shSession, ohObject,
				       pValueTemplate, 4);
	      if (rv != CKR_OK)
		{
		  gnutls_assert ();
		  gnutls_free (pValueTemplate[0].pValue);
		  gnutls_free (pValueTemplate[1].pValue);
		  return GNUTLS_E_PKCS11_ERROR;
		}

	      {
		int ret;
		const gnutls_datum_t cert =
		  { pValueTemplate[1].pValue, pValueTemplate[1].ulValueLen };
		gnutls_x509_crt_t * tmplist;

		if (!pkcs11_keys && trusted)
		  {
		    _gnutls_debug_log("Adding CA certificate %s (%ld)\n",
				      pValueTemplate[0].pValue, cat);
		  }
		else if (pkcs11_keys
			 && have_key (pkcs11_keys, pValueTemplate[0].pValue))
		  {
		    _gnutls_debug_log("Adding user certificate %s\n",
				      pValueTemplate[0].pValue);
		  }
		else
		  {
		    _gnutls_debug_log("Skipping certificate %s (%d/%ld)\n",
				      pValueTemplate[0].pValue, trusted, cat);
		    gnutls_free (pValueTemplate[0].pValue);
		    gnutls_free (pValueTemplate[1].pValue);
		    continue;
		  }

		gnutls_free (pValueTemplate[0].pValue);

		tmplist = gnutls_realloc (*cert_list, sizeof (**cert_list)
					  * (*ncerts + 1));
		if (!tmplist)
		  {
		    gnutls_assert ();
		    gnutls_free (pValueTemplate[1].pValue);
		    return GNUTLS_E_MEMORY_ERROR;
		  }
		*cert_list = tmplist;

		ret = gnutls_x509_crt_init (&(*cert_list)[*ncerts]);
		if (ret != GNUTLS_E_SUCCESS)
		  {
		    gnutls_assert ();
		    gnutls_free (*cert_list);
		    gnutls_free (pValueTemplate[1].pValue);
		    return ret;
		  }

		ret = gnutls_x509_crt_import ((*cert_list)[*ncerts],
					      &cert, GNUTLS_X509_FMT_DER);
		if (ret != GNUTLS_E_SUCCESS)
		  {
		    gnutls_assert ();
		    gnutls_free (*cert_list);
		    gnutls_free (pValueTemplate[1].pValue);
		    return ret;
		  }

		gnutls_free (pValueTemplate[1].pValue);

		(*ncerts)++;
	      }
	    }
	}

      rv = C_FindObjectsFinal(shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}

      rv = C_CloseSession(shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}
    }

  return 0;
}

static int
get_certificates (gnutls_x509_crt_t ** cert_list,
		  unsigned int *ncerts,
		  int user_certs)
{
  CK_ULONG ulSlotCount = 0;
  CK_SLOT_ID_PTR pSlotList;
  CK_RV rv;
  int ret;
  char **pkcs11_keys = NULL;
  size_t i;

  ret = startup_pkcs11 (&ulSlotCount, &pSlotList);
  if (ret < 0)
    return ret;

  if (user_certs)
    {
      ret = find_keys (&pkcs11_keys, ulSlotCount, pSlotList);
      if (ret < 0)
	goto out;
    }

  ret = search_certificates (pkcs11_keys, ulSlotCount, pSlotList,
			     cert_list, ncerts);
  if (ret < 0)
    goto out;

  ret = 0;

 out:
  rv = C_Finalize (NULL_PTR);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      ret = GNUTLS_E_PKCS11_ERROR;
    }
  if (pkcs11_keys)
    {
      for (i = 0; pkcs11_keys[i]; i++)
	gnutls_free (pkcs11_keys[i]);
      gnutls_free (pkcs11_keys);
    }
  gnutls_free (pSlotList);
  return ret;
}

/**
 * gnutls_pkcs11_get_ca_certificates:
 * @cert_list: pointer to output variable containing newly allocated
 *   array of certificates.
 * @ncerts: pointer to output variable indicating size of array.
 *
 * Get a list of X.509 certificates from the PKCS#11 provider which
 * are marked as CKA_TRUSTED.  Each certificate must be deallocated,
 * by the caller, using gnutls_x509_crt_deinit(), and the array itself
 * must be deallocated using gnutls_free().
 *
 * Returns: Returns %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
gnutls_pkcs11_get_ca_certificates (gnutls_x509_crt_t ** cert_list,
				   unsigned int *ncerts)
{
  return get_certificates (cert_list, ncerts, 0);
}

int
gnutls_pkcs11_get_user_certificates (gnutls_x509_crt_t ** cert_list,
				     unsigned int *ncerts)
{
  return get_certificates (cert_list, ncerts, 1);
}

/* Sign. */
static int
sign (CK_ULONG ulSlotCount,
      CK_SLOT_ID_PTR pSlotList,
      const gnutls_datum_t * hash,
      gnutls_datum_t * signature)

{
  CK_SESSION_HANDLE shSession;
  CK_RV rv;
  CK_ULONG i;

  for (i = 0; i < ulSlotCount; i++)
    {
      rv = C_OpenSession (pSlotList[i], CKF_SERIAL_SESSION,
			  NULL, NULL, &shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}

      rv = C_FindObjectsInit(shSession, NULL, 0);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}

      while (1)
	{
	  CK_ULONG ulNumFound = 0;
	  CK_ATTRIBUTE pValueTemplate[1];
	  CK_OBJECT_CLASS ocClass;
	  CK_OBJECT_HANDLE ohObject;

	  rv = C_FindObjects(shSession, &ohObject, 1, &ulNumFound);
	  if (rv != CKR_OK)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_PKCS11_ERROR;
	    }

	  if (ulNumFound == 0)
	    break;

	  pValueTemplate[0].type = CKA_CLASS;
	  pValueTemplate[0].pValue = &ocClass;
	  pValueTemplate[0].ulValueLen = sizeof(ocClass);

	  rv = C_GetAttributeValue(shSession, ohObject, pValueTemplate, 1);
	  if (rv != CKR_OK)
	    {
	      gnutls_assert ();
	      return GNUTLS_E_PKCS11_ERROR;
	    }

	  if (ocClass == CKO_PRIVATE_KEY)
	    {
	      CK_MECHANISM mech;
	      unsigned long len;

	      mech.mechanism = CKM_RSA_PKCS;
	      mech.pParameter = NULL;
	      mech.ulParameterLen = 0;

	      rv = C_SignInit (shSession, &mech, ohObject);
	      if (rv != CKR_OK)
		{
		  gnutls_assert ();
		  return GNUTLS_E_PKCS11_ERROR;
		}

	      len = 0;
	      rv = C_Sign (shSession, hash->data, hash->size, NULL, &len);
	      if (rv != CKR_OK)
		{
		  gnutls_assert ();
		  return GNUTLS_E_PKCS11_ERROR;
		}

	      signature->size = len;
	      signature->data = gnutls_malloc (len);
	      if (!signature->data)
		{
		  gnutls_assert ();
		  return GNUTLS_E_MEMORY_ERROR;
		}

	      rv = C_Sign (shSession, hash->data, hash->size,
			   signature->data, &len);
	      if (rv != CKR_OK)
		{
		  gnutls_assert ();
		  gnutls_free (signature->data);
		  return GNUTLS_E_PKCS11_ERROR;
		}
	    }
	}

      rv = C_FindObjectsFinal(shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	}

      rv = C_CloseSession(shSession);
      if (rv != CKR_OK)
	{
	  gnutls_assert ();
	  return GNUTLS_E_PKCS11_ERROR;
	}
    }

  return 0;
}

int
gnutls_pkcs11_sign (gnutls_datum_t * cert,
		    const gnutls_datum_t * hash,
		    gnutls_datum_t * signature)

{
  CK_ULONG ulSlotCount = 0;
  CK_SLOT_ID_PTR pSlotList;
  CK_RV rv;
  int ret;
  size_t i;

  ret = startup_pkcs11 (&ulSlotCount, &pSlotList);
  if (ret < 0)
    return ret;

  ret = sign (ulSlotCount, pSlotList, hash, signature);
  if (ret < 0)
    goto out;

  ret = 0;

 out:
  rv = C_Finalize (NULL_PTR);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      ret = GNUTLS_E_PKCS11_ERROR;
    }
  gnutls_free (pSlotList);
  return ret;

}
