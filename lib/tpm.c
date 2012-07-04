/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2012 Free Software Foundation.
 * Copyright © 2008-2012 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 * Author: Nikos Mavrogiannopoulos
 *
 * GnuTLS is free software; you can redistribute it and/or
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

/*
 * TPM code based on client-tpm.c from
 * Carolin Latze <latze@angry-red-pla.net> and Tobias Soder
 */

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <pkcs11_int.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

/* Signing function for TPM privkeys, set with gnutls_privkey_import_ext() */

struct tpm_ctx_st
{
  TSS_HCONTEXT tpm_context;
  TSS_HKEY tpm_key;
  TSS_HPOLICY tpm_key_policy;
  TSS_HKEY srk;
  TSS_HPOLICY srk_policy;
};

static void
tpm_deinit_fn (gnutls_privkey_t key, void *_s)
{
  struct tpm_ctx_st *s = _s;

  Tspi_Context_CloseObject (s->tpm_context, s->tpm_key_policy);
  Tspi_Context_CloseObject (s->tpm_context, s->tpm_key);
  Tspi_Context_CloseObject (s->tpm_context, s->srk_policy);
  Tspi_Context_CloseObject (s->tpm_context, s->srk);
  Tspi_Context_Close (s->tpm_context);
  gnutls_free (s);
}

static int
tpm_sign_fn (gnutls_privkey_t key, void *_s,
	     const gnutls_datum_t * data, gnutls_datum_t * sig)
{
  struct tpm_ctx_st *s = _s;
  TSS_HHASH hash;
  int err;

  _gnutls_debug_log ("TPM sign function called for %u bytes.\n",
		     data->size);

  err =
      Tspi_Context_CreateObject (s->tpm_context,
				 TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER,
				 &hash);
  if (err)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Failed to create TPM hash object: %s\n",
			 Trspi_Error_String (err));
      return GNUTLS_E_PK_SIGN_FAILED;
    }
  err = Tspi_Hash_SetHashValue (hash, data->size, data->data);
  if (err)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Failed to set value in TPM hash object: %s\n",
			 Trspi_Error_String (err));
      Tspi_Context_CloseObject (s->tpm_context, hash);
      return GNUTLS_E_PK_SIGN_FAILED;
    }
  err = Tspi_Hash_Sign (hash, s->tpm_key, &sig->size, &sig->data);
  Tspi_Context_CloseObject (s->tpm_context, hash);
  if (err)
    {
      if (s->tpm_key_policy || err != TPM_E_AUTHFAIL)
	_gnutls_debug_log ("TPM hash signature failed: %s\n",
			   Trspi_Error_String (err));
      if (err == TPM_E_AUTHFAIL)
	return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
      else
	return GNUTLS_E_PK_SIGN_FAILED;
    }
  return 0;
}


/**
 * gnutls_privkey_import_tpm_raw:
 * @pkey: The private key
 * @fdata: The TPM key to be imported
 * @format: The format of the private key
 * @password: A password (optional)
 *
 * This function will import the given private key to the abstract
 * #gnutls_privkey_t structure. 
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.1.0
 *
 **/
int
gnutls_privkey_import_tpm_raw (gnutls_privkey_t pkey,
			       const gnutls_datum_t * fdata,
			       gnutls_x509_crt_fmt_t format,
			       const char *password)
{
  static const TSS_UUID SRK_UUID = TSS_UUID_SRK;
  char pin_value[GNUTLS_PKCS11_MAX_PIN_LEN];
  gnutls_datum_t asn1;
  unsigned int tss_len;
  unsigned int attempts = 0;
  int ofs, err, ret;
  struct tpm_ctx_st *s;
  gnutls_datum_t tmp_sig;
  static const char nullpass[20];

  err = gnutls_pem_base64_decode_alloc ("TSS KEY BLOB", fdata, &asn1);
  if (err)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Error decoding TSS key blob: %s\n",
			 gnutls_strerror (err));
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* FIXME: do proper decoding */

  /* Ick. We have to parse the ASN1 OCTET_STRING for ourselves. */
  if (asn1.size < 2 || asn1.data[0] != 0x04 /* OCTET_STRING */ )
    {
      gnutls_assert ();
      _gnutls_debug_log ("Error in TSS key blob\n");
      ret = GNUTLS_E_PARSING_ERROR;
      goto out_blob;
    }

  s = gnutls_malloc (sizeof (*s));
  if (s == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_MEMORY_ERROR;
      goto out_ctx;
    }

  tss_len = asn1.data[1];
  ofs = 2;
  if (tss_len & 0x80)
    {
      unsigned int lenlen = tss_len & 0x7f;

      if (asn1.size < 2 + lenlen || lenlen > 3)
	{
	  gnutls_assert ();
	  _gnutls_debug_log ("Error in TSS key blob\n");
	  ret = GNUTLS_E_PARSING_ERROR;
	  goto out_blob;
	}

      tss_len = 0;
      while (lenlen)
	{
	  tss_len <<= 8;
	  tss_len |= asn1.data[ofs++];
	  lenlen--;
	}
    }
  if (tss_len + ofs != asn1.size)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Error in TSS key blob\n");
      ret = GNUTLS_E_PARSING_ERROR;
      goto out_blob;
    }

  err = Tspi_Context_Create (&s->tpm_context);
  if (err)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Failed to create TPM context: %s\n",
			 Trspi_Error_String (err));
      ret = GNUTLS_E_TPM_ERROR;
      goto out_blob;
    }
  err = Tspi_Context_Connect (s->tpm_context, NULL);
  if (err)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Failed to connect TPM context: %s\n",
			 Trspi_Error_String (err));
      ret = GNUTLS_E_TPM_ERROR;
      goto out_context;
    }
  err =
      Tspi_Context_LoadKeyByUUID (s->tpm_context, TSS_PS_TYPE_SYSTEM,
				  SRK_UUID, &s->srk);
  if (err)
    {
      gnutls_assert ();
      _gnutls_debug_log
	  ("Failed to load TPM SRK key: %s\n", Trspi_Error_String (err));
      ret = GNUTLS_E_TPM_ERROR;
      goto out_context;
    }
  err = Tspi_GetPolicyObject (s->srk, TSS_POLICY_USAGE, &s->srk_policy);
  if (err)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Failed to load TPM SRK policy object: %s\n",
			 Trspi_Error_String (err));
      ret = GNUTLS_E_TPM_ERROR;
      goto out_srk;
    }

  /* We don't seem to get the error here... */
  if (password)
    err = Tspi_Policy_SetSecret (s->srk_policy,
				 TSS_SECRET_MODE_PLAIN,
				 strlen (password), (BYTE *) password);
  else				/* Well-known NULL key */
    err = Tspi_Policy_SetSecret (s->srk_policy,
				 TSS_SECRET_MODE_SHA1,
				 sizeof (nullpass), (BYTE *) nullpass);
  if (err)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Failed to set TPM PIN: %s\n",
			 Trspi_Error_String (err));
      ret = GNUTLS_E_TPM_ERROR;
      goto out_srkpol;
    }

  /* ... we get it here instead. */
  err = Tspi_Context_LoadKeyByBlob (s->tpm_context, s->srk,
				    tss_len, asn1.data + ofs, &s->tpm_key);
  if (err != 0)
    {
      if (password)
	{
	  gnutls_assert ();
	  _gnutls_debug_log
	      ("Failed to load TPM key blob: %s\n",
	       Trspi_Error_String (err));
	}

      if (err != TPM_E_AUTHFAIL)
	{
	  gnutls_assert ();
	  ret = GNUTLS_E_TPM_ERROR;
	  goto out_srkpol;
	}
      else
	{
	  ret = gnutls_assert_val (GNUTLS_E_PIN_ERROR);
	  goto out_srkpol;
	}
    }

  ret =
      gnutls_privkey_import_ext2 (pkey, GNUTLS_PK_RSA, s,
				  tpm_sign_fn, NULL, tpm_deinit_fn, 0);
  if (ret < 0)
    {
      gnutls_assert ();
      goto out_srkpol;
    }

retry_sign:
  ret =
      gnutls_privkey_sign_data (pkey, GNUTLS_DIG_SHA1, 0, fdata, &tmp_sig);
  if (ret == GNUTLS_E_INSUFFICIENT_CREDENTIALS)
    {
      if (!s->tpm_key_policy)
	{
	  err = Tspi_Context_CreateObject (s->tpm_context,
					   TSS_OBJECT_TYPE_POLICY,
					   TSS_POLICY_USAGE,
					   &s->tpm_key_policy);
	  if (err)
	    {
	      gnutls_assert ();
	      _gnutls_debug_log
		  ("Failed to create key policy object: %s\n",
		   Trspi_Error_String (err));
	      ret = GNUTLS_E_TPM_ERROR;
	      goto out_key;
	    }
	  err = Tspi_Policy_AssignToObject (s->tpm_key_policy, s->tpm_key);
	  if (err)
	    {
	      gnutls_assert ();
	      _gnutls_debug_log ("Failed to assign policy to key: %s\n",
				 Trspi_Error_String (err));
	      ret = GNUTLS_E_TPM_ERROR;
	      goto out_key_policy;
	    }
	}

      ret =
	  _gnutls_pin_func (_gnutls_pin_data, attempts++, "tpm:",
			    "TPM key", 0, pin_value,
			    GNUTLS_PKCS11_MAX_PIN_LEN);
      if (ret < 0)
	{
	  ret = gnutls_assert_val (GNUTLS_E_PIN_ERROR);
	  goto out_key_policy;
	}

      err = Tspi_Policy_SetSecret (s->tpm_key_policy,
				   TSS_SECRET_MODE_PLAIN,
				   strlen (pin_value), (void *) pin_value);

      if (err)
	{
	  gnutls_assert ();
	  _gnutls_debug_log ("Failed to set key PIN: %s\n",
			     Trspi_Error_String (err));
	  goto out_key_policy;
	}
      goto retry_sign;
    }
  else if (ret < 0)
    {
      gnutls_assert ();
      goto out_blob;
    }

  gnutls_free (asn1.data);
  return 0;
out_key_policy:
  Tspi_Context_CloseObject (s->tpm_context, s->tpm_key_policy);
  s->tpm_key_policy = 0;
out_key:
  Tspi_Context_CloseObject (s->tpm_context, s->tpm_key);
  s->tpm_key = 0;
out_srkpol:
  Tspi_Context_CloseObject (s->tpm_context, s->srk_policy);
  s->srk_policy = 0;
out_srk:
  Tspi_Context_CloseObject (s->tpm_context, s->srk);
  s->srk = 0;
out_context:
  Tspi_Context_Close (s->tpm_context);
  s->tpm_context = 0;
out_ctx:
  gnutls_free (s);
out_blob:
  gnutls_free (asn1.data);
  return ret;
}

