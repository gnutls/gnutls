/* gc-libgcrypt.c --- Crypto wrappers around Libgcrypt for GC.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 *
 * This file is part of GC.
 *
 * GC is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * GC is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License License along with GC; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

/* Note: This file is only built if GC uses Nettle. */

#include <stdlib.h>

/* Get prototype. */
#include <gc.h>

/* Get libgcrypt API. */
#include <gcrypt.h>

int
gc_init (void)
{
  gcry_error_t err;

  err = gcry_control (GCRYCTL_ANY_INITIALIZATION_P);
  if (err == GPG_ERR_NO_ERROR)
    {
      if (gcry_check_version (GCRYPT_VERSION) == NULL)
	return GC_INIT_ERROR;

      err = gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL, 0);
      if (err != GPG_ERR_NO_ERROR)
	return GC_INIT_ERROR;
    }

  return GC_OK;
}

void
gc_done (void)
{
  return;
}

void
gc_set_allocators (gc_malloc_t func_malloc,
		   gc_malloc_t secure_malloc,
		   gc_secure_check_t secure_check,
		   gc_realloc_t func_realloc, gc_free_t func_free)
{
  gcry_set_allocation_handler (func_malloc, secure_malloc, secure_check,
			       func_realloc, func_free);
}

#include "nettle-meta.h"
#include "aes.h"

#define MAX_BLOCK_SIZE 64

typedef struct cipher_info {
  int alg;
  int mode;
  const struct nettle_cipher *info;
  void *encrypt_context;
  void *decrypt_context;
  char encrypt_iv[MAX_BLOCK_SIZE];
  char decrypt_iv[MAX_BLOCK_SIZE];
} cinfo;

int
gc_cipher_open (int alg, int mode, gc_cipher * outhandle)
{
  cinfo *cinf;

  cinf = malloc (sizeof (*cinf));
  if (!cinf)
    return GC_MALLOC_ERROR;

  cinf->alg = alg;
  cinf->mode = mode;

  switch (alg)
    {
    case GC_AES256:
      cinf->info = &nettle_aes256;
      break;

    case GC_AES128:
      cinf->info = &nettle_aes128;
      break;

    case GC_3DES:
      cinf->info = &nettle_des3;
      break;

    case GC_DES:
      cinf->info = &nettle_des;
      break;

    case GC_ARCFOUR128:
    case GC_ARCFOUR40:
      cinf->info = &nettle_arcfour128;
      break;

      /* FIXME: ARCTWO-40. */

    default:
      free (cinf);
      return GC_INVALID_CIPHER;
    }

  cinf->encrypt_context = malloc (cinf->info->context_size);
  if (!cinf->encrypt_context)
    {
      free (cinf);
      return GC_MALLOC_ERROR;
    }

  cinf->decrypt_context = malloc (cinf->info->context_size);
  if (!cinf->decrypt_context)
    {
      free (cinf->encrypt_context);
      free (cinf);
      return GC_MALLOC_ERROR;
    }

  memset (cinf->encrypt_context, 0, cinf->info->context_size);
  memset (cinf->decrypt_context, 0, cinf->info->context_size);

  *outhandle = cinf;

  return GC_OK;
}

int
gc_cipher_setkey (gc_cipher handle, size_t keylen, char *key)
{
  cinfo *cinf = (cinfo*) handle;

  cinf->info->set_encrypt_key (cinf->encrypt_context, keylen, key);
  cinf->info->set_decrypt_key (cinf->decrypt_context, keylen, key);

  return GC_OK;
}

int
gc_cipher_setiv (gc_cipher handle, size_t ivlen, char *iv)
{
  cinfo *cinf = (cinfo*) handle;

  if (ivlen != cinf->info->block_size)
    return GC_INVALID_CIPHER;

  memcpy (cinf->encrypt_iv, iv, ivlen);
  memcpy (cinf->decrypt_iv, iv, ivlen);

  return GC_OK;
}

int
gc_cipher_encrypt_inline (gc_cipher handle, size_t len, char *data)
{
  cinfo *cinf = (cinfo*) handle;

  if (cinf->mode == GC_CBC)
    cbc_encrypt (cinf->encrypt_context, cinf->info->encrypt,
		 cinf->info->block_size, cinf->encrypt_iv,
		 len, data, data);
  else
    cinf->info->encrypt (cinf->encrypt_context, len, data, data);

  return GC_OK;
}

int
gc_cipher_decrypt_inline (gc_cipher handle, size_t len, char *data)
{
  cinfo *cinf = (cinfo*) handle;

  if (cinf->mode == GC_CBC)
    cbc_decrypt (cinf->decrypt_context, cinf->info->decrypt,
		 cinf->info->block_size, cinf->decrypt_iv,
		 len, data, data);
  else
    cinf->info->decrypt (cinf->decrypt_context, len, data, data);

  return GC_OK;
}

int
gc_cipher_close (gc_cipher handle)
{
  cinfo *cinf = (cinfo*) handle;

  free (cinf->encrypt_context);
  free (cinf->decrypt_context);
  free (cinf);

  return GC_OK;
}
