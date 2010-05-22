/*
 * Copyright (C) 2009, 2010  Free Software Foundation, Inc.
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
 *
 * Written by Nikos Mavrogiannopoulos <nmav@gnutls.org>.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <time.h>
#include "timespec.h"		/* gnulib gettime */

static unsigned char data[64 * 1024];

#define TOTAL_ITER 8*1024

static void
cipher_bench (int algo, int size)
{
  int ret, i;
  gnutls_cipher_hd_t ctx;
  void *_key, *_iv;
  gnutls_datum_t key, iv;
  struct timespec start, stop;
  double secs;
  long data_size = 0;
  double dd;
  int blocksize = gnutls_cipher_get_block_size (algo);
  int keysize = gnutls_cipher_get_key_size (algo);

  _key = malloc (keysize);
  if (_key == NULL)
    return;
  memset (_key, 0xf0, keysize);

  _iv = malloc (blocksize);
  if (_iv == NULL)
    return;
  memset (_iv, 0xf0, blocksize);

  iv.data = _iv;
  iv.size = blocksize;

  key.data = _key;
  key.size = keysize;

  gnutls_global_init ();

  printf ("Checking %s (%dkb payload)... ", gnutls_cipher_get_name (algo),
	  size);
  fflush (stdout);
  gettime (&start);

  ret = gnutls_cipher_init (&ctx, algo, &key, &iv);
  if (ret < 0)
    {
      fprintf (stderr, "error: %s\n", gnutls_strerror (ret));
      goto leave;
    }

  for (i = 0; i < TOTAL_ITER; i++)
    {
      gnutls_cipher_encrypt (ctx, data, size * 1024);
      data_size += size * 1024;
    }

  gnutls_cipher_deinit (ctx);

  gettime (&stop);

  secs = (stop.tv_sec * 1000 + stop.tv_nsec / (1000 * 1000) -
	  (start.tv_sec * 1000 + start.tv_nsec / (1000 * 1000)));
  secs /= 1000;
  dd = (((double) data_size / (double) secs)) / 1000;
  printf ("Encrypted %ld kb in %.2f secs: ", data_size / 1000, secs);
  printf ("%.2f kbyte/sec\n", dd);

leave:
  free (_key);
  free (_iv);

}

static void
mac_bench (int algo, int size)
{
  int i;
  void *_key;
  struct timespec start, stop;
  double secs;
  long data_size = 0;
  double dd;
  int blocksize = gnutls_hmac_get_len (algo);

  _key = malloc (blocksize);
  if (_key == NULL)
    return;
  memset (_key, 0xf0, blocksize);

  gnutls_global_init ();

  printf ("Checking %s (%dkb payload)... ", gnutls_mac_get_name (algo), size);
  fflush (stdout);
  gettime (&start);

  for (i = 0; i < TOTAL_ITER; i++)
    {
      gnutls_hmac_fast (algo, _key, blocksize, data, size * 1024, _key);
      data_size += size * 1024;
    }

  gettime (&stop);

  secs =
    (stop.tv_sec * 1000 + stop.tv_nsec / (1000 * 1000) -
     (start.tv_sec * 1000 + start.tv_nsec / (1000 * 1000)));
  secs /= 1000;
  dd = (((double) data_size / (double) secs)) / 1000;
  printf ("Hashed %ld kb in %.2f secs: ", data_size / 1000, secs);
  printf ("%.2f kbyte/sec\n", dd);

  free (_key);
}

int
main (void)
{
  mac_bench (GNUTLS_MAC_SHA1, 4);
  mac_bench (GNUTLS_MAC_SHA1, 8);
  mac_bench (GNUTLS_MAC_SHA1, 16);

  mac_bench (GNUTLS_MAC_SHA256, 4);
  mac_bench (GNUTLS_MAC_SHA256, 8);
  mac_bench (GNUTLS_MAC_SHA256, 16);

  cipher_bench (GNUTLS_CIPHER_3DES_CBC, 4);
  cipher_bench (GNUTLS_CIPHER_3DES_CBC, 8);
  cipher_bench (GNUTLS_CIPHER_3DES_CBC, 16);

  cipher_bench (GNUTLS_CIPHER_AES_128_CBC, 4);
  cipher_bench (GNUTLS_CIPHER_AES_128_CBC, 8);
  cipher_bench (GNUTLS_CIPHER_AES_128_CBC, 16);

  cipher_bench (GNUTLS_CIPHER_ARCFOUR, 4);
  cipher_bench (GNUTLS_CIPHER_ARCFOUR, 8);
  cipher_bench (GNUTLS_CIPHER_ARCFOUR, 16);

  return 0;
}
