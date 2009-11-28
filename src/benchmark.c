/*
 * Copyright (C) 2009 Free Software Foundation
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <time.h>

static unsigned char data[64*1024];

void cipher_bench(int size)
{
int ret, i;
gnutls_cipher_hd_t ctx;
gnutls_datum_t key = { "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", 16 };
gnutls_datum_t iv = { "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 16 };
struct timespec start, stop;
double secs;
long data_size = 0;
double dd;

  gnutls_global_init();
  
  printf("Checking AES (%dkb payload)... ", size);
  fflush(stdout);
  clock_gettime(CLOCK_MONOTONIC, &start);

  ret = gnutls_cipher_init( &ctx, GNUTLS_CIPHER_AES_128_CBC, &key, &iv);
  if (ret < 0) {
    fprintf(stderr, "error: %s\n", gnutls_strerror(ret));
    return;
  }
  
  for (i=0;i<7*1024;i++) {
    gnutls_cipher_encrypt(ctx, data, size*1024);
    data_size+= size*1024;
  }
  
  gnutls_cipher_deinit(ctx);

  clock_gettime(CLOCK_MONOTONIC, &stop);

  secs = (stop.tv_sec*1000+stop.tv_nsec/(1000*1000)-(start.tv_sec*1000+start.tv_nsec/(1000*1000)));
  secs /= 1000;
  dd = (((double)data_size/(double)secs))/1000;
  printf("Transferred %u kb in %.2f secs: ", data_size/1000, secs);
  printf("%.2f kbyte/sec\n", dd);

}


int main()
{
  cipher_bench(8);
  cipher_bench(16);
  cipher_bench(32);
 
  return 0; 
}
