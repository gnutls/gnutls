/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>

#include <utils.h>
#include "../../lib/gnutls_int.h"
#include "../../lib/x509/x509_int.h"
#include "../../lib/debug.h"

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

char *salt[3] = { "salt1", "ltsa22", "balt33" };
char *pw[3] = { "secret1", "verysecret2", "veryverysecret3" };

char *values[] = {
/* 1.0 */ "85a3c676a66f0960f4807144a28c8d61a0001b81846f301a1ac164289879972f",
/* 1.2 */ "e659da7d5989733a3d268e0bf7752c35c116e5c75919449a98f6812f82a15b16",
/* 1.2 */"878b8a88bf6166ce803b7498822205b1ac82870d3aec20807148779375a61f1e",
/* 2.0 */"1c845be764371d633c7fd1056967a9940385e110e85b58f826d39ae8561a0019",
/* 2.1 */"de8dd3ffd59b65d3d5f59a1f71d7add582741f7752a786c045953e727e4465c0",
/* 2.2 */"9dd7f19e5e6aee5c5008b5deefd35889ab7519356f13478ecdee593c5ed689b1",
/* 3.0 */"1c165e5a291a1539f3dbcf82a3e6ed566eb9d50ad4b0b3b57b599b08f0531236",
/* 3.1 */"5c9abee3cde31656eedfc131b7c2f8061032a3c705961ee2306a826c8b4b1a76",
/* 3.2 */"a9c94e0acdaeaea54d1b1b681c3b64916396a352dea7ffe635fb2c11d8502e98"
};

void
doit (void)
{
  int rc, i, j, x;
  char key[32];
  char tmp[1024];
  
  gnutls_global_init();

  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (99);
    
  x = 0;
  for (i=1;i<4;i++) {
    for (j=0;j<3;j++) {
      rc = _gnutls_pkcs12_string_to_key(i, salt[j], strlen(salt[j]), j+i+15, pw[j], sizeof(key), key);
      if (rc < 0)
        fail ("_gnutls_pkcs12_string_to_key failed[0]\n");
    
      if (strcmp( _gnutls_bin2hex( key, sizeof(key), tmp, sizeof(tmp)), values[x]) != 0)
        fail ("_gnutls_pkcs12_string_to_key failed[1]\n");

      printf("ij: %d.%d: %s\n", i, j, _gnutls_bin2hex( key, sizeof(key), tmp, sizeof(tmp)));
      x++;
    }
  }
  printf("\n");

  success ("_gnutls_pkcs12_string_to_key ok\n");
}
