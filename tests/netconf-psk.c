/*
 * Copyright (C) 2008, 2010 Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <gnutls/gnutls.h>

#include "utils.h"

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "<%d>| %s", level, str);
}

void
doit (void)
{
  const char *known =
    "\x88\xf3\x82\x4b\x3e\x56\x59\xf5\x2d\x00"
    "\xe9\x59\xba\xca\xb9\x54\xb6\x54\x03\x44";
  gnutls_datum_t key = { NULL, 0 };

  gnutls_global_init ();

  gnutls_global_set_log_function (tls_log_func);
  if (debug)
    gnutls_global_set_log_level (2);

  if (gnutls_psk_netconf_derive_key ("password", "psk_identity",
				     "psk_identity_hint", &key) == 0)
    {
      if (debug)
	success ("success: gnutls_psk_netconf_derive_key\n");
    }
  else
    fail ("gnutls_psk_netconf_derive_key failure\n");

  if (debug)
    hexprint (key.data, key.size);

  if (key.size == 20 && memcmp (key.data, known, 20) == 0)
    {
      if (debug)
	success ("success: match.\n");
    }
  else
    fail ("FAIL: key differ.\n");

  gnutls_free (key.data);

  gnutls_global_deinit ();
}
