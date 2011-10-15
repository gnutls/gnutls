/*
 * Copyright (C) 2002-2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS-EXTRA.
 *
 * GnuTLS-extra is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * GnuTLS-extra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS-EXTRA; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/* Note the libgnutls-extra is not a standalone library. It requires
 * to link also against libgnutls.
 */

#ifndef GNUTLS_EXTRA_H
#define GNUTLS_EXTRA_H

#include <gnutls/gnutls.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define GNUTLS_EXTRA_VERSION GNUTLS_VERSION

  int gnutls_global_init_extra (void);

/* returns libgnutls-extra version (call it with a NULL argument) 
 */
  const char *gnutls_extra_check_version (const char *req_version);

#ifdef __cplusplus
}
#endif
#endif
