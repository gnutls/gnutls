/*
 * Copyright (C) 2000-2011 Free Software Foundation, Inc.
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

#ifndef GNUTLS_MEM_H
#define GNUTLS_MEM_H

typedef void svoid;             /* for functions that allocate using gnutls_secure_malloc */

extern int (*_gnutls_is_secure_memory) (const void *);

/* this realloc function will return ptr if size==0, and
 * will free the ptr if the new allocation failed.
 */
void *gnutls_realloc_fast (void *ptr, size_t size);

svoid *gnutls_secure_calloc (size_t nmemb, size_t size);

void *_gnutls_calloc (size_t nmemb, size_t size);
char *_gnutls_strdup (const char *);

#endif /* GNUTLS_MEM_H */
