/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos <nmav@hellug.gr>
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#ifndef GNUTLS_MEM_H
# define GNUTLS_MEM_H

#ifdef USE_DMALLOC
# include <dmalloc.h>
#endif

typedef void svoid;		/* for functions that allocate using gnutls_secure_malloc */

/* Use gnutls_afree() when calling alloca, or
 * memory leaks may occur in systems which do not
 * support alloca.
 */
#ifdef USE_EFENCE
# define gnutls_alloca gnutls_malloc
# define gnutls_afree gnutls_free
#endif

#ifdef HAVE_ALLOCA
# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# endif
# ifndef gnutls_alloca
#  define gnutls_alloca alloca
#  define gnutls_afree(x)
# endif
#else
# ifndef gnutls_alloca
#  define gnutls_alloca gnutls_malloc
#  define gnutls_afree gnutls_free
# endif
#endif				/* HAVE_ALLOCA */

typedef void *(*gnutls_alloc_function) (size_t);
typedef int (*gnutls_is_secure_function) (const void *);
typedef void (*gnutls_free_function) (void *);
typedef void *(*gnutls_realloc_function) (void *, size_t);

extern gnutls_alloc_function gnutls_secure_malloc;
extern gnutls_alloc_function gnutls_malloc;
extern gnutls_free_function gnutls_free;

extern int (*_gnutls_is_secure_memory) (const void *);
extern gnutls_realloc_function gnutls_realloc;

extern void *(*gnutls_calloc) (size_t, size_t);
extern char *(*gnutls_strdup) (const char *);

/* this realloc function will return ptr if size==0, and
 * will free the ptr if the new allocation failed.
 */
void *gnutls_realloc_fast(void *ptr, size_t size);

svoid *gnutls_secure_calloc(size_t nmemb, size_t size);
void *_gnutls_calloc(size_t nmemb, size_t size);

char *_gnutls_strdup(const char *);

#endif				/* GNUTLS_MEM_H */
