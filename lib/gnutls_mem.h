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
