#ifndef GNUTLS_MEM_H
# define GNUTLS_MEM_H

#ifdef USE_DMALLOC
# include <dmalloc.h>
#endif

typedef void svoid; /* for functions that allocate using gnutls_secure_malloc */

/* Use gnutls_afree() when calling alloca, or
 * memory leaks may occur in systems which do not
 * support alloca.
 */
#ifdef HAVE_ALLOCA
# define gnutls_alloca alloca
# define gnutls_afree(x)
#else
# define gnutls_alloca gnutls_malloc
# define gnutls_afree gnutls_free
#endif /* HAVE_ALLOCA */

extern void* (*gnutls_secure_malloc)(size_t);
extern void* (*gnutls_malloc)(size_t);
extern void (*gnutls_free)(void*);
extern int (*_gnutls_is_secure_memory)(const void*);
extern void* (*gnutls_realloc)(void*, size_t);
extern char* (*gnutls_strdup)( const char*);

#define gnutls_realloc_fast(x, y) (y==0?x:realloc(x, y))

svoid* gnutls_secure_calloc( size_t nmemb, size_t size);
void* gnutls_calloc( size_t nmemb, size_t size);

char* _gnutls_strdup( const char*);

#endif /* GNUTLS_MEM_H */
