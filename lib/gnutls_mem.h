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

typedef void* (*ALLOC_FUNC)(size_t);
typedef void (*FREE_FUNC)(void*);
typedef void* (*REALLOC_FUNC)(void*, size_t);

extern ALLOC_FUNC gnutls_secure_malloc;
extern ALLOC_FUNC gnutls_malloc;
extern FREE_FUNC gnutls_free;

extern int (*_gnutls_is_secure_memory)(const void*);
extern REALLOC_FUNC gnutls_realloc;

extern void* (*gnutls_calloc)(size_t, size_t);
extern char* (*gnutls_strdup)( const char*);

#define gnutls_realloc_fast(x, y) (y==0?x:realloc(x, y))

svoid* gnutls_secure_calloc( size_t nmemb, size_t size);
void* _gnutls_calloc( size_t nmemb, size_t size);

char* _gnutls_strdup( const char*);

#endif /* GNUTLS_MEM_H */
