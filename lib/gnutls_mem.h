#ifndef GNUTLS_MEM_H
# define GNUTLS_MEM_H

#ifdef USE_DMALLOC
# include <dmalloc.h>
#endif

typedef void svoid; /* for functions that allocate using gnutls_secure_free */

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

#ifdef USE_LIBCALLOC
# define gnutls_malloc malloc
# define gnutls_realloc realloc
# define gnutls_realloc_fast(x, y) (y==0?x:realloc(x, y))
# define gnutls_free free
# define gnutls_calloc calloc
# define gnutls_secure_malloc malloc
# define gnutls_secure_realloc realloc
# define gnutls_secure_free free
# define gnutls_secure_calloc calloc
# define gnutls_strdup strdup
int _gnutls_is_secure_memory(const void*);

#else

svoid* gnutls_secure_malloc( size_t size);
svoid* gnutls_secure_calloc( size_t nmemb, size_t size);
size_t _gnutls_secure_ptr_size( svoid* ptr);
svoid* gnutls_secure_realloc( svoid* ptr, size_t size);
void gnutls_secure_free( svoid* ptr);
int _gnutls_is_secure_memory(const svoid* mem);

void* gnutls_malloc( size_t size);
void* gnutls_calloc( size_t nmemb, size_t size);
size_t _gnutls_malloc_ptr_size( void* ptr);
void* gnutls_realloc( void* ptr, size_t size);
void* gnutls_realloc_fast( void* ptr, size_t size);
void gnutls_free( void* ptr);
char* gnutls_strdup( const char* s);

#endif

#endif /* GNUTLS_MEM_H */
