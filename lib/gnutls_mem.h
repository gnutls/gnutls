typedef void svoid; /* for functions that allocate using secure_free */

svoid* secure_malloc( size_t size);
svoid* secure_calloc( size_t nmemb, size_t size);
size_t _secure_ptr_size( svoid* ptr);
svoid* secure_realloc( svoid* ptr, size_t size);
void secure_free( svoid* ptr);
int _gnutls_is_secure_memory(const svoid* mem);

void* gnutls_malloc( size_t size);
void* gnutls_calloc( size_t nmemb, size_t size);
size_t _gnutls_malloc_ptr_size( void* ptr);
void* gnutls_realloc( void* ptr, size_t size);
void gnutls_free( void* ptr);
char* gnutls_strdup( const char* s);
