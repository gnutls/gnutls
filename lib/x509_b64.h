int _gnutls_base64_encode(const uint8 * data, size_t data_size, uint8 ** result);
int _gnutls_fbase64_encode(const char *msg, const uint8 * data, int data_size,
			   uint8 ** result);
int _gnutls_base64_decode(const uint8 * data, size_t data_size, uint8 ** result);
int _gnutls_fbase64_decode( const opaque* header, const uint8 * data, size_t data_size,
			   uint8 ** result);

#define B64SIZE( data_size) ((data_size%3==0)?((data_size/3)*4):(4+((data_size/3)*4)))

/* The size for B64 encoding + newlines plus header
 */
 
#define HEADSIZE( hsize) \
	sizeof("-----BEGIN")-1+sizeof("-----\n")-1+ \
	sizeof("\n-----END ")-1+sizeof("-----\n")-1+hsize+hsize

#define B64FSIZE( hsize, dsize) \
	(B64SIZE(dsize) + HEADSIZE(hsize) + /*newlines*/ \
	B64SIZE(dsize)/64 + (B64SIZE(dsize) % 64 > 0 ? 1 : 0))
