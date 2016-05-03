#ifndef GNETTLE_H
# define GNETTLE_H

#include <config.h>
#include <minmax.h>
#include <limits.h>

#define PRIME_CHECK_PARAM 8
#define TOMPZ(x) ((__mpz_struct*)(x))
#define SIZEOF_MPZT sizeof(__mpz_struct)

#ifdef USE_NETTLE3
# define _NETTLE_SIZE_T size_t
# define _NETTLE_UPDATE(func, ctx, size, data) func(ctx, size, data)
#else
# define _NETTLE_SIZE_T unsigned
#define _NETTLE_UPDATE(func, ptr, size, data) { \
	size_t _rsize = size; \
	const uint8_t *_t = data; \
	while(size > 0) { \
		_rsize = MIN(size, UINT_MAX); \
		func(ptr, _rsize, _t); \
		size -= _rsize; \
		_t += _rsize; \
	} \
}

#endif

#endif
