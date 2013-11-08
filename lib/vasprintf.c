#include <config.h>
#include <stdio.h>
#include "vasprintf.h"

#ifndef HAVE_VASPRINTF

#define MAX_BSIZE 1024
#define NO_MORE_MAX (16*MAX_BSIZE)

int _gnutls_vasprintf(char **strp, const char *fmt, va_list ap)
{
	char *buf;
	int ret, max;

	max = MAX_BSIZE / 2;

	do {
		max *= 2;

		buf = malloc(max);
		if (buf == NULL)
			return -1;

		ret = vsnprintf(buf, max, fmt, ap);
	}
	while (ret > max && max < NO_MORE_MAX);

	return ret;
}

#endif
