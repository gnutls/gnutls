/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "defines.h"
#include "gnutls_int.h"
#include "gnutls_random.h"
#ifndef USE_GCRYPT
# include <unistd.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <sys/time.h>
#endif

char *_gnutls_get_random(int bytes, int dev)
{
#ifndef USE_GCRYPT
    int fd;
    struct timeval tv;
    char prand[16];
    char * buf = gnutls_malloc(bytes);
    char *device;
    
    switch(dev) {
    	case 1:
    		device = "/dev/random";
    		break;
    	default:
    		device = "dev/urandom";
    }

    fd = open(device, O_RDONLY);
    if (device == NULL || fd < 0) {
	gettimeofday(&tv, (struct timezone *) 0);
	memcpy(prand, &tv, sizeof(tv));
	fd = getpid();
	memcpy(&prand[8], &fd, sizeof(fd));
	fd = clock();
	memcpy(&prand[12], &fd, sizeof(fd));
	memset(buf, 0, bytes);
	if (bytes > 16)
	    bytes = 16;
	memcpy(buf, prand, bytes);
    } else {
	read(fd, buf, bytes);
	close(fd);
    }
    return buf;
#else				/* using gcrypt */
    return gcry_random_bytes(bytes, dev);
#endif

}

void _gnutls_free_rand(void* rand) {
#ifndef USE_GCRYPT
	gnutls_free(rand);
#else
	gcry_free(rand);
#endif
}