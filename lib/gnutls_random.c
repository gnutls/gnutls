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

#include <gnutls_int.h>
#include <gnutls_random.h>
#include <gnutls_errors.h>
#ifndef USE_GCRYPT
# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# endif
#endif

int _gnutls_get_random(opaque * res, int bytes, int dev)
{
#ifndef USE_GCRYPT
    int fd;
    struct timeval tv;
    char prand[16];
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
	memset(res, 0, bytes);
	if (bytes > 16)
	    bytes = 16;
	memcpy(res, prand, bytes);
    } else {
	read(fd, res, bytes);
	close(fd);
    }
    return 0;
#else				/* using gcrypt */
    char* buf;
    buf = gcry_random_bytes(bytes, dev);
    if (buf==NULL) {
    	gnutls_assert();
    	return GNUTLS_E_MEMORY_ERROR;
    }

    memcpy( res, buf, bytes);
    gcry_free(buf);

    return 0;
#endif

}

