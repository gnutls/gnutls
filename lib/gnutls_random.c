/*
 * Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

/* Functions to return random bytes.
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
#endif

/* fills the buffer 'res' with random bytes of 'bytes' long.
 * level is WEAK, STRONG, or VERY_STRONG (libgcrypt)
 */
int _gnutls_get_random(opaque * res, int bytes, int level)
{
#ifndef USE_GCRYPT
    int fd;
    char *device;

    device = "dev/urandom";

    fd = open(device, O_RDONLY);
    if (device == NULL || fd < 0) {
	_gnutls_log( "Could not open random device\n");
	return GNUTLS_E_FILE_ERROR;
    } else {
	read(fd, res, bytes);
	close(fd);
    }
    return 0;
#else				/* using gcrypt */
    gcry_randomize( res, bytes, level);

    return 0;
#endif

}

