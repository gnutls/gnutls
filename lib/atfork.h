/*
 * Copyright (C) 2014 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef ATFORK_H
#define ATFORK_H

#include <config.h>
#include <gnutls_int.h>

#ifndef _WIN32

/* API */
int _gnutls_register_fork_handler(void); /* global init */

/* Each user of the API that needs to be notified registers
 * a pointer to an int */
void _gnutls_fork_set_val(unsigned int *val);

/* 
 * Each user, calls this function with the integer registered
 * to check whether a fork is detected
 *
 * unsigned _gnutls_fork_detected(unsigned int *v);
 */

# if defined(HAVE___REGISTER_ATFORK) || defined(HAVE_PTHREAD_ATFORK)
inline static
unsigned _gnutls_fork_detected(unsigned int *v)
{
	if (*v != 0) {
		*v = 0;
		return 1;
	}
	return 0;
}
# else
#  include <unistd.h>

inline static
unsigned _gnutls_fork_detected(unsigned int *v)
{
	if (getpid() != (pid_t)*v) {
		*v = getpid();
		return 1;
	}
	return 0;
}

# endif

#else /* _WIN32 */
# define _gnutls_fork_set_val(x) 0
# define _gnutls_register_fork_handler() 0
# define _gnutls_fork_detected(x) 0
#endif

#endif
