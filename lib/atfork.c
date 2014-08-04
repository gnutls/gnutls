/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
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

#include <config.h>
#include <gnutls_int.h>
#include <gnutls_errors.h>

#include <sys/socket.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <atfork.h>

#ifndef _WIN32

# if defined(HAVE___REGISTER_ATFORK) || defined(HAVE_PTHREAD_ATFORK)
#  define HAVE_ATFORK
# endif

/* The maximum number of users of the API */
# define MAX_VALS 6

static unsigned int * fvals[MAX_VALS];
static unsigned int fvals_size = 0;

# ifdef HAVE_ATFORK
static void fork_handler(void)
{
	unsigned i;
	for (i=0;i<fvals_size;i++)
		*fvals[i] = 1;
}
# endif

static void set_val_on_fork(unsigned int *val, unsigned int def)
{
	if (fvals_size >= MAX_VALS)
		abort(); /* internal error */
	*val = def;
	fvals[fvals_size++] = val;
}

void _gnutls_fork_set_val(unsigned int *val)
{
# ifdef HAVE_ATFORK
	set_val_on_fork(val, 0);
# else
	set_val_on_fork(val, getpid());
# endif
}

# if defined(HAVE_PTHREAD_ATFORK)

#  include <pthread.h>

int _gnutls_register_fork_handler(void)
{
	if (pthread_atfork(NULL, NULL, fork_handler) != 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	return 0;
}

# elif defined(HAVE___REGISTER_ATFORK)
extern int __register_atfork(void (*)(void), void(*)(void), void (*)(void), void *);
extern void *__dso_handle;

int _gnutls_register_fork_handler(void)
{
	if (__register_atfork(NULL, NULL, fork_handler, __dso_handle) != 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	return 0;
}

# else

/* we have to detect fork manually */
int _gnutls_register_fork_handler(void)
{
	return 0;
}

# endif

#endif /* !_WIN32 */
