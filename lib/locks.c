/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "gnutls_int.h"
#include "errors.h"
#include <libtasn1.h>
#include <dh.h>
#include <random.h>

#include <locks.h>


/**
 * gnutls_global_set_mutex:
 * @init: mutex initialization function
 * @deinit: mutex deinitialization function
 * @lock: mutex locking function
 * @unlock: mutex unlocking function
 *
 * With this function you are allowed to override the default mutex
 * locks used in some parts of gnutls and dependent libraries. This function
 * should be used if you have complete control of your program and libraries.
 * Do not call this function from a library, or preferably from any application
 * unless really needed to. GnuTLS will use the appropriate locks for the running
 * system.
 *
 * This function must be called prior to any other GnuTLS function; otherwise
 * the behavior is undefined.
 *
 * Deprecated: This function is discouraged on GnuTLS 3.7.3 or later.
 *
 * Since: 2.12.0
 **/
void
gnutls_global_set_mutex(mutex_init_func init, mutex_deinit_func deinit,
			mutex_lock_func lock, mutex_unlock_func unlock)
{
	if (init == NULL || deinit == NULL || lock == NULL || unlock == NULL) {
		return;
	}

	gnutls_mutex_init = init;
	gnutls_mutex_deinit = deinit;
	gnutls_mutex_lock = lock;
	gnutls_mutex_unlock = unlock;
}

int
gnutls_static_mutex_lock(gnutls_static_mutex_t lock)
{
	if (unlikely(glthread_lock_lock(lock))) {
		return gnutls_assert_val(GNUTLS_E_LOCKING_ERROR);
	}
	return 0;
}

int
gnutls_static_mutex_unlock(gnutls_static_mutex_t lock)
{
	if (unlikely(glthread_lock_unlock(lock))) {
		return gnutls_assert_val(GNUTLS_E_LOCKING_ERROR);
	}
	return 0;
}

int
gnutls_rwlock_rdlock(gnutls_rwlock_t rwlock)
{
	if (unlikely(glthread_rwlock_rdlock(rwlock))) {
		return gnutls_assert_val(GNUTLS_E_LOCKING_ERROR);
	}
	return 0;
}

int
gnutls_rwlock_wrlock(gnutls_rwlock_t rwlock)
{
	if (unlikely(glthread_rwlock_wrlock(rwlock))) {
		return gnutls_assert_val(GNUTLS_E_LOCKING_ERROR);
	}
	return 0;
}

int
gnutls_rwlock_unlock(gnutls_rwlock_t rwlock)
{
	if (unlikely(glthread_rwlock_unlock(rwlock))) {
		return gnutls_assert_val(GNUTLS_E_LOCKING_ERROR);
	}
	return 0;
}

int
gnutls_once(gnutls_once_t once, void (*init_func) (void))
{
	if (unlikely(glthread_once(once, init_func))) {
		return gnutls_assert_val(GNUTLS_E_LOCKING_ERROR);
	}
	return 0;
}
