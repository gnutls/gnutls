/*
 * Copyright (C) 2010
 * Free Software Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <libtasn1.h>
#include <gnutls_dh.h>
#include <random.h>

#include <locks.h>

#ifdef HAVE_WIN32_LOCKS

# include <windows.h>

/* FIXME: win32 locks are untested */
static int gnutls_system_mutex_init (void **priv)
{
  CRITICAL_SECTION *lock = malloc (sizeof (CRITICAL_SECTION));
  int ret;

  if (lock==NULL)
    return GNUTLS_E_MEMORY_ERROR;

  InitializeCriticalSection(lock);
     
  *priv = lock;
  
  return 0;
}

static void gnutls_system_mutex_deinit (void *priv)
{
  DeleteCriticalSection(priv);
  free(priv);
}

static int gnutls_system_mutex_lock (void *priv)
{
  EnterCriticalSection(priv);
  return 0;
}

static int gnutls_system_mutex_unlock (void *priv)
{
  LeaveCriticalSection(priv);
  return 0;
}

#endif /* WIN32_LOCKS */

#ifdef HAVE_PTHREAD_LOCKS
# include <pthread.h>

static int gnutls_system_mutex_init (void **priv)
{
  pthread_mutex_t *lock = malloc (sizeof (pthread_mutex_t));
  int ret;

  if (lock==NULL)
    return GNUTLS_E_MEMORY_ERROR;

   ret = pthread_mutex_init (lock, NULL);
   if (ret)
     {
       free(lock);
       gnutls_assert();
       return GNUTLS_E_LOCKING_ERROR;
     }
     
  *priv = lock;
  
  return 0;
}

static void gnutls_system_mutex_deinit (void *priv)
{
  pthread_mutex_destroy(priv);
  free(priv);
}

static int gnutls_system_mutex_lock (void *priv)
{
  if (pthread_mutex_lock(priv))
    {
        gnutls_assert();
        return GNUTLS_E_LOCKING_ERROR;
    }

  return 0;
}

static int gnutls_system_mutex_unlock (void *priv)
{
  if (pthread_mutex_unlock(priv))
    {
        gnutls_assert();
        return GNUTLS_E_LOCKING_ERROR;
    }

  return 0;
}

#endif /* PTHREAD_LOCKS */

#ifdef HAVE_NO_LOCKS

static int gnutls_system_mutex_init (void **priv)
{
  return 0;
}

static void gnutls_system_mutex_deinit (void *priv)
{
  return;
}

static int gnutls_system_mutex_lock (void *priv)
{
  return 0;
}

static int gnutls_system_mutex_unlock (void *priv)
{
  return 0;
}

#endif /* NO_LOCKS */

mutex_init_func gnutls_mutex_init = gnutls_system_mutex_init;
mutex_deinit_func gnutls_mutex_deinit = gnutls_system_mutex_deinit;
mutex_lock_func gnutls_mutex_lock = gnutls_system_mutex_lock;
mutex_unlock_func gnutls_mutex_unlock = gnutls_system_mutex_unlock;

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
 * Do not call this function from a library. Instead only initialize gnutls and
 * the default OS mutex locks will be used.
 * 
 * This function must be called before gnutls_global_init().
 *
 **/
void gnutls_global_set_mutex(mutex_init_func init, mutex_deinit_func deinit, 
        mutex_lock_func lock, mutex_unlock_func unlock)
{
  gnutls_mutex_init = init;
  gnutls_mutex_deinit = deinit;
  gnutls_mutex_lock = lock;
  gnutls_mutex_unlock = unlock;
}

