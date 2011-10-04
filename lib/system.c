/*
 * Copyright (C) 2010 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
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

#include <system.h>
#include <gnutls_int.h>
#include <gnutls_errors.h>

#include <errno.h>

#ifdef _WIN32
#include <windows.h>

#else
#ifdef HAVE_PTHREAD_LOCKS
#include <pthread.h>
#endif
#endif

/* We need to disable gnulib's replacement wrappers to get native
   Windows interfaces. */
#undef recv
#undef send
#undef select

/* System specific function wrappers.
 */

/* wrappers for write() and writev()
 */
#ifdef _WIN32

int
system_errno (gnutls_transport_ptr p)
{
  int tmperr = WSAGetLastError ();
  int ret = 0;
  switch (tmperr)
    {
    case WSAEWOULDBLOCK:
      ret = EAGAIN;
      break;
    case NO_ERROR:
      ret = 0;
      break;
    case WSAEINTR:
      ret = EINTR;
      break;
    default:
      ret = EIO;
      break;
    }
  WSASetLastError (tmperr);

  return ret;
}

ssize_t
system_write (gnutls_transport_ptr ptr, const void *data, size_t data_size)
{
  return send (GNUTLS_POINTER_TO_INT (ptr), data, data_size, 0);
}
#else /* POSIX */
int
system_errno (gnutls_transport_ptr_t ptr)
{
#if defined(_AIX) || defined(AIX)
  if (errno == 0) errno = EAGAIN;
#endif

  return errno;
}

ssize_t
system_writev (gnutls_transport_ptr_t ptr, const giovec_t * iovec,
               int iovec_cnt)
{
  return writev (GNUTLS_POINTER_TO_INT (ptr), (struct iovec *) iovec,
                 iovec_cnt);

}
#endif

ssize_t
system_read (gnutls_transport_ptr_t ptr, void *data, size_t data_size)
{
  return recv (GNUTLS_POINTER_TO_INT (ptr), data, data_size, 0);
}

ssize_t
system_read_peek (gnutls_transport_ptr_t ptr, void *data, size_t data_size)
{
  return recv (GNUTLS_POINTER_TO_INT (ptr), data, data_size, MSG_PEEK);
}

/* Wait for data to be received within a timeout period in milliseconds.
 * If data_size > 0 it will return the specified amount of data in
 * peek mode.
 *
 * Returns -1 on error, 0 on timeout.
 */
int system_recv_timeout(gnutls_transport_ptr_t ptr, unsigned int ms)
{
fd_set rfds;
struct timeval tv;
int ret, ret2;

  FD_ZERO(&rfds);
  FD_SET(GNUTLS_POINTER_TO_INT(ptr), &rfds);
  
  tv.tv_sec = 0;
  tv.tv_usec = ms * 1000;
  
  ret = select(GNUTLS_POINTER_TO_INT(ptr)+1, &rfds, NULL, NULL, &tv);
  if (ret <= 0)
    return ret;

  
  ret2 = recv(GNUTLS_POINTER_TO_INT(ptr), NULL, 0, MSG_PEEK);
  if (ret2 == -1)
    return ret2;
      
  return ret;
}

/* Thread stuff */

#ifdef HAVE_WIN32_LOCKS


/* FIXME: win32 locks are untested */
static int
gnutls_system_mutex_init (void **priv)
{
  CRITICAL_SECTION *lock = malloc (sizeof (CRITICAL_SECTION));

  if (lock == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  InitializeCriticalSection (lock);

  *priv = lock;

  return 0;
}

static int
gnutls_system_mutex_deinit (void **priv)
{
  DeleteCriticalSection ((CRITICAL_SECTION *) * priv);
  free (*priv);

  return 0;
}

static int
gnutls_system_mutex_lock (void **priv)
{
  EnterCriticalSection ((CRITICAL_SECTION *) * priv);
  return 0;
}

static int
gnutls_system_mutex_unlock (void **priv)
{
  LeaveCriticalSection ((CRITICAL_SECTION *) * priv);
  return 0;
}

int
_gnutls_atfork (void (*prepare) (void), void (*parent) (void),
                void (*child) (void))
{
  return 0;
}


#endif /* WIN32_LOCKS */

#ifdef HAVE_PTHREAD_LOCKS

static int
gnutls_system_mutex_init (void **priv)
{
  pthread_mutex_t *lock = malloc (sizeof (pthread_mutex_t));
  int ret;

  if (lock == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  ret = pthread_mutex_init (lock, NULL);
  if (ret)
    {
      free (lock);
      gnutls_assert ();
      return GNUTLS_E_LOCKING_ERROR;
    }

  *priv = lock;

  return 0;
}

static int
gnutls_system_mutex_deinit (void **priv)
{
  pthread_mutex_destroy ((pthread_mutex_t *) * priv);
  free (*priv);
  return 0;
}

static int
gnutls_system_mutex_lock (void **priv)
{
  if (pthread_mutex_lock ((pthread_mutex_t *) * priv))
    {
      gnutls_assert ();
      return GNUTLS_E_LOCKING_ERROR;
    }

  return 0;
}

static int
gnutls_system_mutex_unlock (void **priv)
{
  if (pthread_mutex_unlock ((pthread_mutex_t *) * priv))
    {
      gnutls_assert ();
      return GNUTLS_E_LOCKING_ERROR;
    }

  return 0;
}

int
_gnutls_atfork (void (*prepare) (void), void (*parent) (void),
                void (*child) (void))
{
  return pthread_atfork (prepare, parent, child);
}

#endif /* PTHREAD_LOCKS */

#ifdef HAVE_NO_LOCKS

static int
gnutls_system_mutex_init (void **priv)
{
  return 0;
}

static int
gnutls_system_mutex_deinit (void **priv)
{
  return 0;
}

static int
gnutls_system_mutex_lock (void **priv)
{
  return 0;
}

static int
gnutls_system_mutex_unlock (void **priv)
{
  return 0;
}

int
_gnutls_atfork (void (*prepare) (void), void (*parent) (void),
                void (*child) (void))
{
  return 0;
}

#endif /* NO_LOCKS */

gnutls_time_func gnutls_time = time;
mutex_init_func gnutls_mutex_init = gnutls_system_mutex_init;
mutex_deinit_func gnutls_mutex_deinit = gnutls_system_mutex_deinit;
mutex_lock_func gnutls_mutex_lock = gnutls_system_mutex_lock;
mutex_unlock_func gnutls_mutex_unlock = gnutls_system_mutex_unlock;
