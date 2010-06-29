#ifndef GNUTLS_LOCKS_H
# define GNUTLS_LOCKS_H

#include <gnutls/gnutls.h>
#include <gnutls_int.h>

#ifdef _WIN32
# define HAVE_WIN32_LOCKS
#else
# ifdef HAVE_LIBPTHREAD
#  define HAVE_PTHREAD_LOCKS
# else
#  define HAVE_NO_LOCKS
# endif
#endif

extern mutex_init_func gnutls_mutex_init;
extern mutex_deinit_func gnutls_mutex_deinit;
extern mutex_lock_func gnutls_mutex_lock;
extern mutex_unlock_func gnutls_mutex_unlock;

#endif
