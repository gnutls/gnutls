/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 * Copyright (C) 2000, 2001, 2008 Niels Möller
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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

/* Here is the random generator layer. This code was based on the LSH 
 * random generator (the trivia and device source functions for POSIX)
 * and modified to fit gnutls' needs. Relicenced with permission. 
 * Original author Niels Möller.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <locks.h>
#include <gnutls_num.h>
#include <nettle/yarrow.h>
#ifdef HAVE_GETPID
# include <unistd.h> /* getpid */
#endif
#ifdef HAVE_GETRUSAGE
# include <sys/resource.h>
#endif
#include <errno.h>

#define SOURCES 2

#define RND_LOCK if (gnutls_mutex_lock(&rnd_mutex)!=0) abort()
#define RND_UNLOCK if (gnutls_mutex_unlock(&rnd_mutex)!=0) abort()

enum
{
  RANDOM_SOURCE_TRIVIA = 0,
  RANDOM_SOURCE_DEVICE,
};

static struct yarrow256_ctx yctx;
static struct yarrow_source ysources[SOURCES];

static struct timespec device_last_read = { 0, 0 };
static struct timespec current_time = { 0, 0 };

static time_t trivia_previous_time = 0;
static time_t trivia_time_count = 0;
#ifdef HAVE_GETPID
static pid_t pid; /* detect fork() */
#endif

static void *rnd_mutex;

inline static unsigned int
timespec_sub_sec (struct timespec *a, struct timespec *b)
{
  return (a->tv_sec - b->tv_sec);
}

#define DEVICE_READ_INTERVAL (1200)
/* universal functions */

static int
do_trivia_source (int init)
{
  static struct
  {
    struct timespec now;
#ifdef HAVE_GETRUSAGE
    struct rusage rusage;
#endif
#ifdef HAVE_GETPID
    pid_t pid;
#endif
    unsigned count;
  } event;
  unsigned entropy = 0;

  memcpy(&event.now, &current_time, sizeof(event.now));
#ifdef HAVE_GETRUSAGE
  if (getrusage (RUSAGE_SELF, &event.rusage) < 0)
    {
      _gnutls_debug_log ("getrusage failed: %s\n", strerror (errno));
      abort ();
    }
#endif

  event.count = 0;
  if (init)
    {
      trivia_time_count = 0;
    }
  else
    {
      event.count = trivia_time_count++;

      if (event.now.tv_sec != trivia_previous_time)
        {
          /* Count one bit of entropy if we either have more than two
           * invocations in one second, or more than two seconds
           * between invocations. */
          if ((trivia_time_count > 2)
              || ((event.now.tv_sec - trivia_previous_time) > 2))
            entropy++;

          trivia_time_count = 0;
        }
    }
  trivia_previous_time = event.now.tv_sec;
#ifdef HAVE_GETPID
  event.pid = pid;
#endif
  
  return yarrow256_update (&yctx, RANDOM_SOURCE_TRIVIA, entropy,
                           sizeof (event), (void *) &event);
}



/* System specific functions */
#ifdef _WIN32

#include <windows.h>
#include <wincrypt.h>

#define DEVICE_READ_SIZE 16
#define DEVICE_READ_SIZE_MAX 32

static HCRYPTPROV device_fd = 0;

static int
do_device_source (int init)
{
  int read_size = DEVICE_READ_SIZE;

  if (init)
    {
      int old;

      if (!CryptAcquireContext
          (&device_fd, NULL, NULL, PROV_RSA_FULL,
           CRYPT_SILENT | CRYPT_VERIFYCONTEXT))
        {
          _gnutls_debug_log ("error in CryptAcquireContext!\n");
          return GNUTLS_E_RANDOM_DEVICE_ERROR;
        }
      gettime(&device_last_read);
      read_size = DEVICE_READ_SIZE_MAX; /* initially read more data */
    }

  if ((device_fd != 0)
      && (init || timespec_sub_sec(&current_time, &device_last_read) > DEVICE_READ_INTERVAL))
    {

      /* More than 20 minutes since we last read the device */
      uint8_t buf[DEVICE_READ_SIZE_MAX];

      if (!CryptGenRandom (device_fd, (DWORD) read_size, buf))
        {
          _gnutls_debug_log ("Error in CryptGenRandom: %s\n",
                             GetLastError ());
          return GNUTLS_E_RANDOM_DEVICE_ERROR;
        }

      memcpy(&device_last_read, &current_time, sizeof(device_last_read));
      return yarrow256_update (&yctx, RANDOM_SOURCE_DEVICE,
                               read_size * 8 /
                               2 /* we trust the system RNG */ ,
                               read_size, buf);
    }
  return 0;
}

static void
wrap_nettle_rnd_deinit (void *ctx)
{
  RND_LOCK;
  CryptReleaseContext (device_fd, 0);
  RND_UNLOCK;

  gnutls_mutex_deinit (&rnd_mutex);
  rnd_mutex = NULL;
}

#else /* POSIX */

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <locks.h>
#include "egd.h"

#define DEVICE_READ_SIZE 16
#define DEVICE_READ_SIZE_MAX 32

static int device_fd;

static int
do_device_source_urandom (int init)
{
  unsigned int read_size = DEVICE_READ_SIZE;

  if (init)
    {
      int old;

      device_fd = open ("/dev/urandom", O_RDONLY);
      if (device_fd < 0)
        {
          _gnutls_debug_log ("Cannot open urandom!\n");
          return GNUTLS_E_FILE_ERROR;
        }

      old = fcntl (device_fd, F_GETFD);
      if (old != -1)
        fcntl (device_fd, F_SETFD, old | FD_CLOEXEC);
      memcpy(&device_last_read, &current_time, sizeof(device_last_read));

      read_size = DEVICE_READ_SIZE_MAX; /* initially read more data */
    }

  if ((init || (timespec_sub_sec(&current_time, &device_last_read) > DEVICE_READ_INTERVAL)) && (device_fd > 0))
    {
      /* More than 20 minutes since we last read the device */
      uint8_t buf[DEVICE_READ_SIZE_MAX];
      uint32_t done;

      for (done = 0; done < read_size;)
        {
          int res;
          do
            res = read (device_fd, buf + done, sizeof (buf) - done);
          while (res < 0 && errno == EINTR);

          if (res <= 0)
            {
              if (res < 0)
                {
                  _gnutls_debug_log ("Failed to read /dev/urandom: %s\n",
                                     strerror (errno));
                }
              else
                {
                  _gnutls_debug_log
                    ("Failed to read /dev/urandom: end of file\n");
                }

              return GNUTLS_E_RANDOM_DEVICE_ERROR;
            }

          done += res;
        }

      memcpy(&device_last_read, &current_time, sizeof(device_last_read));
      return yarrow256_update (&yctx, RANDOM_SOURCE_DEVICE,
                               read_size * 8 / 2 /* we trust the RNG */ ,
                               read_size, buf);
    }
  return 0;
}

static int
do_device_source_egd (int init)
{
  unsigned int read_size = DEVICE_READ_SIZE;

  if (init)
    {
      device_fd = _rndegd_connect_socket ();
      if (device_fd < 0)
        {
          _gnutls_debug_log ("Cannot open egd socket!\n");
          return gnutls_assert_val(GNUTLS_E_RANDOM_DEVICE_ERROR);
        }

      memcpy(&device_last_read, &current_time, sizeof(device_last_read));

      read_size = DEVICE_READ_SIZE_MAX; /* initially read more data */
    }

  if ((device_fd > 0)
      && (init || (timespec_sub_sec(&current_time, &device_last_read) > DEVICE_READ_INTERVAL)))
    {

      /* More than 20 minutes since we last read the device */
      uint8_t buf[DEVICE_READ_SIZE_MAX];
      uint32_t done;

      for (done = 0; done < read_size;)
        {
          int res;
          res = _rndegd_read (&device_fd, buf + done, sizeof (buf) - done);
          if (res <= 0)
            {
              if (res < 0)
                {
                  _gnutls_debug_log ("Failed to read egd.\n");
                }
              else
                {
                  _gnutls_debug_log ("Failed to read egd: end of file\n");
                }

              return gnutls_assert_val(GNUTLS_E_RANDOM_DEVICE_ERROR);
            }
          done += res;
        }

      memcpy(&device_last_read, &current_time, sizeof(device_last_read));
      return yarrow256_update (&yctx, RANDOM_SOURCE_DEVICE, read_size * 8 / 2,
                               read_size, buf);
    }
  return 0;
}

static int
do_device_source (int init)
{
  int ret;
  static int (*do_source) (int init) = NULL;
/* using static var here is ok since we are
 * always called with mutexes down 
 */
  if (init == 1)
    {
#ifdef HAVE_GETPID
      pid = getpid();
#endif

      do_source = do_device_source_urandom;
      ret = do_source (init);
      if (ret < 0)
        {
          do_source = do_device_source_egd;
          ret = do_source (init);
        }

      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      return ret;
    }
  else
    {
      ret = do_source (init);
      
      return ret;
    }
}


static void
wrap_nettle_rnd_deinit (void *ctx)
{
  RND_LOCK;
  close (device_fd);
  RND_UNLOCK;

  gnutls_mutex_deinit (&rnd_mutex);
  rnd_mutex = NULL;
}

#endif


/* API functions */

static int
wrap_nettle_rnd_init (void **ctx)
{
  int ret;

  ret = gnutls_mutex_init (&rnd_mutex);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  yarrow256_init (&yctx, SOURCES, ysources);
  gettime(&current_time);

  ret = do_device_source (1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = do_trivia_source (1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  yarrow256_slow_reseed (&yctx);

  return 0;
}


static int
wrap_nettle_rnd (void *_ctx, int level, void *data, size_t datasize)
{
  int ret, reseed = 0;

  RND_LOCK;

#ifdef HAVE_GETPID
  if (getpid() != pid) 
    { /* fork() detected */
      memset(&device_last_read, 0, sizeof(device_last_read));
      pid = getpid();
      reseed = 1;
    }
#endif

  /* update state only when having a non-nonce or if nonce
   * and nsecs%4096 == 0, i.e., one out of 4096 times called .
   *
   * The reason we do that is to avoid any delays when generating nonces.
   */
  if (level != GNUTLS_RND_NONCE || reseed != 0)
    {
      gettime(&current_time);

      ret = do_trivia_source (0);
      if (ret < 0)
        {
          RND_UNLOCK;
          gnutls_assert ();
          return ret;
        }

      ret = do_device_source (0);
      if (ret < 0)
        {
          RND_UNLOCK;
          gnutls_assert ();
          return ret;
        }

      if (reseed)
        yarrow256_slow_reseed (&yctx);
    }

  yarrow256_random (&yctx, datasize, data);
  RND_UNLOCK;
  return 0;
}

static void
wrap_nettle_rnd_refresh (void *_ctx)
{
  RND_LOCK;
  gettime(&current_time);

  do_trivia_source (0);
  do_device_source (0);

  RND_UNLOCK;
  return;
}

int crypto_rnd_prio = INT_MAX;

gnutls_crypto_rnd_st _gnutls_rnd_ops = {
  .init = wrap_nettle_rnd_init,
  .deinit = wrap_nettle_rnd_deinit,
  .rnd = wrap_nettle_rnd,
  .rnd_refresh = wrap_nettle_rnd_refresh,
};
