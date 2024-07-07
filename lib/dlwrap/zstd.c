/*
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "zstd.h"

#if defined(GNUTLS_ZSTD_ENABLE_DLOPEN) && GNUTLS_ZSTD_ENABLE_DLOPEN

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>

/* If ZSTD_LIBRARY_SONAME is defined, dlopen handle can be automatically
 * set; otherwise, the caller needs to call
 * gnutls_zstd_ensure_library with soname determined at run time.
 */
#ifdef ZSTD_LIBRARY_SONAME

static void
ensure_library (void)
{
  if (gnutls_zstd_ensure_library (ZSTD_LIBRARY_SONAME, RTLD_LAZY | RTLD_LOCAL) < 0)
    abort ();
}

#if defined(GNUTLS_ZSTD_ENABLE_PTHREAD) && GNUTLS_ZSTD_ENABLE_PTHREAD
#include <pthread.h>

static pthread_once_t dlopen_once = PTHREAD_ONCE_INIT;

#define ENSURE_LIBRARY pthread_once(&dlopen_once, ensure_library)

#else /* GNUTLS_ZSTD_ENABLE_PTHREAD */

#define ENSURE_LIBRARY do {	    \
    if (!gnutls_zstd_dlhandle) \
      ensure_library();		    \
  } while (0)

#endif /* !GNUTLS_ZSTD_ENABLE_PTHREAD */

#else /* ZSTD_LIBRARY_SONAME */

#define ENSURE_LIBRARY do {} while (0)

#endif /* !ZSTD_LIBRARY_SONAME */

static void *gnutls_zstd_dlhandle;

/* Define redirection symbols */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#if (2 <= __GNUC__ || (4 <= __clang_major__))
#define FUNC(ret, name, args, cargs)			\
  static __typeof__(name)(*gnutls_zstd_sym_##name);
#else
#define FUNC(ret, name, args, cargs)		\
  static ret(*gnutls_zstd_sym_##name)args;
#endif
#define VOID_FUNC FUNC
#include "zstdfuncs.h"
#undef VOID_FUNC
#undef FUNC

#pragma GCC diagnostic pop

/* Define redirection wrapper functions */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#define FUNC(ret, name, args, cargs)        \
ret gnutls_zstd_func_##name args           \
{					    \
  ENSURE_LIBRARY;			    \
  assert (gnutls_zstd_sym_##name);	    \
  return gnutls_zstd_sym_##name cargs;	    \
}
#define VOID_FUNC(ret, name, args, cargs)   \
ret gnutls_zstd_func_##name args           \
{					    \
  ENSURE_LIBRARY;			    \
  assert (gnutls_zstd_sym_##name);	    \
  gnutls_zstd_sym_##name cargs;		    \
}
#include "zstdfuncs.h"
#undef VOID_FUNC
#undef FUNC

#pragma GCC diagnostic pop

static int
ensure_symbol (const char *name, void **symp)
{
  if (!*symp)
    {
      void *sym = dlsym (gnutls_zstd_dlhandle, name);
      if (!sym)
	return -errno;
      *symp = sym;
    }
  return 0;
}

int
gnutls_zstd_ensure_library (const char *soname, int flags)
{
  int err;

  if (!gnutls_zstd_dlhandle)
    {
      gnutls_zstd_dlhandle = dlopen (soname, flags);
      if (!gnutls_zstd_dlhandle)
	return -errno;
    }

#define ENSURE_SYMBOL(name)					\
  ensure_symbol(#name, (void **)&gnutls_zstd_sym_##name)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#define FUNC(ret, name, args, cargs)	\
  err = ENSURE_SYMBOL(name);		\
  if (err < 0)				\
    return err;
#define VOID_FUNC FUNC
#include "zstdfuncs.h"
#undef VOID_FUNC
#undef FUNC

#pragma GCC diagnostic pop

#undef ENSURE_SYMBOL
  return 0;
}

void
gnutls_zstd_unload_library (void)
{
  if (gnutls_zstd_dlhandle)
    dlclose (gnutls_zstd_dlhandle);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#define FUNC(ret, name, args, cargs)		\
  gnutls_zstd_sym_##name = NULL;
#define VOID_FUNC FUNC
#include "zstdfuncs.h"
#undef VOID_FUNC
#undef FUNC

#pragma GCC diagnostic pop

#undef RESET_SYMBOL
}

#else /* GNUTLS_ZSTD_ENABLE_DLOPEN */

int
gnutls_zstd_ensure_library (const char *soname, int flags)
{
  (void) soname;
  (void) flags;
  return 0;
}

void
gnutls_zstd_unload_library (void)
{
}

#endif /* !GNUTLS_ZSTD_ENABLE_DLOPEN */
