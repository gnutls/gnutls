/*
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "brotlienc.h"

#if defined(GNUTLS_BROTLIENC_ENABLE_DLOPEN) && GNUTLS_BROTLIENC_ENABLE_DLOPEN

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>

/* If BROTLIENC_LIBRARY_SONAME_UNUSED is defined, dlopen handle can be automatically
 * set; otherwise, the caller needs to call
 * gnutls_brotlienc_ensure_library with soname determined at run time.
 */
#ifdef BROTLIENC_LIBRARY_SONAME_UNUSED

static void
ensure_library (void)
{
  if (gnutls_brotlienc_ensure_library (BROTLIENC_LIBRARY_SONAME_UNUSED, RTLD_LAZY | RTLD_LOCAL) < 0)
    abort ();
}

#if defined(GNUTLS_BROTLIENC_ENABLE_PTHREAD) && GNUTLS_BROTLIENC_ENABLE_PTHREAD
#include <pthread.h>

static pthread_once_t dlopen_once = PTHREAD_ONCE_INIT;

#define ENSURE_LIBRARY pthread_once(&dlopen_once, ensure_library)

#else /* GNUTLS_BROTLIENC_ENABLE_PTHREAD */

#define ENSURE_LIBRARY do {	    \
    if (!gnutls_brotlienc_dlhandle) \
      ensure_library();		    \
  } while (0)

#endif /* !GNUTLS_BROTLIENC_ENABLE_PTHREAD */

#else /* BROTLIENC_LIBRARY_SONAME_UNUSED */

#define ENSURE_LIBRARY do {} while (0)

#endif /* !BROTLIENC_LIBRARY_SONAME_UNUSED */

static void *gnutls_brotlienc_dlhandle;

/* Define redirection symbols */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#if (2 <= __GNUC__ || (4 <= __clang_major__))
#define FUNC(ret, name, args, cargs)			\
  static __typeof__(name)(*gnutls_brotlienc_sym_##name);
#else
#define FUNC(ret, name, args, cargs)		\
  static ret(*gnutls_brotlienc_sym_##name)args;
#endif
#define VOID_FUNC FUNC
#include "brotliencfuncs.h"
#undef VOID_FUNC
#undef FUNC

#pragma GCC diagnostic pop

/* Define redirection wrapper functions */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#define FUNC(ret, name, args, cargs)        \
ret gnutls_brotlienc_func_##name args           \
{					    \
  ENSURE_LIBRARY;			    \
  assert (gnutls_brotlienc_sym_##name);	    \
  return gnutls_brotlienc_sym_##name cargs;	    \
}
#define VOID_FUNC(ret, name, args, cargs)   \
ret gnutls_brotlienc_func_##name args           \
{					    \
  ENSURE_LIBRARY;			    \
  assert (gnutls_brotlienc_sym_##name);	    \
  gnutls_brotlienc_sym_##name cargs;		    \
}
#include "brotliencfuncs.h"
#undef VOID_FUNC
#undef FUNC

#pragma GCC diagnostic pop

static int
ensure_symbol (const char *name, void **symp)
{
  if (!*symp)
    {
      void *sym = dlsym (gnutls_brotlienc_dlhandle, name);
      if (!sym)
	return -EINVAL;
      *symp = sym;
    }
  return 0;
}

int
gnutls_brotlienc_ensure_library (const char *soname, int flags)
{
  int err;

  if (!gnutls_brotlienc_dlhandle)
    {
      gnutls_brotlienc_dlhandle = dlopen (soname, flags);
      if (!gnutls_brotlienc_dlhandle)
	return -EINVAL;
    }

#define ENSURE_SYMBOL(name)					\
  ensure_symbol(#name, (void **)&gnutls_brotlienc_sym_##name)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#define FUNC(ret, name, args, cargs)		\
  err = ENSURE_SYMBOL(name);			\
  if (err < 0)					\
    {						\
      dlclose (gnutls_brotlienc_dlhandle);	\
      gnutls_brotlienc_dlhandle = NULL;		\
      return err;				\
    }
#define VOID_FUNC FUNC
#include "brotliencfuncs.h"
#undef VOID_FUNC
#undef FUNC

#pragma GCC diagnostic pop

#undef ENSURE_SYMBOL
  return 0;
}

void
gnutls_brotlienc_unload_library (void)
{
  if (gnutls_brotlienc_dlhandle)
    {
      dlclose (gnutls_brotlienc_dlhandle);
      gnutls_brotlienc_dlhandle = NULL;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#define FUNC(ret, name, args, cargs)		\
  gnutls_brotlienc_sym_##name = NULL;
#define VOID_FUNC FUNC
#include "brotliencfuncs.h"
#undef VOID_FUNC
#undef FUNC

#pragma GCC diagnostic pop
}

unsigned
gnutls_brotlienc_is_usable (void)
{
  return gnutls_brotlienc_dlhandle != NULL;
}

#else /* GNUTLS_BROTLIENC_ENABLE_DLOPEN */

int
gnutls_brotlienc_ensure_library (const char *soname, int flags)
{
  (void) soname;
  (void) flags;
  return 0;
}

void
gnutls_brotlienc_unload_library (void)
{
}

unsigned
gnutls_brotlienc_is_usable (void)
{
  /* The library is linked at build time, thus always usable */
  return 1;
}

#endif /* !GNUTLS_BROTLIENC_ENABLE_DLOPEN */
