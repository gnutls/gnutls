/* EINA - EFL data type library
 * Copyright (C) 2007-2009 Jorge Luis Zapata Muga, Cedric Bail, Andre Dieb
 * Martins
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;
 * if not, see <https://www.gnu.org/licenses/>.
 */


/**
 * @page tutorial_log_page Log Tutorial
 *
 * @section tutorial_log_introduction Introduction
 *
 * The Eina Log module provides logging facilities for libraries and
 * applications. It provides colored logging, basic logging levels (error,
 * warning, debug, info, critical) and loggers - called logging domains -
 * which will be covered on next sections.
 *
 * @section tutorial_log_basic_usage Basic Usage
 *
 * Log messages can be displayed using the following macros:
 *
 * @li EINA_LOG_ERR(),
 * @li EINA_LOG_INFO(),
 * @li EINA_LOG_WARN(),
 * @li EINA_LOG_DBG().
 *
 * Here is an example:
 *
 * @code
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * #include <Eina.h>
 *
 * void test(int i)
 * {
 *    EINA_LOG_DBG("Entering test");
 *
 *    if (i < 0)
 *    {
 *        EINA_LOG_ERR("Argument is negative");
 *        return;
 *    }
 *
 *    EINA_LOG_INFO("argument non negative");
 *
 *    EINA_LOG_DBG("Exiting test");
 * }
 *
 * int main(void)
 * {
 *    if (!eina_init())
 *    {
 *        printf("log during the initialization of Eina_Log module\n");
 *        return EXIT_FAILURE;
 *    }
 *
 *    test(-1);
 *    test(0);
 *
 *    eina_shutdown();
 *
 *    return EXIT_SUCCESS;
 * }
 * @endcode
 *
 * If you compiled Eina without debug mode, execution will yield only one log
 * message, which is "argument is negative".
 *
 * Here we introduce the concept of logging domains (or loggers), which might
 * already be familiar to readers. It is basically a way to separate a set of
 * log messages into a context (e.g. a module) and provide a way of controlling
 * this set as a whole.
 *
 * For example, suppose you have 3 different modules on your application and you
 * want to get logging only from one of them (e.g. create some sort of filter).
 * For achieving that, all you need to do is create a logging domain for each
 * module so that all logging inside a module can be considered as a whole.
 *
 * Logging domains are specified by a name, color applied to the name and the
 * level. The first two (name and color) are set through code, that is, inside
 * your application/module/library.
 *
 * The level is used for controlling which messages should appear. It
 * specifies the lowest level that should be displayed (e.g. a message
 * with level 11 being logged on a domain with level set to 10 would be
 * displayed, while a message with level 9 wouldn't).
 *
 * The domain level is set during runtime (in contrast with the name and
 * color) through the environment variable EINA_LOG_LEVELS. This variable
 * expects a list in the form domain_name1:level1,domain_name2:level2,... . For
 * example:
 *
 * @code
 *
 * EINA_LOG_LEVELS=mymodule1:5,mymodule2:2,mymodule3:0 ./myapp
 *
 * @endcode
 *
 * This line would set mymodule1 level to 5, mymodule2 level to 2 and mymodule3
 * level to 0.
 *
 *
 * There's also a global logger to which EINA_LOG_(ERR, DBG, INFO, CRIT, WARN)
 * macros do log on. It is a logger that is created internally by Eina Log with
 * an empty name and can be used for general logging (where logging domains do
 * not apply).
 *
 * Since this global logger doesn't have a name, you can't set its level through
 * EINA_LOG_LEVELS variable. Here we introduce a second environment variable
 * that is a bit more special: EINA_LOG_LEVEL.
 *
 * This variable specifies the level of the global logging domain and the level
 * of domains that haven't been set through EINA_LOG_LEVELS. Here's an example:
 *
 * @code
 *
 * EINA_LOG_LEVEL=3 EINA_LOG_LEVELS=module1:10,module3:2 ./myapp
 *
 * @endcode
 *
 * Supposing you have modules named "module1", "module2" and "module3", this
 * line would result in module1 with level 10, module2 with level 3 and module3
 * with level 2. Note that module2's level wasn't specified, so it's level is
 * set to the global level. This way we can easily apply filters to multiple
 * domains with only one parameter (EINA_LOG_LEVEL=num).
 *
 * The global level (EINA_LOG_LEVEL) can also be set through code, using
 * eina_log_level_set() function.
 *
 *
 * While developing your libraries or applications, you may notice that
 * EINA_LOG_DOM_(ERR, DBG, INFO, CRIT, WARN) macros also print out
 * messages from eina itself. Here we introduce another environment variable
 * that is a bit more special: EINA_LOG_LEVELS_GLOB.
 *
 * This variable allows you to disable the logging of any/all code in eina itself.
 * This is useful when developing your libraries or applications so that you can
 * see your own domain's messages easier without having to sift through a lot of
 * internal eina debug messages. Here's an example:
 *
 * @code
 *
 * EINA_LOG_LEVEL=3 EINA_LOG_LEVELS_GLOB=eina_*:0 ./myapp
 *
 * @endcode
 *
 * This will disable eina_log output from all internal eina code thus allowing
 * you to see your own domain messages easier.
 *
 * @section tutorial_log_advanced_display Advanced usage of print callbacks
 *
 * The log module allows the user to change the way
 * eina_log_print() displays the messages. It suffices to pass to
 * eina_log_print_cb_set() the function used to display the
 * message. That  function must be of type #Eina_Log_Print_Cb. As a
 * custom data can be passed to that callback, powerful display
 * messages can be displayed.
 *
 * It is suggested to not use __FILE__, __FUNCTION__ or __LINE__ when
 * writing that callback, but when defining macros (like
 * EINA_LOG_ERR() and other macros).
 *
 * Here is an example of custom callback, whose behavior can be
 * changed at runtime:
 *
 * @code
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * #include <eina_log.h>
 *
 * #define log(fmt, ...)                                    \
 *    eina_log_print(EINA_LOG_LEVEL_ERR, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
 *
 * typedef struct _Data Data;
 *
 * struct _Data
 * {
 *    int to_stderr;
 * };
 *
 * void print_cb(const Eina_Log_Domain *domain,
 *               Eina_Log_Level level,
 *               const char *file,
 *               const char *fnc,
 *               int line,
 *               const char *fmt,
 *               void *data,
 *               va_list args)
 * {
 *    Data *d;
 *    FILE *output;
 *    char *str;
 *
 *    d = (Data *)data;
 *    if (d->to_stderr)
 *    {
 *       output = stderr;
 *       str = "stderr";
 *    }
 *    else
 *    {
 *       output = stdout;
 *       str = "stdout";
 *    }
 *
 *    fprintf(output, "%s:%s:%s (%d) %s: ",
 *            domain->domain_str, file, fnc, line, str);
 *    vfprintf(output, fmt, args);
 *    putc('\n', output);
 * }
 *
 * void test(Data *data, int i)
 * {
 *    if (i < 0)
 *       data->to_stderr = 0;
 *    else
 *       data->to_stderr = 1;
 *
 *    log("log message...");
 * }
 *
 * int main(void)
 * {
 *    Data data;
 *
 *    if (!eina_init())
 *    {
 *       printf("log during the initialization of Eina_Log module\n");
 *       return EXIT_FAILURE;
 *    }
 *
 *    eina_log_print_cb_set(print_cb, &data);
 *
 *    test(&data, -1);
 *    test(&data, 0);
 *
 *    eina_shutdown();
 *
 *    return EXIT_SUCCESS;
 * }
 * @endcode
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fnmatch.h>
#include <assert.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

#ifdef EFL_HAVE_POSIX_THREADS
#include <pthread.h>
#endif

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "eina_config.h"
#include "eina_private.h"
#include "eina_inlist.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_log.h"

/* TODO
 * + printing logs to stdout or stderr can be implemented
 * using a queue, useful for multiple threads printing
 * + add a wrapper for assert?
 */

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

#define EINA_LOG_ENV_ABORT "EINA_LOG_ABORT"
#define EINA_LOG_ENV_ABORT_LEVEL "EINA_LOG_ABORT_LEVEL"
#define EINA_LOG_ENV_LEVEL "EINA_LOG_LEVEL"
#define EINA_LOG_ENV_LEVELS "EINA_LOG_LEVELS"
#define EINA_LOG_ENV_LEVELS_GLOB "EINA_LOG_LEVELS_GLOB"
#define EINA_LOG_ENV_COLOR_DISABLE "EINA_LOG_COLOR_DISABLE"
#define EINA_LOG_ENV_FILE_DISABLE "EINA_LOG_FILE_DISABLE"
#define EINA_LOG_ENV_FUNCTION_DISABLE "EINA_LOG_FUNCTION_DISABLE"


// Structure for storing domain level settings passed from the command line
// that will be matched with application-defined domains.
typedef struct _Eina_Log_Domain_Level_Pending
    Eina_Log_Domain_Level_Pending;
struct _Eina_Log_Domain_Level_Pending {
	EINA_INLIST;
	unsigned int level;
	size_t namelen;
	char name[];
};

/*
 * List of levels for domains set by the user before the domains are registered,
 * updates the domain levels on the first log and clears itself.
 */
static Eina_Inlist *_pending_list = NULL;
static Eina_Inlist *_glob_list = NULL;

// Disable color flag (can be changed through the env var
// EINA_LOG_ENV_COLOR_DISABLE).
static Eina_Bool _disable_color = EINA_FALSE;
static Eina_Bool _disable_file = EINA_FALSE;
static Eina_Bool _disable_function = EINA_FALSE;
static Eina_Bool _abort_on_critical = EINA_FALSE;
static int _abort_level_on_critical = EINA_LOG_LEVEL_CRITICAL;

#ifdef EFL_HAVE_THREADS

static Eina_Bool _threads_enabled = EINA_FALSE;

#ifdef EFL_HAVE_POSIX_THREADS

typedef pthread_t Thread;

static pthread_t _main_thread;

#define SELF() pthread_self()
#define IS_MAIN(t)  pthread_equal(t, _main_thread)
#define IS_OTHER(t) EINA_UNLIKELY(!IS_MAIN(t))
#define CHECK_MAIN(...)                                         \
   do {                                                           \
      if (!IS_MAIN(pthread_self())) {                             \
         fprintf(stderr,                                          \
                 "ERR: not main thread! current=%lu, main=%lu\n", \
                 (unsigned long)pthread_self(),                   \
                 (unsigned long)_main_thread);                    \
         return __VA_ARGS__;                                      \
      }                                                           \
   } while (0)

#ifdef EFL_HAVE_POSIX_THREADS_SPINLOCK

static pthread_spinlock_t _log_lock;
#define LOG_LOCK()                                                  \
   if (_threads_enabled)                                               \
         do {                                                          \
            if (0) {                                                   \
               fprintf(stderr, "+++LOG LOG_LOCKED!   [%s, %lu]\n",     \
                       __FUNCTION__, (unsigned long)pthread_self()); } \
            if (EINA_UNLIKELY(_threads_enabled)) {                     \
               pthread_spin_lock(&_log_lock); }                        \
         } while (0)
#define LOG_UNLOCK()                                                \
   if (_threads_enabled)                                               \
         do {                                                          \
            if (EINA_UNLIKELY(_threads_enabled)) {                     \
               pthread_spin_unlock(&_log_lock); }                      \
            if (0) {                                                   \
               fprintf(stderr,                                         \
                       "---LOG LOG_UNLOCKED! [%s, %lu]\n",             \
                       __FUNCTION__, (unsigned long)pthread_self()); } \
         } while (0)
#define INIT() pthread_spin_init(&_log_lock, PTHREAD_PROCESS_PRIVATE)
#define SHUTDOWN() pthread_spin_destroy(&_log_lock)

#else				/* ! EFL_HAVE_POSIX_THREADS_SPINLOCK */

static pthread_mutex_t _log_mutex = PTHREAD_MUTEX_INITIALIZER;
#define LOG_LOCK() if(_threads_enabled) {pthread_mutex_lock(&_log_mutex); }
#define LOG_UNLOCK() if(_threads_enabled) {pthread_mutex_unlock(&_log_mutex); }
#define INIT() (1)
#define SHUTDOWN() do {} while (0)

#endif				/* ! EFL_HAVE_POSIX_THREADS_SPINLOCK */

#else				/* EFL_HAVE_WIN32_THREADS */

typedef DWORD Thread;

static DWORD _main_thread;

#define SELF() GetCurrentThreadId()
#define IS_MAIN(t)  (t == _main_thread)
#define IS_OTHER(t) EINA_UNLIKELY(!IS_MAIN(t))
#define CHECK_MAIN(...)                                         \
   do {                                                           \
      if (!IS_MAIN(GetCurrentThreadId())) {                       \
         fprintf(stderr,                                          \
                 "ERR: not main thread! current=%lu, main=%lu\n", \
                 GetCurrentThreadId(), _main_thread);             \
         return __VA_ARGS__;                                      \
      }                                                           \
   } while (0)

static HANDLE _log_mutex = NULL;

#define LOG_LOCK() if(_threads_enabled) WaitForSingleObject(_log_mutex, INFINITE)
#define LOG_UNLOCK() if(_threads_enabled) ReleaseMutex(_log_mutex)
#define INIT() ((_log_mutex = CreateMutex(NULL, FALSE, NULL)) ? 1 : 0)
#define SHUTDOWN()  if (_log_mutex) CloseHandle(_log_mutex)

#endif				/* EFL_HAVE_WIN32_THREADS */

#else				/* ! EFL_HAVE_THREADS */

#define LOG_LOCK() do {} while (0)
#define LOG_UNLOCK() do {} while (0)
#define IS_MAIN(t)  (1)
#define IS_OTHER(t) (0)
#define CHECK_MAIN(...) do {} while (0)
#define INIT() (1)
#define SHUTDOWN() do {} while (0)

#endif				/* ! EFL_HAVE_THREADS */


// List of domains registered
static Eina_Log_Domain *_log_domains = NULL;
static unsigned int _log_domains_count = 0;
static size_t _log_domains_allocated = 0;

// Default function for printing on domains
static Eina_Log_Print_Cb _print_cb = eina_log_print_cb_stderr;
static void *_print_cb_data = NULL;

#ifdef DEBUG
static Eina_Log_Level _log_level = EINA_LOG_LEVEL_DBG;
#elif DEBUG_CRITICAL
static Eina_Log_Level _log_level = EINA_LOG_LEVEL_CRITICAL;
#else
static Eina_Log_Level _log_level = EINA_LOG_LEVEL_ERR;
#endif

/* NOTE: if you change this, also change:
 *   eina_log_print_level_name_get()
 *   eina_log_print_level_name_color_get()
 */
static const char *_names[] = {
	"CRI",
	"ERR",
	"WRN",
	"INF",
	"DBG",
};

#ifdef _WIN32
static int eina_log_win32_color_get(const char *domain_str)
{
	char *str;
	char *tmp;
	char *tmp2;
	int code = -1;
	int lighted = 0;
	int ret = 0;

	str = strdup(domain_str);
	if (!str)
		return 0;

	/* this should not append */
	if (str[0] != '\033') {
		free(str);
		return 0;
	}

	/* we skip the first char and the [ */
	tmp = tmp2 = str + 2;
	while (*tmp != 'm') {
		if (*tmp == ';') {
			*tmp = '\0';
			code = atol(tmp2);
			tmp++;
			tmp2 = tmp;
		}

		tmp++;
	}
	*tmp = '\0';
	if (code < 0)
		code = atol(tmp2);
	else
		lighted = atol(tmp2);

	free(str);

	if (code < lighted) {
		int c;

		c = code;
		code = lighted;
		lighted = c;
	}

	if (lighted)
		ret = FOREGROUND_INTENSITY;

	if (code == 31)
		ret |= FOREGROUND_RED;
	else if (code == 32)
		ret |= FOREGROUND_GREEN;
	else if (code == 33)
		ret |= FOREGROUND_RED | FOREGROUND_GREEN;
	else if (code == 34)
		ret |= FOREGROUND_BLUE;
	else if (code == 36)
		ret |= FOREGROUND_GREEN | FOREGROUND_BLUE;
	else if (code == 37)
		ret |= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

	return ret;
}
#endif

static inline void
eina_log_print_level_name_get(int level, const char **p_name)
{
	static char buf[4];
	/* NOTE: if you change this, also change
	 *    eina_log_print_level_name_color_get()
	 *    eina_log_level_name_get() (at eina_inline_log.x)
	 */
	if (EINA_UNLIKELY(level < 0)) {
		snprintf(buf, sizeof(buf), "%03d", level);
		*p_name = buf;
	} else if (EINA_UNLIKELY(level >= EINA_LOG_LEVELS)) {
		snprintf(buf, sizeof(buf), "%03d", level);
		*p_name = buf;
	} else
		*p_name = _names[level];
}

#ifdef _WIN32
static inline void
eina_log_print_level_name_color_get(int level,
				    const char **p_name, int *p_color)
{
	static char buf[4];
	/* NOTE: if you change this, also change:
	 *   eina_log_print_level_name_get()
	 */
	if (EINA_UNLIKELY(level < 0)) {
		snprintf(buf, sizeof(buf), "%03d", level);
		*p_name = buf;
	} else if (EINA_UNLIKELY(level >= EINA_LOG_LEVELS)) {
		snprintf(buf, sizeof(buf), "%03d", level);
		*p_name = buf;
	} else
		*p_name = _names[level];

	*p_color =
	    eina_log_win32_color_get(eina_log_level_color_get(level));
}
#else
static inline void
eina_log_print_level_name_color_get(int level,
				    const char **p_name,
				    const char **p_color)
{
	static char buf[4];
	/* NOTE: if you change this, also change:
	 *   eina_log_print_level_name_get()
	 */
	if (EINA_UNLIKELY(level < 0)) {
		snprintf(buf, sizeof(buf), "%03d", level);
		*p_name = buf;
	} else if (EINA_UNLIKELY(level >= EINA_LOG_LEVELS)) {
		snprintf(buf, sizeof(buf), "%03d", level);
		*p_name = buf;
	} else
		*p_name = _names[level];

	*p_color = eina_log_level_color_get(level);
}
#endif

#define DECLARE_LEVEL_NAME(level) const char *name; \
   eina_log_print_level_name_get(level, &name)
#ifdef _WIN32
#define DECLARE_LEVEL_NAME_COLOR(level) const char *name; int color; \
   eina_log_print_level_name_color_get(level, &name, &color)
#else
#define DECLARE_LEVEL_NAME_COLOR(level) const char *name, *color; \
   eina_log_print_level_name_color_get(level, &name, &color)
#endif

/** No threads, No color */
static void
eina_log_print_prefix_NOthreads_NOcolor_file_func(FILE * fp,
						  const Eina_Log_Domain *
						  d, Eina_Log_Level level,
						  const char *file,
						  const char *fnc,
						  int line)
{
	DECLARE_LEVEL_NAME(level);
	fprintf(fp, "%s:%s %s:%d %s() ", name, d->domain_str, file, line,
		fnc);
}

static void
eina_log_print_prefix_NOthreads_NOcolor_NOfile_func(FILE * fp,
						    const Eina_Log_Domain *
						    d,
						    Eina_Log_Level level,
						    const char *file
						    __UNUSED__,
						    const char *fnc,
						    int line __UNUSED__)
{
	DECLARE_LEVEL_NAME(level);
	fprintf(fp, "%s:%s %s() ", name, d->domain_str, fnc);
}

static void
eina_log_print_prefix_NOthreads_NOcolor_file_NOfunc(FILE * fp,
						    const Eina_Log_Domain *
						    d,
						    Eina_Log_Level level,
						    const char *file,
						    const char *fnc
						    __UNUSED__, int line)
{
	DECLARE_LEVEL_NAME(level);
	fprintf(fp, "%s:%s %s:%d ", name, d->domain_str, file, line);
}

/* No threads, color */
static void
eina_log_print_prefix_NOthreads_color_file_func(FILE * fp,
						const Eina_Log_Domain * d,
						Eina_Log_Level level,
						const char *file,
						const char *fnc, int line)
{
	DECLARE_LEVEL_NAME_COLOR(level);
#ifdef _WIN32
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
	fprintf(fp, "%s", name);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_RED | FOREGROUND_GREEN |
				FOREGROUND_BLUE);
	fprintf(fp, ":");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				eina_log_win32_color_get(d->domain_str));
	fprintf(fp, "%s", d->name);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_RED | FOREGROUND_GREEN |
				FOREGROUND_BLUE);
	fprintf(fp, " %s:%d ", file, line);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_INTENSITY | FOREGROUND_RED |
				FOREGROUND_GREEN | FOREGROUND_BLUE);
	fprintf(fp, "%s()", fnc);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_RED | FOREGROUND_GREEN |
				FOREGROUND_BLUE);
	fprintf(fp, " ");
#else
	fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s %s:%d "
		EINA_COLOR_HIGH "%s()" EINA_COLOR_RESET " ",
		color, name, d->domain_str, file, line, fnc);
#endif
}

static void
eina_log_print_prefix_NOthreads_color_NOfile_func(FILE * fp,
						  const Eina_Log_Domain *
						  d, Eina_Log_Level level,
						  const char *file
						  __UNUSED__,
						  const char *fnc,
						  int line __UNUSED__)
{
	DECLARE_LEVEL_NAME_COLOR(level);
#ifdef _WIN32
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
	fprintf(fp, "%s", name);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_RED | FOREGROUND_GREEN |
				FOREGROUND_BLUE);
	fprintf(fp, ":");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				eina_log_win32_color_get(d->domain_str));
	fprintf(fp, "%s", d->name);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_INTENSITY | FOREGROUND_RED |
				FOREGROUND_GREEN | FOREGROUND_BLUE);
	fprintf(fp, "%s()", fnc);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_RED | FOREGROUND_GREEN |
				FOREGROUND_BLUE);
	fprintf(fp, " ");
#else
	fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s "
		EINA_COLOR_HIGH "%s()" EINA_COLOR_RESET " ",
		color, name, d->domain_str, fnc);
#endif
}

static void
eina_log_print_prefix_NOthreads_color_file_NOfunc(FILE * fp,
						  const Eina_Log_Domain *
						  d, Eina_Log_Level level,
						  const char *file,
						  const char *fnc
						  __UNUSED__, int line)
{
	DECLARE_LEVEL_NAME_COLOR(level);
#ifdef _WIN32
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
	fprintf(fp, "%s", name);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_RED | FOREGROUND_GREEN |
				FOREGROUND_BLUE);
	fprintf(fp, ":");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				eina_log_win32_color_get(d->domain_str));
	fprintf(fp, "%s", d->name);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
				FOREGROUND_RED | FOREGROUND_GREEN |
				FOREGROUND_BLUE);
	fprintf(fp, " %s:%d ", file, line);
#else
	fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s %s:%d ",
		color, name, d->domain_str, file, line);
#endif
}

/** threads, No color */
#ifdef EFL_HAVE_THREADS
static void
eina_log_print_prefix_threads_NOcolor_file_func(FILE * fp,
						const Eina_Log_Domain * d,
						Eina_Log_Level level,
						const char *file,
						const char *fnc, int line)
{
	Thread cur;

	DECLARE_LEVEL_NAME(level);
	cur = SELF();
	if (IS_OTHER(cur)) {
		fprintf(fp, "%s:%s[T:%lu] %s:%d %s() ",
			name, d->domain_str, (unsigned long) cur, file,
			line, fnc);
		return;
	}

	fprintf(fp, "%s:%s %s:%d %s() ", name, d->domain_str, file, line,
		fnc);
}

static void
eina_log_print_prefix_threads_NOcolor_NOfile_func(FILE * fp,
						  const Eina_Log_Domain *
						  d, Eina_Log_Level level,
						  const char *file
						  __UNUSED__,
						  const char *fnc,
						  int line __UNUSED__)
{
	Thread cur;

	DECLARE_LEVEL_NAME(level);
	cur = SELF();
	if (IS_OTHER(cur)) {
		fprintf(fp, "%s:%s[T:%lu] %s() ",
			name, d->domain_str, (unsigned long) cur, fnc);
		return;
	}

	fprintf(fp, "%s:%s %s() ", name, d->domain_str, fnc);
}

static void
eina_log_print_prefix_threads_NOcolor_file_NOfunc(FILE * fp,
						  const Eina_Log_Domain *
						  d, Eina_Log_Level level,
						  const char *file,
						  const char *fnc
						  __UNUSED__, int line)
{
	Thread cur;

	DECLARE_LEVEL_NAME(level);
	cur = SELF();
	if (IS_OTHER(cur)) {
		fprintf(fp, "%s:%s[T:%lu] %s:%d ",
			name, d->domain_str, (unsigned long) cur, file,
			line);
		return;
	}

	fprintf(fp, "%s:%s %s:%d ", name, d->domain_str, file, line);
}

/* threads, color */
static void
eina_log_print_prefix_threads_color_file_func(FILE * fp,
					      const Eina_Log_Domain * d,
					      Eina_Log_Level level,
					      const char *file,
					      const char *fnc, int line)
{
	Thread cur;

	DECLARE_LEVEL_NAME_COLOR(level);
	cur = SELF();
	if (IS_OTHER(cur)) {
#ifdef _WIN32
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					color);
		fprintf(fp, "%s", name);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, ":");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					eina_log_win32_color_get(d->
								 domain_str));
		fprintf(fp, "%s[T:", d->name);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "[T:");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "%lu", (unsigned long) cur);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "] %s:%d ", file, line);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_INTENSITY |
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "%s()", fnc);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, " ");
#else
		fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s[T:"
			EINA_COLOR_ORANGE "%lu" EINA_COLOR_RESET "] %s:%d "
			EINA_COLOR_HIGH "%s()" EINA_COLOR_RESET " ",
			color, name, d->domain_str, (unsigned long) cur,
			file, line, fnc);
#endif
		return;
	}
#ifdef _WIN32
	eina_log_print_prefix_NOthreads_color_file_func(fp,
							d,
							level,
							file, fnc, line);
#else
	fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s %s:%d "
		EINA_COLOR_HIGH "%s()" EINA_COLOR_RESET " ",
		color, name, d->domain_str, file, line, fnc);
#endif
}

static void
eina_log_print_prefix_threads_color_NOfile_func(FILE * fp,
						const Eina_Log_Domain * d,
						Eina_Log_Level level,
						const char *file
						__UNUSED__,
						const char *fnc,
						int line __UNUSED__)
{
	Thread cur;

	DECLARE_LEVEL_NAME_COLOR(level);
	cur = SELF();
	if (IS_OTHER(cur)) {
#ifdef _WIN32
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					color);
		fprintf(fp, "%s", name);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, ":");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					eina_log_win32_color_get(d->
								 domain_str));
		fprintf(fp, "%s[T:", d->name);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "[T:");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "%lu", (unsigned long) cur);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_INTENSITY |
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "%s()", fnc);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, " ");
#else
		fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s[T:"
			EINA_COLOR_ORANGE "%lu" EINA_COLOR_RESET "] "
			EINA_COLOR_HIGH "%s()" EINA_COLOR_RESET " ",
			color, name, d->domain_str, (unsigned long) cur,
			fnc);
#endif
		return;
	}
#ifdef _WIN32
	eina_log_print_prefix_NOthreads_color_NOfile_func(fp,
							  d,
							  level,
							  file, fnc, line);
#else
	fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s "
		EINA_COLOR_HIGH "%s()" EINA_COLOR_RESET " ",
		color, name, d->domain_str, fnc);
#endif
}

static void
eina_log_print_prefix_threads_color_file_NOfunc(FILE * fp,
						const Eina_Log_Domain * d,
						Eina_Log_Level level,
						const char *file,
						const char *fnc __UNUSED__,
						int line)
{
	Thread cur;

	DECLARE_LEVEL_NAME_COLOR(level);
	cur = SELF();
	if (IS_OTHER(cur)) {
#ifdef _WIN32
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					color);
		fprintf(fp, "%s", name);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, ":");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					eina_log_win32_color_get(d->
								 domain_str));
		fprintf(fp, "%s[T:", d->name);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "[T:");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "%lu", (unsigned long) cur);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
					FOREGROUND_RED | FOREGROUND_GREEN |
					FOREGROUND_BLUE);
		fprintf(fp, "] %s:%d ", file, line);
#else
		fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s[T:"
			EINA_COLOR_ORANGE "%lu" EINA_COLOR_RESET
			"] %s:%d ", color, name, d->domain_str,
			(unsigned long) cur, file, line);
#endif
		return;
	}
#ifdef _WIN32
	eina_log_print_prefix_NOthreads_color_file_NOfunc(fp,
							  d,
							  level,
							  file, fnc, line);
#else
	fprintf(fp, "%s%s" EINA_COLOR_RESET ":%s %s:%d ",
		color, name, d->domain_str, file, line);
#endif
}
#endif				/* EFL_HAVE_THREADS */

static void (*_eina_log_print_prefix) (FILE * fp,
				       const Eina_Log_Domain * d,
				       Eina_Log_Level level,
				       const char *file, const char *fnc,
				       int line) =
    eina_log_print_prefix_NOthreads_color_file_func;

static inline void eina_log_print_prefix_update(void)
{
	if (_disable_file && _disable_function) {
		fprintf(stderr,
			"ERROR: cannot have " EINA_LOG_ENV_FILE_DISABLE
			" and " EINA_LOG_ENV_FUNCTION_DISABLE
			" set at the same time, will "
			"just disable function.\n");
		_disable_file = 0;
	}
#define S(NOthread, NOcolor, NOfile, NOfunc) \
   _eina_log_print_prefix = \
      eina_log_print_prefix_ ## NOthread ## threads_ ## NOcolor ## color_ ## \
      NOfile \
      ## file_ ## NOfunc ## func

#ifdef EFL_HAVE_THREADS
	if (_threads_enabled) {
		if (_disable_color) {
			if (_disable_file)
				S(, NO, NO,);
			else if (_disable_function)
				S(, NO,, NO);
			else
				S(, NO,,);
		} else {
			if (_disable_file)
				S(,, NO,);
			else if (_disable_function)
				S(,,, NO);
			else
				S(,,,);
		}

		return;
	}
#endif

	if (_disable_color) {
		if (_disable_file)
			S(NO, NO, NO,);
		else if (_disable_function)
			S(NO, NO,, NO);
		else
			S(NO, NO,,);
	} else {
		if (_disable_file)
			S(NO,, NO,);
		else if (_disable_function)
			S(NO,,, NO);
		else
			S(NO,,,);
	}

#undef S
}

/*
 * Creates a colored domain name string.
 */
static const char *eina_log_domain_str_get(const char *name,
					   const char *color)
{
	const char *d;

	if (color) {
		size_t name_len;
		size_t color_len;

		name_len = strlen(name);
		color_len = strlen(color);
		d = malloc(sizeof(char) *
			   (color_len + name_len +
			    strlen(EINA_COLOR_RESET) + 1));
		if (!d)
			return NULL;

		memcpy((char *) d, color, color_len);
		memcpy((char *) (d + color_len), name, name_len);
		memcpy((char *) (d + color_len + name_len),
		       EINA_COLOR_RESET, strlen(EINA_COLOR_RESET));
		((char *) d)[color_len + name_len +
			     strlen(EINA_COLOR_RESET)] = '\0';
	} else
		d = strdup(name);

	return d;
}

/*
 * Setups a new logging domain to the name and color specified. Note that this
 * constructor acts upon an pre-allocated object.
 */
static Eina_Log_Domain *eina_log_domain_new(Eina_Log_Domain * d,
					    const char *name,
					    const char *color)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(d, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(name, NULL);

	d->level = EINA_LOG_LEVEL_UNKNOWN;
	d->deleted = EINA_FALSE;

	if (name) {
		if ((color) && (!_disable_color))
			d->domain_str =
			    eina_log_domain_str_get(name, color);
		else
			d->domain_str =
			    eina_log_domain_str_get(name, NULL);

		d->name = strdup(name);
		d->namelen = strlen(name);
	} else {
		d->domain_str = NULL;
		d->name = NULL;
		d->namelen = 0;
	}

	return d;
}

/*
 * Frees internal strings of a log domain, keeping the log domain itself as a
 * slot for next domain registers.
 */
static void eina_log_domain_free(Eina_Log_Domain * d)
{
	EINA_SAFETY_ON_NULL_RETURN(d);

	if (d->domain_str)
		free((char *) d->domain_str);

	if (d->name)
		free((char *) d->name);
}

/*
 * Parses domain levels passed through the env var.
 */
static void eina_log_domain_parse_pendings(void)
{
	const char *start;

	if (!(start = getenv(EINA_LOG_ENV_LEVELS)))
		return;

	// name1:level1,name2:level2,name3:level3,...
	while (1) {
		Eina_Log_Domain_Level_Pending *p;
		char *end = NULL;
		char *tmp = NULL;
		long int level;

		end = strchr(start, ':');
		if (!end)
			break;

		// Parse level, keep going if failed
		level = strtol((char *) (end + 1), &tmp, 10);
		if (tmp == (end + 1))
			goto parse_end;

		// Parse name
		p = malloc(sizeof(Eina_Log_Domain_Level_Pending) + end -
			   start + 1);
		if (!p)
			break;

		p->namelen = end - start;
		memcpy((char *) p->name, start, end - start);
		((char *) p->name)[end - start] = '\0';
		p->level = level;

		_pending_list =
		    eina_inlist_append(_pending_list, EINA_INLIST_GET(p));

	      parse_end:
		start = strchr(tmp, ',');
		if (start)
			start++;
		else
			break;
	}
}

static void eina_log_domain_parse_pending_globs(void)
{
	const char *start;

	if (!(start = getenv(EINA_LOG_ENV_LEVELS_GLOB)))
		return;

	// name1:level1,name2:level2,name3:level3,...
	while (1) {
		Eina_Log_Domain_Level_Pending *p;
		char *end = NULL;
		char *tmp = NULL;
		long int level;

		end = strchr(start, ':');
		if (!end)
			break;

		// Parse level, keep going if failed
		level = strtol((char *) (end + 1), &tmp, 10);
		if (tmp == (end + 1))
			goto parse_end;

		// Parse name
		p = malloc(sizeof(Eina_Log_Domain_Level_Pending) + end -
			   start + 1);
		if (!p)
			break;

		p->namelen = 0;	/* not that useful */
		memcpy((char *) p->name, start, end - start);
		((char *) p->name)[end - start] = '\0';
		p->level = level;

		_glob_list =
		    eina_inlist_append(_glob_list, EINA_INLIST_GET(p));

	      parse_end:
		start = strchr(tmp, ',');
		if (start)
			start++;
		else
			break;
	}
}

static inline int
eina_log_domain_register_unlocked(const char *name, const char *color)
{
	Eina_Log_Domain_Level_Pending *pending = NULL;
	size_t namelen;
	unsigned int i;

	for (i = 0; i < _log_domains_count; i++) {
		if (_log_domains[i].deleted) {
			// Found a flagged slot, free domain_str and replace slot
			eina_log_domain_new(&_log_domains[i], name, color);
			goto finish_register;
		}
	}

	if (_log_domains_count >= _log_domains_allocated) {
		Eina_Log_Domain *tmp;
		size_t size;

		if (!_log_domains)
			// special case for init, eina itself will allocate a dozen of domains
			size = 24;
		else
			// grow 8 buckets to minimize reallocs
			size = _log_domains_allocated + 8;

		tmp =
		    realloc(_log_domains, sizeof(Eina_Log_Domain) * size);

		if (tmp) {
			// Success!
			_log_domains = tmp;
			_log_domains_allocated = size;
		} else
			return -1;
	}
	// Use an allocated slot
	eina_log_domain_new(&_log_domains[i], name, color);
	_log_domains_count++;

      finish_register:
	namelen = _log_domains[i].namelen;

	EINA_INLIST_FOREACH(_pending_list, pending) {
		if ((namelen == pending->namelen)
		    && (strcmp(pending->name, name) == 0)) {
			_log_domains[i].level = pending->level;
			_pending_list =
			    eina_inlist_remove(_pending_list,
					       EINA_INLIST_GET(pending));
			free(pending);
			break;
		}
	}

	if (_log_domains[i].level == EINA_LOG_LEVEL_UNKNOWN) {
		EINA_INLIST_FOREACH(_glob_list, pending) {
			if (!fnmatch(pending->name, name, 0)) {
				_log_domains[i].level = pending->level;
				break;
			}
		}
	}
	// Check if level is still UNKNOWN, set it to global
	if (_log_domains[i].level == EINA_LOG_LEVEL_UNKNOWN)
		_log_domains[i].level = _log_level;

	return i;
}

static inline Eina_Bool eina_log_term_color_supported(const char *term)
{
	const char *tail;

	if (!term)
		return EINA_FALSE;

	tail = term + 1;
	switch (term[0]) {
		/* list of known to support color terminals,
		 * take from gentoo's portage.
		 */

	case 'x':		/* xterm and xterm-color */
		return ((strncmp(tail, "term", sizeof("term") - 1) == 0) &&
			((tail[sizeof("term") - 1] == '\0') ||
			 (strcmp(tail + sizeof("term") - 1, "-color") ==
			  0)));

	case 'E':		/* Eterm */
	case 'a':		/* aterm */
	case 'k':		/* kterm */
		return (strcmp(tail, "term") == 0);

	case 'r':		/* xrvt or rxvt-unicode */
		return ((strncmp(tail, "xvt", sizeof("xvt") - 1) == 0) &&
			((tail[sizeof("xvt") - 1] == '\0') ||
			 (strcmp(tail + sizeof("xvt") - 1, "-unicode") ==
			  0)));

	case 's':		/* screen */
		return (strcmp(tail, "creen") == 0);

	case 'g':		/* gnome */
		return (strcmp(tail, "nome") == 0);

	case 'i':		/* interix */
		return (strcmp(tail, "nterix") == 0);

	default:
		return EINA_FALSE;
	}
}

static inline void eina_log_domain_unregister_unlocked(int domain)
{
	Eina_Log_Domain *d;

	if ((unsigned int) domain >= _log_domains_count)
		return;

	d = &_log_domains[domain];
	eina_log_domain_free(d);
	d->deleted = 1;
}

static inline void
eina_log_print_unlocked(int domain,
			Eina_Log_Level level,
			const char *file,
			const char *fnc,
			int line, const char *fmt, va_list args)
{
	Eina_Log_Domain *d;

#ifdef EINA_SAFETY_CHECKS
	if (EINA_UNLIKELY((unsigned int) domain >= _log_domains_count) ||
	    EINA_UNLIKELY(domain < 0)) {
		if (file && fnc && fmt)
			fprintf(stderr,
				"CRI: %s:%d %s() eina_log_print() unknown domain %d, original message format '%s'\n",
				file, line, fnc, domain, fmt);
		else
			fprintf(stderr,
				"CRI: eina_log_print() unknown domain %d, original message format '%s'\n",
				domain, fmt ? fmt : "");

		if (_abort_on_critical)
			abort();

		return;
	}
#endif
	d = _log_domains + domain;
#ifdef EINA_SAFETY_CHECKS
	if (EINA_UNLIKELY(d->deleted)) {
		fprintf(stderr,
			"ERR: eina_log_print() domain %d is deleted\n",
			domain);
		return;
	}
#endif

	if (level > d->level)
		return;

#ifdef _WIN32
	{
		char *wfmt;
		char *tmp;

		wfmt = strdup(fmt);
		if (!wfmt) {
			fprintf(stderr,
				"ERR: %s: can not allocate memory\n",
				__FUNCTION__);
			return;
		}

		tmp = wfmt;
		while (strchr(tmp, "%")) {
			tmp++;
			if (*tmp == 'z')
				*tmp = 'I';
		}
		_print_cb(d, level, file, fnc, line, wfmt, _print_cb_data,
			  args);
		free(wfmt);
	}
#else
	_print_cb(d, level, file, fnc, line, fmt, _print_cb_data, args);
#endif

	if (EINA_UNLIKELY(_abort_on_critical) &&
	    EINA_UNLIKELY(level <= _abort_level_on_critical))
		abort();
}

/**
 * @endcond
 */


/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Initialize the log module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the log module of Eina. It is called by
 * eina_init().
 *
 * @see eina_init()
 *
 * @warning Not-MT: just call this function from main thread! The
 *          place where this function was called the first time is
 *          considered the main thread.
 */
Eina_Bool eina_log_init(void)
{
	const char *level, *tmp;
	int color_disable;

	assert((sizeof(_names) / sizeof(_names[0])) == EINA_LOG_LEVELS);

	if ((tmp = getenv(EINA_LOG_ENV_COLOR_DISABLE)))
		color_disable = atoi(tmp);
	else
		color_disable = -1;

	/* Check if color is explicitly disabled */
	if (color_disable == 1)
		_disable_color = EINA_TRUE;

#ifndef _WIN32
	/* color was not explicitly disabled or enabled, guess it */
	else if (color_disable == -1) {
		if (!eina_log_term_color_supported(getenv("TERM")))
			_disable_color = EINA_TRUE;
		else {
			/* if not a terminal, but redirected to a file, disable color */
			int fd;

			if (_print_cb == eina_log_print_cb_stderr)
				fd = STDERR_FILENO;
			else if (_print_cb == eina_log_print_cb_stdout)
				fd = STDOUT_FILENO;
			else
				fd = -1;

			if ((fd >= 0) && (!isatty(fd)))
				_disable_color = EINA_TRUE;
		}
	}
#endif

	if ((tmp = getenv(EINA_LOG_ENV_FILE_DISABLE)) && (atoi(tmp) == 1))
		_disable_file = EINA_TRUE;

	if ((tmp = getenv(EINA_LOG_ENV_FUNCTION_DISABLE))
	    && (atoi(tmp) == 1))
		_disable_function = EINA_TRUE;

	if ((tmp = getenv(EINA_LOG_ENV_ABORT)) && (atoi(tmp) == 1))
		_abort_on_critical = EINA_TRUE;

	if ((tmp = getenv(EINA_LOG_ENV_ABORT_LEVEL)))
		_abort_level_on_critical = atoi(tmp);

	eina_log_print_prefix_update();

	// Global log level
	if ((level = getenv(EINA_LOG_ENV_LEVEL)))
		_log_level = atoi(level);

	// Register UNKNOWN domain, the default logger
	EINA_LOG_DOMAIN_GLOBAL = eina_log_domain_register("", NULL);

	if (EINA_LOG_DOMAIN_GLOBAL < 0) {
		fprintf(stderr,
			"Failed to create global logging domain.\n");
		return EINA_FALSE;
	}
	// Parse pending domains passed through EINA_LOG_LEVELS_GLOB
	eina_log_domain_parse_pending_globs();

	// Parse pending domains passed through EINA_LOG_LEVELS
	eina_log_domain_parse_pendings();

	return EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the log module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the log module set up by
 * eina_log_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 *
 * @warning Not-MT: just call this function from main thread! The
 *          place where eina_log_init() (eina_init()) was called the
 *          first time is considered the main thread.
 */
Eina_Bool eina_log_shutdown(void)
{
	Eina_Inlist *tmp;

	while (_log_domains_count--) {
		if (_log_domains[_log_domains_count].deleted)
			continue;

		eina_log_domain_free(&_log_domains[_log_domains_count]);
	}

	free(_log_domains);

	_log_domains = NULL;
	_log_domains_count = 0;
	_log_domains_allocated = 0;

	while (_glob_list) {
		tmp = _glob_list;
		_glob_list = _glob_list->next;
		free(tmp);
	}

	while (_pending_list) {
		tmp = _pending_list;
		_pending_list = _pending_list->next;
		free(tmp);
	}

	return EINA_TRUE;
}

#ifdef EFL_HAVE_THREADS

/**
 * @internal
 * @brief Activate the log mutex.
 *
 * This function activate the mutex in the eina log module. It is called by
 * eina_threads_init().
 *
 * @see eina_threads_init()
 */
void eina_log_threads_init(void)
{
	_main_thread = SELF();
	if (INIT())
		_threads_enabled = EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the log mutex.
 *
 * This function shuts down the mutex in the log module.
 * It is called by eina_threads_shutdown().
 *
 * @see eina_threads_shutdown()
 */
void eina_log_threads_shutdown(void)
{
	CHECK_MAIN();
	SHUTDOWN();
	_threads_enabled = EINA_FALSE;
}

#endif

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Log_Group Log
 *
 * @brief Full-featured logging system.
 *
 * Eina provides eina_log_print(), a standard function to manage all
 * logging messages. This function may be called directly or using the
 * helper macros such as EINA_LOG_DBG(), EINA_LOG_ERR() or those that
 * take a specific domain as argument EINA_LOG_DOM_DBG(),
 * EINA_LOG_DOM_ERR().  Internally, eina_log_print() will call the
 * function defined with eina_log_print_cb_set(), that defaults to
 * eina_log_print_cb_stderr(), but may be changed to do whatever you
 * need, such as networking or syslog logging.
 *
 * The logging system is thread safe once initialized with
 * eina_log_threads_enable(). The thread that calls this function
 * first is considered "main thread" and other threads will have their
 * thread id (pthread_self()) printed in the log message so it is easy
 * to detect from where it is coming.
 *
 * Log domains is the Eina way to differentiate messages. There might
 * be different domains to represent different modules, different
 * feature-set, different categories and so on. Filtering can be
 * applied to domain names by means of @c EINA_LOG_LEVELS environment
 * variable or eina_log_domain_level_set().
 *
 * The different logging levels serve to customize the amount of
 * debugging one want to take and may be used to automatically call
 * abort() once some given level message is printed. This is
 * controlled by environment variable @c EINA_LOG_ABORT and the level
 * to be considered critical with @c EINA_LOG_ABORT_LEVEL. These can
 * be changed with eina_log_abort_on_critical_set() and
 * eina_log_abort_on_critical_level_set().
 *
 * The default maximum level to print is defined by environment
 * variable @c EINA_LOG_LEVEL, but may be set per-domain with @c
 * EINA_LOG_LEVELS. It will default to #EINA_LOG_ERR. This can be
 * changed with eina_log_level_set().
 *
 * To use the log system Eina must be initialized with eina_init() and
 * later shut down with eina_shutdown(). Here is a straightforward
 * example:
 *
 * @code
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * #include <eina_log.h>
 *
 * void test_warn(void)
 * {
 *    EINA_LOG_WARN("Here is a warning message");
 * }
 *
 * int main(void)
 * {
 *    if (!eina_init())
 *    {
 *        printf("log during the initialization of Eina_Log module\n");
 *        return EXIT_FAILURE;
 *    }
 *
 *    test_warn();
 *
 *    eina_shutdown();
 *
 *    return EXIT_SUCCESS;
 * }
 * @endcode
 *
 * Compile this code with the following command:
 *
 * @code
 * gcc -Wall -o test_Eina_Log test_eina.c `pkg-config --cflags --libs eina`
 * @endcode
 *
 * Now execute the program with:
 *
 * @code
 * EINA_LOG_LEVEL=2 ./test_eina_log
 * @endcode
 *
 * You should see a message displayed in the terminal.
 *
 * For more information, you can look at the @ref tutorial_log_page.
 *
 * @{
 */


/**
 * @cond LOCAL
 */

EAPI int EINA_LOG_DOMAIN_GLOBAL = 0;

/**
 * @endcond
 */


/**
 * Enable logging module to handle threads.
 *
 * There is no disable option on purpose, if it is enabled, there is
 * no way back until you call the last eina_shutdown().
 *
 * There is no function to retrieve if threads are enabled as one is
 * not supposed to know this from outside.
 *
 * After this call is executed at least once, if Eina was compiled
 * with threads support then logging will lock around debug messages
 * and threads that are not the main thread will have its identifier
 * printed.
 *
 * The main thread is considered the thread where the first
 * eina_init() was called.
 */
EAPI void eina_log_threads_enable(void)
{
#ifdef EFL_HAVE_THREADS
	_threads_enabled = 1;
	eina_log_print_prefix_update();
#endif
}

/**
 * Sets logging method to use.
 *
 * @param cb The callback to call when printing a log.
 * @param data The data to pass to the callback.
 *
 * By default, eina_log_print_cb_stderr() is used.
 *
 * @note MT: safe to call from any thread.
 *
 * @note MT: given function @a cb will be called protected by mutex.
 *       This means you're safe from other calls but you should never
 *       call eina_log_print(), directly or indirectly.
 */
EAPI void eina_log_print_cb_set(Eina_Log_Print_Cb cb, void *data)
{
	LOG_LOCK();
	_print_cb = cb;
	_print_cb_data = data;
	eina_log_print_prefix_update();
	LOG_UNLOCK();
}

/**
 * @brief Set the default log level.
 *
 * @param level The log level.
 *
 * This function sets the log level @p level. It is used in
 * eina_log_print().
 *
 * @note this is initially set to envvar EINA_LOG_LEVEL by eina_init().
 *
 * @see eina_log_level_get()
 */
EAPI void eina_log_level_set(int level)
{
	_log_level = level;
	if (EINA_LIKELY((EINA_LOG_DOMAIN_GLOBAL >= 0) &&
			((unsigned int) EINA_LOG_DOMAIN_GLOBAL <
			 _log_domains_count)))
		_log_domains[EINA_LOG_DOMAIN_GLOBAL].level = level;
}

/**
 * @brief Get the default log level.
 *
 * @return the log level that limits eina_log_print().
 *
 * @see eina_log_level_set()
 */
EAPI int eina_log_level_get(void)
{
	return _log_level;
}

/**
 * Checks if current thread is the main thread.
 *
 * @return #EINA_TRUE if threads were enabled and the current thread
 *         is the one that called eina_log_threads_init(). If there is
 *         no thread support (compiled with --disable-pthreads) or
 *         they were not enabled, then #EINA_TRUE is also
 *         returned. The only case where #EINA_FALSE is returned is
 *         when threads were successfully enabled but the current
 *         thread is not the main (one that called
 *         eina_log_threads_init()).
 */
EAPI Eina_Bool eina_log_main_thread_check(void)
{
#ifdef EFL_HAVE_THREADS
	return ((!_threads_enabled) || IS_MAIN(SELF()));
#else
	return EINA_TRUE;
#endif
}

/**
 * @brief Set if color logging should be disabled.
 *
 * @param disabled if #EINA_TRUE, color logging should be disabled.
 *
 * @note this is initially set to envvar EINA_LOG_COLOR_DISABLE by eina_init().
 *
 * @see eina_log_color_disable_get()
 */
EAPI void eina_log_color_disable_set(Eina_Bool disabled)
{
	_disable_color = disabled;
}

/**
 * @brief Get if color logging should be disabled.
 *
 * @return if #EINA_TRUE, color logging should be disabled.
 *
 * @see eina_log_color_disable_set()
 */
EAPI Eina_Bool eina_log_color_disable_get(void)
{
	return _disable_color;
}

/**
 * @brief Set if originating file name logging should be disabled.
 *
 * @param disabled if #EINA_TRUE, file name logging should be disabled.
 *
 * @note this is initially set to envvar EINA_LOG_FILE_DISABLE by eina_init().
 *
 * @see eina_log_file_disable_get()
 */
EAPI void eina_log_file_disable_set(Eina_Bool disabled)
{
	_disable_file = disabled;
}

/**
 * @brief Get if originating file name logging should be disabled.
 *
 * @return if #EINA_TRUE, file name logging should be disabled.
 *
 * @see eina_log_file_disable_set()
 */
EAPI Eina_Bool eina_log_file_disable_get(void)
{
	return _disable_file;
}

/**
 * @brief Set if originating function name logging should be disabled.
 *
 * @param disabled if #EINA_TRUE, function name logging should be disabled.
 *
 * @note this is initially set to envvar EINA_LOG_FUNCTION_DISABLE by
 *       eina_init().
 *
 * @see eina_log_function_disable_get()
 */
EAPI void eina_log_function_disable_set(Eina_Bool disabled)
{
	_disable_function = disabled;
}

/**
 * @brief Get if originating function name logging should be disabled.
 *
 * @return if #EINA_TRUE, function name logging should be disabled.
 *
 * @see eina_log_function_disable_set()
 */
EAPI Eina_Bool eina_log_function_disable_get(void)
{
	return _disable_function;
}

/**
 * @brief Set if critical messages should abort the program.
 *
 * @param abort_on_critical if #EINA_TRUE, messages with level equal
 *        or smaller than eina_log_abort_on_critical_level_get() will
 *        abort the program.
 *
 * @note this is initially set to envvar EINA_LOG_ABORT by
 *       eina_init().
 *
 * @see eina_log_abort_on_critical_get()
 * @see eina_log_abort_on_critical_level_set()
 */
EAPI void eina_log_abort_on_critical_set(Eina_Bool abort_on_critical)
{
	_abort_on_critical = abort_on_critical;
}

/**
 * @brief Get if critical messages should abort the program.
 *
 * @return if #EINA_TRUE, any messages with level equal or smaller
 *         than eina_log_abort_on_critical_level_get() will abort the
 *         program.
 *
 * @see eina_log_abort_on_critical_set()
 * @see eina_log_abort_on_critical_level_set()
 */
EAPI Eina_Bool eina_log_abort_on_critical_get(void)
{
	return _abort_on_critical;
}

/**
 * @brief Set level that triggers abort if abort-on-critical is set.
 *
 * @param critical_level levels equal or smaller than the given value
 *        will trigger program abortion if
 *        eina_log_abort_on_critical_get() returns #EINA_TRUE.
 *
 * @note this is initially set to envvar EINA_LOG_ABORT_LEVEL by
 *       eina_init().
 *
 * @see eina_log_abort_on_critical_level_get()
 * @see eina_log_abort_on_critical_get()
 */
EAPI void eina_log_abort_on_critical_level_set(int critical_level)
{
	_abort_level_on_critical = critical_level;
}

/**
 * @brief Get level that triggers abort if abort-on-critical is set.
 *
 * @return critical level equal or smaller than value will trigger
 *        program abortion if eina_log_abort_on_critical_get() returns
 *        #EINA_TRUE.
 *
 * @see eina_log_abort_on_critical_level_set()
 * @see eina_log_abort_on_critical_get()
 */
EAPI int eina_log_abort_on_critical_level_get(void)
{
	return _abort_level_on_critical;
}

/**
 * @param name Domain name
 * @param color Color of the domain name
 *
 * @return Domain index that will be used as the DOMAIN parameter on log
 *         macros. A negative return value means an log occurred.
 *
 * @note MT: safe to call from any thread.
 */
EAPI int eina_log_domain_register(const char *name, const char *color)
{
	int r;

	EINA_SAFETY_ON_NULL_RETURN_VAL(name, -1);

	LOG_LOCK();
	r = eina_log_domain_register_unlocked(name, color);
	LOG_UNLOCK();
	return r;
}

/**
 * Forget about a logging domain registered by eina_log_domain_register()
 *
 * @param domain domain identifier as reported by eina_log_domain_register(),
 *        must be >= 0.
 *
 * @note MT: safe to call from any thread.
 */
EAPI void eina_log_domain_unregister(int domain)
{
	EINA_SAFETY_ON_FALSE_RETURN(domain >= 0);
	LOG_LOCK();
	eina_log_domain_unregister_unlocked(domain);
	LOG_UNLOCK();
}

/**
 * Set the domain level given its name.
 *
 * This call has the same effect as setting
 * EINA_LOG_LEVELS=&lt;@p domain_name&gt;:&lt;@p level&gt;
 *
 * @param domain_name domain name to change the level. It may be of a
 *        still not registered domain. If the domain is not registered
 *        yet, it will be saved as a pending set and applied upon
 *        registration.
 * @param level level to use to limit eina_log_print() for given domain.
 */
EAPI void eina_log_domain_level_set(const char *domain_name, int level)
{
	Eina_Log_Domain_Level_Pending *pending;
	size_t namelen;
	unsigned int i;

	EINA_SAFETY_ON_NULL_RETURN(domain_name);

	namelen = strlen(domain_name);

	for (i = 0; i < _log_domains_count; i++) {
		if (_log_domains[i].deleted)
			continue;

		if ((namelen != _log_domains[i].namelen) ||
		    (strcmp(_log_domains[i].name, domain_name) != 0))
			continue;

		_log_domains[i].level = level;
		return;
	}

	EINA_INLIST_FOREACH(_pending_list, pending) {
		if ((namelen == pending->namelen) &&
		    (strcmp(pending->name, domain_name) == 0)) {
			pending->level = level;
			return;
		}
	}

	pending =
	    malloc(sizeof(Eina_Log_Domain_Level_Pending) + namelen + 1);
	if (!pending)
		return;

	pending->level = level;
	pending->namelen = namelen;
	memcpy(pending->name, domain_name, namelen + 1);

	_pending_list =
	    eina_inlist_append(_pending_list, EINA_INLIST_GET(pending));
}

/**
 * Get the domain level given its name.
 *
 * @param domain_name domain name to retrieve the level. It may be of
 *        a still not registered domain. If the domain is not
 *        registered yet, but there is a pending value, either from
 *        eina_log_domain_level_set(),EINA_LOG_LEVELS environment
 *        variable or from EINA_LOG_LEVELS_GLOB, these are
 *        returned. If nothing else was found, then the global/default
 *        level (eina_log_level_get()) is returned.
 *
 * @return level to use to limit eina_log_print() for given
 *         domain. On error (@p domain_name == NULL),
 *         EINA_LOG_LEVEL_UNKNOWN is returned.
 *
 * @see eina_log_domain_level_set()
 * @see eina_log_domain_registered_level_get()
 */
EAPI int eina_log_domain_level_get(const char *domain_name)
{
	Eina_Log_Domain_Level_Pending *pending;
	size_t namelen;
	unsigned int i;

	EINA_SAFETY_ON_NULL_RETURN_VAL(domain_name,
				       EINA_LOG_LEVEL_UNKNOWN);

	namelen = strlen(domain_name);

	for (i = 0; i < _log_domains_count; i++) {
		if (_log_domains[i].deleted)
			continue;

		if ((namelen != _log_domains[i].namelen) ||
		    (strcmp(_log_domains[i].name, domain_name) != 0))
			continue;

		return _log_domains[i].level;
	}

	EINA_INLIST_FOREACH(_pending_list, pending) {
		if ((namelen == pending->namelen) &&
		    (strcmp(pending->name, domain_name) == 0))
			return pending->level;
	}

	EINA_INLIST_FOREACH(_glob_list, pending) {
		if (!fnmatch(pending->name, domain_name, 0))
			return pending->level;
	}

	return _log_level;
}

/**
 * Get the domain level given its identifier.
 *
 * @param domain identifier, so it must be previously registered with
 *        eina_log_domain_register(). It's a much faster version of
 *        eina_log_domain_level_get(), but relies on domain being
 *        present.
 *
 * @return level to use to limit eina_log_print() for given domain. On
 *         error EINA_LOG_LEVEL_UNKNOWN is returned.
 */
EAPI int eina_log_domain_registered_level_get(int domain)
{
	EINA_SAFETY_ON_FALSE_RETURN_VAL(domain >= 0,
					EINA_LOG_LEVEL_UNKNOWN);
	EINA_SAFETY_ON_FALSE_RETURN_VAL((unsigned int) domain <
					_log_domains_count,
					EINA_LOG_LEVEL_UNKNOWN);
	EINA_SAFETY_ON_TRUE_RETURN_VAL(_log_domains[domain].deleted,
				       EINA_LOG_LEVEL_UNKNOWN);
	return _log_domains[domain].level;
}

/**
 * Default logging method, this will output to standard error stream.
 *
 * This method will colorize output based on domain provided color and
 * message logging level.
 *
 * To disable color, set environment variable
 * EINA_LOG_COLOR_DISABLE=1. To enable color, even if directing to a
 * file or when using a non-supported color terminal, use
 * EINA_LOG_COLOR_DISABLE=0. If EINA_LOG_COLOR_DISABLE is unset (or
 * -1), then Eina will disable color if terminal ($TERM) is
 * unsupported or if redirecting to a file.

   . Similarly, to disable file and line
 * information, set EINA_LOG_FILE_DISABLE=1 or
 * EINA_LOG_FUNCTION_DISABLE=1 to avoid function name in output. It is
 * not acceptable to have both EINA_LOG_FILE_DISABLE and
 * EINA_LOG_FUNCTION_DISABLE at the same time, in this case just
 * EINA_LOG_FUNCTION_DISABLE will be considered and file information
 * will be printed anyways.
 *
 * @note MT: if threads are enabled, this function is called within locks.
 * @note MT: Threads different from main thread will have thread id
 *       appended to domain name.
 */
EAPI void
eina_log_print_cb_stderr(const Eina_Log_Domain * d,
			 Eina_Log_Level level,
			 const char *file,
			 const char *fnc,
			 int line,
			 const char *fmt,
			 __UNUSED__ void *data, va_list args)
{
	_eina_log_print_prefix(stderr, d, level, file, fnc, line);
	vfprintf(stderr, fmt, args);
	putc('\n', stderr);
}

/**
 * Alternative logging method, this will output to standard output stream.
 *
 * @param d The domain.
 * @param level The level.
 * @param file The file which is logged.
 * @param fnc The function which is logged.
 * @param line The line which is logged.
 * @param fmt The ouptut format to use.
 * @param data Not used.
 * @param args The arguments needed by the format.
 *
 * This method will colorize output based on domain provided color and
 * message logging level. To disable color, set environment variable
 * EINA_LOG_COLOR_DISABLE=1. Similarly, to disable file and line
 * information, set EINA_LOG_FILE_DISABLE=1 or
 * EINA_LOG_FUNCTION_DISABLE=1 to avoid function name in output. It is
 * not acceptable to have both EINA_LOG_FILE_DISABLE and
 * EINA_LOG_FUNCTION_DISABLE at the same time, in this case just
 * EINA_LOG_FUNCTION_DISABLE will be considered and file information
 * will be printed anyways.
 *
 * @note MT: if threads are enabled, this function is called within locks.
 * @note MT: Threads different from main thread will have thread id
 *       appended to domain name.
 */
EAPI void
eina_log_print_cb_stdout(const Eina_Log_Domain * d,
			 Eina_Log_Level level,
			 const char *file,
			 const char *fnc,
			 int line,
			 const char *fmt,
			 __UNUSED__ void *data, va_list args)
{
	_eina_log_print_prefix(stdout, d, level, file, fnc, line);
	vprintf(fmt, args);
	putchar('\n');
}

/**
 * Alternative logging method, this will output to given file stream.
 *
 * @param d The domain.
 * @param level Not used.
 * @param file The file which is logged.
 * @param fnc The function which is logged.
 * @param line The line which is logged.
 * @param fmt The ouptut format to use.
 * @param data The file which will store the output (as a FILE *).
 * @param args The arguments needed by the format.
 *
 * This method will never output color.
 *
 * @note MT: if threads are enabled, this function is called within locks.
 * @note MT: Threads different from main thread will have thread id
 *       appended to domain name.
 */
EAPI void
eina_log_print_cb_file(const Eina_Log_Domain * d,
		       __UNUSED__ Eina_Log_Level level,
		       const char *file,
		       const char *fnc,
		       int line, const char *fmt, void *data, va_list args)
{
	FILE *f = data;
#ifdef EFL_HAVE_THREADS
	if (_threads_enabled) {
		Thread cur;

		cur = SELF();
		if (IS_OTHER(cur)) {
			fprintf(f, "%s[T:%lu] %s:%d %s() ", d->name,
				(unsigned long) cur, file, line, fnc);
			goto end;
		}
	}
#endif
	fprintf(f, "%s %s:%d %s() ", d->name, file, line, fnc);
#ifdef EFL_HAVE_THREADS
      end:
#endif
	vfprintf(f, fmt, args);
	putc('\n', f);
}

/**
 * Print out log message using given domain and level.
 *
 * @note Usually you'll not use this function directly but the helper
 *       macros EINA_LOG(), EINA_LOG_DOM_CRIT(), EINA_LOG_CRIT() and
 *       so on. See eina_log.h
 *
 * @param domain logging domain to use or @c EINA_LOG_DOMAIN_GLOBAL if
 *        you registered none. It is recommended that modules and
 *        applications have their own logging domain.
 * @param level message level, those with level greater than user
 *        specified value (eina_log_level_set() or environment
 *        variables EINA_LOG_LEVEL, EINA_LOG_LEVELS) will be ignored.
 * @param file filename that originated the call, must @b not be @c NULL.
 * @param fnc function that originated the call, must @b not be @c NULL.
 * @param line originating line in @a file.
 * @param fmt printf-like format to use. Should not provide trailing
 *        '\n' as it is automatically included.
 *
 * @note MT: this function may be called from different threads if
 *       eina_log_threads_enable() was called before.
 */
EAPI void
eina_log_print(int domain, Eina_Log_Level level, const char *file,
	       const char *fnc, int line, const char *fmt, ...)
{
	va_list args;

#ifdef EINA_SAFETY_CHECKS
	if (EINA_UNLIKELY(!file)) {
		fputs("ERR: eina_log_print() file == NULL\n", stderr);
		return;
	}

	if (EINA_UNLIKELY(!fnc)) {
		fputs("ERR: eina_log_print() fnc == NULL\n", stderr);
		return;
	}

	if (EINA_UNLIKELY(!fmt)) {
		fputs("ERR: eina_log_print() fmt == NULL\n", stderr);
		return;
	}
#endif
	va_start(args, fmt);
	LOG_LOCK();
	eina_log_print_unlocked(domain, level, file, fnc, line, fmt, args);
	LOG_UNLOCK();
	va_end(args);
}

/**
 * Print out log message using given domain and level.
 *
 * @note Usually you'll not use this function directly but the helper
 *       macros EINA_LOG(), EINA_LOG_DOM_CRIT(), EINA_LOG_CRIT() and
 *       so on. See eina_log.h
 *
 * @param domain logging domain to use or @c EINA_LOG_DOMAIN_GLOBAL if
 *        you registered none. It is recommended that modules and
 *        applications have their own logging domain.
 * @param level message level, those with level greater than user
 *        specified value (eina_log_level_set() or environment
 *        variables EINA_LOG_LEVEL, EINA_LOG_LEVELS) will be ignored.
 * @param file filename that originated the call, must @b not be @c NULL.
 * @param fnc function that originated the call, must @b not be @c NULL.
 * @param line originating line in @a file.
 * @param fmt printf-like format to use. Should not provide trailing
 *        '\n' as it is automatically included.
 * @param args the arguments needed by the format.
 *
 * @note MT: this function may be called from different threads if
 *       eina_log_threads_enable() was called before.
 *
 * @see eina_log_print()
 */
EAPI void
eina_log_vprint(int domain, Eina_Log_Level level, const char *file,
		const char *fnc, int line, const char *fmt, va_list args)
{
#ifdef EINA_SAFETY_CHECKS
	if (EINA_UNLIKELY(!file)) {
		fputs("ERR: eina_log_print() file == NULL\n", stderr);
		return;
	}

	if (EINA_UNLIKELY(!fnc)) {
		fputs("ERR: eina_log_print() fnc == NULL\n", stderr);
		return;
	}

	if (EINA_UNLIKELY(!fmt)) {
		fputs("ERR: eina_log_print() fmt == NULL\n", stderr);
		return;
	}
#endif
	LOG_LOCK();
	eina_log_print_unlocked(domain, level, file, fnc, line, fmt, args);
	LOG_UNLOCK();
}

/**
 * @}
 */
