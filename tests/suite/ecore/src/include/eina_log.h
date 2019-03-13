/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Jorge Luis Zapata Muga, Cedric Bail
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

#ifndef EINA_LOG_H_
#define EINA_LOG_H_

#include <stdlib.h>
#include <stdarg.h>

#include "eina_types.h"

#define EINA_COLOR_LIGHTRED  "\033[31;1m"
#define EINA_COLOR_RED       "\033[31m"
#define EINA_COLOR_LIGHTBLUE "\033[34;1m"
#define EINA_COLOR_BLUE      "\033[34m"
#define EINA_COLOR_GREEN     "\033[32;1m"
#define EINA_COLOR_YELLOW    "\033[33;1m"
#define EINA_COLOR_ORANGE    "\033[0;33m"
#define EINA_COLOR_WHITE     "\033[37;1m"
#define EINA_COLOR_LIGHTCYAN "\033[36;1m"
#define EINA_COLOR_CYAN      "\033[36m"
#define EINA_COLOR_RESET     "\033[0m"
#define EINA_COLOR_HIGH      "\033[1m"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_Log_Group Log
 *
 * @{
 */

/**
 * EINA_LOG_DOMAIN_GLOBAL is the general purpose log domain to be
 * used, it is always registered and available everywhere.
 */
EAPI extern int EINA_LOG_DOMAIN_GLOBAL;

#ifndef EINA_LOG_DOMAIN_DEFAULT

/**
 * @def EINA_LOG_DOMAIN_DEFAULT
 * This macro defines the domain to use with the macros EINA_LOG_DOM_DBG(),
 * EINA_LOG_DOM_INFO(), EINA_LOG_DOM_WARN(), EINA_LOG_DOM_ERR() and
 * EINA_LOG_DOM_CRIT().
 *
 * If not defined prior to the inclusion of this header, then it
 * defaults to #EINA_LOG_DOMAIN_GLOBAL.
 *
 * @note One may like to redefine this in its code to avoid typing too
 *       much. In this case the recommended way is:
 *
 * @code
 * #include <Eina.h>
 * #undef EINA_LOG_DOMAIN_DEFAULT
 * #define EINA_LOG_DOMAIN_DEFAULT _log_dom
 * static int _log_dom = -1;
 *
 * int main(void)
 * {
 *    eina_init();
 *    _log_dom = eina_log_domain_register("mydom", EINA_COLOR_CYAN);
 *    EINA_LOG_ERR("using my own domain");
 *    return 0;
 * }
 * @endcode
 *
 * @warning If one defines the domain prior to inclusion of this
 *          header, the defined log domain symbol must be defined
 *          prior as well, otherwise the inlined functions defined by
 *          Eina will fail to find the symbol, causing build failure.
 *
 * @code
 * #define EINA_LOG_DOMAIN_DEFAULT _log_dom
 * static int _log_dom = -1; // must come before inclusion of Eina.h!
 * #include <Eina.h>
 *
 * int main(void)
 * {
 *    eina_init();
 *    _log_dom = eina_log_domain_register("mydom", EINA_COLOR_CYAN);
 *    EINA_LOG_ERR("using my own domain");
 *    return 0;
 * }
 * @endcode
 *
 */
#define EINA_LOG_DOMAIN_DEFAULT EINA_LOG_DOMAIN_GLOBAL

#endif				/* EINA_LOG_DOMAIN_DEFAULT */


/**
 * @def EINA_LOG(DOM, LEVEL, fmt, ...)
 * Logs a message on the specified domain, level and format.
 *
 * @note if @c EINA_LOG_LEVEL_MAXIMUM is defined, then messages larger
 *       than this value will be ignored regardless of current domain
 *       level, the eina_log_print() is not even called! Most
 *       compilers will just detect the two integers make the branch
 *       impossible and remove the branch and function call all
 *       together. Take this as optimization tip and possible remove
 *       debug messages from binaries to be deployed, saving on hot
 *       paths. Never define @c EINA_LOG_LEVEL_MAXIMUM on public
 *       header files.
 */
#ifdef EINA_LOG_LEVEL_MAXIMUM
#define EINA_LOG(DOM, LEVEL, fmt, ...)                                  \
  do {                                                                  \
     if (LEVEL <= EINA_LOG_LEVEL_MAXIMUM) {				\
	eina_log_print(DOM, LEVEL, __FILE__, __FUNCTION__, __LINE__,	\
		       fmt, ## __VA_ARGS__); }				\
  } while (0)
#else
#define EINA_LOG(DOM, LEVEL, fmt, ...)		\
  eina_log_print(DOM,				\
		 LEVEL,				\
		 __FILE__,			\
		 __FUNCTION__,			\
		 __LINE__,			\
		 fmt,				\
		 ## __VA_ARGS__)
#endif

/**
 * @def EINA_LOG_DOM_CRIT(DOM, fmt, ...)
 * Logs a message with level CRITICAL on the specified domain and format.
 */
#define EINA_LOG_DOM_CRIT(DOM, fmt, ...) \
   EINA_LOG(DOM, EINA_LOG_LEVEL_CRITICAL, fmt, ## __VA_ARGS__)

/**
 * @def EINA_LOG_DOM_ERR(DOM, fmt, ...)
 * Logs a message with level ERROR on the specified domain and format.
 */
#define EINA_LOG_DOM_ERR(DOM, fmt, ...) \
   EINA_LOG(DOM, EINA_LOG_LEVEL_ERR, fmt, ## __VA_ARGS__)

/**
 * @def EINA_LOG_DOM_INFO(DOM, fmt, ...)
 * Logs a message with level INFO on the specified domain and format.
 */
#define EINA_LOG_DOM_INFO(DOM, fmt, ...) \
   EINA_LOG(DOM, EINA_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)

/**
 * @def EINA_LOG_DOM_DBG(DOM, fmt, ...)
 * Logs a message with level DEBUG on the specified domain and format.
 */
#define EINA_LOG_DOM_DBG(DOM, fmt, ...) \
   EINA_LOG(DOM, EINA_LOG_LEVEL_DBG, fmt, ## __VA_ARGS__)

/**
 * @def EINA_LOG_DOM_WARN(DOM, fmt, ...)
 * Logs a message with level WARN on the specified domain and format.
 */
#define EINA_LOG_DOM_WARN(DOM, fmt, ...) \
   EINA_LOG(DOM, EINA_LOG_LEVEL_WARN, fmt, ## __VA_ARGS__)

/**
 * @def EINA_LOG_CRIT(fmt, ...)
 * Logs a message with level CRITICAL on the default domain with the specified
 * format.
 */
#define EINA_LOG_CRIT(fmt, ...)	     \
   EINA_LOG(EINA_LOG_DOMAIN_DEFAULT, \
            EINA_LOG_LEVEL_CRITICAL, \
            fmt,		     \
            ## __VA_ARGS__)

/**
 * @def EINA_LOG_ERR(fmt, ...)
 * Logs a message with level ERROR on the default domain with the specified
 * format.
 */
#define EINA_LOG_ERR(fmt, ...) \
   EINA_LOG(EINA_LOG_DOMAIN_DEFAULT, EINA_LOG_LEVEL_ERR, fmt, ## __VA_ARGS__)

/**
 * @def EINA_LOG_INFO(fmt, ...)
 * Logs a message with level INFO on the default domain with the specified
 * format.
 */
#define EINA_LOG_INFO(fmt, ...) \
   EINA_LOG(EINA_LOG_DOMAIN_DEFAULT, EINA_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)

/**
 * @def EINA_LOG_WARN(fmt, ...)
 * Logs a message with level WARN on the default domain with the specified
 * format.
 */
#define EINA_LOG_WARN(fmt, ...) \
   EINA_LOG(EINA_LOG_DOMAIN_DEFAULT, EINA_LOG_LEVEL_WARN, fmt, ## __VA_ARGS__)

/**
 * @def EINA_LOG_DBG(fmt, ...)
 * Logs a message with level DEBUG on the default domain with the specified
 * format.
 */
#define EINA_LOG_DBG(fmt, ...) \
   EINA_LOG(EINA_LOG_DOMAIN_DEFAULT, EINA_LOG_LEVEL_DBG, fmt, ## __VA_ARGS__)

/**
 * @typedef Eina_Log_Domain
 * The domain used for logging.
 */
typedef struct _Eina_Log_Domain Eina_Log_Domain;

/**
 * @struct _Eina_Log_Domain
 * The domain used for logging.
 */
struct _Eina_Log_Domain {
	int level;
	      /**< Max level to log */
	const char *domain_str;
			   /**< Formatted string with color to print */
	const char *name;
		     /**< Domain name */
	size_t namelen;
		   /**< strlen(name) */

	/* Private */
	Eina_Bool deleted:1;
			  /**< Flags deletion of domain, a free slot */
};

EAPI void eina_log_threads_enable(void);

/**
 * @enum _Eina_Log_Level
 * List of available logging levels.
 */
typedef enum _Eina_Log_Level {
	EINA_LOG_LEVEL_CRITICAL,
			    /**< Critical log level */
	EINA_LOG_LEVEL_ERR,
		       /**< Error log level */
	EINA_LOG_LEVEL_WARN,
			/**< Warning log level */
	EINA_LOG_LEVEL_INFO,
			/**< Information log level */
	EINA_LOG_LEVEL_DBG,
		       /**< Debug log level */
	EINA_LOG_LEVELS,
		    /**< Count of default log levels */
	EINA_LOG_LEVEL_UNKNOWN = (-2147483647 - 1)/**< Unknown level */
} Eina_Log_Level;

/**
 * @typedef Eina_Log_Print_Cb
 * Type for print callbacks.
 */
typedef void (*Eina_Log_Print_Cb) (const Eina_Log_Domain * d,
				   Eina_Log_Level level,
				   const char *file, const char *fnc,
				   int line, const char *fmt, void *data,
				   va_list args);

/*
 * Customization
 */
EAPI void
eina_log_print_cb_set(Eina_Log_Print_Cb cb,
		      void *data) EINA_ARG_NONNULL(1);

EAPI void eina_log_level_set(int level);
EAPI int eina_log_level_get(void) EINA_WARN_UNUSED_RESULT;

static inline Eina_Bool eina_log_level_check(int level);

EAPI Eina_Bool eina_log_main_thread_check(void)
EINA_CONST EINA_WARN_UNUSED_RESULT;

EAPI void eina_log_color_disable_set(Eina_Bool disabled);
EAPI Eina_Bool eina_log_color_disable_get(void) EINA_WARN_UNUSED_RESULT;
EAPI void eina_log_file_disable_set(Eina_Bool disabled);
EAPI Eina_Bool eina_log_file_disable_get(void) EINA_WARN_UNUSED_RESULT;
EAPI void eina_log_function_disable_set(Eina_Bool disabled);
EAPI Eina_Bool eina_log_function_disable_get(void) EINA_WARN_UNUSED_RESULT;
EAPI void eina_log_abort_on_critical_set(Eina_Bool abort_on_critical);
EAPI Eina_Bool
eina_log_abort_on_critical_get(void) EINA_WARN_UNUSED_RESULT;
EAPI void eina_log_abort_on_critical_level_set(int critical_level);
EAPI int
eina_log_abort_on_critical_level_get(void) EINA_WARN_UNUSED_RESULT;

EAPI void
eina_log_domain_level_set(const char *domain_name,
			  int level) EINA_ARG_NONNULL(1);
EAPI int eina_log_domain_level_get(const char *domain_name)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);
EAPI int
eina_log_domain_registered_level_get(int domain) EINA_WARN_UNUSED_RESULT;
static inline Eina_Bool eina_log_domain_level_check(int domain, int level);


/*
 * Logging domains
 */
EAPI int
eina_log_domain_register(const char *name,
			 const char *color) EINA_ARG_NONNULL(1);
EAPI void eina_log_domain_unregister(int domain);

/*
 * Logging functions.
 */
EAPI void
eina_log_print(int domain,
	       Eina_Log_Level level,
	       const char *file,
	       const char *function,
	       int line,
	       const char *fmt,
	       ...) EINA_ARG_NONNULL(3, 4, 6) EINA_PRINTF(6,
							  7)
EINA_NOINSTRUMENT;
EAPI void eina_log_vprint(int domain, Eina_Log_Level level,
			  const char *file, const char *fnc, int line,
			  const char *fmt,
			  va_list args) EINA_ARG_NONNULL(3, 4,
							 6)
    EINA_NOINSTRUMENT;


/*
 * Logging methods (change how logging is done).
 */
EAPI void
eina_log_print_cb_stdout(const Eina_Log_Domain * d,
			 Eina_Log_Level level,
			 const char *file,
			 const char *fnc,
			 int line,
			 const char *fmt, void *data, va_list args);
EAPI void
eina_log_print_cb_stderr(const Eina_Log_Domain * d,
			 Eina_Log_Level level,
			 const char *file,
			 const char *fnc,
			 int line,
			 const char *fmt, void *data, va_list args);
EAPI void
eina_log_print_cb_file(const Eina_Log_Domain * d,
		       Eina_Log_Level level,
		       const char *file,
		       const char *fnc,
		       int line,
		       const char *fmt, void *data, va_list args);

#include "eina_inline_log.x"

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_LOG_H_ */
