/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Carsten Haitzler, Vincent Torri, Jorge Luis Zapata Muga
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

#ifndef EINA_TYPES_H_
#define EINA_TYPES_H_

/**
 * @addtogroup Eina_Core_Group Core
 *
 * @{
 */

/**
 * @defgroup Eina_Types_Group Types
 *
 * @{
 */

#ifdef EAPI
#undef EAPI
#endif

#ifdef _WIN32
#ifdef EFL_EINA_BUILD
#ifdef DLL_EXPORT
#define EAPI __declspec(dllexport)
#else
#define EAPI
#endif				/* ! DLL_EXPORT */
#else
#define EAPI __declspec(dllimport)
#endif				/* ! EFL_EINA_BUILD */
#else
#ifdef __GNUC__
#if __GNUC__ >= 4
#define EAPI __attribute__ ((visibility("default")))
#else
#define EAPI
#endif
#else
#define EAPI
#endif
#endif

#include "eina_config.h"

#ifdef EINA_WARN_UNUSED_RESULT
#undef EINA_WARN_UNUSED_RESULT
#endif
#ifdef EINA_ARG_NONNULL
#undef EINA_ARG_NONNULL
#endif
#ifdef EINA_DEPRECATED
#undef EINA_DEPRECATED
#endif
#ifdef EINA_MALLOC
#undef EINA_MALLOC
#endif
#ifdef EINA_PURE
#undef EINA_PURE
#endif
#ifdef EINA_PRINTF
#undef EINA_PRINTF
#endif
#ifdef EINA_SCANF
#undef EINA_SCANF
#endif
#ifdef EINA_FORMAT
#undef EINA_FORMAT
#endif
#ifdef EINA_CONST
#undef EINA_CONST
#endif
#ifdef EINA_NOINSTRUMENT
#undef EINA_NOINSTRUMENT
#endif
#ifdef EINA_UNLIKELY
#undef EINA_UNLIKELY
#endif
#ifdef EINA_LIKELY
#undef EINA_LIKELY
#endif


#ifdef __GNUC__
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#define EINA_WARN_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
#define EINA_WARN_UNUSED_RESULT
#endif

#if (!defined(EINA_SAFETY_CHECKS)) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
#define EINA_ARG_NONNULL(idx, ...) __attribute__ ((nonnull(idx, ## __VA_ARGS__)))
#else
#define EINA_ARG_NONNULL(idx, ...)
#endif

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define EINA_DEPRECATED __attribute__ ((__deprecated__))
#else
#define EINA_DEPRECATED
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96)
#define EINA_MALLOC __attribute__ ((malloc))
#define EINA_PURE __attribute__ ((pure))
#else
#define EINA_MALLOC
#define EINA_PURE
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define EINA_PRINTF(fmt, arg)  __attribute__((format (printf, fmt, arg)))
#define EINA_SCANF(fmt, arg)  __attribute__((format (scanf, fmt, arg)))
#define EINA_FORMAT(fmt) __attribute__((format_arg(fmt)))
#define EINA_CONST __attribute__((const))
#define EINA_NOINSTRUMENT __attribute__((no_instrument_function))
#define EINA_UNLIKELY(exp) __builtin_expect((exp), 0)
#define EINA_LIKELY(exp) __builtin_expect((exp), 1)
#else
#define EINA_PRINTF(fmt, arg)
#define EINA_SCANF(fmt, arg)
#define EINA_FORMAT(fmt)
#define EINA_CONST
#define EINA_NOINSTRUMENT
#define EINA_UNLIKELY(exp) exp
#define EINA_LIKELY(exp) exp
#endif

#elif defined(_WIN32)
#define EINA_WARN_UNUSED_RESULT
#define EINA_ARG_NONNULL(idx, ...)
#if defined(_MSC_VER) && _MSC_VER >= 1300
#define EINA_DEPRECATED __declspec(deprecated)
#else
#define EINA_DEPRECATED
#endif
#define EINA_MALLOC
#define EINA_PURE
#define EINA_PRINTF(fmt, arg)
#define EINA_SCANF(fmt, arg)
#define EINA_FORMAT(fmt)
#define EINA_CONST
#define EINA_NOINSTRUMENT
#define EINA_UNLIKELY(exp) exp
#define EINA_LIKELY(exp) exp

#elif defined(__SUNPRO_C)
#define EINA_WARN_UNUSED_RESULT
#define EINA_ARG_NONNULL(...)
#define EINA_DEPRECATED
#if __SUNPRO_C >= 0x590
#define EINA_MALLOC __attribute__ ((malloc))
#define EINA_PURE __attribute__ ((pure))
#else
#define EINA_MALLOC
#define EINA_PURE
#endif
#define EINA_PRINTF(fmt, arg)
#define EINA_SCANF(fmt, arg)
#define EINA_FORMAT(fmt)
#if __SUNPRO_C >= 0x590
#define EINA_CONST __attribute__ ((const))
#else
#define EINA_CONST
#endif
#define EINA_NOINSTRUMENT
#define EINA_UNLIKELY(exp) exp
#define EINA_LIKELY(exp) exp

#else				/* ! __GNUC__ && ! _WIN32 && ! __SUNPRO_C */

/**
 * @def EINA_WARN_UNUSED_RESULT
 * Used to warn when the returned value of the function is not used.
 */
#define EINA_WARN_UNUSED_RESULT

/**
 * @def EINA_ARG_NONNULL
 * Used to warn when the specified arguments of the function are @c NULL.
 */
#define EINA_ARG_NONNULL(idx, ...)

/**
 * @def EINA_DEPRECATED
 * Used to warn when the function is considered as deprecated.
 */
#define EINA_DEPRECATED
#define EINA_MALLOC
#define EINA_PURE
#define EINA_PRINTF(fmt, arg)
#define EINA_SCANF(fmt, arg)
#define EINA_FORMAT(fmt)
#define EINA_CONST
#define EINA_NOINSTRUMENT
#define EINA_UNLIKELY(exp) exp
#define EINA_LIKELY(exp) exp
#endif				/* ! __GNUC__ && ! _WIN32 && ! __SUNPRO_C */


/**
 * @typedef Eina_Bool
 * Type to mimic a boolean.
 *
 * @note it differs from stdbool.h as this is defined as an unsigned
 *       char to make it usable by bitfields (Eina_Bool name:1) and
 *       also take as few bytes as possible.
 */
typedef unsigned char Eina_Bool;

/**
 * @def EINA_FALSE
 * boolean value FALSE (numerical value 0)
 */
#define EINA_FALSE ((Eina_Bool)0)

/**
 * @def EINA_TRUE
 * boolean value TRUE (numerical value 1)
 */
#define EINA_TRUE ((Eina_Bool)1)

EAPI extern const unsigned int eina_prime_table[];

/**
 * @typedef Eina_Compare_Cb
 * Function used in functions using sorting. It compares @p data1 and
 * @p data2. If @p data1 is 'less' than @p data2, -1 must be returned,
 * if it is 'greater', 1 must be returned, and if they are equal, 0
 * must be returned.
 */
typedef int (*Eina_Compare_Cb) (const void *data1, const void *data2);

/**
 * @def EINA_COMPARE_CB
 * Macro to cast to Eina_Compare_Cb.
 */
#define EINA_COMPARE_CB(function) ((Eina_Compare_Cb)function)

typedef Eina_Bool(*Eina_Each_Cb) (const void *container, void *data,
				  void *fdata);

/**
 * @def EINA_EACH_CB
 * Macro to cast to Eina_Each.
 */
#define EINA_EACH_CB(Function) ((Eina_Each_Cb)Function)

/**
 * @typedef Eina_Free_Cb
 * A callback type used to free data when iterating over a container.
 */
typedef void (*Eina_Free_Cb) (void *data);

/**
 * @def EINA_FREE_CB
 * Macro to cast to Eina_Free_Cb.
 */
#define EINA_FREE_CB(Function) ((Eina_Free_Cb)Function)

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_TYPES_H_ */
