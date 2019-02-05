/* EINA - EFL data type library
 * Copyright (C) 2008 Gustavo Sverzut Barbieri
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eina_private.h"
#include "eina_error.h"
#include "eina_log.h"
#include "eina_safety_checks.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Shut down the safety checks module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the error module set up by
 * eina_safety_checks_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_safety_checks_shutdown(void)
{
	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Safety_Checks_Group Safety Checks
 *
 * Safety checks are a set of macros to check for parameters or values
 * that should never happen, it is similar in concept to assert(), but
 * will log and return instead of abort() your program.
 *
 * Since these cases should never happen, one may wantto keep safety
 * checks enabled during tests but disable then during deploy, not
 * doing any checks at all. This is a common requirement for embedded
 * systems. Whenever to check or not should be set during compile time
 * by using @c --disable-safety-checks or @c --enable-safety-checks
 * options to @c configure script.
 *
 * Whenever these macros capture an error, EINA_LOG_ERR() will be
 * called and @c eina_error set to @c EINA_ERROR_SAFETY_FAILED and can
 * be checked with eina_error_get() after call.
 *
 * @see EINA_SAFETY_ON_NULL_RETURN(), EINA_SAFETY_ON_NULL_RETURN_VAL()
 *      and other macros.
 *
 * @{
 */

/**
 * @cond LOCAL
 */

EAPI Eina_Error EINA_ERROR_SAFETY_FAILED = 0;

static const char EINA_ERROR_SAFETY_FAILED_STR[] = "Safety check failed.";

/**
 * @endcond
 */

/**
 * @internal
 * @brief Initialize the safety checks module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the safety checks module of Eina. It is
 * called by eina_init().
 *
 * @see eina_init()
 */
Eina_Bool eina_safety_checks_init(void)
{
	EINA_ERROR_SAFETY_FAILED =
	    eina_error_msg_static_register(EINA_ERROR_SAFETY_FAILED_STR);
	return EINA_TRUE;
}

/**
 * @}
 */
