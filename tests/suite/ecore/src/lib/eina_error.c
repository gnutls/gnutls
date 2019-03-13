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


/**
 * @page tutorial_error_page Error Tutorial
 *
 * @section tutorial_error_introduction Introduction
 *
 * The Eina error module provides a way to manage errors in a simple
 * but powerful way in libraries and modules. It is also used in Eina
 * itself. Similar to libC's @c errno and strerror() facilities, this
 * is extensible and recommended for other libraries and applications.
 *
 * @section tutorial_error_registering_msg Registering messages
 *
 * The error module can provide a system that mimic the errno system
 * of the C standard library. It consists in 2 parts:
 *
 * @li a way of registering new messages with
 * eina_error_msg_register() and eina_error_msg_get(),
 * @li a way of setting / getting last error message with
 * eina_error_set() / eina_error_get().
 *
 * So one has to fisrt register all the error messages that a program
 * or a lib should manage. Then, when an error can occur, use
 * eina_error_set(), and when errors are managed, use
 * eina_error_get(). If eina_error_set() is used to set an error, do
 * not forget to call before eina_error_set0), to remove previous set
 * errors.
 *
 * Here is an example of use:
 *
 * @code
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * #include <eina_error.h>
 *
 * Eina_Error MY_ERROR_NEGATIVE;
 * Eina_Error MY_ERROR_NULL;
 *
 * voi *data_new()
 * {
 *    eina_error_set(0);
 *
 *    eina_error_set(MY_ERROR_NULL);
 *    return NULL;
 * }
 *
 * int test(int n)
 * {
 *    eina_error_set(0);
 *
 *    if (n < 0)
 *    {
 *       eina_error_set(MY_ERROR_NEGATIVE);
 *       return 0;
 *    }
 *
 *    return 1;
 * }
 *
 * int main(void)
 * {
 *    void *data;
 *
 *    if (!eina_init())
 *    {
 *       printf ("Error during the initialization of eina_error module\n");
 *       return EXIT_FAILURE;
 *    }
 *
 *    MY_ERROR_NEGATIVE = eina_error_msg_register("Negative number");
 *    MY_ERROR_NULL = eina_error_msg_register("NULL pointer");

 *    data = data_new();
 *    if (!data)
 *    {
 *       Eina_Error err;
 *
 *       err = eina_error_get();
 *       if (err)
 *          printf("Error during memory allocation: %s\n",
 *                 eina_error_msg_get(err));
 *    }
 *
 *    if (!test(0))
 *    {
 *       Eina_Error err;
 *
 *       err = eina_error_get();
 *       if (err)
 *          printf("Error during test function: %s\n",
 *                 eina_error_msg_get(err));
 *    }
 *
 *    if (!test(-1))
 *    {
 *       Eina_Error err;
 *
 *       err = eina_error_get();
 *       if (err)
 *          printf("Error during test function: %s\n",
 *                 eina_error_msg_get(err));
 *    }
 *
 *    eina_shutdown();
 *
 *    return EXIT_SUCCESS;
 * }
 * @endcode
 *
 * Of course, instead of printf(), eina_log_print() can be used to
 * have beautiful error messages.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "eina_config.h"
#include "eina_private.h"


/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_error.h"

/* TODO
 * + add a wrapper for assert?
 * + add common error numbers, messages
 * + add a calltrace of errors, not only store the last error but a list of them
 * and also store the function that set it
 */

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

typedef struct _Eina_Error_Message Eina_Error_Message;
struct _Eina_Error_Message {
	Eina_Bool string_allocated;
	const char *string;
};

static Eina_Error_Message *_eina_errors = NULL;
static size_t _eina_errors_count = 0;
static size_t _eina_errors_allocated = 0;
static Eina_Error _eina_last_error;

static Eina_Error_Message *_eina_error_msg_alloc(void)
{
	size_t idx;

	if (_eina_errors_count == _eina_errors_allocated) {
		void *tmp;
		size_t size;

		if (EINA_UNLIKELY(_eina_errors_allocated == 0))
			size = 24;
		else
			size = _eina_errors_allocated + 8;

		tmp =
		    realloc(_eina_errors,
			    sizeof(Eina_Error_Message) * size);
		if (!tmp)
			return NULL;

		_eina_errors = tmp;
		_eina_errors_allocated = size;
	}

	idx = _eina_errors_count;
	_eina_errors_count++;
	return _eina_errors + idx;
}

/**
 * @endcond
 */


/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

EAPI Eina_Error EINA_ERROR_OUT_OF_MEMORY = 0;

static const char EINA_ERROR_OUT_OF_MEMORY_STR[] = "Out of memory";

/**
 * @endcond
 */

/**
 * @internal
 * @brief Initialize the error module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the error module of Eina. It is called by
 * eina_init().
 *
 * This function registers the error #EINA_ERROR_OUT_OF_MEMORY.
 *
 * @see eina_init()
 */
Eina_Bool eina_error_init(void)
{
	/* TODO register the eina's basic errors */
	EINA_ERROR_OUT_OF_MEMORY =
	    eina_error_msg_static_register(EINA_ERROR_OUT_OF_MEMORY_STR);
	return EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the error module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the error module set up by
 * eina_error_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_error_shutdown(void)
{
	Eina_Error_Message *eem, *eem_end;

	eem = _eina_errors;
	eem_end = eem + _eina_errors_count;

	for (; eem < eem_end; eem++)
		if (eem->string_allocated)
			free((char *) eem->string);

	free(_eina_errors);
	_eina_errors = NULL;
	_eina_errors_count = 0;
	_eina_errors_allocated = 0;

	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Error_Group Error
 *
 * @brief These functions provide error management for projects.
 *
 * To use the error system Eina must be initialized with eina_init()
 * and later shut down with eina_shutdown(). Error codes are
 * registered with eina_error_msg_register() and converted from
 * identifier to original message string with eina_error_msg_get().
 *
 * Logging functions are not in eina_error anymore, see
 * eina_log_print() instead.
 *
 * @{
 */

/**
 * @brief Register a new error type.
 *
 * @param msg The description of the error. It will be duplicated using
 *        strdup().
 * @return The unique number identifier for this error.
 *
 * This function stores in a list the error message described by
 * @p msg. The returned value is a unique identifier greater or equal
 * than 1. The description can be retrieve later by passing to
 * eina_error_msg_get() the returned value.
 *
 * @see eina_error_msg_static_register()
 */
EAPI Eina_Error eina_error_msg_register(const char *msg)
{
	Eina_Error_Message *eem;

	EINA_SAFETY_ON_NULL_RETURN_VAL(msg, 0);

	eem = _eina_error_msg_alloc();
	if (!eem)
		return 0;

	eem->string_allocated = EINA_TRUE;
	eem->string = strdup(msg);
	if (!eem->string) {
		_eina_errors_count--;
		return 0;
	}

	return _eina_errors_count;	/* identifier = index + 1 (== _count). */
}

/**
 * @brief Register a new error type, statically allocated message.
 *
 * @param msg The description of the error. This string will not be
 *        duplicated and thus the given pointer should live during
 *        usage of eina_error.
 * @return The unique number identifier for this error.
 *
 * This function stores in a list the error message described by
 * @p msg. The returned value is a unique identifier greater or equal
 * than 1. The description can be retrieve later by passing to
 * eina_error_msg_get() the returned value.
 *
 * @see eina_error_msg_register()
 */
EAPI Eina_Error eina_error_msg_static_register(const char *msg)
{
	Eina_Error_Message *eem;

	EINA_SAFETY_ON_NULL_RETURN_VAL(msg, 0);

	eem = _eina_error_msg_alloc();
	if (!eem)
		return 0;

	eem->string_allocated = EINA_FALSE;
	eem->string = msg;
	return _eina_errors_count;	/* identifier = index + 1 (== _count). */
}

/**
 * @brief Change the message of an already registered message
 *
 * @param error The Eina_Error to change the message of
 * @param msg The description of the error. This string will be
 * duplicated only if the error was registered with @ref eina_error_msg_register
 * otherwise it must remain intact for the duration
 * @return EINA_TRUE if successful, EINA_FALSE on error
 *
 * This function modifies the message associated with @p error and changes
 * it to @p msg.  If the error was previously registered by @ref eina_error_msg_static_register
 * then the string will not be duplicated, otherwise the previous message
 * will be freed and @p msg copied.
 *
 * @see eina_error_msg_register()
 */
EAPI Eina_Bool eina_error_msg_modify(Eina_Error error, const char *msg)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(msg, EINA_FALSE);
	if (error < 1)
		return EINA_FALSE;

	if ((size_t) error > _eina_errors_count)
		return EINA_FALSE;

	if (_eina_errors[error - 1].string_allocated) {
		const char *tmp;

		if (!(tmp = strdup(msg)))
			return EINA_FALSE;

		free((void *) _eina_errors[error - 1].string);
		_eina_errors[error - 1].string = tmp;
		return EINA_TRUE;
	}

	_eina_errors[error - 1].string = msg;
	return EINA_TRUE;
}

/**
 * @brief Return the description of the given an error number.
 *
 * @param error The error number.
 * @return The description of the error.
 *
 * This function returns the description of an error that has been
 * registered with eina_error_msg_register(). If an incorrect error is
 * given, then @c NULL is returned.
 */
EAPI const char *eina_error_msg_get(Eina_Error error)
{
	if (error < 1)
		return NULL;

	if ((size_t) error > _eina_errors_count)
		return NULL;

	return _eina_errors[error - 1].string;
}

/**
 * @brief Return the last set error.
 *
 * @return The last error.
 *
 * This function returns the last error set by eina_error_set(). The
 * description of the message is returned by eina_error_msg_get().
 */
EAPI Eina_Error eina_error_get(void)
{
	return _eina_last_error;
}

/**
 * @brief Set the last error.
 *
 * @param err The error identifier.
 *
 * This function sets the last error identifier. The last error can be
 * retrieved with eina_error_get().
 */
EAPI void eina_error_set(Eina_Error err)
{
	_eina_last_error = err;
}

/**
 * @}
 */
