/* EINA - EFL data type library
 * Copyright (C) 2008 Cedric Bail
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

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "eina_config.h"
#include "eina_private.h"
#include "eina_error.h"
#include "eina_log.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_magic.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

typedef struct _Eina_Magic_String Eina_Magic_String;
struct _Eina_Magic_String {
	Eina_Magic magic;
	Eina_Bool string_allocated;
	const char *string;
};

static int _eina_magic_string_log_dom = -1;

#ifdef ERR
#undef ERR
#endif
#define ERR(...) EINA_LOG_DOM_ERR(_eina_magic_string_log_dom, __VA_ARGS__)

#ifdef DBG
#undef DBG
#endif
#define DBG(...) EINA_LOG_DOM_DBG(_eina_magic_string_log_dom, __VA_ARGS__)

static Eina_Magic_String *_eina_magic_strings = NULL;
static size_t _eina_magic_strings_count = 0;
static size_t _eina_magic_strings_allocated = 0;
static Eina_Bool _eina_magic_strings_dirty = 0;

static int _eina_magic_strings_sort_cmp(const void *p1, const void *p2)
{
	const Eina_Magic_String *a = p1, *b = p2;
	return a->magic - b->magic;
}

static int _eina_magic_strings_find_cmp(const void *p1, const void *p2)
{
	Eina_Magic a = (long) p1;
	const Eina_Magic_String *b = p2;
	return a - b->magic;
}

static Eina_Magic_String *_eina_magic_strings_alloc(void)
{
	size_t idx;

	if (_eina_magic_strings_count == _eina_magic_strings_allocated) {
		void *tmp;
		size_t size;

		if (EINA_UNLIKELY(_eina_magic_strings_allocated == 0))
			size = 48;
		else
			size = _eina_magic_strings_allocated + 16;

		tmp =
		    realloc(_eina_magic_strings,
			    sizeof(Eina_Magic_String) * size);
		if (!tmp) {
#ifdef _WIN32
			ERR("could not realloc magic_strings from %Iu to %Iu buckets.",
#else
			ERR("could not realloc magic_strings from %zu to %zu buckets.",
#endif
			    _eina_magic_strings_allocated, size);
			return NULL;
		}

		_eina_magic_strings = tmp;
		_eina_magic_strings_allocated = size;
	}

	idx = _eina_magic_strings_count;
	_eina_magic_strings_count++;
	return _eina_magic_strings + idx;
}

/**
 * @endcond
 */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Initialize the magic string module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the magic string module of Eina. It is called by
 * eina_init().
 *
 * @see eina_init()
 */
Eina_Bool eina_magic_string_init(void)
{
	_eina_magic_string_log_dom = eina_log_domain_register
	    ("eina_magic_string", EINA_LOG_COLOR_DEFAULT);
	if (_eina_magic_string_log_dom < 0) {
		EINA_LOG_ERR
		    ("Could not register log domain: eina_magic_string");
		return EINA_FALSE;
	}

	return EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the magic string module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the magic string module set up by
 * eina_magic string_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_magic_string_shutdown(void)
{
	Eina_Magic_String *ems, *ems_end;

	ems = _eina_magic_strings;
	ems_end = ems + _eina_magic_strings_count;

	for (; ems < ems_end; ems++)
		if (ems->string_allocated)
			free((char *) ems->string);

	free(_eina_magic_strings);
	_eina_magic_strings = NULL;
	_eina_magic_strings_count = 0;
	_eina_magic_strings_allocated = 0;

	eina_log_domain_unregister(_eina_magic_string_log_dom);
	_eina_magic_string_log_dom = -1;

	return EINA_TRUE;
}

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Magic_Group Magic
 *
 * @brief These functions provide runtime type-checking (magic checks)
 * management for projects.
 *
 * C is a weak statically typed language, in other words, it will just
 * check for types during compile time and any cast will make the
 * compiler believe the type is correct.
 *
 * In real world projects we often need to deal with casts, either
 * explicit or implicit by means of @c void*. We also need to resort
 * to casts when doing inheritance in C, as seen in the example below:
 *
 * @code
 * struct base {
 *    int id;
 *    char *name;
 * };
 * int base_id_get(struct base *ptr) {
 *    return ptr->id;
 * }
 *
 * struct subtype {
 *    struct base base;
 *    time_t date;
 * };
 * @endcode
 *
 * It is perfectly valid to use @c {struct subtype} blobs for functions
 * that expect @c {struct base}, since the fields will have the same
 * offset (as base member is the first, at offset 0). We could give
 * the functions the @c {&subtype->base} and avoid the cast, but often
 * we just cast.
 *
 * In any case, we might be safe and check if the given pointer is
 * actually of the expected type. We can do so by using eina_magic,
 * that is nothing more than attaching an unique type identifier to
 * the members and check for it elsewhere.
 *
 * @code
 * #define BASE_MAGIC 0x12345
 * #define SUBTYPE_MAGIC 0x3333
 * struct base {
 *    int id;
 *    char *name;
 *    EINA_MAGIC;
 * };
 * int base_id_get(struct base *ptr) {
 *    if (!EINA_MAGIC_CHECK(ptr, BASE_MAGIC)) {
 *       EINA_MAGIC_FAIL(ptr, BASE_MAGIC);
 *       return -1;
 *    }
 *    return ptr->id;
 * }
 * void base_free(struct base *ptr) {
 *    if (!EINA_MAGIC_CHECK(ptr, BASE_MAGIC)) {
 *       EINA_MAGIC_FAIL(ptr, BASE_MAGIC);
 *       return;
 *    }
 *    EINA_MAGIC_SET(ptr, EINA_MAGIC_NONE);
 *    free(ptr->name);
 *    free(ptr);
 * }
 * struct base *base_new(int id, const char *name) {
 *    struct base *ptr = malloc(sizeof(struct base));
 *    EINA_MAGIC_SET(ptr, BASE_MAGIC);
 *    ptr->id = id;
 *    ptr->name = strdup(name);
 * }
 *
 * struct subtype {
 *    struct base base;
 *    EINA_MAGIC;
 *    time_t date;
 * };
 *
 * int my_init(void) {
 *    eina_init();
 *    eina_magic_string_set(BASE_MAGIC, "base type");
 *    eina_magic_string_set(SUBTYPE_MAGIC, "subtype");
 * }
 * @endcode
 *
 * This code also shows that it is a good practice to set magic to
 * #EINA_MAGIC_NONE before freeing pointer. Sometimes the pointers are
 * in pages that are still live in memory, so kernel will not send
 * SEGV signal to the process and it may go unnoticed that you're
 * using already freed pointers. By setting them to #EINA_MAGIC_NONE
 * you avoid using the bogus pointer any further and gets a nice error
 * message.
 *
 * @{
 */

/**
 * @brief Return the string associated to the given magic identifier.
 *
 * @param magic The magic identifier.
 * @return The string associated to the identifier.
 *
 * This function returns the string associated to @p magic. If none
 * are found, the this function still returns non @c NULL, in this
 * case an identifier such as "(none)", "(undefined)" or
 * "(unknown)". The returned value must not be freed.
 *
 * The following identifiers may be returned whenever magic is
 * invalid, with their meanings:
 *
 *   - (none): no magic was registered exists at all.
 *   - (undefined): magic was registered and found, but no string associated.
 *   - (unknown): magic was not found in the registry.
 */
EAPI const char *eina_magic_string_get(Eina_Magic magic)
{
	Eina_Magic_String *ems;

	if (!_eina_magic_strings)
		return "(none)";

	if (_eina_magic_strings_dirty) {
		qsort(_eina_magic_strings, _eina_magic_strings_count,
		      sizeof(Eina_Magic_String),
		      _eina_magic_strings_sort_cmp);
		_eina_magic_strings_dirty = 0;
	}

	ems = bsearch((void *) (long) magic, _eina_magic_strings,
		      _eina_magic_strings_count, sizeof(Eina_Magic_String),
		      _eina_magic_strings_find_cmp);
	if (ems)
		return ems->string ? ems->string : "(undefined)";

	return "(unknown)";
}

/**
 * @brief Set the string associated to the given magic identifier.
 *
 * @param magic The magic identifier.
 * @param magic_name The string associated to the identifier, must not
 *        be @c NULL.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets the string @p magic_name to @p magic. It is not
 * checked if number or string are already set, then you might end
 * with duplicates in that case.
 *
 * @see eina_magic_string_static_set()
 */
EAPI Eina_Bool
eina_magic_string_set(Eina_Magic magic, const char *magic_name)
{
	Eina_Magic_String *ems;

	EINA_SAFETY_ON_NULL_RETURN_VAL(magic_name, EINA_FALSE);

	ems = _eina_magic_strings_alloc();
	if (!ems)
		return EINA_FALSE;

	ems->magic = magic;
	ems->string_allocated = EINA_TRUE;
	ems->string = strdup(magic_name);
	if (!ems->string) {
		ERR("could not allocate string '%s'", magic_name);
		_eina_magic_strings_count--;
		return EINA_FALSE;
	}

	_eina_magic_strings_dirty = 1;
	return EINA_TRUE;
}

/**
 * @brief Set the string associated to the given magic identifier.
 *
 * @param magic The magic identifier.
 * @param magic_name The string associated to the identifier, must not be
 *        @c NULL, it will not be duplcated, just referenced thus it must
 *        be live during magic number usage.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets the string @p magic_name to @p magic. It is not
 * checked if number or string are already set, then you might end
 * with duplicates in that case.
 *
 * @see eina_magic_string_set()
 */
EAPI Eina_Bool
eina_magic_string_static_set(Eina_Magic magic, const char *magic_name)
{
	Eina_Magic_String *ems;

	EINA_SAFETY_ON_NULL_RETURN_VAL(magic_name, EINA_FALSE);

	ems = _eina_magic_strings_alloc();
	if (!ems)
		return EINA_FALSE;

	ems->magic = magic;
	ems->string_allocated = EINA_FALSE;
	ems->string = magic_name;

	_eina_magic_strings_dirty = 1;
	return EINA_TRUE;
}

#ifdef eina_magic_fail
#undef eina_magic_fail
#endif

/**
 * @brief Display a message or abort is a magic check failed.
 *
 * @param d The checked data pointer.
 * @param m The magic identifer to check.
 * @param req_m The requested magic identifier to check.
 * @param file The file in which the magic check failed.
 * @param fnc The function in which the magic check failed.
 * @param line The line at which the magic check failed.
 *
 * This function displays an error message if a magic check has
 * failed, using the following logic in the following order:
 * @li If @p d is @c NULL, a message warns about a @c NULL pointer.
 * @li Otherwise, if @p m is equal to #EINA_MAGIC_NONE, a message
 * warns about a handle that was already freed.
 * @li Otherwise, if @p m is equal to @p req_m, a message warns about
 * a handle that is of wrong type.
 * @li Otherwise, a message warns you about ab-using that function...
 *
 * If the environment variable EINA_ERROR_ABORT is set, abort() is
 * called and the program stops. It is useful for debugging programs
 * with gdb.
 */
EAPI void
eina_magic_fail(void *d,
		Eina_Magic m,
		Eina_Magic req_m,
		const char *file, const char *fnc, int line)
{
	if (!d)
		eina_log_print(EINA_LOG_DOMAIN_GLOBAL,
			       EINA_LOG_LEVEL_CRITICAL, file, fnc, line,
			       "*** Eina Magic Check Failed !!!\n"
			       "    Input handle pointer is NULL !\n"
			       "*** NAUGHTY PROGRAMMER!!!\n"
			       "*** SPANK SPANK SPANK!!!\n"
			       "*** Now go fix your code. Tut tut tut!\n"
			       "\n");
	else if (m == EINA_MAGIC_NONE)
		eina_log_print(EINA_LOG_DOMAIN_GLOBAL,
			       EINA_LOG_LEVEL_CRITICAL, file, fnc, line,
			       "*** Eina Magic Check Failed !!!\n"
			       "    Input handle has already been freed!\n"
			       "*** NAUGHTY PROGRAMMER!!!\n"
			       "*** SPANK SPANK SPANK!!!\n"
			       "*** Now go fix your code. Tut tut tut!\n"
			       "\n");
	else if (m != req_m)
		eina_log_print(EINA_LOG_DOMAIN_GLOBAL,
			       EINA_LOG_LEVEL_CRITICAL, file, fnc, line,
			       "*** Eina Magic Check Failed !!!\n"
			       "    Input handle is wrong type\n"
			       "    Expected: %08x - %s\n"
			       "    Supplied: %08x - %s\n"
			       "*** NAUGHTY PROGRAMMER!!!\n"
			       "*** SPANK SPANK SPANK!!!\n"
			       "*** Now go fix your code. Tut tut tut!\n"
			       "\n", req_m, eina_magic_string_get(req_m),
			       m, eina_magic_string_get(m));
	else
		eina_log_print(EINA_LOG_DOMAIN_GLOBAL,
			       EINA_LOG_LEVEL_CRITICAL, file, fnc, line,
			       "*** Eina Magic Check Failed !!!\n"
			       "    Why did you call me !\n"
			       "*** NAUGHTY PROGRAMMER!!!\n"
			       "*** SPANK SPANK SPANK!!!\n"
			       "*** Now go fix your code. Tut tut tut!\n"
			       "\n");
}

/**
 * @}
 */
