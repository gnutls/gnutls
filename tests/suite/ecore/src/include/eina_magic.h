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

#ifndef EINA_MAGIC_H_
#define EINA_MAGIC_H_


#include "eina_config.h"
#include "eina_types.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_Magic_Group Magic
 *
 * @{
 */

typedef unsigned int Eina_Magic;

/**
 * @typedef Eina_Magic
 * An abstract type for a magic number.
 */
EAPI const char *eina_magic_string_get(Eina_Magic magic)
EINA_PURE EINA_WARN_UNUSED_RESULT;
EAPI Eina_Bool eina_magic_string_set(Eina_Magic magic,
				     const char *magic_name)
EINA_ARG_NONNULL(2);
EAPI Eina_Bool eina_magic_string_static_set(Eina_Magic magic,
					    const char *magic_name)
EINA_ARG_NONNULL(2);

/**
 * @def EINA_MAGIC_NONE
 * Random value for specifying that a structure using the magic
 * feature has already been freed. It is used by eina_magic_fail().
 *
 * If the magic feature of Eina is disabled, #EINA_MAGIC_NONE is just
 * @c 0.
 */
#define EINA_MAGIC_NONE            0x1234fedc

#ifdef EINA_MAGIC_DEBUG

/**
 * @def EINA_MAGIC
 * Declaration of a variable of type #Eina_Magic. To put in a structure
 * when one wants to use the magic feature of Eina with the functions
 * of that structure, like that:
 *
 * @code
 * struct Foo
 * {
 *    int i;
 *
 *    EINA_MAGIC
 * };
 * @endcode
 *
 * If the magic feature of Eina is disabled, #EINA_MAGIC does nothing.
 */
#define EINA_MAGIC      Eina_Magic __magic;

/**
 * @def EINA_MAGIC_SET(d, m)
 * Set the magic number of @p d to @p m. @p d must be a valid pointer
 * to a structure holding an Eina magic number declaration. Use
 * #EINA_MAGIC to add such declaration.
 *
 * If the magic feature of Eina is disabled, #EINA_MAGIC_CHECK is just
 * the value @c 0.
 */
#define EINA_MAGIC_SET(d, m)       (d)->__magic = (m)

/**
 * @def EINA_MAGIC_CHECK(d, m)
 * Test if @p d is @c NULL or not, and if not @c NULL, if
 * @p d->__eina_magic is equal to @p m. @p d must be a structure that
 * holds an Eina magic number declaration. Use #EINA_MAGIC to add such
 * declaration.
 *
 * If the magic feature of Eina is disabled, #EINA_MAGIC_CHECK is just
 * the value @c 1.
 */
#define EINA_MAGIC_CHECK(d, m)     ((d) && ((d)->__magic == (m)))

/**
 * @def EINA_MAGIC_FAIL(d, m)
 * Call eina_magic_fail() with the parameters @p d, @p d->__magic, @p
 * m, __FILE__, __FUNCTION__ and __LINE__. @p d must be a structure that
 * holds an Eina magic number declaration. Use #EINA_MAGIC to add such
 * declaration.
 *
 * If the magic feature of Eina is disabled, #EINA_MAGIC_FAIL does
 * nothing.
 */
#define EINA_MAGIC_FAIL(d, m)			\
  eina_magic_fail((void *)(d),			\
		  (d) ? (d)->__magic : 0,	\
		  (m),				\
		  __FILE__,			\
		  __FUNCTION__,			\
		  __LINE__);

EAPI void eina_magic_fail(void *d, Eina_Magic m, Eina_Magic req_m,
			  const char *file, const char *fnc,
			  int line) EINA_ARG_NONNULL(4, 5);

#else

/**
 * @cond LOCAL
 */

#define EINA_MAGIC
#define EINA_MAGIC_SET(d, m)       ((void)0)
#define EINA_MAGIC_CHECK(d, m)     (1)
#define EINA_MAGIC_FAIL(d, m)      ((void)0)

#define eina_magic_fail(d, m, req_m, file, fnx, line) ((void)0)

/**
 * @endcond
 */

#endif

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_MAGIC_H_ */
