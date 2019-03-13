/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Carsten Haitzler, Vincent Torri, Jorge Luis Zapata Muga
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

#ifndef EINA_TRASH_H__
#define EINA_TRASH_H__

/**
 * @addtogroup Eina_Data_Types_Group Data Types
 *
 * @{
 */

/**
 * @addtogroup Eina_Containers_Group Containers
 *
 * @{
 */

/**
 * @defgroup Eina_Trash_Group Trash
 *
 * @{
 */

/**
 * @typedef Eina_Trash
 * Type for a generic container of unused allocated pointer.
 */
typedef struct _Eina_Trash Eina_Trash;

/**
 * @struct _Eina_Trash
 * Type for a generic container of unused allocated pointer.
 */
struct _Eina_Trash {
	Eina_Trash *next;
		     /**< next item in trash. */
};

static inline void eina_trash_init(Eina_Trash **
				   trash) EINA_ARG_NONNULL(1);
static inline void eina_trash_push(Eina_Trash ** trash,
				   void *data) EINA_ARG_NONNULL(1);
static inline void *eina_trash_pop(Eina_Trash **
				   trash) EINA_ARG_NONNULL(1)
    EINA_WARN_UNUSED_RESULT;

/**
 * @def EINA_TRASH_CLEAN
 * @brief Macro to remove all pointer from the trash.
 *
 * @param trash The trash to clean.
 * @param data The pointer extracted from the trash.
 *
 * This macro allow the cleaning of @p trash in an easy way. It will
 * remove all pointers from @p trash until it's empty.
 *
 * This macro can be used for freeing the data in the trash, like in
 * the following example:
 *
 * @code
 * Eina_Trash *trash = NULL;
 * char *data;
 *
 * // trash is filled with pointer to some duped strings.
 *
 * EINA_TRASH_CLEAN(&trash, data)
 *   free(data);
 * @endcode
 *
 * @note this macro is useful when you implement some memory pool.
 */
#define EINA_TRASH_CLEAN(trash, data) while ((data = eina_trash_pop(trash))

#include "eina_inline_trash.x"

/**
 * @}
 */

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_TRASH_H_ */
