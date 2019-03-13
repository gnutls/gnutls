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

#ifndef EINA_INLINE_TRASH_X__
#define EINA_INLINE_TRASH_X__

/**
 * @brief Initialize a trash before using it.
 *
 * @param trash The trash.
 *
 * This function just set to zero the trash to correctly
 * initialize it.
 *
 * @note You can just set *trash to NULL and you will have
 * the same result.
 */
static inline void
eina_trash_init(Eina_Trash **trash)
{
   *trash = NULL;
}

/**
 * @brief Push an unused pointer in the trash instead of freeing it.
 *
 * @param trash A pointer to an Eina_Trash.
 * @param data An unused pointer big enougth to put a (void*).
 *
 * Instead of freeing a pointer and put pressure on malloc/free
 * you can push it in a trash for a later use. This function just
 * provide a fast way to push a now unused pointer into a trash.
 *
 * @note Do never use the pointer after insertion or bad things will
 * happens.
 *
 * @note This trash will not resize, nor do anything with the size of
 * the region pointed by @p data, so it's your duty to manage the size.
 */
static inline void
eina_trash_push(Eina_Trash **trash, void *data)
{
   Eina_Trash *tmp;

   tmp = (Eina_Trash *)data;
   tmp->next = *trash;
   *trash = tmp;
}

/**
 * @brief Pop an available pointer from the trash if possible.
 *
 * @param trash A pointer to an Eina_Trash.
 *
 * Instead of calling malloc, and putting pressure on malloc/free
 * you can recycle the content of the trash, if it's not empty.
 *
 * @note This trash will not resize, nor do anything with the size of
 * the region pointed by pointer inside the trash, so it's your duty
 * to manage the size of the returned pointer.
 */
static inline void*
eina_trash_pop(Eina_Trash **trash)
{
   void *tmp;

   tmp = *trash;

   if (*trash)
     *trash = (*trash)->next;

   return tmp;
}

#endif
