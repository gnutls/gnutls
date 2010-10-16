/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Cedric BAIL
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
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EINA_RBTREE_INLINE_H_
#define EINA_RBTREE_INLINE_H_

/**
 * @addtogroup Eina_Rbtree_Group Red-Black tree
 *
 * @brief These functions provide Red-Black trees management.
 *
 * @{
 */

static inline Eina_Rbtree *
eina_rbtree_inline_lookup(const Eina_Rbtree *root, const void *key, int length, Eina_Rbtree_Cmp_Key_Cb cmp, const void *data)
{
   int result;

   while (root)
     {
        result = cmp(root, key, length, (void*) data);
        if (result == 0) return (Eina_Rbtree*) root;

        root = root->son[result < 0 ? 0 : 1];
     }

   return NULL;
}

/**
 * @}
 */

#endif
