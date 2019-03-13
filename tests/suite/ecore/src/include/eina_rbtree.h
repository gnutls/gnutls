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

#ifndef EINA_RBTREE_H__
#define EINA_RBTREE_H__

#include <stdlib.h>

#include "eina_types.h"
#include "eina_error.h"
#include "eina_iterator.h"

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
 * @defgroup Eina_Rbtree_Group Red-Black tree
 *
 * @{
 */

/**
 * @typedef Eina_Rbtree_Color
 * node color.
 */
typedef enum {
	EINA_RBTREE_RED,
	EINA_RBTREE_BLACK
} Eina_Rbtree_Color;

/**
 * @typedef Eina_Rbtree_Direction
 * walk direction.
 */
typedef enum {
	EINA_RBTREE_LEFT = 0,
	EINA_RBTREE_RIGHT = 1
} Eina_Rbtree_Direction;

/**
 * @typedef Eina_Rbtree
 * Type for a Red-Black tree node. It should be inlined into user's type.
 */
typedef struct _Eina_Rbtree Eina_Rbtree;
struct _Eina_Rbtree {
	Eina_Rbtree *son[2];

	Eina_Rbtree_Color color:1;
};

/**
 * @def EINA_RBTREE
 * recommended way to declare the inlined Eina_Rbtree in your type.
 *
 * @code
 * struct my_type {
 *    EINA_RBTREE;
 *    int my_value;
 *    char *my_name;
 * };
 * @endcode
 *
 * @see EINA_RBTREE_GET()
 */
#define EINA_RBTREE Eina_Rbtree __rbtree

/**
 * @def EINA_RBTREE_GET
 * access the inlined node if it was created with #EINA_RBTREE.
 */
#define EINA_RBTREE_GET(Rbtree) & ((Rbtree)->__rbtree)

/**
 * @typedef Eina_Rbtree_Cmp_Node_Cb
 * Function used compare two nodes and see which direction to navigate.
 */
typedef Eina_Rbtree_Direction(*Eina_Rbtree_Cmp_Node_Cb) (const Eina_Rbtree
							 * left,
							 const Eina_Rbtree
							 * right,
							 void *data);

/**
 * @def EINA_RBTREE_CMP_NODE_CB
 * Cast using #Eina_Rbtree_Cmp_Node_Cb
 */
#define EINA_RBTREE_CMP_NODE_CB(Function) ((Eina_Rbtree_Cmp_Node_Cb)Function)

/**
 * @typedef Eina_Rbtree_Cmp_Key_Cb
 * Function used compare node with a given key of specified length.
 */
typedef int (*Eina_Rbtree_Cmp_Key_Cb) (const Eina_Rbtree * node,
				       const void *key, int length,
				       void *data);
/**
 * @def EINA_RBTREE_CMP_KEY_CB
 * Cast using #Eina_Rbtree_Cmp_Key_Cb
 */
#define EINA_RBTREE_CMP_KEY_CB(Function) ((Eina_Rbtree_Cmp_Key_Cb)Function)

/**
 * @typedef Eina_Rbtree_Free_Cb
 * Function used free a node.
 */
typedef void (*Eina_Rbtree_Free_Cb) (Eina_Rbtree * node, void *data);
/**
 * @def EINA_RBTREE_FREE_CB
 * Cast using #Eina_Rbtree_Free_Cb
 */
#define EINA_RBTREE_FREE_CB(Function) ((Eina_Rbtree_Free_Cb)Function)

EAPI Eina_Rbtree *eina_rbtree_inline_insert(Eina_Rbtree * root,
					    Eina_Rbtree * node,
					    Eina_Rbtree_Cmp_Node_Cb cmp,
					    const void *data)
EINA_ARG_NONNULL(2, 3) EINA_WARN_UNUSED_RESULT;
EAPI Eina_Rbtree *eina_rbtree_inline_remove(Eina_Rbtree * root,
					    Eina_Rbtree * node,
					    Eina_Rbtree_Cmp_Node_Cb cmp,
					    const void *data)
EINA_ARG_NONNULL(2, 3) EINA_WARN_UNUSED_RESULT;
EAPI void eina_rbtree_delete(Eina_Rbtree * root, Eina_Rbtree_Free_Cb func,
			     void *data) EINA_ARG_NONNULL(2);

static inline Eina_Rbtree *eina_rbtree_inline_lookup(const Eina_Rbtree *
						     root, const void *key,
						     int length,
						     Eina_Rbtree_Cmp_Key_Cb
						     cmp, const void *data)
EINA_PURE EINA_ARG_NONNULL(2, 4) EINA_WARN_UNUSED_RESULT;

EAPI Eina_Iterator *eina_rbtree_iterator_prefix(const Eina_Rbtree * root)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI Eina_Iterator *eina_rbtree_iterator_infix(const Eina_Rbtree * root)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI Eina_Iterator *eina_rbtree_iterator_postfix(const Eina_Rbtree * root)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;

#include "eina_inline_rbtree.x"


/**
 * @}
 */

/**
 * @}
 */

/**
 * @}
 */

#endif
