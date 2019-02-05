/* EINA - EFL data type library
 * Copyright (C) 2009 Gustavo Sverzut Barbieri
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

#ifndef EINA_MATRIXSPARSE_H_
#define EINA_MATRIXSPARSE_H_

#include <stdlib.h>

#include "eina_config.h"

#include "eina_types.h"
#include "eina_iterator.h"
#include "eina_accessor.h"

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
 * @defgroup Eina_Matrixsparse_Group Sparse Matrix
 *
 * @{
 */

/**
 * @typedef Eina_Matrixsparse
 * Type for a generic sparse matrix.
 */
typedef struct _Eina_Matrixsparse Eina_Matrixsparse;

/**
 * @typedef Eina_Matrixsparse_Row
 * Type for a generic sparse matrix row, opaque for users.
 */
typedef struct _Eina_Matrixsparse_Row Eina_Matrixsparse_Row;

/**
 * @typedef Eina_Matrixsparse_Cell
 * Type for a generic sparse matrix cell, opaque for users.
 */
typedef struct _Eina_Matrixsparse_Cell Eina_Matrixsparse_Cell;

typedef struct _Eina_Matrixsparse_Item_Cell Eina_Matrixsparse_Item_Cell;
typedef struct _Eina_Matrixsparse_Item_Row Eina_Matrixsparse_Item_Row;


/* constructors and destructors */
EAPI Eina_Matrixsparse *eina_matrixsparse_new(unsigned long rows,
					      unsigned long cols,
					      void (*free_func) (void
								 *user_data,
								 void
								 *cell_data),
					      const void *user_data);
EAPI void eina_matrixsparse_free(Eina_Matrixsparse * m);

/* size manipulation */
EAPI void eina_matrixsparse_size_get(const Eina_Matrixsparse * m,
				     unsigned long *rows,
				     unsigned long *cols);
EAPI Eina_Bool eina_matrixsparse_size_set(Eina_Matrixsparse * m,
					  unsigned long rows,
					  unsigned long cols);

/* data getting */
EAPI Eina_Bool eina_matrixsparse_cell_idx_get(const Eina_Matrixsparse * m,
					      unsigned long row,
					      unsigned long col,
					      Eina_Matrixsparse_Cell **
					      cell);
EAPI void *eina_matrixsparse_cell_data_get(const Eina_Matrixsparse_Cell *
					   cell);
EAPI void *eina_matrixsparse_data_idx_get(const Eina_Matrixsparse * m,
					  unsigned long row,
					  unsigned long col);
EAPI Eina_Bool eina_matrixsparse_cell_position_get(const
						   Eina_Matrixsparse_Cell *
						   cell,
						   unsigned long *row,
						   unsigned long *col);

/* data setting */
EAPI Eina_Bool eina_matrixsparse_cell_data_replace(Eina_Matrixsparse_Cell *
						   cell, const void *data,
						   void **p_old);
EAPI Eina_Bool eina_matrixsparse_cell_data_set(Eina_Matrixsparse_Cell *
					       cell, const void *data);
EAPI Eina_Bool eina_matrixsparse_data_idx_replace(Eina_Matrixsparse * m,
						  unsigned long row,
						  unsigned long col,
						  const void *data,
						  void **p_old);
EAPI Eina_Bool eina_matrixsparse_data_idx_set(Eina_Matrixsparse * m,
					      unsigned long row,
					      unsigned long col,
					      const void *data);

/* data deleting */
EAPI Eina_Bool eina_matrixsparse_row_idx_clear(Eina_Matrixsparse * m,
					       unsigned long row);
EAPI Eina_Bool eina_matrixsparse_column_idx_clear(Eina_Matrixsparse * m,
						  unsigned long col);
EAPI Eina_Bool eina_matrixsparse_cell_idx_clear(Eina_Matrixsparse * m,
						unsigned long row,
						unsigned long col);
EAPI Eina_Bool eina_matrixsparse_cell_clear(Eina_Matrixsparse_Cell * cell);

/* iterators */
EAPI Eina_Iterator *eina_matrixsparse_iterator_new(const Eina_Matrixsparse
						   * m);
EAPI Eina_Iterator *eina_matrixsparse_iterator_complete_new(const
							    Eina_Matrixsparse
							    * m);

/**
 * @}
 */

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_MATRIXSPARSE_H_ */
