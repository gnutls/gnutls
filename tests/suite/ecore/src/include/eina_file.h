/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Jorge Luis Zapata Muga
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

#ifndef EINA_FILE_H_
#define EINA_FILE_H_

#include <limits.h>

#include "eina_types.h"
#include "eina_array.h"
#include "eina_iterator.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_File_Group File
 *
 * @{
 */

/**
 * @typedef Eina_File_Direct_Info
 * A typedef to #_Eina_File_Direct_Info.
 */
typedef struct _Eina_File_Direct_Info Eina_File_Direct_Info;

/**
 * @typedef Eina_File_Dir_List_Cb
 * Type for a callback to be called when iterating over the files of a
 * directory.
 */
typedef void (*Eina_File_Dir_List_Cb) (const char *name, const char *path,
				       void *data);

#ifndef _POSIX_PATH_MAX
# define _POSIX_PATH_MAX 256
#endif

/**
 * @struct _Eina_File_Direct_Info
 * A structure to store informations of a path.
 */
struct _Eina_File_Direct_Info {
	size_t path_length;
		       /**< size of the whole path */
	size_t name_length;
		       /**< size of the filename/basename component */
	size_t name_start;
		      /**< where the filename/basename component starts */
	char path[_POSIX_PATH_MAX];
			/**< the path */
	const struct dirent *dirent;
				/**< the dirent structure of the path */
};

/**
 * @def EINA_FILE_DIR_LIST_CB
 * @brief cast to an #Eina_File_Dir_List_Cb.
 *
 * @param function The function to cast.
 *
 * This macro casts @p function to Eina_File_Dir_List_Cb.
 */
#define EINA_FILE_DIR_LIST_CB(function) ((Eina_File_Dir_List_Cb)function)

EAPI Eina_Bool eina_file_dir_list(const char *dir,
				  Eina_Bool recursive,
				  Eina_File_Dir_List_Cb cb,
				  void *data) EINA_ARG_NONNULL(1, 3);
EAPI Eina_Array *eina_file_split(char *path)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1) EINA_MALLOC;
EAPI Eina_Iterator *eina_file_ls(const char *dir)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1) EINA_MALLOC;
EAPI Eina_Iterator *eina_file_direct_ls(const char *dir)
EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1) EINA_MALLOC;

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_FILE_H_ */
