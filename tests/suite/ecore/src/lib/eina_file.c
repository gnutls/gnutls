/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Jorge Luis Zapata Muga, Vincent Torri
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

#ifndef _WIN32
#define _GNU_SOURCE
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#elif defined __GNUC__
#define alloca __builtin_alloca
#elif defined _AIX
#define alloca __alloca
#elif defined _MSC_VER
#include <malloc.h>
#define alloca _alloca
#else
#include <stddef.h>
#ifdef  __cplusplus
extern "C"
#endif
void *alloca(size_t);
#endif

#include <string.h>
#include <dirent.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <Evil.h>
#endif				/* _WIN2 */

#ifndef _WIN32
#define PATH_DELIM '/'
#else
#define PATH_DELIM '\\'
#define NAME_MAX MAX_PATH
#endif

#ifdef __sun
#ifndef NAME_MAX
#define NAME_MAX 255
#endif
#endif

#include "eina_config.h"
#include "eina_private.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_file.h"
#include "eina_stringshare.h"

typedef struct _Eina_File_Iterator Eina_File_Iterator;
struct _Eina_File_Iterator {
	Eina_Iterator iterator;

	DIR *dirp;
	int length;

	char dir[1];
};

static Eina_Bool
_eina_file_ls_iterator_next(Eina_File_Iterator * it, void **data)
{
	struct dirent *dp;
	char *name;
	size_t length;

	do {
		dp = readdir(it->dirp);
		if (!dp)
			return EINA_FALSE;
	}
	while ((dp->d_name[0] == '.') &&
	       ((dp->d_name[1] == '\0') ||
		((dp->d_name[1] == '.') && (dp->d_name[2] == '\0'))));

	length = strlen(dp->d_name);
	name = alloca(length + 2 + it->length);

	memcpy(name, it->dir, it->length);
	memcpy(name + it->length, "/", 1);
	memcpy(name + it->length + 1, dp->d_name, length + 1);

	*data = (char *) eina_stringshare_add(name);
	return EINA_TRUE;
}

static char *_eina_file_ls_iterator_container(Eina_File_Iterator * it)
{
	return it->dir;
}

static void _eina_file_ls_iterator_free(Eina_File_Iterator * it)
{
	closedir(it->dirp);

	EINA_MAGIC_SET(&it->iterator, 0);
	free(it);
}

typedef struct _Eina_File_Direct_Iterator Eina_File_Direct_Iterator;
struct _Eina_File_Direct_Iterator {
	Eina_Iterator iterator;

	DIR *dirp;
	int length;

	Eina_File_Direct_Info info;

	char dir[1];
};

static Eina_Bool
_eina_file_direct_ls_iterator_next(Eina_File_Direct_Iterator * it,
				   void **data)
{
	struct dirent *dp;
	size_t length;

	do {
		dp = readdir(it->dirp);
		if (!dp)
			return EINA_FALSE;

		length = strlen(dp->d_name);
		if (it->info.name_start + length + 1 >= PATH_MAX)
			continue;
	}
	while ((dp->d_name[0] == '.') &&
	       ((dp->d_name[1] == '\0') ||
		((dp->d_name[1] == '.') && (dp->d_name[2] == '\0'))));

	memcpy(it->info.path + it->info.name_start, dp->d_name, length);
	it->info.name_length = length;
	it->info.path_length = it->info.name_start + length;
	it->info.path[it->info.path_length] = '\0';
	it->info.dirent = dp;

	*data = &it->info;
	return EINA_TRUE;
}

static char
    *_eina_file_direct_ls_iterator_container(Eina_File_Direct_Iterator *
					     it)
{
	return it->dir;
}

static void
_eina_file_direct_ls_iterator_free(Eina_File_Direct_Iterator * it)
{
	closedir(it->dirp);

	EINA_MAGIC_SET(&it->iterator, 0);
	free(it);
}

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_File_Group File
 *
 * @brief Functions to traverse directories and split paths.
 *
 * @li eina_file_dir_list() list the content of a directory,
 * recusrsively or not, and can call a callback function for eachfound
 * file.
 * @li eina_file_split() split a path into all the subdirectories that
 * compose it, according to the separator of the file system.
 *
 * @{
 */

/**
 * @brief List all files on the directory calling the function for every file found.
 *
 * @param dir The directory name.
 * @param recursive Iterate recursively in the directory.
 * @param cb The callback to be called.
 * @param data The data to pass to the callback.
 * @return #EINA_TRUE on success, #EINA_FALSE otherwise.
 *
 * This function lists all the files in @p dir. To list also all the
 * sub directoris recursively, @p recursive must be set to #EINA_TRUE,
 * otherwise it must be set to #EINA_FALSE. For each found file, @p cb
 * is called and @p data is passed to it.
 *
 * If @p cb or @p dir are @c NULL, or if @p dir is a string of size 0,
 * or if @p dir can not be opened, this function returns #EINA_FALSE
 * immediately. otherwise, it returns #EINA_TRUE.
 */
EAPI Eina_Bool
eina_file_dir_list(const char *dir,
		   Eina_Bool recursive,
		   Eina_File_Dir_List_Cb cb, void *data)
{
#ifndef _WIN32
	struct dirent *de;
	DIR *d;

	EINA_SAFETY_ON_NULL_RETURN_VAL(cb, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(dir, EINA_FALSE);
	EINA_SAFETY_ON_TRUE_RETURN_VAL(dir[0] == '\0', EINA_FALSE);

	d = opendir(dir);
	if (!d)
		return EINA_FALSE;

	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		cb(de->d_name, dir, data);
		/* d_type is only available on linux and bsd (_BSD_SOURCE) */

		if (recursive == EINA_TRUE) {
			char *path;

			path =
			    alloca(strlen(dir) + strlen(de->d_name) + 2);
			strcpy(path, dir);
			strcat(path, "/");
			strcat(path, de->d_name);
#ifndef sun
			if (de->d_type == DT_UNKNOWN) {
#endif
				struct stat st;

				if (stat(path, &st))
					continue;

				if (!S_ISDIR(st.st_mode))
					continue;

#ifndef sun
			} else if (de->d_type != DT_DIR)
				continue;

#endif

			eina_file_dir_list(path, recursive, cb, data);
		}
	}

	closedir(d);
#else
	WIN32_FIND_DATA file;
	HANDLE hSearch;
	char *new_dir;
	TCHAR *tdir;
	size_t length_dir;

	EINA_SAFETY_ON_NULL_RETURN_VAL(cb, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(dir, EINA_FALSE);
	EINA_SAFETY_ON_TRUE_RETURN_VAL(dir[0] == '\0', EINA_FALSE);

	length_dir = strlen(dir);
	new_dir = (char *) alloca(length_dir + 5);
	if (!new_dir)
		return EINA_FALSE;

	memcpy(new_dir, dir, length_dir);
	memcpy(new_dir + length_dir, "/*.*", 5);

#ifdef UNICODE
	tdir = evil_char_to_wchar(new_dir);
#else
	tdir = new_dir;
#endif				/* ! UNICODE */
	hSearch = FindFirstFile(tdir, &file);
#ifdef UNICODE
	free(tdir);
#endif				/* UNICODE */

	if (hSearch == INVALID_HANDLE_VALUE)
		return EINA_FALSE;

	do {
		char *filename;

#ifdef UNICODE
		filename = evil_wchar_to_char(file.cFileName);
#else
		filename = file.cFileName;
#endif				/* ! UNICODE */
		if (!strcmp(filename, ".") || !strcmp(filename, ".."))
			continue;

		cb(filename, dir, data);

		if (recursive == EINA_TRUE) {
			char *path;

			path = alloca(strlen(dir) + strlen(filename) + 2);
			strcpy(path, dir);
			strcat(path, "/");
			strcat(path, filename);

			if (!
			    (file.
			     dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				continue;

			eina_file_dir_list(path, recursive, cb, data);
		}
#ifdef UNICODE
		free(filename);
#endif				/* UNICODE */

	} while (FindNextFile(hSearch, &file));
	FindClose(hSearch);
#endif				/* _WIN32 */

	return EINA_TRUE;
}

/**
 * @brief Split a path according to the delimiter of the filesystem.
 *
 * @param path The path to split.
 * @return An array of the parts of the path to split.
 *
 * This function splits @p path according to the delimiter of the used
 * filesystem. If  @p path is @c NULL or if the array can not be
 * created, @c NULL is returned, otherwise, an array with the
 * different parts of @p path is returned.
 */
EAPI Eina_Array *eina_file_split(char *path)
{
	Eina_Array *ea;
	char *current;
	size_t length;

	EINA_SAFETY_ON_NULL_RETURN_VAL(path, NULL);

	ea = eina_array_new(16);

	if (!ea)
		return NULL;

	for (current = strchr(path, PATH_DELIM);
	     current;
	     path = current + 1, current = strchr(path, PATH_DELIM)) {
		length = current - path;

		if (length <= 0)
			continue;

		eina_array_push(ea, path);
		*current = '\0';
	}

	if (*path != '\0')
		eina_array_push(ea, path);

	return ea;
}

/**
 * Get an iterator to list the content of a directory.
 *
 * Iterators are cheap to be created and allow interruption at any
 * iteration. At each iteration, only the next directory entry is read
 * from the filesystem with readdir().
 *
 * The iterator will handle the user a stringshared value with the
 * full path. One must call eina_stringshare_del() on it after usage
 * to not leak!
 *
 * The eina_file_direct_ls() function will provide a possibly faster
 * alternative if you need to filter the results somehow, like
 * checking extension.
 *
 * The iterator will walk over '.' and '..' without returning them.
 *
 * @param  dir The name of the directory to list
 * @return Return an Eina_Iterator that will walk over the files and
 *         directory in the pointed directory. On failure it will
 *         return NULL. The iterator emits stringshared value with the
 *         full path and must be freed with eina_stringshare_del().
 *
 * @see eina_file_direct_ls()
 */
EAPI Eina_Iterator *eina_file_ls(const char *dir)
{
	Eina_File_Iterator *it;
	size_t length;

	if (!dir)
		return NULL;

	length = strlen(dir);
	if (length < 1)
		return NULL;

	it = calloc(1, sizeof(Eina_File_Iterator) + length);
	if (!it)
		return NULL;

	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);

	it->dirp = opendir(dir);
	if (!it->dirp) {
		free(it);
		return NULL;
	}

	memcpy(it->dir, dir, length + 1);
	if (dir[length - 1] != '/')
		it->length = length;
	else
		it->length = length - 1;

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next =
	    FUNC_ITERATOR_NEXT(_eina_file_ls_iterator_next);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER(_eina_file_ls_iterator_container);
	it->iterator.free =
	    FUNC_ITERATOR_FREE(_eina_file_ls_iterator_free);

	return &it->iterator;
}

/**
 * Get an iterator to list the content of a directory, with direct information.
 *
 * Iterators are cheap to be created and allow interruption at any
 * iteration. At each iteration, only the next directory entry is read
 * from the filesystem with readdir().
 *
 * The iterator returns the direct pointer to couple of useful information in
 * #Eina_File_Direct_Info and that pointer should not be modified anyhow!
 *
 * The iterator will walk over '.' and '..' without returning them.
 *
 * @param  dir The name of the directory to list

 * @return Return an Eina_Iterator that will walk over the files and
 *         directory in the pointed directory. On failure it will
 *         return NULL. The iterator emits #Eina_File_Direct_Info
 *         pointers that could be used but not modified. The lifetime
 *         of the returned pointer is until the next iteration and
 *         while the iterator is live, deleting the iterator
 *         invalidates the pointer.
 *
 * @see eina_file_ls()
 */
EAPI Eina_Iterator *eina_file_direct_ls(const char *dir)
{
	Eina_File_Direct_Iterator *it;
	size_t length;

	if (!dir)
		return NULL;

	length = strlen(dir);
	if (length < 1)
		return NULL;

	if (length + NAME_MAX + 2 >= PATH_MAX)
		return NULL;

	it = calloc(1, sizeof(Eina_File_Direct_Iterator) + length);
	if (!it)
		return NULL;

	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);

	it->dirp = opendir(dir);
	if (!it->dirp) {
		free(it);
		return NULL;
	}

	memcpy(it->dir, dir, length + 1);
	it->length = length;

	memcpy(it->info.path, dir, length);
	if (dir[length - 1] == '/')
		it->info.name_start = length;
	else {
		it->info.path[length] = '/';
		it->info.name_start = length + 1;
	}

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next =
	    FUNC_ITERATOR_NEXT(_eina_file_direct_ls_iterator_next);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER
	    (_eina_file_direct_ls_iterator_container);
	it->iterator.free =
	    FUNC_ITERATOR_FREE(_eina_file_direct_ls_iterator_free);

	return &it->iterator;
}

/**
 * @}
 */
