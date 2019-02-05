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

#ifndef EINA_MODULE_H_
#define EINA_MODULE_H_

#include "eina_types.h"
#include "eina_array.h"
#include "eina_error.h"

/**
 * @addtogroup Eina_Tools_Group Tools
 *
 * @{
 */

/**
 * @defgroup Eina_Module_Group Module
 *
 * Eina module provides some helpers over POSIX dlopen(). It is not
 * meant to replace, abstract or make a "portable" version of the
 * POSIX, but enhance its usage by defining some good practices.
 *
 * Modules are created with eina_module_new() and later loaded with
 * eina_module_load(). Loads are reference counted and there must be
 * the same number of eina_module_unload() in order to have it to call
 * dlclose(). This makes simple to have different users for the same
 * module.
 *
 * The loaded shared objects may have two visible functions that will
 * be called and might provide initialization and shutdown
 * proceedures. The symbols are @c __eina_module_init and
 * @c __eina_module_shutdown and will be defined by the macros
 * EINA_MODULE_INIT() and EINA_MODULE_SHUTDOWN().
 *
 * There are some helpers to automatically create modules based on
 * directory listing. See eina_module_arch_list_get(),
 * eina_module_list_get() and eina_module_find().
 *
 * @{
 */

/**
 * @typedef Eina_Module
 * Dynamic module loader handle.
 */
typedef struct _Eina_Module Eina_Module;

typedef Eina_Bool(*Eina_Module_Cb) (Eina_Module * m, void *data);

/**
 * @typedef Eina_Module_Init
 * If a function with such signature is exported by module as
 * __eina_module_init, it will be called on the first load after
 * dlopen() and if #EINA_FALSE is returned, load will fail, #EINA_TRUE
 * means the module was successfully initialized.
 * @see Eina_Module_Shutdown
 */
typedef Eina_Bool(*Eina_Module_Init) (void);

/**
 * @typedef Eina_Module_Shutdown
 * If a function with such signature is exported by module as
 * __eina_module_shutdown, it will be called before calling dlclose()
 * @see Eina_Module_Init
 */
typedef void (*Eina_Module_Shutdown) (void);

/**
 * @def EINA_MODULE_INIT
 * declares the given function as the module initializer (__eina_module_init).
 * It must be of signature #Eina_Module_Init
 */
#define EINA_MODULE_INIT(f) EAPI Eina_Module_Init __eina_module_init = &f

/**
 * @def EINA_MODULE_SHUTDOWN
 * declares the given function as the module shutdownializer
 * (__eina_module_shutdown).  It must be of signature
 * #Eina_Module_Shutdown
 */
#define EINA_MODULE_SHUTDOWN(f) EAPI Eina_Module_Shutdown __eina_module_shutdown = &f

/**
 * @var EINA_ERROR_WRONG_MODULE
 * Error identifier corresponding to a wrong module.
 */
extern EAPI Eina_Error EINA_ERROR_WRONG_MODULE;

/**
 * @var EINA_ERROR_MODULE_INIT_FAILED
 * Error identifier corresponding to a failure during the initialisation of a module.
 */
extern EAPI Eina_Error EINA_ERROR_MODULE_INIT_FAILED;

EAPI Eina_Module *eina_module_new(const char *file)
EINA_MALLOC EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);
EAPI Eina_Bool eina_module_free(Eina_Module * m) EINA_ARG_NONNULL(1);
EAPI Eina_Bool eina_module_load(Eina_Module * module) EINA_ARG_NONNULL(1);
EAPI Eina_Bool eina_module_unload(Eina_Module * m) EINA_ARG_NONNULL(1);
EAPI void *eina_module_symbol_get(const Eina_Module * module,
				  const char *symbol)
EINA_PURE EINA_ARG_NONNULL(1, 2) EINA_WARN_UNUSED_RESULT;
EAPI const char *eina_module_file_get(const Eina_Module * m)
EINA_PURE EINA_WARN_UNUSED_RESULT EINA_ARG_NONNULL(1);

EAPI char *eina_module_symbol_path_get(const void *symbol,
				       const char *sub_dir);
EAPI char *eina_module_environment_path_get(const char *env,
					    const char *sub_dir);

EAPI Eina_Array *eina_module_arch_list_get(Eina_Array * array,
					   const char *path,
					   const char *arch);
EAPI Eina_Array *eina_module_list_get(Eina_Array * array, const char *path,
				      Eina_Bool recursive,
				      Eina_Module_Cb cb, void *data)
EINA_MALLOC EINA_WARN_UNUSED_RESULT;
EAPI void eina_module_list_load(Eina_Array * list) EINA_ARG_NONNULL(1);
EAPI void eina_module_list_unload(Eina_Array * list) EINA_ARG_NONNULL(1);
EAPI void eina_module_list_free(Eina_Array * list) EINA_ARG_NONNULL(1);
EAPI Eina_Module *eina_module_find(const Eina_Array * array,
				   const char *module) EINA_ARG_NONNULL(1,
									2);

/**
 * @}
 */

/**
 * @}
 */

#endif				/*EINA_MODULE_H_ */
