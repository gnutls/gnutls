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

#ifndef EINA_MAIN_H_
#define EINA_MAIN_H_

#include "eina_types.h"

/**
 * @addtogroup Eina_Core_Group Core
 *
 * @{
 */

/**
 * @defgroup Eina_Main_Group Main
 *
 * @{
 */

/**
 * @def EINA_VERSION_MAJOR
 * @brief Major version of Eina
 */
#define EINA_VERSION_MAJOR 1

/**
 * @def EINA_VERSION_MINOR
 * @brief Minor version of Eina
 */
#define EINA_VERSION_MINOR 0

/**
 * @typedef Eina_Version
 * The version of Eina.
 */
typedef struct _Eina_Version {
	int major;
		 /**< Major component of the version */
	int minor;
		 /**< Minor component of the version */
	int micro;
		 /**< Micro component of the version */
	int revision;
		 /**< Revision component of the version */
} Eina_Version;

EAPI extern Eina_Version *eina_version;

EAPI int eina_init(void);
EAPI int eina_shutdown(void);
EAPI int eina_threads_init(void);
EAPI int eina_threads_shutdown(void);

/**
 * @}
 */

/**
 * @}
 */

#endif				/* EINA_MAIN_H_ */
