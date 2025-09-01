/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Author: Daiki Ueno
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <dlfcn.h>
#include <p11-kit/pkcs11.h>
#include <p11-kit/pkcs11x.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "softhsm.h"

/* This provides a mock PKCS #11 module that delegates all the
 * operations to SoftHSM except that it returns CKR_CANT_LOCK upon
 * C_Initialize if CKF_OS_LOCKING_OK is set.
 */

static void *dl;
static CK_C_Initialize base_C_Initialize;
static CK_FUNCTION_LIST override_funcs;

#ifdef __sun
#pragma fini(mock_deinit)
#pragma init(mock_init)
#define _CONSTRUCTOR
#define _DESTRUCTOR
#else
#define _CONSTRUCTOR __attribute__((constructor))
#define _DESTRUCTOR __attribute__((destructor))
#endif

static CK_RV override_C_Initialize(void *args)
{
	CK_C_INITIALIZE_ARGS *init_args = args;
	static bool first = true;

	assert(init_args);

	if (first) {
		assert(init_args->flags & CKF_OS_LOCKING_OK);
		first = false;
		return CKR_CANT_LOCK;
	} else {
		assert(!(init_args->flags & CKF_OS_LOCKING_OK));
	}

	return base_C_Initialize(args);
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST **function_list)
{
	CK_C_GetFunctionList func;
	CK_FUNCTION_LIST *funcs;

	assert(dl);

	func = dlsym(dl, "C_GetFunctionList");
	if (func == NULL) {
		return CKR_GENERAL_ERROR;
	}

	func(&funcs);

	base_C_Initialize = funcs->C_Initialize;

	memcpy(&override_funcs, funcs, sizeof(CK_FUNCTION_LIST));
	override_funcs.C_Initialize = override_C_Initialize;
	*function_list = &override_funcs;

	return CKR_OK;
}

static _CONSTRUCTOR void mock_init(void)
{
	const char *lib;

	/* suppress compiler warning */
	(void)set_softhsm_conf;

	lib = softhsm_lib();

	dl = dlopen(lib, RTLD_NOW);
	if (dl == NULL)
		exit(77);
}

static _DESTRUCTOR void mock_deinit(void)
{
	dlclose(dl);
}
