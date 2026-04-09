/*
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * Author: Alexander Sosedkin
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "softhsm.h"

#ifdef __sun
#pragma fini(mock_deinit)
#pragma init(mock_init)
#define _CONSTRUCTOR
#define _DESTRUCTOR
#else
#define _CONSTRUCTOR __attribute__((constructor))
#define _DESTRUCTOR __attribute__((destructor))
#endif

/*
 * A mock PKCS #11 module that delegates all operations to SoftHSM
 * that allows fault injection via the P11MOCKLIB5_FAULT environment variable.
 *
 * Format: "FUNCTION_NAME:CALL_NUMBER:ERROR_CODE,..."
 * Example: P11MOCKLIB5_FAULT='C_Initialize:1:5,C_FindObjects:0:5' means
 *   1. fail the 1st call of C_Initialize with CKR_GENERAL_ERROR (5)
 *   2. fail all C_FindObjects calls with CKR_DEVICE_ERROR (5).
 *
 * Limitation: currently can only fault a single call per function
 * and does not support repeated function names.
 */

#define MAX_FAULTS 16
#define MAX_FUNC_NAME 64

#define dbg(...)                                        \
	do {                                            \
		if (getenv("P11MOCKLIB5_DEBUG"))        \
			fprintf(stderr, ##__VA_ARGS__); \
	} while (0)

static void *dl;
static CK_FUNCTION_LIST override_funcs;
static CK_FUNCTION_LIST *base_funcs;

struct fault_rule {
	char func_name[MAX_FUNC_NAME];
	uint64_t call_number; /* 0 = all calls, N = Nth only */
	CK_RV error_code;
	uint64_t call_count;
};

static struct fault_rule faults[MAX_FAULTS];
static unsigned num_faults = 0;

static bool parse_fault_rule(struct fault_rule *rule, const char *s, size_t len)
{
	const char *p = s;
	const char *end = s + len;

	/* parse FUNCTION_NAME:CALL_NUMBER:ERROR_CODE */
	const char *colon = p;
	while (colon < end && *colon != ':')
		colon++;
	if (colon == end)
		return false; /* invalid format: no first colon */

	/* function name */
	size_t name_len = (size_t)(colon - p);
	if (name_len >= MAX_FUNC_NAME)
		name_len = MAX_FUNC_NAME - 1;
	memcpy(rule->func_name, p, name_len);
	rule->func_name[name_len] = '\0';

	/* move to call number */
	colon++;
	rule->call_number = atoi(colon);

	/* find second colon */
	while (colon < end && *colon != ':')
		colon++;
	if (colon == end)
		return false; /* invalid format: no second colon */

	/* error code */
	colon++;
	rule->error_code = (CK_RV)atoi(colon);
	rule->call_count = 0;

	return true;
}

static void parse_fault_rules(void)
{
	const char *env = getenv("P11MOCKLIB5_FAULT");
	if (env == NULL || strlen(env) == 0) {
		dbg("pkcs11-mock5: No P11MOCKLIB5_FAULT set\n");
		return;
	}
	const char *p = env;
	while (*p != '\0' && num_faults < MAX_FAULTS) {
		const char *start = p;
		/* scan to the end of this rule (comma or null) */
		while (*p != '\0' && *p != ',')
			p++;
		size_t len = (size_t)(p - start);
		if (len > 0)
			if (parse_fault_rule(&faults[num_faults], start, len))
				num_faults++;
		if (*p == ',')
			p++;
	}

	dbg("pkcs11-mock5: Parsed %u fault rules:\n", num_faults);
	for (unsigned i = 0; i < num_faults; i++) {
		if (faults[i].call_number == 0)
			dbg("  - %s: ALL calls -> %ld\n", faults[i].func_name,
			    (long)faults[i].error_code);
		else
			dbg("  - %s: call #%lu -> %ld\n", faults[i].func_name,
			    (unsigned long)faults[i].call_number,
			    (long)faults[i].error_code);
	}
}

static struct fault_rule *find_rule(const char *func_name)
{
	unsigned i;
	for (i = 0; i < num_faults; i++) {
		if (strcmp(faults[i].func_name, func_name) == 0)
			return &faults[i];
	}
	return NULL;
}

static bool match_rule(const struct fault_rule *rule)
{
	if (!rule)
		return false;
	if (rule->call_number == 0)
		return true; /* 0 = fail all calls */
	if (rule->call_count == rule->call_number)
		return true; /* N = fail Nth call */
	return false;
}

/* Macro to create a fault-injecting wrapper for a PKCS #11 function. */
#define DEFINE_FAULT_WRAPPER(func_name, sig, call_args)                      \
	static CK_RV(*base_##func_name) sig;                                 \
	static CK_RV override_##func_name sig;                               \
	static CK_RV override_##func_name sig                                \
	{                                                                    \
		CK_RV result;                                                \
		struct fault_rule *rule = find_rule(#func_name);             \
		if (!rule) {                                                 \
			result = base_##func_name call_args;                 \
			dbg("pkcs11-mock5: %s no rule -> %ld\n", #func_name, \
			    (long)result);                                   \
			return result;                                       \
		}                                                            \
		rule->call_count++;                                          \
		bool match = match_rule(rule);                               \
		if (match) {                                                 \
			result = rule->error_code;                           \
			dbg("pkcs11-mock5: %s #%lu intercept -> %ld\n",      \
			    #func_name, rule->call_count, (long)result);     \
		} else {                                                     \
			result = base_##func_name call_args;                 \
			dbg("pkcs11-mock5: %s #%lu pass through -> %ld\n",   \
			    #func_name, rule->call_count, (long)result);     \
		}                                                            \
		return result;                                               \
	}
DEFINE_FAULT_WRAPPER(C_Initialize, (void *args), (args))
DEFINE_FAULT_WRAPPER(C_Finalize, (void *reserved), (reserved))
DEFINE_FAULT_WRAPPER(C_GetAttributeValue,
		     (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		      CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount),
		     (hSession, hObject, pTemplate, ulCount))
/* Override function list with our wrappers */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST **function_list)
{
	CK_C_GetFunctionList func;
	assert(dl);
	func = dlsym(dl, "C_GetFunctionList");
	if (func == NULL)
		return CKR_GENERAL_ERROR;
	func(&base_funcs);
	memcpy(&override_funcs, base_funcs, sizeof(CK_FUNCTION_LIST));

	/* set base function pointers for the wrappers */
	base_C_Initialize = base_funcs->C_Initialize;
	base_C_Finalize = base_funcs->C_Finalize;
	base_C_GetAttributeValue = base_funcs->C_GetAttributeValue;

	/* override with our fault-injection wrappers */
	override_funcs.C_Initialize = override_C_Initialize;
	override_funcs.C_Finalize = override_C_Finalize;
	override_funcs.C_GetAttributeValue = override_C_GetAttributeValue;
	/* mind that one also needs to extend the macros above */

	*function_list = &override_funcs;
	return CKR_OK;
}

static _CONSTRUCTOR void mock_init(void)
{
	const char *lib;

	/* suppress compiler warning */
	(void)set_softhsm_conf;

	parse_fault_rules();

	lib = softhsm_lib();

	dl = dlopen(lib, RTLD_NOW);
	if (dl == NULL)
		exit(77);
}

static _DESTRUCTOR void mock_deinit(void)
{
	dlclose(dl);
}
