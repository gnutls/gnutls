/*
 * GnuTLS PKCS#11 support
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 * Copyright (C) 2008 Joe Orton <joe@manyfish.co.uk>
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 * 
 * Authors: Nikos Mavrogiannopoulos, Stef Walter
 *
 * Inspired and some parts (pkcs11_login) based on neon PKCS #11 support 
 * by Joe Orton. More ideas came from the pkcs11-helper library by 
 * Alon Bar-Lev.
 *
 * GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include <gnutls_int.h>
#include <gnutls/pkcs11.h>
#include <string.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <x509/common.h>
#include <locks.h>

#include <pin.h>
#include <pkcs11_int.h>
#include <p11-kit/p11-kit.h>
#include <p11-kit/pin.h>
#ifdef HAVE_GETPID
# include <unistd.h>
#endif

#define MAX_PROVIDERS 16

/* XXX: try to eliminate this */
#define MAX_CERT_SIZE 32*1024
#define MAX_SLOTS 48

extern void *_gnutls_pkcs11_mutex;

struct gnutls_pkcs11_provider_st {
	struct ck_function_list *module;
	unsigned active;
	unsigned trusted; /* in the sense of p11-kit trusted:
	                   * it can be used for verification */
	struct ck_info info;
};

struct find_flags_data_st {
	struct p11_kit_uri *info;
	unsigned int slot_flags;
	unsigned int trusted;
};

struct find_url_data_st {
	gnutls_pkcs11_obj_t crt;
};

struct find_obj_data_st {
	gnutls_pkcs11_obj_t *p_list;
	unsigned int *n_list;
	unsigned int current;
	gnutls_pkcs11_obj_attr_t flags;
	struct p11_kit_uri *info;
};

struct find_token_num {
	struct p11_kit_uri *info;
	unsigned int seq;	/* which one we are looking for */
	unsigned int current;	/* which one are we now */
};

struct find_pkey_list_st {
	gnutls_buffer_st *key_ids;
	size_t key_ids_size;
};

struct find_cert_st {
	gnutls_datum_t dn;
	gnutls_datum_t issuer_dn;
	gnutls_datum_t key_id;
	gnutls_datum_t serial;

	unsigned need_import;
	gnutls_pkcs11_obj_t obj;
	gnutls_x509_crt_t crt; /* used when compare flag is specified */
	unsigned flags;
};


static struct gnutls_pkcs11_provider_st providers[MAX_PROVIDERS];
static unsigned int active_providers = 0;
static unsigned int providers_initialized = 0;
#ifdef HAVE_GETPID
static pid_t init_pid = -1;
#endif

gnutls_pkcs11_token_callback_t _gnutls_token_func;
void *_gnutls_token_data;

int pkcs11_rv_to_err(ck_rv_t rv)
{
	switch (rv) {
	case CKR_OK:
		return 0;
	case CKR_HOST_MEMORY:
		return GNUTLS_E_MEMORY_ERROR;
	case CKR_SLOT_ID_INVALID:
		return GNUTLS_E_PKCS11_SLOT_ERROR;
	case CKR_ARGUMENTS_BAD:
	case CKR_MECHANISM_PARAM_INVALID:
		return GNUTLS_E_INVALID_REQUEST;
	case CKR_NEED_TO_CREATE_THREADS:
	case CKR_CANT_LOCK:
	case CKR_FUNCTION_NOT_PARALLEL:
	case CKR_MUTEX_BAD:
	case CKR_MUTEX_NOT_LOCKED:
		return GNUTLS_E_LOCKING_ERROR;
	case CKR_ATTRIBUTE_READ_ONLY:
	case CKR_ATTRIBUTE_SENSITIVE:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_VALUE_INVALID:
		return GNUTLS_E_PKCS11_ATTRIBUTE_ERROR;
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
		return GNUTLS_E_PKCS11_DEVICE_ERROR;
	case CKR_DATA_INVALID:
	case CKR_DATA_LEN_RANGE:
	case CKR_ENCRYPTED_DATA_INVALID:
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
	case CKR_OBJECT_HANDLE_INVALID:
		return GNUTLS_E_PKCS11_DATA_ERROR;
	case CKR_FUNCTION_NOT_SUPPORTED:
	case CKR_MECHANISM_INVALID:
		return GNUTLS_E_PKCS11_UNSUPPORTED_FEATURE_ERROR;
	case CKR_KEY_HANDLE_INVALID:
	case CKR_KEY_SIZE_RANGE:
	case CKR_KEY_TYPE_INCONSISTENT:
	case CKR_KEY_NOT_NEEDED:
	case CKR_KEY_CHANGED:
	case CKR_KEY_NEEDED:
	case CKR_KEY_INDIGESTIBLE:
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
	case CKR_KEY_NOT_WRAPPABLE:
	case CKR_KEY_UNEXTRACTABLE:
		return GNUTLS_E_PKCS11_KEY_ERROR;
	case CKR_PIN_INCORRECT:
	case CKR_PIN_INVALID:
	case CKR_PIN_LEN_RANGE:
		return GNUTLS_E_PKCS11_PIN_ERROR;
	case CKR_PIN_EXPIRED:
		return GNUTLS_E_PKCS11_PIN_EXPIRED;
	case CKR_PIN_LOCKED:
		return GNUTLS_E_PKCS11_PIN_LOCKED;
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_COUNT:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
	case CKR_SESSION_READ_ONLY:
	case CKR_SESSION_EXISTS:
	case CKR_SESSION_READ_ONLY_EXISTS:
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
		return GNUTLS_E_PKCS11_SESSION_ERROR;
	case CKR_SIGNATURE_INVALID:
	case CKR_SIGNATURE_LEN_RANGE:
		return GNUTLS_E_PKCS11_SIGNATURE_ERROR;
	case CKR_TOKEN_NOT_PRESENT:
	case CKR_TOKEN_NOT_RECOGNIZED:
	case CKR_TOKEN_WRITE_PROTECTED:
		return GNUTLS_E_PKCS11_TOKEN_ERROR;
	case CKR_USER_ALREADY_LOGGED_IN:
	case CKR_USER_NOT_LOGGED_IN:
	case CKR_USER_PIN_NOT_INITIALIZED:
	case CKR_USER_TYPE_INVALID:
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
	case CKR_USER_TOO_MANY_TYPES:
		return GNUTLS_E_PKCS11_USER_ERROR;
	case CKR_BUFFER_TOO_SMALL:
		return GNUTLS_E_SHORT_MEMORY_BUFFER;
	default:
		return GNUTLS_E_PKCS11_ERROR;
	}
}


static int scan_slots(struct gnutls_pkcs11_provider_st *p,
		      ck_slot_id_t * slots, unsigned long *nslots)
{
	ck_rv_t rv;

	rv = pkcs11_get_slot_list(p->module, 1, slots, nslots);
	if (rv != CKR_OK) {
		gnutls_assert();
		return pkcs11_rv_to_err(rv);
	}
	return 0;
}

static int
pkcs11_add_module(const char* name, struct ck_function_list *module, const char *params)
{
	unsigned int i;
	struct ck_info info;

	if (active_providers >= MAX_PROVIDERS) {
		gnutls_assert();
		return GNUTLS_E_CONSTRAINT_ERROR;
	}
	
	memset(&info, 0, sizeof(info));
	pkcs11_get_module_info(module, &info);

	/* initially check if this module is a duplicate */
	for (i = 0; i < active_providers; i++) {
		/* already loaded, skip the rest */
		if (module == providers[i].module) {
			_gnutls_debug_log("p11: module %s is already loaded.\n", name);
			return GNUTLS_E_INT_RET_0;
		}
	}

	active_providers++;
	providers[active_providers - 1].module = module;
	providers[active_providers - 1].active = 1;

	if (p11_kit_module_get_flags(module) & P11_KIT_MODULE_TRUSTED ||
		(params != NULL && strstr(params, "trusted") != 0))
		providers[active_providers - 1].trusted = 1;

	memcpy(&providers[active_providers - 1].info, &info, sizeof(info));

	return 0;
}

int _gnutls_pkcs11_check_init(void)
{
	int ret;
	
	ret = gnutls_mutex_lock(&_gnutls_pkcs11_mutex);
	if (ret != 0)
		return gnutls_assert_val(GNUTLS_E_LOCKING_ERROR);

#ifdef HAVE_GETPID
	if (init_pid == 0)
		init_pid = getpid();
#endif

	if (providers_initialized != 0) {
		ret = 0;
#ifdef HAVE_GETPID
		if (init_pid != getpid()) {
			/* if we are initialized but a fork is detected */
			ret = gnutls_pkcs11_reinit();
		}
#endif

		gnutls_mutex_unlock(&_gnutls_pkcs11_mutex);
		return ret;
	}

#ifdef HAVE_GETPID
	init_pid = getpid();
#endif

	providers_initialized = 1;
	_gnutls_debug_log("Initializing PKCS #11 modules\n");
	ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_AUTO, NULL);
	
	gnutls_mutex_unlock(&_gnutls_pkcs11_mutex);
	
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 0;
}


/**
 * gnutls_pkcs11_add_provider:
 * @name: The filename of the module
 * @params: should be NULL
 *
 * This function will load and add a PKCS 11 module to the module
 * list used in gnutls. After this function is called the module will
 * be used for PKCS 11 operations.
 *
 * When loading a module to be used for certificate verification,
 * use the string 'trusted' as @params.
 *
 * Note that this function is not thread safe.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int gnutls_pkcs11_add_provider(const char *name, const char *params)
{
	struct ck_function_list *module;
	int ret;

	module = p11_kit_module_load(name, P11_KIT_MODULE_CRITICAL);
	if (module == NULL) {
		gnutls_assert();
		_gnutls_debug_log("p11: Cannot load provider %s\n", name);
		return GNUTLS_E_PKCS11_LOAD_ERROR;
	}

	_gnutls_debug_log
		    ("p11: Initializing module: %s\n", name);

	ret = p11_kit_module_initialize(module);
	if (ret != CKR_OK) {
		p11_kit_module_release(module);
		gnutls_assert();
		return pkcs11_rv_to_err(ret);
	}

	ret = pkcs11_add_module(name, module, params);
	if (ret != 0) {
		if (ret == GNUTLS_E_INT_RET_0)
			ret = 0;
		p11_kit_module_finalize(module);
		p11_kit_module_release(module);
		gnutls_assert();
	}

	return ret;
}


/**
 * gnutls_pkcs11_obj_get_info:
 * @crt: should contain a #gnutls_pkcs11_obj_t structure
 * @itype: Denotes the type of information requested
 * @output: where output will be stored
 * @output_size: contains the maximum size of the output and will be overwritten with actual
 *
 * This function will return information about the PKCS11 certificate
 * such as the label, id as well as token information where the key is
 * stored. When output is text it returns null terminated string
 * although @output_size contains the size of the actual data only.
 *
 * Returns: %GNUTLS_E_SUCCESS (0) on success or a negative error code on error.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_obj_get_info(gnutls_pkcs11_obj_t crt,
			   gnutls_pkcs11_obj_info_t itype,
			   void *output, size_t * output_size)
{
	return pkcs11_get_info(crt->info, itype, output, output_size);
}

int
pkcs11_get_info(struct p11_kit_uri *info,
		gnutls_pkcs11_obj_info_t itype, void *output,
		size_t * output_size)
{
	struct ck_attribute *attr = NULL;
	struct ck_version *version = NULL;
	const uint8_t *str = NULL;
	size_t str_max = 0;
	int terminate = 0;
	int hexify = 0;
	size_t length = 0;
	const char *data = NULL;
	char buf[32];

	/*
	 * Either attr, str or version is valid by the time switch
	 * finishes
	 */

	switch (itype) {
	case GNUTLS_PKCS11_OBJ_ID:
		attr = p11_kit_uri_get_attribute(info, CKA_ID);
		break;
	case GNUTLS_PKCS11_OBJ_ID_HEX:
		attr = p11_kit_uri_get_attribute(info, CKA_ID);
		hexify = 1;
		terminate = 1;
		break;
	case GNUTLS_PKCS11_OBJ_LABEL:
		attr = p11_kit_uri_get_attribute(info, CKA_LABEL);
		terminate = 1;
		break;
	case GNUTLS_PKCS11_OBJ_TOKEN_LABEL:
		str = p11_kit_uri_get_token_info(info)->label;
		str_max = 32;
		break;
	case GNUTLS_PKCS11_OBJ_TOKEN_SERIAL:
		str = p11_kit_uri_get_token_info(info)->serial_number;
		str_max = 16;
		break;
	case GNUTLS_PKCS11_OBJ_TOKEN_MANUFACTURER:
		str = p11_kit_uri_get_token_info(info)->manufacturer_id;
		str_max = 32;
		break;
	case GNUTLS_PKCS11_OBJ_TOKEN_MODEL:
		str = p11_kit_uri_get_token_info(info)->model;
		str_max = 16;
		break;
	case GNUTLS_PKCS11_OBJ_LIBRARY_DESCRIPTION:
		str =
		    p11_kit_uri_get_module_info(info)->library_description;
		str_max = 32;
		break;
	case GNUTLS_PKCS11_OBJ_LIBRARY_VERSION:
		version =
		    &p11_kit_uri_get_module_info(info)->library_version;
		break;
	case GNUTLS_PKCS11_OBJ_LIBRARY_MANUFACTURER:
		str = p11_kit_uri_get_module_info(info)->manufacturer_id;
		str_max = 32;
		break;
	default:
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	if (attr != NULL) {
		data = attr->value;
		length = attr->value_len;
	} else if (str != NULL) {
		data = (void *) str;
		length = p11_kit_space_strlen(str, str_max);
		terminate = 1;
	} else if (version != NULL) {
		data = buf;
		length =
		    snprintf(buf, sizeof(buf), "%d.%d",
			     (int) version->major, (int) version->minor);
		terminate = 1;
	} else {
		*output_size = 0;
		if (output)
			((uint8_t *) output)[0] = 0;
		return 0;
	}

	if (hexify) {
		/* terminate is assumed with hexify */
		if (*output_size < length * 3) {
			*output_size = length * 3;
			return GNUTLS_E_SHORT_MEMORY_BUFFER;
		}
		if (output && length > 0)
			_gnutls_bin2hex(data, length, output, *output_size,
					":");
		*output_size = length * 3;
		return 0;
	} else {
		if (*output_size < length + terminate) {
			*output_size = length + terminate;
			return GNUTLS_E_SHORT_MEMORY_BUFFER;
		}
		if (output) {
			memcpy(output, data, length);
			if (terminate)
				((unsigned char *) output)[length] = '\0';
		}
		*output_size = length + terminate;
	}

	return 0;
}

static int init = 0;

/* tries to load modules from /etc/gnutls/pkcs11.conf if it exists
 */
static void compat_load(const char *configfile)
{
	FILE *fp;
	int ret;
	char line[512];
	const char *library;

	if (configfile == NULL)
		configfile = "/etc/gnutls/pkcs11.conf";

	fp = fopen(configfile, "r");
	if (fp == NULL) {
		gnutls_assert();
		return;
	}

	_gnutls_debug_log("Loading PKCS #11 libraries from %s\n",
			  configfile);
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strncmp(line, "load", sizeof("load") - 1) == 0) {
			char *p;
			p = strchr(line, '=');
			if (p == NULL)
				continue;

			library = ++p;
			p = strchr(line, '\n');
			if (p != NULL)
				*p = 0;

			ret = gnutls_pkcs11_add_provider(library, NULL);
			if (ret < 0) {
				gnutls_assert();
				_gnutls_debug_log
				    ("Cannot load provider: %s\n",
				     library);
				continue;
			}
		}
	}
	fclose(fp);

	return;
}

static int auto_load(void)
{
	struct ck_function_list **modules;
	int i, ret;
	char* name;

	modules = p11_kit_modules_load_and_initialize(0);
	if (modules == NULL) {
		gnutls_assert();
		_gnutls_debug_log
		    ("Cannot initialize registered modules: %s\n",
		     p11_kit_message());
		return GNUTLS_E_PKCS11_LOAD_ERROR;
	}

	for (i = 0; modules[i] != NULL; i++) {
		name = p11_kit_module_get_name(modules[i]);
		_gnutls_debug_log
			    ("p11: Initializing module: %s\n", name);

		ret = pkcs11_add_module(name, modules[i], NULL);
		if (ret < 0) {
			gnutls_assert();
			_gnutls_debug_log
			    ("Cannot load PKCS #11 module: %s\n", name);
		}
		free(name);
	}

	/* Shallow free */
	free(modules);
	return 0;
}

/**
 * gnutls_pkcs11_init:
 * @flags: An ORed sequence of %GNUTLS_PKCS11_FLAG_*
 * @deprecated_config_file: either NULL or the location of a deprecated
 *     configuration file
 *
 * This function will initialize the PKCS 11 subsystem in gnutls. It will
 * read configuration files if %GNUTLS_PKCS11_FLAG_AUTO is used or allow
 * you to independently load PKCS 11 modules using gnutls_pkcs11_add_provider()
 * if %GNUTLS_PKCS11_FLAG_MANUAL is specified.
 *
 * Normally you don't need to call this function since it is being called
 * when the first PKCS 11 operation is requested using the %GNUTLS_PKCS11_FLAG_AUTO
 * flag. If another flags are required then it must be called independently
 * prior to any PKCS 11 operation.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_init(unsigned int flags, const char *deprecated_config_file)
{
	int ret = 0;

	if (init != 0) {
		init++;
		return 0;
	}
	init++;

	p11_kit_pin_register_callback(P11_KIT_PIN_FALLBACK,
				      p11_kit_pin_file_callback, NULL,
				      NULL);

	if (flags == GNUTLS_PKCS11_FLAG_MANUAL)
		return 0;
	else if (flags & GNUTLS_PKCS11_FLAG_AUTO) {
		if (deprecated_config_file == NULL)
			ret = auto_load();

		compat_load(deprecated_config_file);

		return ret;
	}

	return 0;
}

/**
 * gnutls_pkcs11_reinit:
 *
 * This function will reinitialize the PKCS 11 subsystem in gnutls. 
 * This is required by PKCS 11 when an application uses fork(). The
 * reinitialization function must be called on the child.
 *
 * Note that since GnuTLS 3.3.0, the reinitialization of the PKCS #11
 * subsystem occurs automatically after fork.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.0
 **/
int gnutls_pkcs11_reinit(void)
{
	unsigned i;
	ck_rv_t rv;

	/* make sure that we don't call more than once after a fork */
	if (init_pid == getpid())
		return 0;

	for (i = 0; i < active_providers; i++) {
		if (providers[i].module != NULL) {
			rv = p11_kit_module_initialize(providers
						       [i].module);
			if (rv != CKR_OK) {
				providers[i].active = 1;
			} else {
				providers[i].active = 0;
				_gnutls_debug_log
				    ("Cannot re-initialize registered module '%s': %s\n",
				     providers[i].info.library_description,
				     p11_kit_strerror(rv));
			}
		}
	}
#ifdef HAVE_GETPID
	init_pid = getpid();
#endif

	return 0;
}

/**
 * gnutls_pkcs11_deinit:
 *
 * This function will deinitialize the PKCS 11 subsystem in gnutls.
 * This function is only needed if you need to deinitialize the
 * subsystem without calling gnutls_global_deinit().
 *
 * Since: 2.12.0
 **/
void gnutls_pkcs11_deinit(void)
{
	unsigned int i;

	if (init == 0)
		return;

	init--;
	if (init > 0)
		return;

	for (i = 0; i < active_providers; i++) {
		if (providers[i].active)
			p11_kit_module_finalize(providers[i].module);
		p11_kit_module_release(providers[i].module);
	}
	active_providers = 0;
	providers_initialized = 0;

	gnutls_pkcs11_set_pin_function(NULL, NULL);
	gnutls_pkcs11_set_token_function(NULL, NULL);
	p11_kit_pin_unregister_callback(P11_KIT_PIN_FALLBACK,
					p11_kit_pin_file_callback, NULL);
}

/**
 * gnutls_pkcs11_set_token_function:
 * @fn: The token callback
 * @userdata: data to be supplied to callback
 *
 * This function will set a callback function to be used when a token
 * needs to be inserted to continue PKCS 11 operations.
 *
 * Since: 2.12.0
 **/
void
gnutls_pkcs11_set_token_function(gnutls_pkcs11_token_callback_t fn,
				 void *userdata)
{
	_gnutls_token_func = fn;
	_gnutls_token_data = userdata;
}

int pkcs11_url_to_info(const char *url, struct p11_kit_uri **info)
{
	int allocated = 0;
	int ret;

	if (*info == NULL) {
		*info = p11_kit_uri_new();
		if (*info == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		allocated = 1;
	}

	ret = p11_kit_uri_parse(url, P11_KIT_URI_FOR_ANY, *info);
	if (ret < 0) {
		if (allocated) {
			p11_kit_uri_free(*info);
			*info = NULL;
		}
		gnutls_assert();
		return ret == P11_KIT_URI_NO_MEMORY ?
		    GNUTLS_E_MEMORY_ERROR : GNUTLS_E_PARSING_ERROR;
	}

	return 0;
}

int
pkcs11_info_to_url(struct p11_kit_uri *info,
		   gnutls_pkcs11_url_type_t detailed, char **url)
{
	p11_kit_uri_type_t type = 0;
	int ret;

	switch (detailed) {
	case GNUTLS_PKCS11_URL_GENERIC:
		type = P11_KIT_URI_FOR_OBJECT_ON_TOKEN;
		break;
	case GNUTLS_PKCS11_URL_LIB:
		type = P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE;
		break;
	case GNUTLS_PKCS11_URL_LIB_VERSION:
		type =
		    P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE |
		    P11_KIT_URI_FOR_MODULE_WITH_VERSION;
		break;
	}

	ret = p11_kit_uri_format(info, type, url);
	if (ret < 0) {
		gnutls_assert();
		return ret == P11_KIT_URI_NO_MEMORY ?
		    GNUTLS_E_MEMORY_ERROR : GNUTLS_E_INTERNAL_ERROR;
	}

	return 0;
}

/**
 * gnutls_pkcs11_obj_init:
 * @obj: The structure to be initialized
 *
 * This function will initialize a pkcs11 certificate structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int gnutls_pkcs11_obj_init(gnutls_pkcs11_obj_t * obj)
{
	*obj = gnutls_calloc(1, sizeof(struct gnutls_pkcs11_obj_st));
	if (*obj == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	(*obj)->info = p11_kit_uri_new();
	if ((*obj)->info == NULL) {
		gnutls_free(*obj);
		*obj = NULL;
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;
}

/**
 * gnutls_pkcs11_obj_set_pin_function:
 * @obj: The object structure
 * @fn: the callback
 * @userdata: data associated with the callback
 *
 * This function will set a callback function to be used when
 * required to access the object. This function overrides the global
 * set using gnutls_pkcs11_set_pin_function().
 *
 * Since: 3.1.0
 **/
void
gnutls_pkcs11_obj_set_pin_function(gnutls_pkcs11_obj_t obj,
				   gnutls_pin_callback_t fn,
				   void *userdata)
{
	obj->pin.cb = fn;
	obj->pin.data = userdata;
}

/**
 * gnutls_pkcs11_obj_deinit:
 * @obj: The structure to be initialized
 *
 * This function will deinitialize a certificate structure.
 *
 * Since: 2.12.0
 **/
void gnutls_pkcs11_obj_deinit(gnutls_pkcs11_obj_t obj)
{
	_gnutls_free_datum(&obj->raw);
	p11_kit_uri_free(obj->info);
	free(obj);
}

/**
 * gnutls_pkcs11_obj_export:
 * @obj: Holds the object
 * @output_data: will contain the object data
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the PKCS11 object data.  It is normal for
 * data to be inaccesible and in that case %GNUTLS_E_INVALID_REQUEST
 * will be returned.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and %GNUTLS_E_SUCCESS (0) on success.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_obj_export(gnutls_pkcs11_obj_t obj,
			 void *output_data, size_t * output_data_size)
{
	if (obj == NULL || obj->raw.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	if (output_data == NULL || *output_data_size < obj->raw.size) {
		*output_data_size = obj->raw.size;
		gnutls_assert();
		return GNUTLS_E_SHORT_MEMORY_BUFFER;
	}
	*output_data_size = obj->raw.size;

	memcpy(output_data, obj->raw.data, obj->raw.size);
	return 0;
}

/**
 * gnutls_pkcs11_obj_export2:
 * @obj: Holds the object
 * @out: will contain the object data
 *
 * This function will export the PKCS11 object data.  It is normal for
 * data to be inaccesible and in that case %GNUTLS_E_INVALID_REQUEST
 * will be returned.
 *
 * The output buffer is allocated using gnutls_malloc().
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and %GNUTLS_E_SUCCESS (0) on success.
 *
 * Since: 3.1.3
 **/
int
gnutls_pkcs11_obj_export2(gnutls_pkcs11_obj_t obj, gnutls_datum_t * out)
{
	if (obj == NULL || obj->raw.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	return _gnutls_set_datum(out, obj->raw.data, obj->raw.size);
}

/**
 * gnutls_pkcs11_obj_export3:
 * @obj: Holds the object
 * @out: will contain the object data
 * @fmt: The format of the exported data
 *
 * This function will export the PKCS11 object data.  It is normal for
 * data to be inaccesible and in that case %GNUTLS_E_INVALID_REQUEST
 * will be returned.
 *
 * The output buffer is allocated using gnutls_malloc().
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and %GNUTLS_E_SUCCESS (0) on success.
 *
 * Since: 3.2.7
 **/
int
gnutls_pkcs11_obj_export3(gnutls_pkcs11_obj_t obj,
			  gnutls_x509_crt_fmt_t fmt, gnutls_datum_t * out)
{
	int ret;

	if (obj == NULL || obj->raw.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	if (fmt == GNUTLS_X509_FMT_DER)
		return _gnutls_set_datum(out, obj->raw.data,
					 obj->raw.size);
	else if (fmt == GNUTLS_X509_FMT_PEM) {
		switch (obj->type) {
		case GNUTLS_PKCS11_OBJ_X509_CRT:
			return
			    gnutls_pem_base64_encode_alloc(PEM_X509_CERT2,
							   &obj->raw, out);
		case GNUTLS_PKCS11_OBJ_PUBKEY:{
				gnutls_pubkey_t pubkey;
				/* more complex */
				ret = gnutls_pubkey_init(&pubkey);
				if (ret < 0)
					return gnutls_assert_val(ret);

				ret =
				    gnutls_pubkey_import_pkcs11(pubkey,
								obj, 0);
				if (ret < 0) {
					gnutls_assert();
					goto pcleanup;
				}

				ret =
				    gnutls_pubkey_export2(pubkey, fmt,
							  out);

			      pcleanup:
				gnutls_pubkey_deinit(pubkey);
				return ret;
			}
		default:
			return gnutls_pem_base64_encode_alloc("DATA",
							      &obj->raw,
							      out);
		}
	} else
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
}


int
pkcs11_find_slot(struct ck_function_list **module, ck_slot_id_t * slot,
		 struct p11_kit_uri *info, struct token_info *_tinfo)
{
	unsigned int x, z;
	int ret;
	unsigned long nslots;
	ck_slot_id_t slots[MAX_SLOTS];
	
	for (x = 0; x < active_providers; x++) {
		if (providers[x].active == 0)
			continue;

		nslots = sizeof(slots) / sizeof(slots[0]);
		ret = scan_slots(&providers[x], slots, &nslots);
		if (ret < 0) {
			gnutls_assert();
			continue;
		}

		for (z = 0; z < nslots; z++) {
			struct token_info tinfo;

			if (pkcs11_get_token_info
			    (providers[x].module, slots[z],
			     &tinfo.tinfo) != CKR_OK) {
				continue;
			}
			tinfo.sid = slots[z];
			tinfo.prov = &providers[x];

			if (pkcs11_get_slot_info
			    (providers[x].module, slots[z],
			     &tinfo.sinfo) != CKR_OK) {
				continue;
			}

			if (!p11_kit_uri_match_token_info
			    (info, &tinfo.tinfo)
			    || !p11_kit_uri_match_module_info(info,
							      &providers
							      [x].info)) {
				continue;
			}

			/* ok found */
			*module = providers[x].module;
			*slot = slots[z];

			if (_tinfo != NULL)
				memcpy(_tinfo, &tinfo, sizeof(tinfo));

			return 0;
		}
	}

	gnutls_assert();
	return GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILBLE;
}

int
pkcs11_open_session(struct pkcs11_session_info *sinfo,
		    struct pin_info_st *pin_info,
		    struct p11_kit_uri *info, unsigned int flags)
{
	ck_rv_t rv;
	int ret;
	ck_session_handle_t pks = 0;
	struct ck_function_list *module;
	ck_slot_id_t slot;
	struct token_info tinfo;
	
	ret = pkcs11_find_slot(&module, &slot, info, &tinfo);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	rv = (module)->C_OpenSession(slot, ((flags & SESSION_WRITE)
					    ? CKF_RW_SESSION : 0) |
				     CKF_SERIAL_SESSION, NULL, NULL, &pks);
	if (rv != CKR_OK) {
		gnutls_assert();
		return pkcs11_rv_to_err(rv);
	}

	/* ok found */
	sinfo->pks = pks;
	sinfo->module = module;
	sinfo->init = 1;
	memcpy(&sinfo->tinfo, &tinfo.tinfo, sizeof(sinfo->tinfo));

	if (flags & SESSION_LOGIN) {
		ret =
		    pkcs11_login(sinfo, pin_info, &tinfo, info,
				 (flags & SESSION_SO) ? 1 : 0);
		if (ret < 0) {
			gnutls_assert();
			pkcs11_close_session(sinfo);
			return ret;
		}
	}

	return 0;
}


int
_pkcs11_traverse_tokens(find_func_t find_func, void *input,
			struct p11_kit_uri *info,
			struct pin_info_st *pin_info, unsigned int flags)
{
	ck_rv_t rv;
	unsigned int found = 0, x, z;
	int ret;
	ck_session_handle_t pks = 0;
	struct pkcs11_session_info sinfo;
	struct ck_function_list *module = NULL;
	unsigned long nslots;
	ck_slot_id_t slots[MAX_SLOTS];

	for (x = 0; x < active_providers; x++) {
		if (providers[x].active == 0)
			continue;

		if (flags & SESSION_TRUSTED && providers[x].trusted == 0)
			continue;

		nslots = sizeof(slots) / sizeof(slots[0]);
		ret = scan_slots(&providers[x], slots, &nslots);
		if (ret < 0) {
			gnutls_assert();
			continue;
		}

		module = providers[x].module;
		for (z = 0; z < nslots; z++) {
			struct token_info tinfo;

			if (pkcs11_get_token_info(module, slots[z],
						  &tinfo.tinfo) != CKR_OK) {
				continue;
			}
			tinfo.sid = slots[z];
			tinfo.prov = &providers[x];

			if (pkcs11_get_slot_info(module, slots[z],
						 &tinfo.sinfo) != CKR_OK) {
				continue;
			}

			if (info != NULL) {
    			    if (!p11_kit_uri_match_token_info
	    		        (info, &tinfo.tinfo)
	    		        || !p11_kit_uri_match_module_info(info,
							      &providers
							      [x].info)) {
				continue;
                            }
                        }

			rv = (module)->C_OpenSession(slots[z],
						     ((flags & SESSION_WRITE) ? CKF_RW_SESSION : 0)
						     | CKF_SERIAL_SESSION,
						     NULL, NULL, &pks);
			if (rv != CKR_OK) {
				continue;
			}

			sinfo.module = module;
			sinfo.pks = pks;

			if (flags & SESSION_LOGIN) {
				ret =
				    pkcs11_login(&sinfo, pin_info, &tinfo,
						 info, (flags & SESSION_SO) ? 1 :	 0);
				if (ret < 0) {
					gnutls_assert();
					return ret;
				}
			}

			ret =
			    find_func(&sinfo, &tinfo, &providers[x].info, input);

			if (ret == 0) {
				found = 1;
				goto finish;
			} else {
				pkcs11_close_session(&sinfo);
				pks = 0;
			}
		}
	}

      finish:
	/* final call */

	if (found == 0) {
		if (module) {
			sinfo.module = module;
			sinfo.pks = pks;
			ret = find_func(&sinfo, NULL, NULL, input);
		} else
			ret =
			    gnutls_assert_val
			    (GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
	} else {
		ret = 0;
	}

	if (pks != 0 && module != NULL) {
		pkcs11_close_session(&sinfo);
	}

	return ret;
}

/* imports an object from a token to a pkcs11_obj_t structure.
 */
static int
pkcs11_obj_import(ck_object_class_t class, gnutls_pkcs11_obj_t obj,
		  const gnutls_datum_t * data,
		  const gnutls_datum_t * id,
		  const gnutls_datum_t * label,
		  struct ck_token_info *tinfo, struct ck_info *lib_info)
{
	struct ck_attribute attr;
	int ret;

	switch (class) {
	case CKO_CERTIFICATE:
		obj->type = GNUTLS_PKCS11_OBJ_X509_CRT;
		break;
	case CKO_PUBLIC_KEY:
		obj->type = GNUTLS_PKCS11_OBJ_PUBKEY;
		break;
	case CKO_PRIVATE_KEY:
		obj->type = GNUTLS_PKCS11_OBJ_PRIVKEY;
		break;
	case CKO_SECRET_KEY:
		obj->type = GNUTLS_PKCS11_OBJ_SECRET_KEY;
		break;
	case CKO_DATA:
		obj->type = GNUTLS_PKCS11_OBJ_DATA;
		break;
	default:
		obj->type = GNUTLS_PKCS11_OBJ_UNKNOWN;
	}

	attr.type = CKA_CLASS;
	attr.value = &class;
	attr.value_len = sizeof(class);
	ret = p11_kit_uri_set_attribute(obj->info, &attr);
	if (ret < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (data && data->data) {
		ret = _gnutls_set_datum(&obj->raw, data->data, data->size);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	}

	/* copy the token and library info into the uri */
	memcpy(p11_kit_uri_get_token_info(obj->info), tinfo,
	       sizeof(struct ck_token_info));
	memcpy(p11_kit_uri_get_module_info(obj->info), lib_info,
	       sizeof(struct ck_info));

	if (label && label->data) {
		attr.type = CKA_LABEL;
		attr.value = label->data;
		attr.value_len = label->size;
		ret = p11_kit_uri_set_attribute(obj->info, &attr);
		if (ret < 0) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
	}

	if (id && id->data) {
		attr.type = CKA_ID;
		attr.value = id->data;
		attr.value_len = id->size;
		ret = p11_kit_uri_set_attribute(obj->info, &attr);
		if (ret < 0) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
	}

	return 0;
}

#define MAX_PK_PARAM_SIZE 2048

int pkcs11_read_pubkey(struct ck_function_list *module,
		       ck_session_handle_t pks, ck_object_handle_t obj,
		       ck_key_type_t key_type, gnutls_datum_t * pubkey)
{
	struct ck_attribute a[4];
	uint8_t *tmp1;
	uint8_t *tmp2 = NULL;
	size_t tmp1_size, tmp2_size;
	int ret;
	
	tmp1_size = tmp2_size = MAX_PK_PARAM_SIZE;
	tmp1 = gnutls_malloc(tmp1_size);
	if (tmp1 == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	tmp2 = gnutls_malloc(tmp2_size);
	if (tmp2 == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto cleanup;
	}

	switch (key_type) {
	case CKK_RSA:
		a[0].type = CKA_MODULUS;
		a[0].value = tmp1;
		a[0].value_len = tmp1_size;
		a[1].type = CKA_PUBLIC_EXPONENT;
		a[1].value = tmp2;
		a[1].value_len = tmp2_size;

		if (pkcs11_get_attribute_value(module, pks, obj, a, 2) ==
		    CKR_OK) {

			pubkey[0].data = a[0].value;
			pubkey[0].size = a[0].value_len;

			pubkey[1].data = a[1].value;
			pubkey[1].size = a[1].value_len;
		} else {
			gnutls_assert();
			ret = GNUTLS_E_PKCS11_ERROR;
			goto cleanup;
		}
		break;
	case CKK_DSA:
		a[0].type = CKA_PRIME;
		a[0].value = tmp1;
		a[0].value_len = tmp1_size;
		a[1].type = CKA_SUBPRIME;
		a[1].value = tmp2;
		a[1].value_len = tmp2_size;

		if (pkcs11_get_attribute_value(module, pks, obj, a, 2) ==
		    CKR_OK) {
			ret =
			    _gnutls_set_datum(&pubkey[0], a[0].value,
					      a[0].value_len);

			if (ret >= 0)
				ret =
				    _gnutls_set_datum(&pubkey
						      [1], a[1].value,
						      a[1].value_len);

			if (ret < 0) {
				gnutls_assert();
				_gnutls_free_datum(&pubkey[1]);
				_gnutls_free_datum(&pubkey[0]);
				ret = GNUTLS_E_MEMORY_ERROR;
				goto cleanup;
			}
		} else {
			gnutls_assert();
			ret = GNUTLS_E_PKCS11_ERROR;
			goto cleanup;
		}

		a[0].type = CKA_BASE;
		a[0].value = tmp1;
		a[0].value_len = tmp1_size;
		a[1].type = CKA_VALUE;
		a[1].value = tmp2;
		a[1].value_len = tmp2_size;

		if (pkcs11_get_attribute_value(module, pks, obj, a, 2) ==
		    CKR_OK) {
			pubkey[2].data = a[0].value;
			pubkey[2].size = a[0].value_len;

			pubkey[3].data = a[1].value;
			pubkey[3].size = a[1].value_len;

		} else {
			gnutls_assert();
			ret = GNUTLS_E_PKCS11_ERROR;
			goto cleanup;
		}
		break;
	case CKK_ECDSA:
		a[0].type = CKA_EC_PARAMS;
		a[0].value = tmp1;
		a[0].value_len = tmp1_size;
		a[1].type = CKA_EC_POINT;
		a[1].value = tmp2;
		a[1].value_len = tmp2_size;

		if (pkcs11_get_attribute_value(module, pks, obj, a, 2) ==
		    CKR_OK) {

			pubkey[0].data = a[0].value;
			pubkey[0].size = a[0].value_len;

			pubkey[1].data = a[1].value;
			pubkey[1].size = a[1].value_len;
		} else {
			gnutls_assert();
			ret = GNUTLS_E_PKCS11_ERROR;
			goto cleanup;
		}

		break;
	default:
		ret = gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
		goto cleanup;
	}

	return 0;

cleanup:
	gnutls_free(tmp1);
	gnutls_free(tmp2);
	
	return ret;
}

static int
pkcs11_obj_import_pubkey(struct ck_function_list *module,
			 ck_session_handle_t pks,
			 ck_object_handle_t obj,
			 gnutls_pkcs11_obj_t crt,
			 const gnutls_datum_t * id,
			 const gnutls_datum_t * label,
			 struct ck_token_info *tinfo,
			 struct ck_info *lib_info)
{
	struct ck_attribute a[4];
	ck_key_type_t key_type;
	int ret;
	ck_bool_t tval;

	a[0].type = CKA_KEY_TYPE;
	a[0].value = &key_type;
	a[0].value_len = sizeof(key_type);

	if (pkcs11_get_attribute_value(module, pks, obj, a, 1) == CKR_OK) {
		crt->pk_algorithm = mech_to_pk(key_type);

		ret =
		    pkcs11_read_pubkey(module, pks, obj, key_type,
				       crt->pubkey);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* read key usage flags */
	a[0].type = CKA_ENCRYPT;
	a[0].value = &tval;
	a[0].value_len = sizeof(tval);

	if (pkcs11_get_attribute_value(module, pks, obj, a, 1) == CKR_OK) {
		if (tval != 0) {
			crt->key_usage |= GNUTLS_KEY_DATA_ENCIPHERMENT;
		}
	}

	a[0].type = CKA_VERIFY;
	a[0].value = &tval;
	a[0].value_len = sizeof(tval);

	if (pkcs11_get_attribute_value(module, pks, obj, a, 1) == CKR_OK) {
		if (tval != 0) {
			crt->key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE |
			    GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN
			    | GNUTLS_KEY_NON_REPUDIATION;
		}
	}

	a[0].type = CKA_VERIFY_RECOVER;
	a[0].value = &tval;
	a[0].value_len = sizeof(tval);

	if (pkcs11_get_attribute_value(module, pks, obj, a, 1) == CKR_OK) {
		if (tval != 0) {
			crt->key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE |
			    GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN
			    | GNUTLS_KEY_NON_REPUDIATION;
		}
	}

	a[0].type = CKA_DERIVE;
	a[0].value = &tval;
	a[0].value_len = sizeof(tval);

	if (pkcs11_get_attribute_value(module, pks, obj, a, 1) == CKR_OK) {
		if (tval != 0) {
			crt->key_usage |= GNUTLS_KEY_KEY_AGREEMENT;
		}
	}

	a[0].type = CKA_WRAP;
	a[0].value = &tval;
	a[0].value_len = sizeof(tval);

	if (pkcs11_get_attribute_value(module, pks, obj, a, 1) == CKR_OK) {
		if (tval != 0) {
			crt->key_usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
		}
	}

	return pkcs11_obj_import(CKO_PUBLIC_KEY, crt, NULL, id, label,
				 tinfo, lib_info);
}

static int
find_obj_url(struct pkcs11_session_info *sinfo,
	     struct token_info *info, struct ck_info *lib_info,
	     void *input)
{
	struct find_url_data_st *find_data = input;
	struct ck_attribute a[4];
	struct ck_attribute *attr;
	ck_object_class_t class = -1;
	ck_certificate_type_t type = (ck_certificate_type_t) - 1;
	ck_rv_t rv;
	ck_object_handle_t obj;
	unsigned long count, a_vals;
	int found = 0, ret;
	uint8_t *cert_data = NULL;
	char label_tmp[PKCS11_LABEL_SIZE];
	char id_tmp[PKCS11_ID_SIZE];

	if (info == NULL) {	/* we don't support multiple calls */
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	/* do not bother reading the token if basic fields do not match
	 */
	if (!p11_kit_uri_match_token_info
	    (find_data->crt->info, &info->tinfo)
	    || !p11_kit_uri_match_module_info(find_data->crt->info,
					      lib_info)) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	a_vals = 0;
	attr = p11_kit_uri_get_attribute(find_data->crt->info, CKA_ID);
	if (attr) {
		memcpy(a + a_vals, attr, sizeof(struct ck_attribute));
		a_vals++;
	}

	attr = p11_kit_uri_get_attribute(find_data->crt->info, CKA_LABEL);
	if (attr) {
		memcpy(a + a_vals, attr, sizeof(struct ck_attribute));
		a_vals++;
	}

	if (!a_vals) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	/* search the token for the id */

	cert_data = gnutls_malloc(MAX_CERT_SIZE);
	if (cert_data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* Find objects with given class and type */
	attr = p11_kit_uri_get_attribute(find_data->crt->info, CKA_CLASS);
	if (attr) {
		if (attr->value
		    && attr->value_len == sizeof(ck_object_class_t))
			class = *((ck_object_class_t *) attr->value);
		if (class == CKO_CERTIFICATE)
			type = CKC_X_509;
		memcpy(a + a_vals, attr, sizeof(struct ck_attribute));
		a_vals++;
	}

	if (type != (ck_certificate_type_t) - 1) {
		a[a_vals].type = CKA_CERTIFICATE_TYPE;
		a[a_vals].value = &type;
		a[a_vals].value_len = sizeof type;
		a_vals++;
	}

	rv = pkcs11_find_objects_init(sinfo->module, sinfo->pks, a,
				      a_vals);
	if (rv != CKR_OK) {
		gnutls_assert();
		_gnutls_debug_log("p11: FindObjectsInit failed.\n");
		ret = pkcs11_rv_to_err(rv);
		goto cleanup;
	}

	while (pkcs11_find_objects
	       (sinfo->module, sinfo->pks, &obj, 1, &count) == CKR_OK
	       && count == 1) {
		a[0].type = CKA_VALUE;
		a[0].value = cert_data;
		a[0].value_len = MAX_CERT_SIZE;
		a[1].type = CKA_LABEL;
		a[1].value = label_tmp;
		a[1].value_len = sizeof(label_tmp);
		a[2].type = CKA_ID;
		a[2].value = id_tmp;
		a[2].value_len = sizeof(id_tmp);

		if (pkcs11_get_attribute_value
		    (sinfo->module, sinfo->pks, obj, a, 3) == CKR_OK) {
			gnutls_datum_t id = { a[2].value, a[2].value_len };
			gnutls_datum_t data =
			    { a[0].value, a[0].value_len };
			gnutls_datum_t label =
			    { a[1].value, a[1].value_len };

			if (class == CKO_PUBLIC_KEY) {
				ret =
				    pkcs11_obj_import_pubkey(sinfo->module,
							     sinfo->pks,
							     obj,
							     find_data->crt,
							     &id, &label,
							     &info->tinfo,
							     lib_info);
			} else {
				ret =
				    pkcs11_obj_import(class,
						      find_data->crt,
						      &data, &id, &label,
						      &info->tinfo,
						      lib_info);
			}
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}

			found = 1;
			break;
		} else {
			_gnutls_debug_log
			    ("p11: Skipped cert, missing attrs.\n");
		}
	}

	if (found == 0) {
		gnutls_assert();
		ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	} else {
		ret = 0;
	}

      cleanup:
	gnutls_free(cert_data);
	pkcs11_find_objects_final(sinfo);

	return ret;
}

unsigned int pkcs11_obj_flags_to_int(unsigned int flags)
{
	unsigned int ret_flags = 0;

	if (flags & GNUTLS_PKCS11_OBJ_FLAG_LOGIN)
		ret_flags |= SESSION_LOGIN;
	if (flags & GNUTLS_PKCS11_OBJ_FLAG_LOGIN_SO)
		ret_flags |= SESSION_LOGIN | SESSION_SO;
	if (flags & GNUTLS_PKCS11_OBJ_FLAG_PRESENT_IN_TRUSTED_MODULE)
		ret_flags |= SESSION_TRUSTED;

	return ret_flags;
}

/**
 * gnutls_pkcs11_obj_import_url:
 * @obj: The structure to store the object
 * @url: a PKCS 11 url identifying the key
 * @flags: One of GNUTLS_PKCS11_OBJ_* flags
 *
 * This function will "import" a PKCS 11 URL identifying an object (e.g. certificate)
 * to the #gnutls_pkcs11_obj_t structure. This does not involve any
 * parsing (such as X.509 or OpenPGP) since the #gnutls_pkcs11_obj_t is
 * format agnostic. Only data are transferred.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_obj_import_url(gnutls_pkcs11_obj_t obj, const char *url,
			     unsigned int flags)
{
	int ret;
	struct find_url_data_st find_data;

	PKCS11_CHECK_INIT;

	/* fill in the find data structure */
	find_data.crt = obj;

	ret = pkcs11_url_to_info(url, &obj->info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret =
	    _pkcs11_traverse_tokens(find_obj_url, &find_data, obj->info,
				    &obj->pin,
				    pkcs11_obj_flags_to_int(flags));

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

static int
find_token_num(struct pkcs11_session_info *sinfo,
	       struct token_info *tinfo,
	       struct ck_info *lib_info, void *input)
{
	struct find_token_num *find_data = input;

	if (tinfo == NULL) {	/* we don't support multiple calls */
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if (find_data->current == find_data->seq) {
		memcpy(p11_kit_uri_get_token_info(find_data->info),
		       &tinfo->tinfo, sizeof(struct ck_token_info));
		memcpy(p11_kit_uri_get_module_info(find_data->info),
		       lib_info, sizeof(struct ck_info));
		return 0;
	}

	find_data->current++;
	/* search the token for the id */


	return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;	/* non zero is enough */
}

/**
 * gnutls_pkcs11_token_get_url:
 * @seq: sequence number starting from 0
 * @detailed: non zero if a detailed URL is required
 * @url: will contain an allocated url
 *
 * This function will return the URL for each token available
 * in system. The url has to be released using gnutls_free()
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE if the sequence number
 * exceeds the available tokens, otherwise a negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_token_get_url(unsigned int seq,
			    gnutls_pkcs11_url_type_t detailed, char **url)
{
	int ret;
	struct find_token_num tn;

	PKCS11_CHECK_INIT;

	memset(&tn, 0, sizeof(tn));
	tn.seq = seq;
	tn.info = p11_kit_uri_new();

	ret = _pkcs11_traverse_tokens(find_token_num, &tn, NULL, NULL, 0);
	if (ret < 0) {
		p11_kit_uri_free(tn.info);
		gnutls_assert();
		return ret;
	}

	ret = pkcs11_info_to_url(tn.info, detailed, url);
	p11_kit_uri_free(tn.info);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;

}

/**
 * gnutls_pkcs11_token_get_info:
 * @url: should contain a PKCS 11 URL
 * @ttype: Denotes the type of information requested
 * @output: where output will be stored
 * @output_size: contains the maximum size of the output and will be overwritten with actual
 *
 * This function will return information about the PKCS 11 token such
 * as the label, id, etc.
 *
 * Returns: %GNUTLS_E_SUCCESS (0) on success or a negative error code
 * on error.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_token_get_info(const char *url,
			     gnutls_pkcs11_token_info_t ttype,
			     void *output, size_t * output_size)
{
	struct p11_kit_uri *info = NULL;
	const uint8_t *str;
	size_t str_max;
	size_t len;
	int ret;

	PKCS11_CHECK_INIT;

	ret = pkcs11_url_to_info(url, &info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	switch (ttype) {
	case GNUTLS_PKCS11_TOKEN_LABEL:
		str = p11_kit_uri_get_token_info(info)->label;
		str_max = 32;
		break;
	case GNUTLS_PKCS11_TOKEN_SERIAL:
		str = p11_kit_uri_get_token_info(info)->serial_number;
		str_max = 16;
		break;
	case GNUTLS_PKCS11_TOKEN_MANUFACTURER:
		str = p11_kit_uri_get_token_info(info)->manufacturer_id;
		str_max = 32;
		break;
	case GNUTLS_PKCS11_TOKEN_MODEL:
		str = p11_kit_uri_get_token_info(info)->model;
		str_max = 16;
		break;
	default:
		p11_kit_uri_free(info);
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	len = p11_kit_space_strlen(str, str_max);

	if (len + 1 > *output_size) {
		*output_size = len + 1;
		return GNUTLS_E_SHORT_MEMORY_BUFFER;
	}

	memcpy(output, str, len);
	((char *) output)[len] = '\0';

	*output_size = len;

	ret = 0;

	p11_kit_uri_free(info);
	return ret;
}

/**
 * gnutls_pkcs11_obj_export_url:
 * @obj: Holds the PKCS 11 certificate
 * @detailed: non zero if a detailed URL is required
 * @url: will contain an allocated url
 *
 * This function will export a URL identifying the given certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_obj_export_url(gnutls_pkcs11_obj_t obj,
			     gnutls_pkcs11_url_type_t detailed, char **url)
{
	int ret;

	ret = pkcs11_info_to_url(obj->info, detailed, url);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/**
 * gnutls_pkcs11_obj_get_type:
 * @obj: Holds the PKCS 11 object
 *
 * This function will return the type of the certificate being
 * stored in the structure.
 *
 * Returns: The type of the certificate.
 *
 * Since: 2.12.0
 **/
gnutls_pkcs11_obj_type_t
gnutls_pkcs11_obj_get_type(gnutls_pkcs11_obj_t obj)
{
	return obj->type;
}

static int
retrieve_pin_from_source(const char *pinfile,
			 struct ck_token_info *token_info, int attempts,
			 ck_user_type_t user_type,
			 struct p11_kit_pin **pin)
{
	unsigned int flags = 0;
	struct p11_kit_uri *token_uri;
	struct p11_kit_pin *result;
	char *label;

	label =
	    p11_kit_space_strdup(token_info->label,
				 sizeof(token_info->label));
	if (label == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	token_uri = p11_kit_uri_new();
	if (token_uri == NULL) {
		free(label);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	memcpy(p11_kit_uri_get_token_info(token_uri), token_info,
	       sizeof(struct ck_token_info));

	if (attempts)
		flags |= P11_KIT_PIN_FLAGS_RETRY;
	if (user_type == CKU_USER) {
		flags |= P11_KIT_PIN_FLAGS_USER_LOGIN;
		if (token_info->flags & CKF_USER_PIN_COUNT_LOW)
			flags |= P11_KIT_PIN_FLAGS_MANY_TRIES;
		if (token_info->flags & CKF_USER_PIN_FINAL_TRY)
			flags |= P11_KIT_PIN_FLAGS_FINAL_TRY;
	} else if (user_type == CKU_SO) {
		flags |= P11_KIT_PIN_FLAGS_SO_LOGIN;
		if (token_info->flags & CKF_SO_PIN_COUNT_LOW)
			flags |= P11_KIT_PIN_FLAGS_MANY_TRIES;
		if (token_info->flags & CKF_SO_PIN_FINAL_TRY)
			flags |= P11_KIT_PIN_FLAGS_FINAL_TRY;
	} else if (user_type == CKU_CONTEXT_SPECIFIC) {
		flags |= P11_KIT_PIN_FLAGS_CONTEXT_LOGIN;
	}

	result = p11_kit_pin_request(pinfile, token_uri, label, flags);
	p11_kit_uri_free(token_uri);
	free(label);

	if (result == NULL) {
		gnutls_assert();
		return GNUTLS_E_PKCS11_PIN_ERROR;
	}

	*pin = result;
	return 0;
}

static int
retrieve_pin_from_callback(const struct pin_info_st *pin_info,
			   struct ck_token_info *token_info,
			   int attempts, ck_user_type_t user_type,
			   struct p11_kit_pin **pin)
{
	char pin_value[GNUTLS_PKCS11_MAX_PIN_LEN];
	unsigned int flags = 0;
	char *token_str;
	char *label;
	struct p11_kit_uri *token_uri;
	int ret = 0;

	label =
	    p11_kit_space_strdup(token_info->label,
				 sizeof(token_info->label));
	if (label == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	token_uri = p11_kit_uri_new();
	if (token_uri == NULL) {
		free(label);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	memcpy(p11_kit_uri_get_token_info(token_uri), token_info,
	       sizeof(struct ck_token_info));
	ret = pkcs11_info_to_url(token_uri, 1, &token_str);
	p11_kit_uri_free(token_uri);

	if (ret < 0) {
		free(label);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (user_type == CKU_USER) {
		flags |= GNUTLS_PIN_USER;
		if (token_info->flags & CKF_USER_PIN_COUNT_LOW)
			flags |= GNUTLS_PIN_COUNT_LOW;
		if (token_info->flags & CKF_USER_PIN_FINAL_TRY)
			flags |= GNUTLS_PIN_FINAL_TRY;
	} else if (user_type == CKU_SO) {
		flags |= GNUTLS_PIN_SO;
		if (token_info->flags & CKF_SO_PIN_COUNT_LOW)
			flags |= GNUTLS_PIN_COUNT_LOW;
		if (token_info->flags & CKF_SO_PIN_FINAL_TRY)
			flags |= GNUTLS_PIN_FINAL_TRY;
	}

	if (attempts > 0)
		flags |= GNUTLS_PIN_WRONG;

	if (pin_info && pin_info->cb)
		ret =
		    pin_info->cb(pin_info->data, attempts,
				 (char *) token_str, label, flags,
				 pin_value, GNUTLS_PKCS11_MAX_PIN_LEN);
	else if (_gnutls_pin_func)
		ret =
		    _gnutls_pin_func(_gnutls_pin_data, attempts,
				     (char *) token_str, label, flags,
				     pin_value, GNUTLS_PKCS11_MAX_PIN_LEN);
	else
		ret = gnutls_assert_val(GNUTLS_E_PKCS11_PIN_ERROR);

	free(token_str);
	free(label);

	if (ret < 0)
		return gnutls_assert_val(GNUTLS_E_PKCS11_PIN_ERROR);

	*pin = p11_kit_pin_new_for_string(pin_value);

	if (*pin == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	return 0;
}

static int
retrieve_pin(struct pin_info_st *pin_info, struct p11_kit_uri *info,
	     struct ck_token_info *token_info, int attempts,
	     ck_user_type_t user_type, struct p11_kit_pin **pin)
{
	const char *pinfile;
	int ret = GNUTLS_E_PKCS11_PIN_ERROR;

	*pin = NULL;

	/* Check if a pinfile is specified, and use that if possible */
	pinfile = p11_kit_uri_get_pinfile(info);
	if (pinfile != NULL) {
		_gnutls_debug_log("p11: Using pinfile to retrieve PIN\n");
		ret =
		    retrieve_pin_from_source(pinfile, token_info, attempts,
					     user_type, pin);
	}

	/* The global gnutls pin callback */
	if (ret < 0)
		ret =
		    retrieve_pin_from_callback(pin_info, token_info,
					       attempts, user_type, pin);

	/* Otherwise, PIN entry is necessary for login, so fail if there's
	 * no callback. */

	if (ret < 0) {
		gnutls_assert();
		_gnutls_debug_log
		    ("p11: No suitable pin callback but login required.\n");
	}

	return ret;
}

int
pkcs11_login(struct pkcs11_session_info *sinfo,
	     struct pin_info_st *pin_info,
	     const struct token_info *tokinfo, struct p11_kit_uri *info,
	     int so)
{
	struct ck_session_info session_info;
	int attempt = 0, ret;
	ck_user_type_t user_type;
	ck_rv_t rv;

	user_type = (so == 0) ? CKU_USER : CKU_SO;
	if (so == 0 && (tokinfo->tinfo.flags & CKF_LOGIN_REQUIRED) == 0) {
		gnutls_assert();
		_gnutls_debug_log("p11: No login required.\n");
		return 0;
	}

	/* For a token with a "protected" (out-of-band) authentication
	 * path, calling login with a NULL username is all that is
	 * required. */
	if (tokinfo->tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
		rv = (sinfo->module)->C_Login(sinfo->pks,
					      (so ==
					       0) ? CKU_USER : CKU_SO,
					      NULL, 0);
		if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) {
			return 0;
		} else {
			gnutls_assert();
			_gnutls_debug_log
			    ("p11: Protected login failed.\n");
			ret = GNUTLS_E_PKCS11_ERROR;
			goto cleanup;
		}
	}

	do {
		struct p11_kit_pin *pin;
		struct ck_token_info tinfo;

		memcpy(&tinfo, &tokinfo->tinfo, sizeof(tinfo));

		/* Check whether the session is already logged in, and if so, just skip */
		rv = (sinfo->module)->C_GetSessionInfo(sinfo->pks,
						       &session_info);
		if (rv == CKR_OK
		    && (session_info.state == CKS_RO_USER_FUNCTIONS
			|| session_info.state == CKS_RW_USER_FUNCTIONS)) {
			ret = 0;
			goto cleanup;
		}

		/* If login has been attempted once already, check the token
		 * status again, the flags might change. */
		if (attempt) {
			if (pkcs11_get_token_info
			    (tokinfo->prov->module, tokinfo->sid,
			     &tinfo) != CKR_OK) {
				gnutls_assert();
				_gnutls_debug_log
				    ("p11: GetTokenInfo failed\n");
				ret = GNUTLS_E_PKCS11_ERROR;
				goto cleanup;
			}
		}

		ret =
		    retrieve_pin(pin_info, info, &tinfo, attempt++,
				 user_type, &pin);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		rv = (sinfo->module)->C_Login(sinfo->pks, user_type,
					      (unsigned char *)
					      p11_kit_pin_get_value(pin,
								    NULL),
					      p11_kit_pin_get_length(pin));

		p11_kit_pin_unref(pin);
	}
	while (rv == CKR_PIN_INCORRECT);

	_gnutls_debug_log("p11: Login result = %lu\n", rv);


	ret = (rv == CKR_OK
	       || rv ==
	       CKR_USER_ALREADY_LOGGED_IN) ? 0 : pkcs11_rv_to_err(rv);

      cleanup:
	return ret;
}

int pkcs11_call_token_func(struct p11_kit_uri *info, const unsigned retry)
{
	struct ck_token_info *tinfo;
	char *label;
	int ret = 0;

	tinfo = p11_kit_uri_get_token_info(info);
	label = p11_kit_space_strdup(tinfo->label, sizeof(tinfo->label));
	ret = (_gnutls_token_func) (_gnutls_token_data, label, retry);
	free(label);

	return ret;
}


static int
find_privkeys(struct pkcs11_session_info *sinfo,
	      struct token_info *info, struct find_pkey_list_st *list)
{
	struct ck_attribute a[3];
	ck_object_class_t class;
	ck_rv_t rv;
	ck_object_handle_t obj;
	unsigned long count, current;
	char certid_tmp[PKCS11_ID_SIZE];

	class = CKO_PRIVATE_KEY;

	/* Find an object with private key class and a certificate ID
	 * which matches the certificate. */
	/* FIXME: also match the cert subject. */
	a[0].type = CKA_CLASS;
	a[0].value = &class;
	a[0].value_len = sizeof class;

	rv = pkcs11_find_objects_init(sinfo->module, sinfo->pks, a, 1);
	if (rv != CKR_OK) {
		gnutls_assert();
		return pkcs11_rv_to_err(rv);
	}

	list->key_ids_size = 0;
	while (pkcs11_find_objects
	       (sinfo->module, sinfo->pks, &obj, 1, &count) == CKR_OK
	       && count == 1) {
		list->key_ids_size++;
	}

	pkcs11_find_objects_final(sinfo);

	if (list->key_ids_size == 0) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	list->key_ids =
	    gnutls_malloc(sizeof(gnutls_buffer_st) * list->key_ids_size);
	if (list->key_ids == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* actual search */
	a[0].type = CKA_CLASS;
	a[0].value = &class;
	a[0].value_len = sizeof class;

	rv = pkcs11_find_objects_init(sinfo->module, sinfo->pks, a, 1);
	if (rv != CKR_OK) {
		gnutls_assert();
		return pkcs11_rv_to_err(rv);
	}

	current = 0;
	while (pkcs11_find_objects
	       (sinfo->module, sinfo->pks, &obj, 1, &count) == CKR_OK
	       && count == 1) {

		a[0].type = CKA_ID;
		a[0].value = certid_tmp;
		a[0].value_len = sizeof(certid_tmp);

		_gnutls_buffer_init(&list->key_ids[current]);

		if (pkcs11_get_attribute_value
		    (sinfo->module, sinfo->pks, obj, a, 1) == CKR_OK) {
			_gnutls_buffer_append_data(&list->key_ids[current],
						   a[0].value,
						   a[0].value_len);
			current++;
		}

		if (current > list->key_ids_size)
			break;
	}

	pkcs11_find_objects_final(sinfo);

	list->key_ids_size = current - 1;

	return 0;
}

/* Recover certificate list from tokens */


static int
find_objs(struct pkcs11_session_info *sinfo,
	  struct token_info *info, struct ck_info *lib_info, void *input)
{
	struct find_obj_data_st *find_data = input;
	struct ck_attribute a[6];
	struct ck_attribute *attr;
	ck_object_class_t class = (ck_object_class_t) - 1;
	ck_certificate_type_t type = (ck_certificate_type_t) - 1;
	ck_bool_t trusted;
	unsigned long category;
	ck_rv_t rv;
	ck_object_handle_t obj;
	unsigned long count;
	uint8_t *cert_data;
	char certid_tmp[PKCS11_ID_SIZE];
	char label_tmp[PKCS11_LABEL_SIZE];
	int ret;
	struct find_pkey_list_st plist;	/* private key holder */
	unsigned int i, tot_values = 0;

	if (info == NULL) {	/* final call */
		if (find_data->current <= *find_data->n_list)
			ret = 0;
		else
			ret = GNUTLS_E_SHORT_MEMORY_BUFFER;

		*find_data->n_list = find_data->current;

		return ret;
	}

	/* do not bother reading the token if basic fields do not match
	 */
	if (!p11_kit_uri_match_token_info(find_data->info, &info->tinfo) ||
	    !p11_kit_uri_match_module_info(find_data->info, lib_info)) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	memset(&plist, 0, sizeof(plist));

	if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY) {
		ret = find_privkeys(sinfo, info, &plist);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		if (plist.key_ids_size == 0) {
			gnutls_assert();
			return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		}
	}

	/* Find objects with given class and type */
	attr = p11_kit_uri_get_attribute(find_data->info, CKA_CLASS);
	if (attr) {
		if (attr->value
		    && attr->value_len == sizeof(ck_object_class_t))
			class = *((ck_object_class_t *) attr->value);
		if (class == CKO_CERTIFICATE)
			type = CKC_X_509;
	}

	cert_data = gnutls_malloc(MAX_CERT_SIZE);
	if (cert_data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* Find objects with cert class and X.509 cert type. */

	tot_values = 0;

	if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL
	    || find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY)
	{
		class = CKO_CERTIFICATE;
		type = CKC_X_509;
		trusted = 1;

		a[tot_values].type = CKA_CLASS;
		a[tot_values].value = &class;
		a[tot_values].value_len = sizeof class;
		tot_values++;

		a[tot_values].type = CKA_CERTIFICATE_TYPE;
		a[tot_values].value = &type;
		a[tot_values].value_len = sizeof type;
		tot_values++;

	} else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED) {
		class = CKO_CERTIFICATE;
		type = CKC_X_509;
		trusted = 1;

		a[tot_values].type = CKA_CLASS;
		a[tot_values].value = &class;
		a[tot_values].value_len = sizeof class;
		tot_values++;

		a[tot_values].type = CKA_TRUSTED;
		a[tot_values].value = &trusted;
		a[tot_values].value_len = sizeof trusted;
		tot_values++;

	} else if (find_data->flags ==
		   GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED_CA) {
		class = CKO_CERTIFICATE;
		type = CKC_X_509;
		trusted = 1;

		a[tot_values].type = CKA_CLASS;
		a[tot_values].value = &class;
		a[tot_values].value_len = sizeof class;
		tot_values++;

		a[tot_values].type = CKA_TRUSTED;
		a[tot_values].value = &trusted;
		a[tot_values].value_len = sizeof trusted;
		tot_values++;

		category = 2;
		a[tot_values].type = CKA_CERTIFICATE_CATEGORY;
		a[tot_values].value = &category;
		a[tot_values].value_len = sizeof category;
		tot_values++;
	} else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_PUBKEY) {
		class = CKO_PUBLIC_KEY;

		a[tot_values].type = CKA_CLASS;
		a[tot_values].value = &class;
		a[tot_values].value_len = sizeof class;
		tot_values++;
	} else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_PRIVKEY) {
		class = CKO_PRIVATE_KEY;

		a[tot_values].type = CKA_CLASS;
		a[tot_values].value = &class;
		a[tot_values].value_len = sizeof class;
		tot_values++;
	} else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_ALL) {
		if (class != (ck_object_class_t) - 1) {
			a[tot_values].type = CKA_CLASS;
			a[tot_values].value = &class;
			a[tot_values].value_len = sizeof class;
			tot_values++;
		}
		if (type != (ck_certificate_type_t) - 1) {
			a[tot_values].type = CKA_CERTIFICATE_TYPE;
			a[tot_values].value = &type;
			a[tot_values].value_len = sizeof type;
			tot_values++;
		}
	} else {
		gnutls_assert();
		ret = GNUTLS_E_INVALID_REQUEST;
		goto fail;
	}

	attr = p11_kit_uri_get_attribute(find_data->info, CKA_ID);
	if (attr != NULL) {
		memcpy(a + tot_values, attr, sizeof(struct ck_attribute));
		tot_values++;
	}

	rv = pkcs11_find_objects_init(sinfo->module, sinfo->pks, a,
				      tot_values);
	if (rv != CKR_OK) {
		gnutls_assert();
		_gnutls_debug_log("p11: FindObjectsInit failed.\n");
		return pkcs11_rv_to_err(rv);
	}

	while (pkcs11_find_objects
	       (sinfo->module, sinfo->pks, &obj, 1, &count) == CKR_OK
	       && count == 1) {
		gnutls_datum_t label, id, value;

		a[0].type = CKA_LABEL;
		a[0].value = label_tmp;
		a[0].value_len = sizeof label_tmp;

		if (pkcs11_get_attribute_value
		    (sinfo->module, sinfo->pks, obj, a, 1) == CKR_OK) {
			label.data = a[0].value;
			label.size = a[0].value_len;
		} else {
			label.data = NULL;
			label.size = 0;
		}

		a[0].type = CKA_ID;
		a[0].value = certid_tmp;
		a[0].value_len = sizeof certid_tmp;

		if (pkcs11_get_attribute_value
		    (sinfo->module, sinfo->pks, obj, a, 1) == CKR_OK) {
			id.data = a[0].value;
			id.size = a[0].value_len;
		} else {
			id.data = NULL;
			id.size = 0;
		}

		a[0].type = CKA_VALUE;
		a[0].value = cert_data;
		a[0].value_len = MAX_CERT_SIZE;
		if (pkcs11_get_attribute_value
		    (sinfo->module, sinfo->pks, obj, a, 1) == CKR_OK) {
			value.data = a[0].value;
			value.size = a[0].value_len;
		} else {
			value.data = NULL;
			value.size = 0;
		}

		if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_ALL) {
			a[0].type = CKA_CLASS;
			a[0].value = &class;
			a[0].value_len = sizeof class;

			rv = pkcs11_get_attribute_value(sinfo->module,
						   sinfo->pks, obj, a, 1);
			if (rv != CKR_OK) {
				class = -1;
			}
		}

		if (find_data->flags ==
		    GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY) {
			for (i = 0; i < plist.key_ids_size; i++) {
				if (plist.key_ids[i].length !=
				    a[1].value_len
				    || memcmp(plist.key_ids[i].data,
					      a[1].value,
					      a[1].value_len) != 0) {
					/* not found */
					continue;
				}
			}
		}

		if (find_data->current < *find_data->n_list) {
			ret =
			    gnutls_pkcs11_obj_init(&find_data->p_list
						   [find_data->current]);
			if (ret < 0) {
				gnutls_assert();
				goto fail;
			}

			if (class == CKO_PUBLIC_KEY) {
				ret =
				    pkcs11_obj_import_pubkey(sinfo->module,
							     sinfo->pks,
							     obj,
							     find_data->p_list
							     [find_data->current],
							     &id, &label,
							     &info->tinfo,
							     lib_info);
			} else {
				ret =
				    pkcs11_obj_import(class,
						      find_data->p_list
						      [find_data->current],
						      &value, &id, &label,
						      &info->tinfo,
						      lib_info);
			}
			if (ret < 0) {
				gnutls_assert();
				goto fail;
			}
		}

		find_data->current++;

	}

	gnutls_free(cert_data);
	pkcs11_find_objects_final(sinfo);

	return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;	/* continue until all tokens have been checked */

      fail:
	gnutls_free(cert_data);
	pkcs11_find_objects_final(sinfo);
	if (plist.key_ids != NULL) {
		for (i = 0; i < plist.key_ids_size; i++) {
			_gnutls_buffer_clear(&plist.key_ids[i]);
		}
		gnutls_free(plist.key_ids);
	}
	for (i = 0; i < find_data->current; i++) {
		gnutls_pkcs11_obj_deinit(find_data->p_list[i]);
	}
	find_data->current = 0;

	return ret;
}

/**
 * gnutls_pkcs11_obj_list_import_url:
 * @p_list: An uninitialized object list (may be NULL)
 * @n_list: initially should hold the maximum size of the list. Will contain the actual size.
 * @url: A PKCS 11 url identifying a set of objects
 * @attrs: Attributes of type #gnutls_pkcs11_obj_attr_t that can be used to limit output
 * @flags: One of GNUTLS_PKCS11_OBJ_* flags
 *
 * This function will initialize and set values to an object list
 * by using all objects identified by a PKCS 11 URL.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_obj_list_import_url(gnutls_pkcs11_obj_t * p_list,
				  unsigned int *n_list,
				  const char *url,
				  gnutls_pkcs11_obj_attr_t attrs,
				  unsigned int flags)
{
	int ret;
	struct find_obj_data_st priv;

	PKCS11_CHECK_INIT;

	memset(&priv, 0, sizeof(priv));

	/* fill in the find data structure */
	priv.p_list = p_list;
	priv.n_list = n_list;
	priv.flags = attrs;
	priv.current = 0;

	if (url == NULL || url[0] == 0) {
		url = "pkcs11:";
	}

	ret = pkcs11_url_to_info(url, &priv.info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret =
	    _pkcs11_traverse_tokens(find_objs, &priv, priv.info,
				    NULL, pkcs11_obj_flags_to_int(flags));
	p11_kit_uri_free(priv.info);

	if (ret < 0) {
		gnutls_assert();
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			*n_list = 0;
			ret = 0;
		}
		return ret;
	}

	return 0;
}

/**
 * gnutls_pkcs11_obj_list_import_url2:
 * @p_list: An uninitialized object list (may be NULL)
 * @n_list: It will contain the size of the list.
 * @url: A PKCS 11 url identifying a set of objects
 * @attrs: Attributes of type #gnutls_pkcs11_obj_attr_t that can be used to limit output
 * @flags: One of GNUTLS_PKCS11_OBJ_* flags
 *
 * This function will initialize and set values to an object list
 * by using all objects identified by the PKCS 11 URL. The output
 * is stored in @p_list, which will be initialized.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.1.0
 **/
int
gnutls_pkcs11_obj_list_import_url2(gnutls_pkcs11_obj_t ** p_list,
				   unsigned int *n_list,
				   const char *url,
				   gnutls_pkcs11_obj_attr_t attrs,
				   unsigned int flags)
{
	unsigned int init = 128;
	int ret;

	*p_list = gnutls_malloc(sizeof(gnutls_pkcs11_obj_t) * init);
	if (*p_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret =
	    gnutls_pkcs11_obj_list_import_url(*p_list, &init, url, attrs,
					      flags);
	if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
		*p_list =
		    gnutls_realloc_fast(*p_list,
					sizeof(gnutls_pkcs11_obj_t) *
					init);
		if (*p_list == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

		ret =
		    gnutls_pkcs11_obj_list_import_url(*p_list, &init, url,
						      attrs, flags);
	}

	if (ret < 0) {
		gnutls_assert();
		gnutls_free(*p_list);
		*p_list = NULL;
		return ret;
	}

	*n_list = init;
	return 0;

}

/**
 * gnutls_x509_crt_import_pkcs11_url:
 * @crt: A certificate of type #gnutls_x509_crt_t
 * @url: A PKCS 11 url
 * @flags: One of GNUTLS_PKCS11_OBJ_* flags
 *
 * This function will import a PKCS 11 certificate directly from a token
 * without involving the #gnutls_pkcs11_obj_t structure. This function will
 * fail if the certificate stored is not of X.509 type.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_x509_crt_import_pkcs11_url(gnutls_x509_crt_t crt,
				  const char *url, unsigned int flags)
{
	gnutls_pkcs11_obj_t pcrt;
	int ret;

	ret = gnutls_pkcs11_obj_init(&pcrt);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if (crt->pin.cb)
		gnutls_pkcs11_obj_set_pin_function(pcrt, crt->pin.cb,
						   crt->pin.data);

	ret = gnutls_pkcs11_obj_import_url(pcrt, url, flags);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_x509_crt_import(crt, &pcrt->raw, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
      cleanup:

	gnutls_pkcs11_obj_deinit(pcrt);

	return ret;
}

/**
 * gnutls_x509_crt_import_pkcs11:
 * @crt: A certificate of type #gnutls_x509_crt_t
 * @pkcs11_crt: A PKCS 11 object that contains a certificate
 *
 * This function will import a PKCS 11 certificate to a #gnutls_x509_crt_t
 * structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_x509_crt_import_pkcs11(gnutls_x509_crt_t crt,
			      gnutls_pkcs11_obj_t pkcs11_crt)
{
	return gnutls_x509_crt_import(crt, &pkcs11_crt->raw,
				      GNUTLS_X509_FMT_DER);
}

/**
 * gnutls_x509_crt_list_import_pkcs11:
 * @certs: A list of certificates of type #gnutls_x509_crt_t
 * @cert_max: The maximum size of the list
 * @objs: A list of PKCS 11 objects
 * @flags: 0 for now
 *
 * This function will import a PKCS 11 certificate list to a list of 
 * #gnutls_x509_crt_t structure. These must not be initialized.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 2.12.0
 **/
int
gnutls_x509_crt_list_import_pkcs11(gnutls_x509_crt_t * certs,
				   unsigned int cert_max,
				   gnutls_pkcs11_obj_t * const objs,
				   unsigned int flags)
{
	unsigned int i, j;
	int ret;

	for (i = 0; i < cert_max; i++) {
		ret = gnutls_x509_crt_init(&certs[i]);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = gnutls_x509_crt_import_pkcs11(certs[i], objs[i]);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}

	return 0;

      cleanup:
	for (j = 0; j < i; j++) {
		gnutls_x509_crt_deinit(certs[j]);
	}

	return ret;
}

static int
find_flags(struct pkcs11_session_info *sinfo,
	   struct token_info *info, struct ck_info *lib_info, void *input)
{
	struct find_flags_data_st *find_data = input;

	if (info == NULL) {	/* we don't support multiple calls */
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	/* do not bother reading the token if basic fields do not match
	 */
	if (!p11_kit_uri_match_token_info(find_data->info, &info->tinfo) ||
	    !p11_kit_uri_match_module_info(find_data->info, lib_info)) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	/* found token! */
	if (p11_kit_module_get_flags(sinfo->module) & P11_KIT_MODULE_TRUSTED)
		find_data->trusted = 1;
	else
		find_data->trusted = 0;
	find_data->slot_flags = info->sinfo.flags;

	return 0;
}

/**
 * gnutls_pkcs11_token_get_flags:
 * @url: should contain a PKCS 11 URL
 * @flags: The output flags (GNUTLS_PKCS11_TOKEN_*)
 *
 * This function will return information about the PKCS 11 token flags.
 *
 * The supported flags are: %GNUTLS_PKCS11_TOKEN_HW and %GNUTLS_PKCS11_TOKEN_TRUSTED.
 *
 * Returns: %GNUTLS_E_SUCCESS (0) on success or a negative error code on error.
 *
 * Since: 2.12.0
 **/
int gnutls_pkcs11_token_get_flags(const char *url, unsigned int *flags)
{
	struct find_flags_data_st find_data;
	int ret;

	PKCS11_CHECK_INIT;

	memset(&find_data, 0, sizeof(find_data));
	ret = pkcs11_url_to_info(url, &find_data.info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret =
	    _pkcs11_traverse_tokens(find_flags, &find_data, find_data.info,
				    NULL, 0);
	p11_kit_uri_free(find_data.info);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	*flags = 0;
	if (find_data.slot_flags & CKF_HW_SLOT)
		*flags |= GNUTLS_PKCS11_TOKEN_HW;

	if (find_data.trusted != 0)
		*flags |= GNUTLS_PKCS11_TOKEN_TRUSTED;

	return 0;

}

/**
 * gnutls_pkcs11_token_get_mechanism:
 * @url: should contain a PKCS 11 URL
 * @idx: The index of the mechanism
 * @mechanism: The PKCS #11 mechanism ID
 *
 * This function will return the names of the supported mechanisms
 * by the token. It should be called with an increasing index until
 * it return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE.
 *
 * Returns: %GNUTLS_E_SUCCESS (0) on success or a negative error code on error.
 *
 * Since: 2.12.0
 **/
int
gnutls_pkcs11_token_get_mechanism(const char *url, unsigned int idx,
				  unsigned long *mechanism)
{
	int ret;
	ck_rv_t rv;
	struct ck_function_list *module;
	ck_slot_id_t slot;
	struct token_info tinfo;
	struct p11_kit_uri *info = NULL;
	unsigned long count;
	ck_mechanism_type_t mlist[400];
	
	PKCS11_CHECK_INIT;

	ret = pkcs11_url_to_info(url, &info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = pkcs11_find_slot(&module, &slot, info, &tinfo);
	p11_kit_uri_free(info);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	count = sizeof(mlist) / sizeof(mlist[0]);
	rv = pkcs11_get_mechanism_list(module, slot, mlist, &count);
	if (rv != CKR_OK) {
		gnutls_assert();
		return pkcs11_rv_to_err(rv);
	}

	if (idx >= count) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	*mechanism = mlist[idx];

	return 0;

}

/**
 * gnutls_pkcs11_type_get_name:
 * @type: Holds the PKCS 11 object type, a #gnutls_pkcs11_obj_type_t.
 *
 * This function will return a human readable description of the
 * PKCS11 object type @obj.  It will return "Unknown" for unknown
 * types.
 *
 * Returns: human readable string labeling the PKCS11 object type
 * @type.
 *
 * Since: 2.12.0
 **/
const char *gnutls_pkcs11_type_get_name(gnutls_pkcs11_obj_type_t type)
{
	switch (type) {
	case GNUTLS_PKCS11_OBJ_X509_CRT:
		return "X.509 Certificate";
	case GNUTLS_PKCS11_OBJ_PUBKEY:
		return "Public key";
	case GNUTLS_PKCS11_OBJ_PRIVKEY:
		return "Private key";
	case GNUTLS_PKCS11_OBJ_SECRET_KEY:
		return "Secret key";
	case GNUTLS_PKCS11_OBJ_DATA:
		return "Data";
	case GNUTLS_PKCS11_OBJ_UNKNOWN:
	default:
		return "Unknown";
	}
}

#ifndef CKA_X_DISTRUSTED
# define CKA_X_VENDOR (CKA_VENDOR_DEFINED | 0x58444700UL)
# define CKA_X_DISTRUSTED (CKA_X_VENDOR + 100)
#endif

static int
find_cert(struct pkcs11_session_info *sinfo,
	    struct token_info *info, struct ck_info *lib_info, void *input)
{
	struct ck_attribute a[10];
	ck_object_class_t class = -1;
	ck_certificate_type_t type = (ck_certificate_type_t) - 1;
	ck_rv_t rv;
	ck_object_handle_t obj;
	unsigned long count, a_vals;
	int found = 0, ret;
	uint8_t *cert_data = NULL;
	struct find_cert_st *priv = input;
	char label_tmp[PKCS11_LABEL_SIZE];
	char id_tmp[PKCS11_ID_SIZE];
	unsigned tries, i, finalized;
	ck_bool_t trusted = 1;

	if (info == NULL) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	/* the DISTRUSTED flag is p11-kit module specific */
	if (priv->flags & GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_DISTRUSTED) {
		if (memcmp(lib_info->manufacturer_id, "PKCS#11 Kit", 11) != 0) {
			gnutls_assert();
			return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		}
	}

	if (priv->dn.size == 0 && priv->key_id.size == 0 && priv->issuer_dn.size == 0 &&
		priv->serial.size == 0)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	/* search the token for the key ID */

	cert_data = gnutls_malloc(MAX_CERT_SIZE);
	if (cert_data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* Find objects with given class and type */

	if (priv->key_id.size > 0 && priv->dn.size > 0)
		tries = 2;
	else
		tries = 1;

	for (i = 0; i < tries; i++) {

		a_vals = 0;
		class = CKO_CERTIFICATE;
		a[a_vals].type = CKA_CLASS;
		a[a_vals].value = &class;
		a[a_vals].value_len = sizeof class;
		a_vals++;

		if (priv->flags & GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_TRUSTED) {
			a[a_vals].type = CKA_TRUSTED;
			a[a_vals].value = &trusted;
			a[a_vals].value_len = sizeof trusted;
			a_vals++;
		}

		if (priv->flags & GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_DISTRUSTED) {
			a[a_vals].type = CKA_X_DISTRUSTED;
			a[a_vals].value = &trusted;
			a[a_vals].value_len = sizeof trusted;
			a_vals++;
		}

		if (priv->need_import != 0) {
			type = CKC_X_509;
			a[a_vals].type = CKA_CERTIFICATE_TYPE;
			a[a_vals].value = &type;
			a[a_vals].value_len = sizeof type;
			a_vals++;
		}

		if (i == 0 && priv->key_id.size > 0) {
			a[a_vals].type = CKA_ID;
			a[a_vals].value = priv->key_id.data;
			a[a_vals].value_len = priv->key_id.size;
			a_vals++;
		}

		if (priv->dn.size > 0) {
			a[a_vals].type = CKA_SUBJECT;
			a[a_vals].value = priv->dn.data;
			a[a_vals].value_len = priv->dn.size;
			a_vals++;
		}

		if (priv->serial.size > 0) {
			a[a_vals].type = CKA_SERIAL_NUMBER;
			a[a_vals].value = priv->serial.data;
			a[a_vals].value_len = priv->serial.size;
			a_vals++;
		}

		if (priv->issuer_dn.size > 0) {
			a[a_vals].type = CKA_ISSUER;
			a[a_vals].value = priv->issuer_dn.data;
			a[a_vals].value_len = priv->issuer_dn.size;
			a_vals++;
		}

		finalized = 0;
		rv = pkcs11_find_objects_init(sinfo->module, sinfo->pks, a,
					      a_vals);
		if (rv != CKR_OK) {
			gnutls_assert();
			_gnutls_debug_log
			    ("p11: FindObjectsInit failed.\n");
			ret = pkcs11_rv_to_err(rv);
			goto cleanup;
		}

		while (pkcs11_find_objects
		       (sinfo->module, sinfo->pks, &obj, 1,
			&count) == CKR_OK && count == 1) {

			if (priv->need_import == 0 && !(priv->flags & GNUTLS_PKCS11_OBJ_FLAG_COMPARE)) {
				found = 1;
				break;
			}

			a[0].type = CKA_VALUE;
			a[0].value = cert_data;
			a[0].value_len = MAX_CERT_SIZE;

			a[1].type = CKA_LABEL;
			a[1].value = label_tmp;
			a[1].value_len = sizeof(label_tmp);

			a[2].type = CKA_ID;
			a[2].value = id_tmp;
			a[2].value_len = sizeof(id_tmp);

			if (pkcs11_get_attribute_value
			    (sinfo->module, sinfo->pks, obj, a,
			     3) == CKR_OK) {
				gnutls_datum_t id =
				    { a[2].value, a[2].value_len };
				gnutls_datum_t data =
				    { a[0].value, a[0].value_len };
				gnutls_datum_t label =
				    { a[1].value, a[1].value_len };

				if (priv->need_import != 0) {
					ret =
					    pkcs11_obj_import(class, priv->obj,
							      &data, &id, &label,
							      &info->tinfo,
							      lib_info);
					if (ret < 0) {
						gnutls_assert();
						goto cleanup;
					}
				}
				
				if (priv->flags & GNUTLS_PKCS11_OBJ_FLAG_COMPARE) {
					if (priv->crt == NULL) {
						gnutls_assert();
						break;
					}

					if (_gnutls_check_if_same_cert2(priv->crt, &data) == 0) {
						/* doesn't match */
						break;
					}
				}

				found = 1;
				break;
			} else {
				_gnutls_debug_log
				    ("p11: Skipped cert, missing attrs.\n");
			}
		}

		pkcs11_find_objects_final(sinfo);
		finalized = 1;

		if (found != 0)
			break;
	}

	if (found == 0) {
		gnutls_assert();
		ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	} else {
		ret = 0;
	}

      cleanup:
	gnutls_free(cert_data);
	if (finalized == 0)
		pkcs11_find_objects_final(sinfo);

	return ret;
}

/**
 * gnutls_pkcs11_get_raw_issuer:
 * @url: A PKCS 11 url identifying a token
 * @cert: is the certificate to find issuer for
 * @issuer: Will hold the issuer if any in an allocated buffer. 
 * @fmt: The format of the exported issuer.
 * @flags: Use zero or flags from %GNUTLS_PKCS11_OBJ_FLAG.
 *
 * This function will return the issuer of a given certificate, if it
 * is stored in the token. By default only marked as trusted issuers
 * are retuned. If any issuer should be returned specify
 * %GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_ANY in @flags.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.2.7
 **/
int gnutls_pkcs11_get_raw_issuer(const char *url, gnutls_x509_crt_t cert,
				 gnutls_datum_t * issuer,
				 gnutls_x509_crt_fmt_t fmt,
				 unsigned int flags)
{
	int ret;
	struct find_cert_st priv;
	uint8_t id[PKCS11_ID_SIZE];
	size_t id_size;
	struct p11_kit_uri *info = NULL;

	PKCS11_CHECK_INIT;

	memset(&priv, 0, sizeof(priv));

	if (url == NULL || url[0] == 0) {
		url = "pkcs11:";
	}

	ret = pkcs11_url_to_info(url, &info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	id_size = sizeof(id);
	ret =
	    gnutls_x509_crt_get_authority_key_id(cert, id, &id_size, NULL);
	if (ret >= 0) {
		priv.key_id.data = id;
		priv.key_id.size = id_size;
	}

	priv.dn.data = cert->raw_issuer_dn.data;
	priv.dn.size = cert->raw_issuer_dn.size;

	if (!(flags & GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_ANY))
		flags |= GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_TRUSTED;

	priv.flags = flags;

	ret = gnutls_pkcs11_obj_init(&priv.obj);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}
	priv.need_import = 1;

	ret =
	    _pkcs11_traverse_tokens(find_cert, &priv, info,
				    NULL, pkcs11_obj_flags_to_int(flags));
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_pkcs11_obj_export3(priv.obj, fmt, issuer);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

      cleanup:
	if (priv.obj)
		gnutls_pkcs11_obj_deinit(priv.obj);
	if (info)
		p11_kit_uri_free(info);

	return ret;
}

/**
 * gnutls_pkcs11_crt_is_known:
 * @url: A PKCS 11 url identifying a token
 * @cert: is the certificate to find issuer for
 * @issuer: Will hold the issuer if any in an allocated buffer. 
 * @fmt: The format of the exported issuer.
 * @flags: Use zero or flags from %GNUTLS_PKCS11_OBJ_FLAG.
 *
 * This function will check whether the provided certificate is stored
 * in the specified token. This is useful in combination with 
 * %GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_TRUSTED or 
 * %GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_DISTRUSTED,
 * to check whether a CA is present or a certificate is blacklisted in
 * a trust PKCS #11 module.
 *
 * This function can be used with a @url of "pkcs11:", and in that case all modules
 * will be searched. To restrict the modules to the marked as trusted in p11-kit
 * use the %GNUTLS_PKCS11_OBJ_FLAG_PRESENT_IN_TRUSTED_MODULE flag.
 *
 * Note that the flag %GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_DISTRUSTED is
 * specific to p11-kit trust modules.
 *
 * Returns: If the certificate exists non-zero is returned, otherwise zero.
 *
 * Since: 3.3.0
 **/
int gnutls_pkcs11_crt_is_known(const char *url, gnutls_x509_crt_t cert,
				 unsigned int flags)
{
	int ret;
	struct find_cert_st priv;
	uint8_t serial[ASN1_MAX_TL_SIZE+64];
	size_t serial_size;
	uint8_t tag[ASN1_MAX_TL_SIZE];
	unsigned int tag_size;
	struct p11_kit_uri *info = NULL;

	PKCS11_CHECK_INIT_RET(0);

	memset(&priv, 0, sizeof(priv));

	if (url == NULL || url[0] == 0) {
		url = "pkcs11:";
	}

	ret = pkcs11_url_to_info(url, &info);
	if (ret < 0) {
		gnutls_assert();
		return 0;
	}

	/* Attempt searching using the issuer DN + serial number */
	serial_size = sizeof(serial) - sizeof(tag);
	ret =
	    gnutls_x509_crt_get_serial(cert, serial+sizeof(tag), &serial_size);
	if (ret < 0) {
		gnutls_assert();
		return 0;
	}

	/* PKCS#11 requires a DER encoded serial, wtf. $@(*$@ */
	tag_size = sizeof(tag);
	ret = asn1_encode_simple_der(ASN1_ETYPE_INTEGER, serial+sizeof(tag), serial_size,
		tag, &tag_size);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		return 0;
	}

	memcpy(serial+sizeof(tag)-tag_size, tag, tag_size);
	
	priv.serial.data = serial+sizeof(tag)-tag_size;
	priv.serial.size = serial_size + tag_size;
	priv.crt = cert;

	priv.issuer_dn.data = cert->raw_issuer_dn.data;
	priv.issuer_dn.size = cert->raw_issuer_dn.size;
	
	/* when looking for a trusted certificate, we always fully compare
	 * with the given */
	if (flags & GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_TRUSTED)
		flags |= GNUTLS_PKCS11_OBJ_FLAG_COMPARE;

	priv.flags = flags;

	ret =
	    _pkcs11_traverse_tokens(find_cert, &priv, info,
				    NULL, pkcs11_obj_flags_to_int(flags));
	if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
		/* attempt searching with the subject DN only */
		memset(&priv, 0, sizeof(priv));
		priv.crt = cert;
		priv.flags = flags;

		priv.dn.data = cert->raw_dn.data;
		priv.dn.size = cert->raw_dn.size;
		ret =
		    _pkcs11_traverse_tokens(find_cert, &priv, info,
				    NULL, pkcs11_obj_flags_to_int(flags));
	}
	if (ret < 0) {
		gnutls_assert();
		ret = 0;
		goto cleanup;
	}

	ret = 1;

      cleanup:
	if (info)
		p11_kit_uri_free(info);

	return ret;
}
