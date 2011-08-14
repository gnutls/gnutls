/*
 * GnuTLS PKCS#11 support
 * Copyright (C) 2010 Free Software Foundation
 * Copyright (C) 2008, Joe Orton <joe@manyfish.co.uk>
 * 
 * Author: Nikos Mavrogiannopoulos
 *
 * Inspired and some parts (pkcs11_login) based on neon PKCS #11 support 
 * by Joe Orton. More ideas came from the pkcs11-helper library by 
 * Alon Bar-Lev.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA
*/

#include <gnutls_int.h>
#include <gnutls/pkcs11.h>
#include <stdio.h>
#include <string.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <pkcs11_int.h>
#include <p11-kit/p11-kit.h>
#include <p11-kit/pin.h>
#include <errno.h>

#define MAX_PROVIDERS 16

/* XXX: try to eliminate this */
#define MAX_CERT_SIZE 8*1024

struct gnutls_pkcs11_provider_s
{
  struct ck_function_list *module;
  unsigned long nslots;
  ck_slot_id_t *slots;
  struct ck_info info;
  int initialized;
};

struct flags_find_data_st
{
  struct p11_kit_uri *info;
  unsigned int slot_flags;
};

struct url_find_data_st
{
  gnutls_pkcs11_obj_t crt;
};

struct crt_find_data_st
{
  gnutls_pkcs11_obj_t *p_list;
  unsigned int *n_list;
  unsigned int current;
  gnutls_pkcs11_obj_attr_t flags;
  struct p11_kit_uri *info;
};


static struct gnutls_pkcs11_provider_s providers[MAX_PROVIDERS];
static int active_providers = 0;
static int initialized_registered = 0;

static gnutls_pkcs11_pin_callback_t pin_func;
static void *pin_data;

gnutls_pkcs11_token_callback_t token_func;
void *token_data;

int
pkcs11_rv_to_err (ck_rv_t rv)
{
  switch (rv)
    {
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

/* Fake scan */
void
pkcs11_rescan_slots (void)
{
  unsigned long slots;

  pkcs11_get_slot_list (providers[active_providers - 1].module, 0,
                          NULL, &slots);
}

static int
pkcs11_add_module (const char *name, struct ck_function_list *module)
{
  struct ck_info info;
  int i;

  if (active_providers >= MAX_PROVIDERS)
    {
      gnutls_assert ();
      return GNUTLS_E_CONSTRAINT_ERROR;
    }

  /* initially check if this module is a duplicate */
  memset(&info, 0, sizeof(info));
  pkcs11_get_module_info (module, &info);
  for (i=0;i<active_providers;i++)
    {
      /* already loaded, skip the rest */
      if (memcmp(&info, &providers[i].info, sizeof(info)) == 0)
        {
          _gnutls_debug_log("%s is already loaded.\n", name);
          return 0;
        }
    }

  active_providers++;
  providers[active_providers - 1].module = module;

  /* cache the number of slots in this module */
  if (pkcs11_get_slot_list
      (providers[active_providers - 1].module, 0, NULL,
       &providers[active_providers - 1].nslots) != CKR_OK)
    {
      gnutls_assert ();
      goto fail;
    }

  providers[active_providers - 1].slots =
    gnutls_malloc (sizeof (*providers[active_providers - 1].slots) *
                   providers[active_providers - 1].nslots);
  if (providers[active_providers - 1].slots == NULL)
    {
      gnutls_assert ();
      goto fail;
    }

  if (pkcs11_get_slot_list
      (providers[active_providers - 1].module, 0,
       providers[active_providers - 1].slots,
       &providers[active_providers - 1].nslots) != CKR_OK)
    {
      gnutls_assert ();
      gnutls_free (providers[active_providers - 1].slots);
      goto fail;
    }

  memcpy (&providers[active_providers - 1].info, &info, sizeof(info));

  _gnutls_debug_log ("p11: loaded provider '%s' with %d slots\n",
                     name, (int) providers[active_providers - 1].nslots);

  return 0;

fail:
  active_providers--;
  return GNUTLS_E_PKCS11_LOAD_ERROR;
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
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs11_add_provider (const char *name, const char *params)
{
  struct ck_function_list *module;
  int ret;

  active_providers++;
  if (p11_kit_load_initialize_module (name, &module) != CKR_OK)
    {
      gnutls_assert ();
      _gnutls_debug_log ("p11: Cannot load provider %s\n", name);
      active_providers--;
      return GNUTLS_E_PKCS11_LOAD_ERROR;
    }

  ret = pkcs11_add_module (name, module);
  if (ret == 0)
    {
      /* Mark this one as having been separately initialized */
      providers[active_providers - 1].initialized = 1;
    }
  else
    {
      p11_kit_finalize_module (module);
      gnutls_assert ();
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
 * This function will return information about the PKCS 11 certificatesuch
 * as the label, id as well as token information where the key is stored. When
 * output is text it returns null terminated string although %output_size contains
 * the size of the actual data only.
 *
 * Returns: zero on success or a negative value on error.
 **/
int
gnutls_pkcs11_obj_get_info (gnutls_pkcs11_obj_t crt,
                            gnutls_pkcs11_obj_info_t itype,
                            void *output, size_t * output_size)
{
  return pkcs11_get_info (crt->info, itype, output, output_size);
}

int
pkcs11_get_info (struct p11_kit_uri *info,
                 gnutls_pkcs11_obj_info_t itype, void *output,
                 size_t * output_size)
{
  struct ck_attribute *attr = NULL;
  struct ck_version *version = NULL;
  const char *str = NULL;
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

  switch (itype)
    {
    case GNUTLS_PKCS11_OBJ_ID:
      attr = p11_kit_uri_get_attribute (info, CKA_ID);
      break;
    case GNUTLS_PKCS11_OBJ_ID_HEX:
      attr = p11_kit_uri_get_attribute (info, CKA_ID);
      hexify = 1;
      terminate = 1;
      break;
    case GNUTLS_PKCS11_OBJ_LABEL:
      attr = p11_kit_uri_get_attribute (info, CKA_LABEL);
      terminate = 1;
      break;
    case GNUTLS_PKCS11_OBJ_TOKEN_LABEL:
      str = p11_kit_uri_get_token_info (info)->label;
      str_max = 32;
      break;
    case GNUTLS_PKCS11_OBJ_TOKEN_SERIAL:
      str = p11_kit_uri_get_token_info (info)->serial_number;
      str_max = 16;
      break;
    case GNUTLS_PKCS11_OBJ_TOKEN_MANUFACTURER:
      str = p11_kit_uri_get_token_info (info)->manufacturer_id;
      str_max = 32;
      break;
    case GNUTLS_PKCS11_OBJ_TOKEN_MODEL:
      str = p11_kit_uri_get_token_info (info)->model;
      str_max = 16;
      break;
    case GNUTLS_PKCS11_OBJ_LIBRARY_DESCRIPTION:
      str = p11_kit_uri_get_module_info (info)->library_description;
      str_max = 32;
      break;
    case GNUTLS_PKCS11_OBJ_LIBRARY_VERSION:
      version = &p11_kit_uri_get_module_info (info)->library_version;
      break;
    case GNUTLS_PKCS11_OBJ_LIBRARY_MANUFACTURER:
      str = p11_kit_uri_get_module_info (info)->manufacturer_id;
      str_max = 32;
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (attr != NULL)
    {
      data = attr->value;
      length = attr->value_len;
    }
  else if (str != NULL)
    {
      data = str;
      length = p11_kit_space_strlen (str, str_max);
      terminate = 1;
    }
  else if (version != NULL)
    {
      data = buf;
      length = snprintf (buf, sizeof (buf), "%d.%d", (int)version->major,
                         (int)version->minor);
      terminate = 1;
    }

  if (hexify)
    {
      /* terminate is assumed with hexify */
      if (*output_size < length * 3)
        {
          *output_size = length * 3;
          return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
      if (output)
        _gnutls_bin2hex (data, length, output, *output_size, ":");
      *output_size = length * 3;
      return 0;
    }
  else
    {
      if (*output_size < length + terminate)
        {
          *output_size = length + terminate;
          return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
      if (output)
        {
          memcpy (output, data, length);
          if (terminate)
            ((unsigned char*)output)[length] = '\0';
        }
      *output_size = length + terminate;
    }

  return 0;
}

static int init = 0;

static int
initialize_automatic_p11_kit (void)
{
  struct ck_function_list **modules;
  const char *name;
  ck_rv_t rv;
  int i, ret;

  rv = p11_kit_initialize_registered ();
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      _gnutls_debug_log ("Cannot initialize registered module: %s\n",
                         p11_kit_strerror (rv));
      return GNUTLS_E_INTERNAL_ERROR;
    }

  initialized_registered = 1;

  modules = p11_kit_registered_modules ();
  for (i = 0; modules[i] != NULL; i++)
    {
      name = p11_kit_registered_module_to_name (modules[i]);
      ret = pkcs11_add_module (name, modules[i]);
      if (ret != 0)
        {
          gnutls_assert ();
          _gnutls_debug_log ("Cannot add registered module: %s\n", name);
        }
    }

  free (modules);
  return 0;
}

static int
initialize_automatic_legacy (const char *configfile)
{
  FILE *fp;
  char line[512];
  const char *library;
  int ret;

  if (configfile == NULL)
    configfile = "/etc/gnutls/pkcs11.conf";

  fp = fopen (configfile, "r");
  if (fp == NULL)
    {
      if (errno == ENOENT)
        return 0;
      gnutls_assert ();
      _gnutls_debug_log ("Cannot load %s\n", configfile);
      return GNUTLS_E_FILE_ERROR;
    }

  while (fgets (line, sizeof (line), fp) != NULL)
    {
      if (strncmp (line, "load", sizeof ("load") - 1) == 0)
        {
          char *p;
          p = strchr (line, '=');
          if (p == NULL)
            continue;

          library = ++p;

          p = strchr (line, '\n');
          if (p != NULL)
            {
              *p = 0;
            }

          ret = gnutls_pkcs11_add_provider (library, NULL);
          if (ret < 0)
            {
              gnutls_assert ();
              _gnutls_debug_log ("Cannot load provider: %s\n", library);
              continue;
            }
        }
    }

  fclose(fp);
  return 0;
}

/**
 * gnutls_pkcs11_init:
 * @flags: %GNUTLS_PKCS11_FLAG_MANUAL or %GNUTLS_PKCS11_FLAG_AUTO
 * @deprecated_config_file: either NULL or the location of a deprecated
 *     configuration file
 *
 * This function will initialize the PKCS 11 subsystem in gnutls. It will
 * read configuration files if %GNUTLS_PKCS11_FLAG_AUTO is used or allow
 * you to independently load PKCS 11 modules using gnutls_pkcs11_add_provider()
 * if %GNUTLS_PKCS11_FLAG_MANUAL is specified.
 *
 * Using a custom configfile is deprecated and will not be supported in future
 * versions of gnutls.
 *
 * Normally you don't need to call this function since it is being called
 * by gnutls_global_init() using the %GNUTLS_PKCS11_FLAG_AUTO. If you need to
 * call this function, you must call it before gnutls_global_init().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs11_init (unsigned int flags, const char *deprecated_config_file)
{
  int ret = 0;

  if (init != 0)
    {
      init++;
      return 0;
    }
  init++;

  if (flags == GNUTLS_PKCS11_FLAG_AUTO)
    {
      if (deprecated_config_file == NULL)
        ret = initialize_automatic_p11_kit ();

      if (ret == 0)
        ret = initialize_automatic_legacy (deprecated_config_file);
    }

  return ret;
}

/**
 * gnutls_pkcs11_deinit:
 *
 * This function will deinitialize the PKCS 11 subsystem in gnutls.
 *
 **/
void
gnutls_pkcs11_deinit (void)
{
  int i;

  init--;
  if (init > 0)
    return;
  if (init < 0)
    {
      init = 0;
      return;
    }

  for (i = 0; i < active_providers; i++)
    {
      if (providers[i].initialized)
        p11_kit_finalize_module (providers[i].module);
    }
  active_providers = 0;

  if (initialized_registered != 0)
    p11_kit_finalize_registered ();
  initialized_registered = 0;
}

/**
 * gnutls_pkcs11_set_pin_function:
 * @fn: The PIN callback
 * @userdata: data to be supplied to callback
 *
 * This function will set a callback function to be used when a PIN
 * is required for PKCS 11 operations.
 *
 * Callback for PKCS#11 PIN entry.  The callback provides the PIN code
 * to unlock the token with label 'token_label', specified by the URL 
 * 'token_url'.
 *
 * The PIN code, as a NUL-terminated ASCII string, should be copied
 * into the 'pin' buffer (of maximum size pin_max), and
 * return 0 to indicate success. Alternatively, the callback may
 * return a negative gnutls error code to indicate failure and cancel
 * PIN entry (in which case, the contents of the 'pin' parameter are ignored).
 *
 * When a PIN is required, the callback will be invoked repeatedly
 * (and indefinitely) until either the returned PIN code is correct,
 * the callback returns failure, or the token refuses login (e.g. when
 * the token is locked due to too many incorrect PINs!).  For the
 * first such invocation, the 'attempt' counter will have value zero;
 * it will increase by one for each subsequent attempt.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
void
gnutls_pkcs11_set_pin_function (gnutls_pkcs11_pin_callback_t fn,
                                void *userdata)
{
  pin_func = fn;
  pin_data = userdata;
}

/**
 * gnutls_pkcs11_set_token_function:
 * @fn: The token callback
 * @userdata: data to be supplied to callback
 *
 * This function will set a callback function to be used when a token
 * needs to be inserted to continue PKCS 11 operations.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
void
gnutls_pkcs11_set_token_function (gnutls_pkcs11_token_callback_t fn,
                                  void *userdata)
{
  token_func = fn;
  token_data = userdata;
}

int
pkcs11_url_to_info (const char *url, struct p11_kit_uri **info)
{
  int allocated = 0;
  int ret;

  if (*info == NULL)
    {
      *info = p11_kit_uri_new ();
      if (*info == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
      allocated = 1;
    }

  ret = p11_kit_uri_parse (url, P11_KIT_URI_FOR_ANY, *info);
  if (ret < 0)
    {
      if (allocated)
        {
          p11_kit_uri_free (*info);
          *info = NULL;
        }
      gnutls_assert ();
      return ret == P11_KIT_URI_NO_MEMORY ?
          GNUTLS_E_MEMORY_ERROR : GNUTLS_E_PARSING_ERROR;
    }

  return 0;
}

int
pkcs11_info_to_url (struct p11_kit_uri *info,
                    gnutls_pkcs11_url_type_t detailed, char **url)
{
  p11_kit_uri_type_t type = 0;
  int ret;

  switch (detailed)
    {
      case GNUTLS_PKCS11_URL_GENERIC:
        type = P11_KIT_URI_FOR_OBJECT_ON_TOKEN;
        break;
      case GNUTLS_PKCS11_URL_LIB:
        type = P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE;
        break;
      case GNUTLS_PKCS11_URL_LIB_VERSION:
        type = P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE | P11_KIT_URI_FOR_MODULE_WITH_VERSION;
        break;
    }

  ret = p11_kit_uri_format (info, type, url);
  if (ret < 0)
    {
      gnutls_assert ();
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
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs11_obj_init (gnutls_pkcs11_obj_t * obj)
{
  *obj = gnutls_calloc (1, sizeof (struct gnutls_pkcs11_obj_st));
  if (*obj == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  (*obj)->info = p11_kit_uri_new ();
  if ((*obj)->info == NULL)
    {
      free (*obj);
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  return 0;
}

/**
 * gnutls_pkcs11_obj_deinit:
 * @obj: The structure to be initialized
 *
 * This function will deinitialize a certificate structure.
 **/
void
gnutls_pkcs11_obj_deinit (gnutls_pkcs11_obj_t obj)
{
  _gnutls_free_datum (&obj->raw);
  p11_kit_uri_free (obj->info);
  free (obj);
}

/**
 * gnutls_pkcs11_obj_export:
 * @obj: Holds the object
 * @output_data: will contain a certificate PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the pkcs11 object data. It is normal
 * for PKCS #11 data to be inaccesible and in that case %GNUTLS_E_INVALID_REQUEST
 * will be returned.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN CERTIFICATE".
 *
 * Return value: In case of failure a negative value will be
 *   returned, and 0 on success.
 **/
int
gnutls_pkcs11_obj_export (gnutls_pkcs11_obj_t obj,
                          void *output_data, size_t * output_data_size)
{
  if (obj == NULL || obj->raw.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (output_data == NULL || *output_data_size < obj->raw.size)
    {
      *output_data_size = obj->raw.size;
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }
  *output_data_size = obj->raw.size;

  memcpy (output_data, obj->raw.data, obj->raw.size);
  return 0;
}

int
pkcs11_find_object (struct ck_function_list ** _module,
                    ck_session_handle_t * _pks,
                    ck_object_handle_t * _obj,
                    struct p11_kit_uri *info, unsigned int flags)
{
  int ret;
  struct ck_function_list *module;
  ck_session_handle_t pks;
  ck_object_handle_t obj;
  struct ck_attribute *attrs;
  unsigned long attr_count;
  unsigned long count;
  ck_rv_t rv;

  ret = pkcs11_open_session (&module, &pks, info, flags & SESSION_LOGIN);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  attrs = p11_kit_uri_get_attributes (info, &attr_count);
  rv = pkcs11_find_objects_init (module, pks, attrs, attr_count);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      _gnutls_debug_log ("pk11: FindObjectsInit failed.\n");
      ret = pkcs11_rv_to_err (rv);
      goto fail;
    }

  if (pkcs11_find_objects (module, pks, &obj, 1, &count) == CKR_OK && count == 1)
    {
      *_obj = obj;
      *_pks = pks;
      *_module = module;
      pkcs11_find_objects_final (module, pks);
      return 0;
    }

  ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  pkcs11_find_objects_final (module, pks);
fail:
  pkcs11_close_session (module, pks);

  return ret;
}

int
pkcs11_find_slot (struct ck_function_list ** module, ck_slot_id_t * slot,
                  struct p11_kit_uri *info, struct token_info *_tinfo)
{
  int x, z;

  for (x = 0; x < active_providers; x++)
    {
      for (z = 0; z < providers[x].nslots; z++)
        {
          struct token_info tinfo;

          if (pkcs11_get_token_info
              (providers[x].module, providers[x].slots[z],
               &tinfo.tinfo) != CKR_OK)
            {
              continue;
            }
          tinfo.sid = providers[x].slots[z];
          tinfo.prov = &providers[x];

          if (pkcs11_get_slot_info
              (providers[x].module, providers[x].slots[z],
               &tinfo.sinfo) != CKR_OK)
            {
              continue;
            }

          if (!p11_kit_uri_match_token_info (info, &tinfo.tinfo) ||
              !p11_kit_uri_match_module_info (info, &providers[x].info))
            {
              continue;
            }

          /* ok found */
          *module = providers[x].module;
          *slot = providers[x].slots[z];

          if (_tinfo != NULL)
            memcpy (_tinfo, &tinfo, sizeof (tinfo));

          return 0;
        }
    }

  gnutls_assert ();
  return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
}

int
pkcs11_open_session (struct ck_function_list ** _module, ck_session_handle_t * _pks,
                     struct p11_kit_uri *info, unsigned int flags)
{
  ck_rv_t rv;
  int ret;
  ck_session_handle_t pks = 0;
  struct ck_function_list *module;
  ck_slot_id_t slot;
  struct token_info tinfo;

  ret = pkcs11_find_slot (&module, &slot, info, &tinfo);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  rv = (module)->C_OpenSession (slot,
                              ((flags & SESSION_WRITE)
                               ? CKF_RW_SESSION : 0) |
                              CKF_SERIAL_SESSION, NULL, NULL, &pks);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      return pkcs11_rv_to_err (rv);
    }

  if (flags & SESSION_LOGIN)
    {
      ret = pkcs11_login (module, pks, &tinfo, info, (flags & SESSION_SO) ? 1 : 0);
      if (ret < 0)
        {
          gnutls_assert ();
          pkcs11_close_session (module, pks);
          return ret;
        }
    }

  /* ok found */
  *_pks = pks;
  *_module = module;
  return 0;
}


int
_pkcs11_traverse_tokens (find_func_t find_func, void *input,
                         struct p11_kit_uri *info, unsigned int flags)
{
  ck_rv_t rv;
  int found = 0, x, z, ret;
  ck_session_handle_t pks = 0;
  struct ck_function_list *module = NULL;

  for (x = 0; x < active_providers; x++)
    {
      module = providers[x].module;
      for (z = 0; z < providers[x].nslots; z++)
        {
          struct token_info tinfo;

          ret = GNUTLS_E_PKCS11_ERROR;

          if (pkcs11_get_token_info (module, providers[x].slots[z],
               &tinfo.tinfo) != CKR_OK)
            {
              continue;
            }
          tinfo.sid = providers[x].slots[z];
          tinfo.prov = &providers[x];

          if (pkcs11_get_slot_info (module, providers[x].slots[z],
               &tinfo.sinfo) != CKR_OK)
            {
              continue;
            }

          rv = (module)->C_OpenSession (providers[x].slots[z],
                                        ((flags & SESSION_WRITE)
                                          ? CKF_RW_SESSION : 0) |
                                        CKF_SERIAL_SESSION, NULL, NULL, &pks);
          if (rv != CKR_OK)
            {
              continue;
            }

          if (flags & SESSION_LOGIN)
            {
              ret = pkcs11_login (module, pks, &tinfo, info, (flags & SESSION_SO) ? 1 : 0);
              if (ret < 0)
                {
                  gnutls_assert ();
                  return ret;
                }
            }

          ret = find_func (module, pks, &tinfo, &providers[x].info, input);

          if (ret == 0)
            {
              found = 1;
              goto finish;
            }
          else
            {
              pkcs11_close_session (module, pks);
              pks = 0;
            }
        }
    }

finish:
  /* final call */

  if (found == 0)
    {
      if (module)
        ret = find_func (module, pks, NULL, NULL, input);
      else
        ret = gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
    }
  else
    {
      ret = 0;
    }

  if (pks != 0 && module != NULL)
    {
      pkcs11_close_session (module, pks);
    }

  return ret;
}

/* imports a raw certificate from a token to a pkcs11_obj_t structure.
 */
static int
pkcs11_obj_import (ck_object_class_t class, gnutls_pkcs11_obj_t obj,
                   const gnutls_datum_t * data,
                   const gnutls_datum_t * id,
                   const gnutls_datum_t * label,
                   struct ck_token_info *tinfo, struct ck_info *lib_info)
{
  struct ck_attribute attr;
  int ret;

  switch (class)
    {
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
      break;
    }

  attr.type = CKA_CLASS;
  attr.value = &class;
  attr.value_len = sizeof (class);
  ret = p11_kit_uri_set_attribute (obj->info, &attr);
  if (ret < 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  if (data && data->data)
    {
      ret = _gnutls_set_datum (&obj->raw, data->data, data->size);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }

  /* copy the token and library info into the uri */
  memcpy (p11_kit_uri_get_token_info (obj->info), tinfo, sizeof (struct ck_token_info));
  memcpy (p11_kit_uri_get_module_info (obj->info), lib_info, sizeof (struct ck_info));

  if (label && label->data)
    {
      attr.type = CKA_LABEL;
      attr.value = label->data;
      attr.value_len = label->size;
      ret = p11_kit_uri_set_attribute (obj->info, &attr);
      if (ret < 0)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
    }

  if (id && id->data)
    {
      attr.type = CKA_ID;
      attr.value = id->data;
      attr.value_len = id->size;
      ret = p11_kit_uri_set_attribute (obj->info, &attr);
      if (ret < 0)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
    }

  return 0;
}

static int
pkcs11_obj_import_pubkey (struct ck_function_list *module,
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
  opaque tmp1[2048];
  opaque tmp2[2048];
  int ret;
  ck_bool_t tval;

  a[0].type = CKA_KEY_TYPE;
  a[0].value = &key_type;
  a[0].value_len = sizeof (key_type);

  if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
    {
      switch (key_type)
        {
        case CKK_RSA:
          a[0].type = CKA_MODULUS;
          a[0].value = tmp1;
          a[0].value_len = sizeof (tmp1);
          a[1].type = CKA_PUBLIC_EXPONENT;
          a[1].value = tmp2;
          a[1].value_len = sizeof (tmp2);

          if (pkcs11_get_attribute_value (module, pks, obj, a, 2) == CKR_OK)
            {

              ret =
                _gnutls_set_datum (&crt->pubkey[0],
                                   a[0].value, a[0].value_len);

              if (ret >= 0)
                ret =
                  _gnutls_set_datum (&crt->pubkey
                                     [1], a[1].value, a[1].value_len);

              if (ret < 0)
                {
                  gnutls_assert ();
                  _gnutls_free_datum (&crt->pubkey[1]);
                  _gnutls_free_datum (&crt->pubkey[0]);
                  return GNUTLS_E_MEMORY_ERROR;
                }
            }
          else
            {
              gnutls_assert ();
              return GNUTLS_E_PKCS11_ERROR;
            }
          crt->pk_algorithm = GNUTLS_PK_RSA;
          break;
        case CKK_DSA:
          a[0].type = CKA_PRIME;
          a[0].value = tmp1;
          a[0].value_len = sizeof (tmp1);
          a[1].type = CKA_SUBPRIME;
          a[1].value = tmp2;
          a[1].value_len = sizeof (tmp2);

          if (pkcs11_get_attribute_value (module, pks, obj, a, 2) == CKR_OK)
            {
              ret =
                _gnutls_set_datum (&crt->pubkey[0],
                                   a[0].value, a[0].value_len);

              if (ret >= 0)
                ret =
                  _gnutls_set_datum (&crt->pubkey
                                     [1], a[1].value, a[1].value_len);

              if (ret < 0)
                {
                  gnutls_assert ();
                  _gnutls_free_datum (&crt->pubkey[1]);
                  _gnutls_free_datum (&crt->pubkey[0]);
                  return GNUTLS_E_MEMORY_ERROR;
                }
            }
          else
            {
              gnutls_assert ();
              return GNUTLS_E_PKCS11_ERROR;
            }

          a[0].type = CKA_BASE;
          a[0].value = tmp1;
          a[0].value_len = sizeof (tmp1);
          a[1].type = CKA_VALUE;
          a[1].value = tmp2;
          a[1].value_len = sizeof (tmp2);

          if (pkcs11_get_attribute_value (module, pks, obj, a, 2) == CKR_OK)
            {
              ret =
                _gnutls_set_datum (&crt->pubkey[2],
                                   a[0].value, a[0].value_len);

              if (ret >= 0)
                ret =
                  _gnutls_set_datum (&crt->pubkey
                                     [3], a[1].value, a[1].value_len);

              if (ret < 0)
                {
                  gnutls_assert ();
                  _gnutls_free_datum (&crt->pubkey[0]);
                  _gnutls_free_datum (&crt->pubkey[1]);
                  _gnutls_free_datum (&crt->pubkey[2]);
                  _gnutls_free_datum (&crt->pubkey[3]);
                  return GNUTLS_E_MEMORY_ERROR;
                }
            }
          else
            {
              gnutls_assert ();
              return GNUTLS_E_PKCS11_ERROR;
            }
          crt->pk_algorithm = GNUTLS_PK_RSA;
          break;
        default:
          gnutls_assert ();
          return GNUTLS_E_UNIMPLEMENTED_FEATURE;
        }
    }

  /* read key usage flags */
  a[0].type = CKA_ENCRYPT;
  a[0].value = &tval;
  a[0].value_len = sizeof (tval);

  if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
    {
      if (tval != 0)
        {
          crt->key_usage |= GNUTLS_KEY_DATA_ENCIPHERMENT;
        }
    }

  a[0].type = CKA_VERIFY;
  a[0].value = &tval;
  a[0].value_len = sizeof (tval);

  if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
    {
      if (tval != 0)
        {
          crt->key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE |
            GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN
            | GNUTLS_KEY_NON_REPUDIATION;
        }
    }

  a[0].type = CKA_VERIFY_RECOVER;
  a[0].value = &tval;
  a[0].value_len = sizeof (tval);

  if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
    {
      if (tval != 0)
        {
          crt->key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE |
            GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN
            | GNUTLS_KEY_NON_REPUDIATION;
        }
    }

  a[0].type = CKA_DERIVE;
  a[0].value = &tval;
  a[0].value_len = sizeof (tval);

  if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
    {
      if (tval != 0)
        {
          crt->key_usage |= GNUTLS_KEY_KEY_AGREEMENT;
        }
    }

  a[0].type = CKA_WRAP;
  a[0].value = &tval;
  a[0].value_len = sizeof (tval);

  if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
    {
      if (tval != 0)
        {
          crt->key_usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
        }
    }

  return pkcs11_obj_import (CKO_PUBLIC_KEY, crt, NULL, id, label,
                            tinfo, lib_info);
}

static int
find_obj_url (struct ck_function_list *module, ck_session_handle_t pks,
              struct token_info *info, struct ck_info *lib_info, void *input)
{
  struct url_find_data_st *find_data = input;
  struct ck_attribute a[4];
  struct ck_attribute *attr;
  ck_object_class_t class = -1;
  ck_certificate_type_t type = -1;
  ck_rv_t rv;
  ck_object_handle_t obj;
  unsigned long count, a_vals;
  int found = 0, ret;
  opaque *cert_data = NULL;
  char label_tmp[PKCS11_LABEL_SIZE];

  if (info == NULL)
    {                           /* we don't support multiple calls */
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  /* do not bother reading the token if basic fields do not match
   */
  if (!p11_kit_uri_match_token_info (find_data->crt->info, &info->tinfo) ||
      !p11_kit_uri_match_module_info (find_data->crt->info, lib_info))
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  attr = p11_kit_uri_get_attribute (find_data->crt->info, CKA_ID);
  if (attr == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* search the token for the id */

  cert_data = gnutls_malloc (MAX_CERT_SIZE);
  if (cert_data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* Find objects with given class and type */
  memcpy (a, attr, sizeof (struct ck_attribute));
  a_vals = 1;

  attr = p11_kit_uri_get_attribute (find_data->crt->info, CKA_CLASS);
  if (attr)
    {
      if(attr->value && attr->value_len == sizeof (ck_object_class_t))
        class = *((ck_object_class_t*)attr->value);
      if (class == CKO_CERTIFICATE)
        type = CKC_X_509;
      memcpy (a + a_vals, attr, sizeof (struct ck_attribute));
      a_vals++;
    }

  if (type != -1)
    {
      a[a_vals].type = CKA_CERTIFICATE_TYPE;
      a[a_vals].value = &type;
      a[a_vals].value_len = sizeof type;
      a_vals++;
    }

  rv = pkcs11_find_objects_init (module, pks, a, a_vals);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      _gnutls_debug_log ("pk11: FindObjectsInit failed.\n");
      ret = pkcs11_rv_to_err (rv);
      goto cleanup;
    }

  while (pkcs11_find_objects (module, pks, &obj, 1, &count) == CKR_OK && count == 1)
    {

      a[0].type = CKA_VALUE;
      a[0].value = cert_data;
      a[0].value_len = MAX_CERT_SIZE;
      a[1].type = CKA_LABEL;
      a[1].value = label_tmp;
      a[1].value_len = sizeof (label_tmp);

      if (pkcs11_get_attribute_value (module, pks, obj, a, 2) == CKR_OK)
        {
          gnutls_datum_t id;
          gnutls_datum_t data = { a[0].value, a[0].value_len };
          gnutls_datum_t label = { a[1].value, a[1].value_len };

          attr = p11_kit_uri_get_attribute (find_data->crt->info, CKA_ID);
          id.data = attr->value;
          id.size = attr->value_len;

          if (class == CKO_PUBLIC_KEY)
            {
              ret =
                pkcs11_obj_import_pubkey (module, pks, obj,
                                          find_data->crt,
                                          &id, &label,
                                          &info->tinfo, lib_info);
            }
          else
            {
              ret =
                pkcs11_obj_import (class,
                                   find_data->crt,
                                   &data, &id, &label,
                                   &info->tinfo, lib_info);
            }
          if (ret < 0)
            {
              gnutls_assert ();
              goto cleanup;
            }

          found = 1;
          break;
        }
      else
        {
          _gnutls_debug_log ("pk11: Skipped cert, missing attrs.\n");
        }
    }

  if (found == 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }
  else
    {
      ret = 0;
    }

cleanup:
  gnutls_free (cert_data);
  pkcs11_find_objects_final (module, pks);

  return ret;
}

unsigned int
pkcs11_obj_flags_to_int (unsigned int flags)
{
  unsigned int ret_flags = 0;

  if (flags & GNUTLS_PKCS11_OBJ_FLAG_LOGIN)
    ret_flags |= SESSION_LOGIN;
  if (flags & GNUTLS_PKCS11_OBJ_FLAG_LOGIN_SO)
    ret_flags |= SESSION_LOGIN|SESSION_SO;

  return ret_flags;
}

/**
 * gnutls_pkcs11_privkey_import_url:
 * @cert: The structure to store the parsed certificate
 * @url: a PKCS 11 url identifying the key
 * @flags: One of GNUTLS_PKCS11_OBJ_* flags
 *
 * This function will "import" a PKCS 11 URL identifying a certificate
 * key to the #gnutls_pkcs11_obj_t structure. This does not involve any
 * parsing (such as X.509 or OpenPGP) since the #gnutls_pkcs11_obj_t is
 * format agnostic. Only data are transferred.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs11_obj_import_url (gnutls_pkcs11_obj_t cert, const char *url,
                              unsigned int flags)
{
  int ret;
  struct url_find_data_st find_data;

  /* fill in the find data structure */
  find_data.crt = cert;

  ret = pkcs11_url_to_info (url, &cert->info);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    _pkcs11_traverse_tokens (find_obj_url, &find_data, cert->info,
                             pkcs11_obj_flags_to_int (flags));

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

struct token_num
{
  struct p11_kit_uri *info;
  unsigned int seq;             /* which one we are looking for */
  unsigned int current;         /* which one are we now */
};

static int
find_token_num (struct ck_function_list *module,
                ck_session_handle_t pks,
                struct token_info *tinfo,
                struct ck_info *lib_info, void *input)
{
  struct token_num *find_data = input;

  if (tinfo == NULL)
    {                           /* we don't support multiple calls */
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (find_data->current == find_data->seq)
    {
      memcpy (p11_kit_uri_get_token_info (find_data->info), &tinfo->tinfo, sizeof (struct ck_token_info));
      memcpy (p11_kit_uri_get_module_info (find_data->info), lib_info, sizeof (struct ck_info));
      return 0;
    }

  find_data->current++;
  /* search the token for the id */


  return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE; /* non zero is enough */
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
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the sequence number exceeds the available tokens, otherwise a negative error value.
 **/

int
gnutls_pkcs11_token_get_url (unsigned int seq,
                             gnutls_pkcs11_url_type_t detailed, char **url)
{
  int ret;
  struct token_num tn;

  memset (&tn, 0, sizeof (tn));
  tn.seq = seq;
  tn.info = p11_kit_uri_new ();

  ret = _pkcs11_traverse_tokens (find_token_num, &tn, NULL, 0);
  if (ret < 0)
    {
      p11_kit_uri_free (tn.info);
      gnutls_assert ();
      return ret;
    }

  ret = pkcs11_info_to_url (tn.info, detailed, url);
  p11_kit_uri_free (tn.info);

  if (ret < 0)
    {
      gnutls_assert ();
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
 * as the label, id as well as token information where the key is stored.
 *
 * Returns: zero on success or a negative value on error.
 **/
int
gnutls_pkcs11_token_get_info (const char *url,
                              gnutls_pkcs11_token_info_t ttype,
                              void *output, size_t * output_size)
{
  struct p11_kit_uri *info = NULL;
  const char *str;
  size_t str_max;
  size_t len;
  int ret;

  ret = pkcs11_url_to_info (url, &info);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  switch (ttype)
    {
    case GNUTLS_PKCS11_TOKEN_LABEL:
      str = p11_kit_uri_get_token_info (info)->label;
      str_max = 32;
      break;
    case GNUTLS_PKCS11_TOKEN_SERIAL:
      str = p11_kit_uri_get_token_info (info)->serial_number;
      str_max = 16;
      break;
    case GNUTLS_PKCS11_TOKEN_MANUFACTURER:
      str = p11_kit_uri_get_token_info (info)->manufacturer_id;
      str_max = 32;
      break;
    case GNUTLS_PKCS11_TOKEN_MODEL:
      str = p11_kit_uri_get_token_info (info)->model;
      str_max = 16;
      break;
    default:
      p11_kit_uri_free (info);
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = p11_kit_space_strlen (str, str_max);

  if (len + 1 > *output_size)
    {
      *output_size = len + 1;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  memcpy (output, str, len);
  ((char*)output)[len] = '\0';

  *output_size = len;

  p11_kit_uri_free (info);
  return 0;
}

/**
 * gnutls_pkcs11_obj_export_url:
 * @obj: Holds the PKCS 11 certificate
 * @detailed: non zero if a detailed URL is required
 * @url: will contain an allocated url
 *
 * This function will export a URL identifying the given certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs11_obj_export_url (gnutls_pkcs11_obj_t obj,
                              gnutls_pkcs11_url_type_t detailed, char **url)
{
  int ret;

  ret = pkcs11_info_to_url (obj->info, detailed, url);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

/**
 * gnutls_pkcs11_obj_get_type:
 * @certificate: Holds the PKCS 11 certificate
 *
 * This function will return the type of the certificate being
 * stored in the structure.
 *
 * Returns: The type of the certificate.
 **/
gnutls_pkcs11_obj_type_t
gnutls_pkcs11_obj_get_type (gnutls_pkcs11_obj_t obj)
{
  return obj->type;
}

struct pkey_list
{
  gnutls_buffer_st *key_ids;
  size_t key_ids_size;
};


static int
retrieve_pin_for_pinfile (const char *pinfile, struct ck_token_info *token_info,
                          int attempts, ck_user_type_t user_type, struct p11_kit_pin **pin)
{
  unsigned int flags = 0;
  struct p11_kit_uri *token_uri;
  struct p11_kit_pin *result;
  char *label;

  label = p11_kit_space_strdup (token_info->label, sizeof (token_info->label));
  if (label == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  token_uri = p11_kit_uri_new ();
  if (token_uri == NULL)
    {
      free (label);
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  memcpy (p11_kit_uri_get_token_info (token_uri), token_info,
          sizeof (struct ck_token_info));

  if (attempts)
    flags |= P11_KIT_PIN_FLAGS_RETRY;
  if (user_type == CKU_USER)
    {
      flags |= P11_KIT_PIN_FLAGS_USER_LOGIN;
      if (token_info->flags & CKF_USER_PIN_COUNT_LOW)
        flags |= P11_KIT_PIN_FLAGS_MANY_TRIES;
      if (token_info->flags & CKF_USER_PIN_FINAL_TRY)
        flags |= P11_KIT_PIN_FLAGS_FINAL_TRY;
    }
  else if (user_type == CKU_SO)
    {
      flags |= P11_KIT_PIN_FLAGS_SO_LOGIN;
      if (token_info->flags & CKF_SO_PIN_COUNT_LOW)
        flags |= P11_KIT_PIN_FLAGS_MANY_TRIES;
      if (token_info->flags & CKF_SO_PIN_FINAL_TRY)
        flags |= P11_KIT_PIN_FLAGS_FINAL_TRY;
    }
  else if (user_type == CKU_CONTEXT_SPECIFIC)
    {
      flags |= P11_KIT_PIN_FLAGS_CONTEXT_LOGIN;
    }

  result = p11_kit_pin_request (pinfile, token_uri, label, flags);
  p11_kit_uri_free (token_uri);
  free (label);

  if (result == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_PKCS11_PIN_ERROR;
    }

  *pin = result;
  return 0;
}

static int
retrieve_pin_for_callback (struct ck_token_info *token_info, int attempts,
                           ck_user_type_t user_type, struct p11_kit_pin **pin)
{
  char pin_value[GNUTLS_PKCS11_MAX_PIN_LEN];
  unsigned int flags = 0;
  char *token_str;
  char *label;
  struct p11_kit_uri *token_uri;
  int ret = 0;

  label = p11_kit_space_strdup (token_info->label, sizeof (token_info->label));
  if (label == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  token_uri = p11_kit_uri_new ();
  if (token_uri == NULL)
    {
      free (label);
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  memcpy (p11_kit_uri_get_token_info (token_uri), token_info,
          sizeof (struct ck_token_info));
  ret = pkcs11_info_to_url (token_uri, 1, &token_str);
  p11_kit_uri_free (token_uri);

  if (ret < 0)
    {
      free (label);
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  if (user_type == CKU_USER)
    {
      flags |= GNUTLS_PKCS11_PIN_USER;
      if (token_info->flags & CKF_USER_PIN_COUNT_LOW)
        flags |= GNUTLS_PKCS11_PIN_COUNT_LOW;
      if (token_info->flags & CKF_USER_PIN_FINAL_TRY)
        flags |= GNUTLS_PKCS11_PIN_FINAL_TRY;
    }
  else if (user_type == CKU_SO)
    {
      flags |= GNUTLS_PKCS11_PIN_SO;
      if (token_info->flags & CKF_SO_PIN_COUNT_LOW)
        flags |= GNUTLS_PKCS11_PIN_COUNT_LOW;
      if (token_info->flags & CKF_SO_PIN_FINAL_TRY)
        flags |= GNUTLS_PKCS11_PIN_FINAL_TRY;
    }

  if (attempts > 0)
    flags |= GNUTLS_PKCS11_PIN_WRONG;

  ret = pin_func (pin_data, attempts, (char*)token_str, label,
                  flags, pin_value, GNUTLS_PKCS11_MAX_PIN_LEN);
  free (token_str);
  free (label);

  if (ret < 0)
    return gnutls_assert_val(GNUTLS_E_PKCS11_PIN_ERROR);

  *pin = p11_kit_pin_new_for_string (pin_value);
  
  if (*pin == NULL)
    return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

  return 0;
}

static int
retrieve_pin (struct p11_kit_uri *info, struct ck_token_info *token_info,
              int attempts, ck_user_type_t user_type, struct p11_kit_pin **pin)
{
  const char *pinfile;

  *pin = NULL;

  /* Check if a pinfile is specified, and use that if possible */
  pinfile = p11_kit_uri_get_pinfile (info);
  if (pinfile != NULL)
    {
      _gnutls_debug_log("pk11: Using pinfile to retrieve PIN\n");
      return retrieve_pin_for_pinfile (pinfile, token_info, attempts, user_type, pin);
    }

  /* The global gnutls pin callback */
  else if (pin_func)
    return retrieve_pin_for_callback (token_info, attempts, user_type, pin);

  /* Otherwise, PIN entry is necessary for login, so fail if there's
   * no callback. */
  else
    {
      gnutls_assert ();
      _gnutls_debug_log ("pk11: No pin callback but login required.\n");
      return GNUTLS_E_PKCS11_ERROR;
    }
}

int
pkcs11_login (struct ck_function_list * module, ck_session_handle_t pks,
              const struct token_info *tokinfo, struct p11_kit_uri *info, int so)
{
  struct ck_session_info session_info;
  int attempt = 0, ret;
  ck_user_type_t user_type;
  ck_rv_t rv;

  user_type = (so == 0) ? CKU_USER : CKU_SO;
  if (so == 0 && (tokinfo->tinfo.flags & CKF_LOGIN_REQUIRED) == 0)
    {
      gnutls_assert ();
      _gnutls_debug_log ("pk11: No login required.\n");
      return 0;
    }

  /* For a token with a "protected" (out-of-band) authentication
   * path, calling login with a NULL username is all that is
   * required. */
  if (tokinfo->tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
    {
      rv = (module)->C_Login (pks, (so == 0) ? CKU_USER : CKU_SO, NULL, 0);
      if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN)
        {
          return 0;
        }
      else
        {
          gnutls_assert ();
          _gnutls_debug_log ("pk11: Protected login failed.\n");
          ret = GNUTLS_E_PKCS11_ERROR;
          goto cleanup;
        }
    }

  do
    {
      struct p11_kit_pin *pin;
      struct ck_token_info tinfo;

      memcpy (&tinfo, &tokinfo->tinfo, sizeof(tinfo));

      /* Check whether the session is already logged in, and if so, just skip */
      rv = (module)->C_GetSessionInfo (pks, &session_info);
      if (rv == CKR_OK && (session_info.state == CKS_RO_USER_FUNCTIONS ||
                           session_info.state == CKS_RW_USER_FUNCTIONS))
        {
          ret = 0;
          goto cleanup;
        }

      /* If login has been attempted once already, check the token
       * status again, the flags might change. */
      if (attempt)
        {
          if (pkcs11_get_token_info
              (tokinfo->prov->module, tokinfo->sid, &tinfo) != CKR_OK)
            {
              gnutls_assert ();
              _gnutls_debug_log ("pk11: GetTokenInfo failed\n");
              ret = GNUTLS_E_PKCS11_ERROR;
              goto cleanup;
            }
        }

      ret = retrieve_pin (info, &tinfo, attempt++, user_type, &pin);
      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }

      rv = (module)->C_Login (pks, user_type,
                              (unsigned char *)p11_kit_pin_get_value (pin, NULL),
                              p11_kit_pin_get_length (pin));

      p11_kit_pin_unref (pin);
    }
  while (rv == CKR_PIN_INCORRECT);

  _gnutls_debug_log ("pk11: Login result = %lu\n", rv);


  ret = (rv == CKR_OK
         || rv == CKR_USER_ALREADY_LOGGED_IN) ? 0 : pkcs11_rv_to_err (rv);

cleanup:
  return ret;
}

int
pkcs11_call_token_func (struct p11_kit_uri *info, const unsigned retry)
{
  struct ck_token_info *tinfo;
  char *label;
  int ret = 0;

  tinfo = p11_kit_uri_get_token_info (info);
  label = p11_kit_space_strdup (tinfo->label, sizeof (tinfo->label));
  ret = (token_func) (token_data, label, retry);
  free (label);

  return ret;
}


static int
find_privkeys (struct ck_function_list *module, ck_session_handle_t pks,
               struct token_info *info, struct pkey_list *list)
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

  rv = pkcs11_find_objects_init (module, pks, a, 1);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      return pkcs11_rv_to_err (rv);
    }

  list->key_ids_size = 0;
  while (pkcs11_find_objects (module, pks, &obj, 1, &count) == CKR_OK && count == 1)
    {
      list->key_ids_size++;
    }

  pkcs11_find_objects_final (module, pks);

  if (list->key_ids_size == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  list->key_ids =
    gnutls_malloc (sizeof (gnutls_buffer_st) * list->key_ids_size);
  if (list->key_ids == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* actual search */
  a[0].type = CKA_CLASS;
  a[0].value = &class;
  a[0].value_len = sizeof class;

  rv = pkcs11_find_objects_init (module, pks, a, 1);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      return pkcs11_rv_to_err (rv);
    }

  current = 0;
  while (pkcs11_find_objects (module, pks, &obj, 1, &count) == CKR_OK && count == 1)
    {

      a[0].type = CKA_ID;
      a[0].value = certid_tmp;
      a[0].value_len = sizeof (certid_tmp);

      _gnutls_buffer_init (&list->key_ids[current]);

      if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
        {
          _gnutls_buffer_append_data (&list->key_ids[current],
                                      a[0].value, a[0].value_len);
          current++;
        }

      if (current > list->key_ids_size)
        break;
    }

  pkcs11_find_objects_final (module, pks);

  list->key_ids_size = current - 1;

  return 0;
}

/* Recover certificate list from tokens */


static int
find_objs (struct ck_function_list * module, ck_session_handle_t pks,
           struct token_info *info, struct ck_info *lib_info, void *input)
{
  struct crt_find_data_st *find_data = input;
  struct ck_attribute a[4];
  struct ck_attribute *attr;
  ck_object_class_t class = -1;
  ck_certificate_type_t type = -1;
  unsigned int trusted;
  ck_rv_t rv;
  ck_object_handle_t obj;
  unsigned long count;
  opaque *cert_data;
  char certid_tmp[PKCS11_ID_SIZE];
  char label_tmp[PKCS11_LABEL_SIZE];
  int ret, i;
  struct pkey_list plist;       /* private key holder */
  int tot_values = 0;

  if (info == NULL)
    {                           /* final call */
      if (find_data->current <= *find_data->n_list)
        ret = 0;
      else
        ret = GNUTLS_E_SHORT_MEMORY_BUFFER;

      *find_data->n_list = find_data->current;

      return ret;
    }

  /* do not bother reading the token if basic fields do not match
   */
  if (!p11_kit_uri_match_token_info (find_data->info, &info->tinfo) ||
      !p11_kit_uri_match_module_info (find_data->info, lib_info))
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  memset (&plist, 0, sizeof (plist));

  if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY)
    {
      ret = find_privkeys (module, pks, info, &plist);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      if (plist.key_ids_size == 0)
        {
          gnutls_assert ();
          return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
        }
    }

  cert_data = gnutls_malloc (MAX_CERT_SIZE);
  if (cert_data == NULL)
    {
      gnutls_assert ();
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

    }
  else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED)
    {
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

    }
  else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_PUBKEY)
    {
      class = CKO_PUBLIC_KEY;

      a[tot_values].type = CKA_CLASS;
      a[tot_values].value = &class;
      a[tot_values].value_len = sizeof class;
      tot_values++;
    }
  else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_PRIVKEY)
    {
      class = CKO_PRIVATE_KEY;

      a[tot_values].type = CKA_CLASS;
      a[tot_values].value = &class;
      a[tot_values].value_len = sizeof class;
      tot_values++;
    }
  else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_ALL)
    {
      if (class != -1)
        {
          a[tot_values].type = CKA_CLASS;
          a[tot_values].value = &class;
          a[tot_values].value_len = sizeof class;
          tot_values++;
        }
      if (type != -1)
        {
          a[tot_values].type = CKA_CERTIFICATE_TYPE;
          a[tot_values].value = &type;
          a[tot_values].value_len = sizeof type;
          tot_values++;
        }
    }
  else
    {
      gnutls_assert ();
      ret = GNUTLS_E_INVALID_REQUEST;
      goto fail;
    }

  attr = p11_kit_uri_get_attribute (find_data->info, CKA_ID);
  if (attr != NULL)
    {
      memcpy (a + tot_values, attr, sizeof (struct ck_attribute));
      tot_values++;
    }

  rv = pkcs11_find_objects_init (module, pks, a, tot_values);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      _gnutls_debug_log ("pk11: FindObjectsInit failed.\n");
      return pkcs11_rv_to_err (rv);
    }

  while (pkcs11_find_objects (module, pks, &obj, 1, &count) == CKR_OK && count == 1)
    {
      gnutls_datum_t label, id, value;

      a[0].type = CKA_LABEL;
      a[0].value = label_tmp;
      a[0].value_len = sizeof label_tmp;

      if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
        {
          label.data = a[0].value;
          label.size = a[0].value_len;
        }
      else
        {
          label.data = NULL;
          label.size = 0;
        }

      a[0].type = CKA_ID;
      a[0].value = certid_tmp;
      a[0].value_len = sizeof certid_tmp;

      if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
        {
          id.data = a[0].value;
          id.size = a[0].value_len;
        }
      else
        {
          id.data = NULL;
          id.size = 0;
        }

      a[0].type = CKA_VALUE;
      a[0].value = cert_data;
      a[0].value_len = MAX_CERT_SIZE;
      if (pkcs11_get_attribute_value (module, pks, obj, a, 1) == CKR_OK)
        {
          value.data = a[0].value;
          value.size = a[0].value_len;
        }
      else
        {
          value.data = NULL;
          value.size = 0;
        }

      if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_ALL)
        {
          a[0].type = CKA_CLASS;
          a[0].value = &class;
          a[0].value_len = sizeof class;

          pkcs11_get_attribute_value (module, pks, obj, a, 1);
        }

      if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY)
        {
          for (i = 0; i < plist.key_ids_size; i++)
            {
              if (plist.key_ids[i].length !=
                  a[1].value_len
                  || memcmp (plist.key_ids[i].data,
                             a[1].value, a[1].value_len) != 0)
                {
                  /* not found */
                  continue;
                }
            }
        }

      if (find_data->current < *find_data->n_list)
        {
          ret =
            gnutls_pkcs11_obj_init (&find_data->p_list[find_data->current]);
          if (ret < 0)
            {
              gnutls_assert ();
              goto fail;
            }

          if (class == CKO_PUBLIC_KEY)
            {
              ret =
                pkcs11_obj_import_pubkey (module, pks, obj,
                                          find_data->p_list
                                          [find_data->current],
                                          &id, &label,
                                          &info->tinfo, lib_info);
            }
          else
            {
              ret =
                pkcs11_obj_import (class,
                                   find_data->p_list
                                   [find_data->current],
                                   &value, &id, &label,
                                   &info->tinfo, lib_info);
            }
          if (ret < 0)
            {
              gnutls_assert ();
              goto fail;
            }
        }

      find_data->current++;

    }

  gnutls_free (cert_data);
  pkcs11_find_objects_final (module, pks);

  return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE; /* continue until all tokens have been checked */

fail:
  gnutls_free (cert_data);
  pkcs11_find_objects_final (module, pks);
  if (plist.key_ids != NULL)
    {
      for (i = 0; i < plist.key_ids_size; i++)
        {
          _gnutls_buffer_clear (&plist.key_ids[i]);
        }
      gnutls_free (plist.key_ids);
    }
  for (i = 0; i < find_data->current; i++)
    {
      gnutls_pkcs11_obj_deinit (find_data->p_list[i]);
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
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs11_obj_list_import_url (gnutls_pkcs11_obj_t * p_list,
                                   unsigned int *n_list,
                                   const char *url,
                                   gnutls_pkcs11_obj_attr_t attrs,
                                   unsigned int flags)
{
  int ret;
  struct crt_find_data_st find_data;

  memset (&find_data, 0, sizeof (find_data));

  /* fill in the find data structure */
  find_data.p_list = p_list;
  find_data.n_list = n_list;
  find_data.flags = attrs;
  find_data.current = 0;

  if (url == NULL || url[0] == 0)
    {
      url = "pkcs11:";
    }

  ret = pkcs11_url_to_info (url, &find_data.info);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    _pkcs11_traverse_tokens (find_objs, &find_data, find_data.info,
                             pkcs11_obj_flags_to_int (flags));
  p11_kit_uri_free (find_data.info);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

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
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_import_pkcs11_url (gnutls_x509_crt_t crt,
                                   const char *url, unsigned int flags)
{
  gnutls_pkcs11_obj_t pcrt;
  int ret;

  ret = gnutls_pkcs11_obj_init (&pcrt);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = gnutls_pkcs11_obj_import_url (pcrt, url, flags);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = gnutls_x509_crt_import (crt, &pcrt->raw, GNUTLS_X509_FMT_DER);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = 0;
cleanup:

  gnutls_pkcs11_obj_deinit (pcrt);

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
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_import_pkcs11 (gnutls_x509_crt_t crt,
                               gnutls_pkcs11_obj_t pkcs11_crt)
{
  return gnutls_x509_crt_import (crt, &pkcs11_crt->raw, GNUTLS_X509_FMT_DER);
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
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_crt_list_import_pkcs11 (gnutls_x509_crt_t * certs,
                                    unsigned int cert_max,
                                    gnutls_pkcs11_obj_t * const objs,
                                    unsigned int flags)
{
  int i, j;
  int ret;

  for (i = 0; i < cert_max; i++)
    {
      ret = gnutls_x509_crt_init (&certs[i]);
      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }

      ret = gnutls_x509_crt_import_pkcs11 (certs[i], objs[i]);
      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }
    }

  return 0;

cleanup:
  for (j = 0; j < i; j++)
    {
      gnutls_x509_crt_deinit (certs[j]);
    }

  return ret;
}

static int
find_flags (struct ck_function_list * module, ck_session_handle_t pks,
            struct token_info *info, struct ck_info *lib_info, void *input)
{
  struct flags_find_data_st *find_data = input;

  if (info == NULL)
    {                           /* we don't support multiple calls */
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  /* do not bother reading the token if basic fields do not match
   */
  if (!p11_kit_uri_match_token_info (find_data->info, &info->tinfo) ||
      !p11_kit_uri_match_module_info (find_data->info, lib_info))
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  /* found token! */

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
 * Returns: zero on success or a negative value on error.
 **/
int
gnutls_pkcs11_token_get_flags (const char *url, unsigned int *flags)
{
  struct flags_find_data_st find_data;
  int ret;

  memset (&find_data, 0, sizeof (find_data));
  ret = pkcs11_url_to_info (url, &find_data.info);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _pkcs11_traverse_tokens (find_flags, &find_data, find_data.info, 0);
  p11_kit_uri_free (find_data.info);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  *flags = 0;
  if (find_data.slot_flags & CKF_HW_SLOT)
    *flags |= GNUTLS_PKCS11_TOKEN_HW;

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
 * Returns: zero on success or a negative value on error.
 **/
int
gnutls_pkcs11_token_get_mechanism (const char *url, int idx,
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

  ret = pkcs11_url_to_info (url, &info);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }


  ret = pkcs11_find_slot (&module, &slot, info, &tinfo);
  p11_kit_uri_free (info);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  count = sizeof (mlist) / sizeof (mlist[0]);
  rv = pkcs11_get_mechanism_list (module, slot, mlist, &count);
  if (rv != CKR_OK)
    {
      gnutls_assert ();
      return pkcs11_rv_to_err (rv);
    }

  if (idx >= count)
    {
      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  *mechanism = mlist[idx];

  return 0;

}


const char *
gnutls_pkcs11_type_get_name (gnutls_pkcs11_obj_type_t type)
{
  switch (type)
    {
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

ck_rv_t
pkcs11_get_slot_list (struct ck_function_list * module, unsigned char token_present,
                      ck_slot_id_t *slot_list, unsigned long *count)
{
	return (module)->C_GetSlotList (token_present, slot_list, count);
}

ck_rv_t
pkcs11_get_module_info (struct ck_function_list * module,
                        struct ck_info * info)
{
	return (module)->C_GetInfo (info);
}

ck_rv_t
pkcs11_get_slot_info(struct ck_function_list * module,
                     ck_slot_id_t slot_id,
                     struct ck_slot_info *info)
{
	return (module)->C_GetSlotInfo (slot_id, info);
}

ck_rv_t
pkcs11_get_token_info (struct ck_function_list * module,
                       ck_slot_id_t slot_id,
                       struct ck_token_info *info)
{
	return (module)->C_GetTokenInfo (slot_id, info);
}

ck_rv_t
pkcs11_find_objects_init (struct ck_function_list *module,
                          ck_session_handle_t sess,
                          struct ck_attribute *templ,
                          unsigned long count)
{
	return (module)->C_FindObjectsInit (sess, templ, count);
}

ck_rv_t
pkcs11_find_objects (struct ck_function_list *module,
                       ck_session_handle_t sess,
                       ck_object_handle_t *objects,
                       unsigned long max_object_count,
                       unsigned long *object_count)
{
	return (module)->C_FindObjects (sess, objects, max_object_count, object_count);
}

ck_rv_t
pkcs11_find_objects_final (struct ck_function_list *module,
                           ck_session_handle_t sess)
{
	return (module)->C_FindObjectsFinal (sess);
}

ck_rv_t
pkcs11_close_session (struct ck_function_list *module,
                      ck_session_handle_t sess)
{
	return (module)->C_CloseSession (sess);
}

ck_rv_t
pkcs11_get_attribute_value(struct ck_function_list *module,
                           ck_session_handle_t sess,
                           ck_object_handle_t object,
                           struct ck_attribute *templ,
                           unsigned long count)
{
	return (module)->C_GetAttributeValue (sess, object, templ, count);
}

ck_rv_t
pkcs11_get_mechanism_list (struct ck_function_list *module,
                           ck_slot_id_t slot_id,
                           ck_mechanism_type_t *mechanism_list,
                           unsigned long *count)
{
	return (module)->C_GetMechanismList (slot_id, mechanism_list, count);
}

ck_rv_t
pkcs11_sign_init (struct ck_function_list *module,
                  ck_session_handle_t sess,
                  struct ck_mechanism *mechanism,
                  ck_object_handle_t key)
{
	return (module)->C_SignInit (sess, mechanism, key);
}

ck_rv_t
pkcs11_sign (struct ck_function_list *module,
             ck_session_handle_t sess,
             unsigned char *data,
             unsigned long data_len,
             unsigned char *signature,
             unsigned long *signature_len)
{
	return (module)->C_Sign (sess, data, data_len, signature, signature_len);
}

ck_rv_t
pkcs11_decrypt_init (struct ck_function_list *module,
                     ck_session_handle_t sess,
                     struct ck_mechanism *mechanism,
                     ck_object_handle_t key)
{
	return (module)->C_DecryptInit (sess, mechanism, key);
}

ck_rv_t
pkcs11_decrypt (struct ck_function_list *module,
                ck_session_handle_t sess,
                unsigned char *encrypted_data,
                unsigned long encrypted_data_len,
                unsigned char *data, unsigned long *data_len)
{
	return (module)->C_Decrypt (sess, encrypted_data, encrypted_data_len,
	                            data, data_len);
}

ck_rv_t
pkcs11_create_object (struct ck_function_list *module,
                      ck_session_handle_t sess,
                      struct ck_attribute *templ,
                      unsigned long count,
                      ck_object_handle_t *object)
{
	return (module)->C_CreateObject (sess, templ, count, object);
}

ck_rv_t
pkcs11_destroy_object (struct ck_function_list *module,
                       ck_session_handle_t sess,
                       ck_object_handle_t object)
{
	return (module)->C_DestroyObject (sess, object);
}

ck_rv_t
pkcs11_init_token (struct ck_function_list *module,
                   ck_slot_id_t slot_id, unsigned char *pin,
                   unsigned long pin_len, unsigned char *label)
{
	return (module)->C_InitToken (slot_id, pin, pin_len, label);
}

ck_rv_t
pkcs11_init_pin (struct ck_function_list *module,
                 ck_session_handle_t sess,
                 unsigned char *pin,
                 unsigned long pin_len)
{
	return (module)->C_InitPIN (sess, pin, pin_len);
}

ck_rv_t
pkcs11_set_pin (struct ck_function_list *module,
                ck_session_handle_t sess,
                unsigned char *old_pin,
                unsigned long old_len,
                unsigned char *new_pin,
                unsigned long new_len)
{
	return (module)->C_SetPIN (sess, old_pin, old_len, new_pin, new_len);
}

const char *
pkcs11_strerror (ck_rv_t rv)
{
	return p11_kit_strerror (rv);
}
