/*
 * GnuTLS PKCS#11 support
 * Copyright (C) 2010 Free Software Foundation
 * 
 * Author: Nikos Mavrogiannopoulos
 *
 * Inspired and some parts based on neon PKCS #11 support by Joe Orton.
 * More ideas came from the pkcs11-helper library.
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
#include <stdbool.h>
#include <string.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <pkcs11_int.h>

#define MAX_PROVIDERS 16

/* XXX: try to eliminate this */
#define MAX_CERT_SIZE 8*1024

struct gnutls_pkcs11_provider_s {
    pakchois_module_t *module;
    unsigned long nslots;
    ck_slot_id_t *slots;
};

struct url_find_data_st {
    gnutls_pkcs11_obj_t crt;
};

struct flags_find_data_st {
    struct pkcs11_url_info info;
    unsigned int slot_flags;
};

struct crt_find_data_st {
    gnutls_pkcs11_obj_t *p_list;
    unsigned int* n_list;
    unsigned int current;
    gnutls_pkcs11_obj_attr_t flags;
    struct pkcs11_url_info info;
};

static struct gnutls_pkcs11_provider_s providers[MAX_PROVIDERS];
static int active_providers = 0;

static gnutls_pkcs11_pin_callback_t pin_func;
static void* pin_data;

gnutls_pkcs11_token_callback_t token_func;
void* token_data;

/* Fake scan */
void pkcs11_rescan_slots(void)
{
unsigned long slots;

    pakchois_get_slot_list(providers[active_providers-1].module, 0, NULL, &slots);
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
int gnutls_pkcs11_add_provider (const char * name, const char * params)
{

    if (active_providers >= MAX_PROVIDERS) {
        gnutls_assert();
        return GNUTLS_E_CONSTRAINT_ERROR;
    }

    active_providers++;
    if (pakchois_module_load(&providers[active_providers-1].module, name) != CKR_OK) {
        gnutls_assert();
        _gnutls_debug_log("p11: Cannot load provider %s\n", name);
        active_providers--;
        return GNUTLS_E_PKCS11_LOAD_ERROR;
    }

    /* cache the number of slots in this module */
    if (pakchois_get_slot_list(providers[active_providers-1].module, 0, NULL, &providers[active_providers-1].nslots) != CKR_OK) {
        gnutls_assert();
        goto fail;
    }
    
    providers[active_providers-1].slots = gnutls_malloc(sizeof(*providers[active_providers-1].slots)*providers[active_providers-1].nslots);
    if (providers[active_providers-1].slots==NULL) {
        gnutls_assert();
        goto fail;
    }

    if (pakchois_get_slot_list(providers[active_providers-1].module, 0, providers[active_providers-1].slots, &providers[active_providers-1].nslots) != CKR_OK)  {
        gnutls_assert();
        gnutls_free(providers[active_providers-1].slots);
        goto fail;
    }
    
    _gnutls_debug_log("p11: loaded provider '%s' with %d slots\n", name, (int)providers[active_providers-1].nslots);

    return 0;

fail:
    pakchois_module_destroy(providers[active_providers-1].module);
    active_providers--;
    return GNUTLS_E_PKCS11_LOAD_ERROR;

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
<<<<<<< HEAD:lib/pkcs11.c
int gnutls_pkcs11_crt_get_info(gnutls_pkcs11_crt_t crt, gnutls_pkcs11_cert_info_t itype,
=======
int gnutls_pkcs11_obj_get_info(gnutls_pkcs11_obj_t crt, gnutls_pkcs11_obj_info_t itype, 
>>>>>>> Added gnutls_pubkey_t abstract type to handle public keys. It can currently:lib/pkcs11.c
    void* output, size_t* output_size)
{
    return pkcs11_get_info(&crt->info, itype, output, output_size);
}

int pkcs11_get_info(struct pkcs11_url_info *info, gnutls_pkcs11_obj_info_t itype,
    void* output, size_t* output_size)
{
    const char* str = NULL;
    size_t len;

    switch(itype) {
        case GNUTLS_PKCS11_OBJ_ID:
            if (*output_size < info->certid_raw_size) {
                *output_size = info->certid_raw_size;
                return GNUTLS_E_SHORT_MEMORY_BUFFER;
            }
            if (output) memcpy(output, info->certid_raw, info->certid_raw_size);
            *output_size = info->certid_raw_size;
            
            return 0;
        case GNUTLS_PKCS11_OBJ_ID_HEX:
            str = info->id;
            break;
        case GNUTLS_PKCS11_OBJ_LABEL:
            str = info->label;
            break;
        case GNUTLS_PKCS11_OBJ_TOKEN_LABEL:
            str = info->token;
            break;
        case GNUTLS_PKCS11_OBJ_TOKEN_SERIAL:
            str = info->serial;
            break;
        case GNUTLS_PKCS11_OBJ_TOKEN_MANUFACTURER:
            str = info->manufacturer;
            break;
        case GNUTLS_PKCS11_OBJ_TOKEN_MODEL:
            str = info->model;
            break;
        default:
            gnutls_assert();
            return GNUTLS_E_INVALID_REQUEST;
    }

    len = strlen(str);

    if (len+1>*output_size) {
        *output_size = len+1;
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    strcpy(output, str);

    *output_size = len;

    return 0;
}

static int init = 0;


/**
 * gnutls_pkcs11_init:
 * @flags: GNUTLS_PKCS11_FLAG_MANUAL or GNUTLS_PKCS11_FLAG_AUTO
 * @configfile: either NULL or the location of a configuration file
 *
 * This function will initialize the PKCS 11 subsystem in gnutls. It will
 * read a configuration file if %GNUTLS_PKCS11_FLAG_AUTO is used or allow
 * you to independently load PKCS 11 modules using gnutls_pkcs11_add_provider()
 * if %GNUTLS_PKCS11_FLAG_MANUAL is specified.
 *
 * Normally you don't need to call this function since it is being called
 * by gnutls_global_init(). Otherwise you must call it before it.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs11_init(unsigned int flags, const char* configfile)
{
    int ret;
    
    if (init != 0) {
        init++;
        return 0;
    }
    init++;

    if (flags == GNUTLS_PKCS11_FLAG_MANUAL)
        return 0;
    else {
        FILE *fp;
        char line[512];
        const char* library;
        
        if (configfile == NULL)
            configfile = "/etc/gnutls/pkcs11.conf";
        
        fp = fopen(configfile, "r");
        if (fp == NULL) {
            gnutls_assert();
            _gnutls_debug_log("Cannot load %s\n", configfile);
            return GNUTLS_E_FILE_ERROR;
        }
        
        while (fgets (line, sizeof (line), fp) != NULL) {
            if (strncmp(line, "load", sizeof("load")-1) == 0) {
                char* p;
                p = strchr(line, '=');
                if (p==NULL) continue;
                
                library = ++p;
                
                p = strchr(line, '\n');
                if (p!=NULL) {
                    *p=0;
                }

                ret = gnutls_pkcs11_add_provider(library, NULL);
                if (ret < 0) {
                    gnutls_assert();
                    _gnutls_debug_log("Cannot load provider: %s\n", library);
                    continue;
                }
            }
        }
    }
    
    return 0;
}

/**
 * gnutls_pkcs11_deinit:
 *
 * This function will deinitialize the PKCS 11 subsystem in gnutls.
 *
 **/
void gnutls_pkcs11_deinit (void)
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
    
    for (i=0;i<active_providers;i++) {
        pakchois_module_destroy(providers[i].module);
    }
    active_providers = 0;
}

/**
 * gnutls_pkcs11_set_pin_function:
 * @fn: The PIN callback
 * @userdata: data to be supplied to callback
 *
 * This function will set a callback function to be used when a PIN
 * is required for PKCS 11 operations.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
void gnutls_pkcs11_set_pin_function(gnutls_pkcs11_pin_callback_t fn,
                                void *userdata)
{
    pin_func = fn;
    pin_data = userdata;
}

/**
 * gnutls_pkcs11_set_token_function:
 * @fn: The PIN callback
 * @userdata: data to be supplied to callback
 *
 * This function will set a callback function to be used when a token
 * needs to be inserted to continue PKCS 11 operations.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
void gnutls_pkcs11_set_token_function(gnutls_pkcs11_token_callback_t fn,
                                void *userdata)
{
    token_func = fn;
    token_data = userdata;
}

static int unescape_string (char* output, const char* input, size_t* size, char terminator)
{
    gnutls_string str;
    int ret = 0;
    char* p;
    int len;
    
    _gnutls_string_init(&str, gnutls_malloc, gnutls_realloc, gnutls_free);
    
    /* find terminator */
    p = strchr(input, terminator);
    if (p!=NULL)
        len = p-input;
    else
        len = strlen(input);

    ret = _gnutls_string_append_data(&str, input, len);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = _gnutls_string_unescape(&str);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = _gnutls_string_append_data(&str, "", 1);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    _gnutls_string_get_data(&str, output, size);

    _gnutls_string_clear(&str);

    return ret;
}

int pkcs11_url_to_info(const char* url, struct pkcs11_url_info* info)
{
int ret;
char* p1, *p2;
size_t l;

    memset( info, 0, sizeof(*info));

    if (strstr(url, "pkcs11:")==NULL) {
        ret = GNUTLS_E_PARSING_ERROR;
        goto cleanup;
    }

    if ((p1=strstr(url, "manufacturer="))!= NULL) {
        p1+=sizeof("manufacturer=")-1;
        l=sizeof (info->manufacturer);

        ret = unescape_string(info->manufacturer, p1, &l, ';');
        if (ret < 0) {
                goto cleanup;
        }
    }

    if ((p1=strstr(url, "token="))!= NULL) {
        p1+=sizeof("token=")-1;
        l=sizeof (info->token);

        ret = unescape_string(info->token, p1, &l, ';');
        if (ret < 0) {
                goto cleanup;
        }
    }

    if ((p1=strstr(url, "object="))!= NULL) {
        p1+=sizeof("object=")-1;
        l=sizeof (info->label);

        ret = unescape_string(info->label, p1, &l, ';');
        if (ret < 0) {
                goto cleanup;
        }
    }

    if ((p1=strstr(url, "serial="))!= NULL) {
        p1+=sizeof("serial=")-1;
        l=sizeof (info->serial);

        ret = unescape_string (info->serial, p1, &l, ';');
        if (ret < 0) {
                goto cleanup;
        }
    }

    if ((p1=strstr(url, "model="))!= NULL) {
        p1+=sizeof("model=")-1;
        l=sizeof (info->model);

        ret = unescape_string (info->model,
                        p1, &l, ';');
        if (ret < 0) {
                goto cleanup;
        }
    }

    if ((p1=strstr(url, "objecttype="))!= NULL) {
        p1+=sizeof("objecttype=")-1;
        l=sizeof (info->model);

        ret = unescape_string (info->type,
                        p1, &l, ';');
        if (ret < 0) {
                goto cleanup;
        }
    }

    if (((p1=strstr(url, ";id="))!= NULL) || ((p1=strstr(url, ":id="))!= NULL)) {
        p1+=sizeof(";id=")-1;

        if ((p2=strchr(p1, ';'))== NULL) {
            l = strlen(p1);
        } else {
            l = p2 - p1;
        }

        if (l > sizeof(info->id)-1) {
            gnutls_assert();
            ret = GNUTLS_E_PARSING_ERROR;
        }

        memcpy(info->id, p1, l);
        info->id[l] = 0;

        /* convert to raw */
        info->certid_raw_size = sizeof(info->certid_raw);
        ret = _gnutls_hex2bin(info->id, strlen(info->id), info->certid_raw, &info->certid_raw_size);
        if (ret < 0) {
            gnutls_assert();
            goto cleanup;
        }

        memcpy(info->id, p1, l);
        info->id[l] = 0;
    }
    
    ret = 0;
   
cleanup:
    return ret;

}

#define INVALID_CHARS       "\\/\"'%&#@!?$* <>{}[]()`|:;,.+-"

static int append(gnutls_string* dest, const char* tname, const char* p11name, int init)
{
        gnutls_string tmpstr;
        int ret;

        _gnutls_string_init(&tmpstr, gnutls_malloc, gnutls_realloc, gnutls_free);
        if ((ret=_gnutls_string_append_str(&tmpstr, tname))<0) {
                gnutls_assert();
                goto cleanup;
        }

        ret = _gnutls_string_escape(&tmpstr, INVALID_CHARS);
        if (ret < 0) {
                gnutls_assert();
                goto cleanup;
        }

        if ((ret=_gnutls_string_append_data(&tmpstr, "", 1)) < 0) {
                gnutls_assert();
                goto cleanup;
        }

        if ((ret=_gnutls_string_append_printf(dest, "%s%s=%s", (init!=0)?";":"", p11name, tmpstr.data)) < 0) {
                gnutls_assert();
                goto cleanup;
        }

        ret = 0;

cleanup:
        _gnutls_string_clear(&tmpstr);

        return ret;

}


int pkcs11_info_to_url(const struct pkcs11_url_info* info, char** url)
{
    gnutls_string str;
    int init = 0;
    int ret;
    
    _gnutls_string_init (&str, gnutls_malloc, gnutls_realloc, gnutls_free);

    _gnutls_string_append_str(&str, "pkcs11:");

    if (info->token[0]) {
        ret = append(&str, info->token, "token", init);
        if (ret < 0) {
                gnutls_assert();
                goto cleanup;
        }
        init = 1;
    }

    if (info->serial[0]) {
        ret = append(&str, info->serial, "serial", init);
        if (ret < 0) {
                gnutls_assert();
                goto cleanup;
        }
        init = 1;
    }

    if (info->model[0]) {
        ret = append(&str, info->model, "model", init);
        if (ret < 0) {
                gnutls_assert();
                goto cleanup;
        }
        init = 1;
    }


    if (info->manufacturer[0]) {
        ret = append(&str, info->manufacturer, "manufacturer", init);
        if (ret < 0) {
                gnutls_assert();
                goto cleanup;
        }
        init = 1;
    }

    if (info->label[0]) {
        ret = append(&str, info->label, "object", init);
        if (ret < 0) {
                gnutls_assert();
                goto cleanup;
        }
        init = 1;
    }

    if (info->type[0]) {
        ret = append(&str, info->type, "objecttype", init);
        if (ret < 0) {
                gnutls_assert();
                goto cleanup;
        }
        init = 1;
    }

    if (info->id[0] != 0) {
        ret = _gnutls_string_append_printf(&str, ";id=%s", info->id);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }
    }
    
    _gnutls_string_append_data(&str, "", 1);

    *url = str.data;
    
    return 0;

cleanup:
    _gnutls_string_clear(&str);
    return ret;
}

/**
 * gnutls_pkcs11_obj_init:
 * @crt: The structure to be initialized
 *
 * This function will initialize a pkcs11 certificate structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs11_obj_init(gnutls_pkcs11_obj_t * crt)
{
    *crt = gnutls_calloc(1, sizeof(struct gnutls_pkcs11_obj_st));

    if (*crt == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }
 
    return 0;
}

/**
 * gnutls_pkcs11_obj_deinit:
 * @key: The structure to be initialized
 *
 * This function will deinitialize a certificate structure.
 **/
void gnutls_pkcs11_obj_deinit(gnutls_pkcs11_obj_t crt)
{
    _gnutls_free_datum(&crt->raw);
    free(crt);
}

/**
 * gnutls_pkcs11_obj_export:
 * @key: Holds the object
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
gnutls_pkcs11_obj_export(gnutls_pkcs11_obj_t obj,
		     void *output_data,
		     size_t * output_data_size)
{
	if (obj == NULL || obj->raw.data == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

    if (output_data==NULL || *output_data_size < obj->raw.size) {
        *output_data_size = obj->raw.size;
        gnutls_assert();
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }
    *output_data_size = obj->raw.size;

    memcpy(output_data, obj->raw.data, obj->raw.size);
    return 0;
}

static void terminate_string(unsigned char *str, size_t len)
{
    unsigned char *ptr = str + len - 1;

    while ((*ptr == ' ' || *ptr == '\t' || *ptr == '\0') && ptr >= str)
        ptr--;

    if (ptr == str - 1)
        str[0] = '\0';
    else if (ptr == str + len - 1)
        str[len-1] = '\0';
    else
        ptr[1] = '\0';
}


int _pkcs11_traverse_tokens (find_func_t find_func, void* input, int leave_session)
{
    ck_rv_t rv;
    int found = 0, x, z, ret;
    pakchois_session_t *pks = NULL;

    for (x=0;x<active_providers;x++) {
        for (z=0;z<providers[x].nslots;z++) {
            struct token_info info;

            rv = pakchois_open_session(providers[x].module, providers[x].slots[z], 
                CKF_SERIAL_SESSION, NULL, NULL, &pks);
            if (rv != CKR_OK) {
                continue;
            }

            if (pakchois_get_token_info(providers[x].module, providers[x].slots[z], &info.tinfo) != CKR_OK) {
                continue;
            }
            info.sid = providers[x].slots[z];
            info.prov = &providers[x];

            if (pakchois_get_slot_info(providers[x].module, providers[x].slots[z], &info.sinfo) != CKR_OK) {
                continue;
            }

            /* XXX make wrapper for token_info? */
            terminate_string(info.tinfo.manufacturer_id, sizeof info.tinfo.manufacturer_id);
            terminate_string(info.tinfo.label, sizeof info.tinfo.label);
            terminate_string(info.tinfo.model, sizeof info.tinfo.model);
            terminate_string(info.tinfo.serial_number, sizeof info.tinfo.serial_number);

            ret = find_func(pks, &info, input);
            
            if (ret == 0) {
                found = 1;
                goto finish;
            } else {
                pakchois_close_session(pks);
                pks = NULL;
            }
        }
    }

finish:
    /* final call */

    if (found == 0) {
        ret = find_func(pks, NULL, input);
    } else {
        ret = 0;
    }

    if (pks != NULL) {
        if (leave_session==0 || ret != 0)  {
            pakchois_close_session(pks);
        }
    }
   
    return ret;
}

static const char* pkcs11_obj_type_to_str(gnutls_pkcs11_obj_type_t type)
{
    switch(type) {
        case GNUTLS_PKCS11_OBJ_X509_CRT:
            return "cert";
        case GNUTLS_PKCS11_OBJ_PUBKEY:
            return "public";
        case GNUTLS_PKCS11_OBJ_PRIVKEY:
            return "private";
        case GNUTLS_PKCS11_OBJ_SECRET_KEY:
            return "secretkey";
        case GNUTLS_PKCS11_OBJ_DATA:
            return "data";
        case GNUTLS_PKCS11_OBJ_UNKNOWN:
        default:
            return "unknown";
    }
}

/* imports a raw certificate from a token to a pkcs11_obj_t structure.
 */
static int pkcs11_obj_import(unsigned int class, gnutls_pkcs11_obj_t crt, const gnutls_datum_t* data, 
   const gnutls_datum_t * id, const gnutls_datum_t * label, struct ck_token_info* tinfo)
{
    char *s;
    int ret;

    switch(class) {
        case CKO_CERTIFICATE:
            crt->type = GNUTLS_PKCS11_OBJ_X509_CRT;
            break;
        case CKO_PUBLIC_KEY:
            crt->type = GNUTLS_PKCS11_OBJ_PUBKEY;
            break;
        case CKO_PRIVATE_KEY:
            crt->type = GNUTLS_PKCS11_OBJ_PRIVKEY;
            break;
        case CKO_SECRET_KEY:
            crt->type = GNUTLS_PKCS11_OBJ_SECRET_KEY;
            break;
        case CKO_DATA:
            crt->type = GNUTLS_PKCS11_OBJ_DATA;
            break;
        default:
            crt->type = GNUTLS_PKCS11_OBJ_UNKNOWN;
    }
    
    if (crt->type != GNUTLS_PKCS11_OBJ_UNKNOWN)
        strcpy(crt->info.type, pkcs11_obj_type_to_str(crt->type));

    if (data && data->data) {
        ret = _gnutls_set_datum(&crt->raw, data->data, data->size);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }
    }

    terminate_string(tinfo->manufacturer_id, sizeof tinfo->manufacturer_id);
    terminate_string(tinfo->label, sizeof tinfo->label);
    terminate_string(tinfo->model, sizeof tinfo->model);
    terminate_string(tinfo->serial_number, sizeof tinfo->serial_number);

    /* write data */
    snprintf(crt->info.manufacturer, sizeof(crt->info.manufacturer), "%s", tinfo->manufacturer_id);
    snprintf(crt->info.token, sizeof(crt->info.token), "%s", tinfo->label);
    snprintf(crt->info.model, sizeof(crt->info.model), "%s", tinfo->model);
    snprintf(crt->info.serial, sizeof(crt->info.serial), "%s", tinfo->serial_number);

    if (label && label->data) {
        memcpy(crt->info.label, label->data, label->size);
        crt->info.label[label->size] = 0;
    }

    if (id && id->data) {
        s = _gnutls_bin2hex(id->data, id->size, crt->info.id, sizeof(crt->info.id), ":");
        if (s == NULL) {
            gnutls_assert();
            return GNUTLS_E_PKCS11_ERROR;
        }
    
        memmove(crt->info.certid_raw, id->data, id->size);
        crt->info.certid_raw_size = id->size;
    }

    memmove(crt->info.certid_raw, id->data, id->size);
    crt->info.certid_raw_size = id->size;

    return 0;
}

static int pkcs11_obj_import_pubkey(pakchois_session_t *pks, ck_object_handle_t obj,
    gnutls_pkcs11_obj_t crt, const gnutls_datum_t * id,
    const gnutls_datum_t* label, struct ck_token_info* tinfo)
{

    struct ck_attribute a[4];
    ck_key_type_t key_type;
    opaque tmp1[2048];
    opaque tmp2[2048];
    int ret;
    unsigned int tval;

    a[0].type = CKA_KEY_TYPE;
    a[0].value = &key_type;
    a[0].value_len = sizeof(key_type);

    if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
        switch(key_type) {
            case CKK_RSA:
                a[0].type = CKA_MODULUS;
                a[0].value = tmp1;
                a[0].value_len = sizeof(tmp1);
                a[1].type = CKA_PUBLIC_EXPONENT;
                a[1].value = tmp2;
                a[1].value_len = sizeof(tmp2);

                if (pakchois_get_attribute_value(pks, obj, a, 2) == CKR_OK) {

                    ret = _gnutls_set_datum(&crt->pubkey[0], a[0].value, a[0].value_len);

                    if (ret >= 0)
                        ret = _gnutls_set_datum(&crt->pubkey[1], a[1].value, a[1].value_len);

                    if (ret < 0) {
                        gnutls_assert();
                        _gnutls_free_datum(&crt->pubkey[1]);
                        _gnutls_free_datum(&crt->pubkey[0]);
                        return GNUTLS_E_MEMORY_ERROR;
                    }
                } else {
                    gnutls_assert();
                    return GNUTLS_E_PKCS11_ERROR;
                }
                crt->pk_algorithm = GNUTLS_PK_RSA;
                break;
            case CKK_DSA:
                a[0].type = CKA_PRIME;
                a[0].value = tmp1;
                a[0].value_len = sizeof(tmp1);
                a[1].type = CKA_SUBPRIME;
                a[1].value = tmp2;
                a[1].value_len = sizeof(tmp2);

                if (pakchois_get_attribute_value(pks, obj, a, 2) == CKR_OK) {
                    ret = _gnutls_set_datum(&crt->pubkey[0], a[0].value, a[0].value_len);

                    if (ret >= 0)
                        ret = _gnutls_set_datum(&crt->pubkey[1], a[1].value, a[1].value_len);

                    if (ret < 0) {
                        gnutls_assert();
                        _gnutls_free_datum(&crt->pubkey[1]);
                        _gnutls_free_datum(&crt->pubkey[0]);
                        return GNUTLS_E_MEMORY_ERROR;
                    }
                } else {
                    gnutls_assert();
                    return GNUTLS_E_PKCS11_ERROR;
                }

                a[0].type = CKA_BASE;
                a[0].value = tmp1;
                a[0].value_len = sizeof(tmp1);
                a[1].type = CKA_VALUE;
                a[1].value = tmp2;
                a[1].value_len = sizeof(tmp2);

                if (pakchois_get_attribute_value(pks, obj, a, 2) == CKR_OK) {
                    ret = _gnutls_set_datum(&crt->pubkey[2], a[0].value, a[0].value_len);

                    if (ret >= 0)
                        ret = _gnutls_set_datum(&crt->pubkey[3], a[1].value, a[1].value_len);

                    if (ret < 0) {
                        gnutls_assert();
                        _gnutls_free_datum(&crt->pubkey[0]);
                        _gnutls_free_datum(&crt->pubkey[1]);
                        _gnutls_free_datum(&crt->pubkey[2]);
                        _gnutls_free_datum(&crt->pubkey[3]);
                        return GNUTLS_E_MEMORY_ERROR;
                    }
                } else {
                    gnutls_assert();
                    return GNUTLS_E_PKCS11_ERROR;
                }
                crt->pk_algorithm = GNUTLS_PK_RSA;
                break;
            default:
                gnutls_assert();
                return GNUTLS_E_UNIMPLEMENTED_FEATURE;
        }
    }

    /* read key usage flags */
    a[0].type = CKA_ENCRYPT;
    a[0].value = &tval;
    a[0].value_len = sizeof(tval);

    if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
        if (tval != 0) {
            crt->key_usage |= GNUTLS_KEY_DATA_ENCIPHERMENT;
        }
    }

    a[0].type = CKA_VERIFY;
    a[0].value = &tval;
    a[0].value_len = sizeof(tval);

    if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
        if (tval != 0) {
            crt->key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE| \
            GNUTLS_KEY_KEY_CERT_SIGN|GNUTLS_KEY_CRL_SIGN|GNUTLS_KEY_NON_REPUDIATION;
        }
    }

    a[0].type = CKA_VERIFY_RECOVER;
    a[0].value = &tval;
    a[0].value_len = sizeof(tval);

    if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
        if (tval != 0) {
            crt->key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE| \
            GNUTLS_KEY_KEY_CERT_SIGN|GNUTLS_KEY_CRL_SIGN|GNUTLS_KEY_NON_REPUDIATION;
        }
    }

    a[0].type = CKA_DERIVE;
    a[0].value = &tval;
    a[0].value_len = sizeof(tval);

    if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
        if (tval != 0) {
            crt->key_usage |= GNUTLS_KEY_KEY_AGREEMENT;
        }
    }

    a[0].type = CKA_WRAP;
    a[0].value = &tval;
    a[0].value_len = sizeof(tval);

    if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
        if (tval != 0) {
            crt->key_usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
        }
    }

    return pkcs11_obj_import(CKO_PUBLIC_KEY, crt, NULL, id, label, tinfo);
}



static int find_obj_url(pakchois_session_t *pks, struct token_info *info, void* input)
{
    struct url_find_data_st* find_data = input;
    struct ck_attribute a[4];
    ck_object_class_t class;
    ck_certificate_type_t type = -1;
    ck_rv_t rv;
    ck_object_handle_t obj;
    unsigned long count, a_vals;
    int found = 0, ret;
    opaque* cert_data = NULL;
    char label_tmp[PKCS11_LABEL_SIZE];
    
    if (info == NULL) { /* we don't support multiple calls */
        gnutls_assert();
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }
    
    /* do not bother reading the token if basic fields do not match
     */
    if (find_data->crt->info.manufacturer[0] != 0) {
        if (strcmp(find_data->crt->info.manufacturer, info->tinfo.manufacturer_id) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->crt->info.token[0] != 0) {
        if (strcmp(find_data->crt->info.token, info->tinfo.label) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->crt->info.model[0] != 0) {
        if (strcmp(find_data->crt->info.model, info->tinfo.model) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->crt->info.serial[0] != 0) {
        if (strcmp(find_data->crt->info.serial, info->tinfo.serial_number) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    class = CKO_CERTIFICATE; /* default  */

    if (find_data->crt->info.type[0] != 0) {
        if (strcmp(find_data->crt->info.type, "cert") == 0) {
            class = CKO_CERTIFICATE;
            type = CKC_X_509;
        } else if (strcmp(find_data->crt->info.type, "public") == 0) {
            class = CKO_PUBLIC_KEY;
        } else if (strcmp(find_data->crt->info.type, "private") == 0) {
            class = CKO_PRIVATE_KEY;
        } else if (strcmp(find_data->crt->info.type, "secretkey") == 0) {
            class = CKO_SECRET_KEY;
        } else if (strcmp(find_data->crt->info.type, "data") == 0) {
            class = CKO_DATA;
        }
    }

    /* search the token for the id */
    
    cert_data = gnutls_malloc(MAX_CERT_SIZE);
    if (cert_data == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }
    
    /* Find objects with given class and type */

    a[0].type = CKA_CLASS;
    a[0].value = &class;
    a[0].value_len = sizeof class;

    a[1].type = CKA_ID;
    a[1].value = find_data->crt->info.certid_raw;
    a[1].value_len = find_data->crt->info.certid_raw_size;

    a_vals = 2;

    if (type != -1) {
        a[2].type = CKA_CERTIFICATE_TYPE;
        a[2].value = &type;
        a[2].value_len = sizeof type;
        a_vals++;
    }

    rv = pakchois_find_objects_init(pks, a, a_vals);
    if (rv != CKR_OK) {
        gnutls_assert();
        _gnutls_debug_log("pk11: FindObjectsInit failed.\n");
        ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
        goto cleanup;
    }

    while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
           && count == 1) {

        a[0].type = CKA_VALUE;
        a[0].value = cert_data;
        a[0].value_len = MAX_CERT_SIZE;
        a[1].type = CKA_LABEL;
        a[1].value = label_tmp;
        a[1].value_len = sizeof(label_tmp);

        if (pakchois_get_attribute_value(pks, obj, a, 2) == CKR_OK) {
            gnutls_datum_t id = { find_data->crt->info.certid_raw, find_data->crt->info.certid_raw_size };
            gnutls_datum_t data = { a[0].value, a[0].value_len };
            gnutls_datum_t label = { a[1].value, a[1].value_len };
            
            if (class == CKO_PUBLIC_KEY) {
                ret = pkcs11_obj_import_pubkey(pks, obj, find_data->crt, &id, &label, &info->tinfo);
            } else {
                ret = pkcs11_obj_import(class, find_data->crt, &data, &id, &label, &info->tinfo);
            }
            if (ret < 0) {
                gnutls_assert();
                goto cleanup;
            }

            found = 1;
            break;
        }
        else {
            _gnutls_debug_log("pk11: Skipped cert, missing attrs.\n");
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
    pakchois_find_objects_final(pks);
    
    return ret;
}

/**
 * gnutls_pkcs11_privkey_import_url:
 * @cert: The structure to store the parsed certificate
 * @url: a PKCS 11 url identifying the key
 *
 * This function will "import" a PKCS 11 URL identifying a certificate
 * key to the #gnutls_pkcs11_obj_t structure. This does not involve any
 * parsing (such as X.509 or OpenPGP) since the #gnutls_pkcs11_obj_t is
 * format agnostic. Only data are transferred.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs11_obj_import_url (gnutls_pkcs11_obj_t cert, const char * url)
{
    int ret;
    struct url_find_data_st find_data;
    
    /* fill in the find data structure */
    find_data.crt = cert;

    ret = pkcs11_url_to_info(url, &cert->info);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = _pkcs11_traverse_tokens(find_obj_url, &find_data, 0);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }
    
    return 0;
}

struct token_num {
    struct pkcs11_url_info info;
    unsigned int seq; /* which one we are looking for */
    unsigned int current; /* which one are we now */
};

static int find_token_num(pakchois_session_t *pks, struct token_info *tinfo, void* input)
{
    struct token_num* find_data = input;

    if (tinfo == NULL) { /* we don't support multiple calls */
        gnutls_assert();
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->current == find_data->seq) {
        strcpy(find_data->info.manufacturer, tinfo->tinfo.manufacturer_id);
        strcpy(find_data->info.token, tinfo->tinfo.label);
        strcpy(find_data->info.model, tinfo->tinfo.model);
        strcpy(find_data->info.serial, tinfo->tinfo.serial_number);

        return 0;
    }

    find_data->current++;
    /* search the token for the id */


    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE; /* non zero is enough */
}

/**
 * gnutls_pkcs11_token_get_url:
 * @seq: sequence number starting from 0
 * @url: will contain an allocated url
 *
 * This function will return the URL for each token available
 * in system. The url has to be released using gnutls_free()
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the sequence number exceeds the available tokens, otherwise a negative error value.
 **/

int gnutls_pkcs11_token_get_url (unsigned int seq, char** url)
{
    int ret;
    struct token_num tn;

    memset(&tn, 0, sizeof(tn));
    tn.seq = seq;
    
    ret = _pkcs11_traverse_tokens(find_token_num, &tn, 0);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = pkcs11_info_to_url(&tn.info, url);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    return 0;

}

/**
 * gnutls_pkcs11_token_get_info:
 * @url: should contain a PKCS 11 URL
 * @itype: Denotes the type of information requested
 * @output: where output will be stored
 * @output_size: contains the maximum size of the output and will be overwritten with actual
 *
 * This function will return information about the PKCS 11 token such
 * as the label, id as well as token information where the key is stored.
 *
 * Returns: zero on success or a negative value on error.
 **/
int gnutls_pkcs11_token_get_info(const char* url, gnutls_pkcs11_token_info_t ttype, void* output, size_t *output_size)
{
    const char* str;
    size_t len;
    struct pkcs11_url_info info;
    int ret;

    ret = pkcs11_url_to_info(url, &info);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    switch(ttype) {
        case GNUTLS_PKCS11_TOKEN_LABEL:
            str = info.token;
            break;
        case GNUTLS_PKCS11_TOKEN_SERIAL:
            str = info.serial;
            break;
        case GNUTLS_PKCS11_TOKEN_MANUFACTURER:
            str = info.manufacturer;
            break;
        case GNUTLS_PKCS11_TOKEN_MODEL:
            str = info.model;
            break;
        default:
            gnutls_assert();
            return GNUTLS_E_INVALID_REQUEST;
    }

    len = strlen(str);

    if (len+1>*output_size) {
        *output_size = len+1;
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    strcpy(output, str);

    *output_size = len;

    return 0;
}

/**
 * gnutls_pkcs11_obj_export_url:
 * @crt: Holds the PKCS 11 certificate
 * @url: will contain an allocated url
 *
 * This function will export a URL identifying the given certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs11_obj_export_url (gnutls_pkcs11_obj_t cert, char ** url)
{
int ret;

    ret = pkcs11_info_to_url(&cert->info, url);
    if (ret < 0) {
        gnutls_assert();
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
gnutls_pkcs11_obj_type_t gnutls_pkcs11_obj_get_type (gnutls_pkcs11_obj_t obj)
{
    return obj->type;
}

struct pkey_list {
    gnutls_string *key_ids;
    size_t key_ids_size;
};

int pkcs11_login(pakchois_session_t *pks, struct token_info *info)
{
    int attempt = 0;
    ck_rv_t rv;

    if (pakchois_get_token_info(info->prov->module, info->sid, &info->tinfo) != CKR_OK) {
        gnutls_assert();
        _gnutls_debug_log( "pk11: GetTokenInfo failed\n");
        return GNUTLS_E_PKCS11_ERROR;
    }

    /* force login on HW tokens. Some tokens will not list private keys
     * if login has not been performed.
     */
    if ((info->tinfo.flags & CKF_LOGIN_REQUIRED) == 0) {
        gnutls_assert();
        _gnutls_debug_log( "pk11: No login required.\n");
        return 0;
    }

    /* For a token with a "protected" (out-of-band) authentication
     * path, calling login with a NULL username is all that is
     * required. */
    if (info->tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
        if (pakchois_login(pks, CKU_USER, NULL, 0) == CKR_OK) {
            return 0;
        }
        else {
            gnutls_assert();
            _gnutls_debug_log( "pk11: Protected login failed.\n");
            return GNUTLS_E_PKCS11_ERROR;
        }
    }

    /* Otherwise, PIN entry is necessary for login, so fail if there's
     * no callback. */
    if (!pin_func) {
        gnutls_assert();
        _gnutls_debug_log("pk11: No pin callback but login required.\n");
        return GNUTLS_E_PKCS11_ERROR;
    }

    terminate_string(info->sinfo.slot_description, sizeof info->sinfo.slot_description);

    do {
        char pin[GNUTLS_PKCS11_MAX_PIN_LEN];
        unsigned int flags = 0;

        /* If login has been attempted once already, check the token
         * status again, the flags might change. */
        if (attempt) {
            if (pakchois_get_token_info(info->prov->module, info->sid,
                                        &info->tinfo) != CKR_OK) {
                gnutls_assert();
                _gnutls_debug_log( "pk11: GetTokenInfo failed\n");
                return GNUTLS_E_PKCS11_ERROR;
            }
        }

        if (info->tinfo.flags & CKF_USER_PIN_COUNT_LOW)
            flags |= GNUTLS_PKCS11_PIN_COUNT_LOW;
        if (info->tinfo.flags & CKF_USER_PIN_FINAL_TRY)
            flags |= GNUTLS_PKCS11_PIN_FINAL_TRY;

        terminate_string(info->tinfo.label, sizeof info->tinfo.label);

        if (pin_func(pin_data, attempt++,
                         (char *)info->sinfo.slot_description,
                         (char *)info->tinfo.label, flags, pin, sizeof(pin))) {
            gnutls_assert();
            return GNUTLS_E_PKCS11_PIN_ERROR;
        }

        rv = pakchois_login(pks, CKU_USER, (unsigned char *)pin, strlen(pin));
        /* Try to scrub the pin off the stack.  Clever compilers will
         * probably optimize this away, oh well. */
        memset(pin, 0, sizeof pin);
    } while (rv == CKR_PIN_INCORRECT);

    _gnutls_debug_log("pk11: Login result = %lu\n", rv);

    return (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) ? 0 : GNUTLS_E_PKCS11_ERROR;
}

static int find_privkeys(pakchois_session_t *pks, struct token_info* info, struct pkey_list *list)
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

    rv = pakchois_find_objects_init(pks, a, 1);
    if (rv != CKR_OK) {
        gnutls_assert();
        return GNUTLS_E_PKCS11_ERROR;
    }

    list->key_ids_size = 0;
    while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
           && count == 1) {
        list->key_ids_size++;
    }

    pakchois_find_objects_final(pks);

    if (list->key_ids_size == 0) {
        gnutls_assert();
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    list->key_ids = gnutls_malloc(sizeof(gnutls_string)*list->key_ids_size);
    if (list->key_ids == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* actual search */
    a[0].type = CKA_CLASS;
    a[0].value = &class;
    a[0].value_len = sizeof class;

    rv = pakchois_find_objects_init(pks, a, 1);
    if (rv != CKR_OK) {
        gnutls_assert();
        return GNUTLS_E_PKCS11_ERROR;
    }

    current = 0;
    while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
           && count == 1) {

        a[0].type = CKA_ID;
        a[0].value = certid_tmp;
        a[0].value_len = sizeof(certid_tmp);

        _gnutls_string_init(&list->key_ids[current], gnutls_malloc, gnutls_realloc, gnutls_free);

        if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
            _gnutls_string_append_data(&list->key_ids[current], a[0].value, a[0].value_len);
            current++;
        }

        if (current > list->key_ids_size)
            break;
    }

    pakchois_find_objects_final(pks);

    list->key_ids_size = current-1;

    return 0;
}

struct pkey_list {
    gnutls_string *key_ids;
    size_t key_ids_size;
};

int pkcs11_login(pakchois_session_t *pks, struct token_info *info)
{
    int attempt = 0;
    ck_rv_t rv;

    if (pakchois_get_token_info(info->prov->module, info->sid, &info->tinfo) != CKR_OK) {
        gnutls_assert();
        _gnutls_debug_log( "pk11: GetTokenInfo failed\n");
        return GNUTLS_E_PKCS11_ERROR;
    }

    /* force login on HW tokens. Some tokens will not list private keys
     * if login has not been performed.
     */
//    if (!(info->sinfo.flags & CKF_HW_SLOT) && (info->tinfo.flags & CKF_LOGIN_REQUIRED) == 0) {
    if ((info->tinfo.flags & CKF_LOGIN_REQUIRED) == 0) {
        gnutls_assert();
        _gnutls_debug_log( "pk11: No login required.\n");
        return 0;
    }

    /* For a token with a "protected" (out-of-band) authentication
     * path, calling login with a NULL username is all that is
     * required. */
    if (info->tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
        if (pakchois_login(pks, CKU_USER, NULL, 0) == CKR_OK) {
            return 0;
        }
        else {
            gnutls_assert();
            _gnutls_debug_log( "pk11: Protected login failed.\n");
            return GNUTLS_E_PKCS11_ERROR;
        }
    }

    /* Otherwise, PIN entry is necessary for login, so fail if there's
     * no callback. */
    if (!pin_func) {
        gnutls_assert();
        _gnutls_debug_log("pk11: No pin callback but login required.\n");
        return GNUTLS_E_PKCS11_ERROR;
    }

    terminate_string(info->sinfo.slot_description, sizeof info->sinfo.slot_description);

    do {
        char pin[GNUTLS_PKCS11_MAX_PIN_LEN];
        unsigned int flags = 0;

        /* If login has been attempted once already, check the token
         * status again, the flags might change. */
        if (attempt) {
            if (pakchois_get_token_info(info->prov->module, info->sid,
                                        &info->tinfo) != CKR_OK) {
                gnutls_assert();
                _gnutls_debug_log( "pk11: GetTokenInfo failed\n");
                return GNUTLS_E_PKCS11_ERROR;
            }
        }

        if (info->tinfo.flags & CKF_USER_PIN_COUNT_LOW)
            flags |= GNUTLS_PKCS11_PIN_COUNT_LOW;
        if (info->tinfo.flags & CKF_USER_PIN_FINAL_TRY)
            flags |= GNUTLS_PKCS11_PIN_FINAL_TRY;

        terminate_string(info->tinfo.label, sizeof info->tinfo.label);

        if (pin_func(pin_data, attempt++,
                         (char *)info->sinfo.slot_description,
                         (char *)info->tinfo.label, flags, pin, sizeof(pin))) {
            gnutls_assert();
            return GNUTLS_E_PKCS11_PIN_ERROR;
        }

        rv = pakchois_login(pks, CKU_USER, (unsigned char *)pin, strlen(pin));
        /* Try to scrub the pin off the stack.  Clever compilers will
         * probably optimize this away, oh well. */
        memset(pin, 0, sizeof pin);
    } while (rv == CKR_PIN_INCORRECT);

    _gnutls_debug_log("pk11: Login result = %lu\n", rv);

    return (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) ? 0 : GNUTLS_E_PKCS11_ERROR;
}


static int find_privkeys(pakchois_session_t *pks, struct token_info* info, struct pkey_list *list)
{
    struct ck_attribute a[3];
    ck_object_class_t class;
    ck_rv_t rv;
    ck_object_handle_t obj;
    unsigned long count, current;
    char certid_tmp[PKCS11_ID_SIZE];
    int ret;

    class = CKO_PRIVATE_KEY;

    ret = pkcs11_login(pks, info);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    /* Find an object with private key class and a certificate ID
     * which matches the certificate. */
    /* FIXME: also match the cert subject. */
    a[0].type = CKA_CLASS;
    a[0].value = &class;
    a[0].value_len = sizeof class;

    rv = pakchois_find_objects_init(pks, a, 1);
    if (rv != CKR_OK) {
        gnutls_assert();
        return GNUTLS_E_PKCS11_ERROR;
    }

    list->key_ids_size = 0;
    while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
           && count == 1) {
        list->key_ids_size++;
    }

    pakchois_find_objects_final(pks);

    if (list->key_ids_size == 0) {
        gnutls_assert();
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    list->key_ids = gnutls_malloc(sizeof(gnutls_string)*list->key_ids_size);
    if (list->key_ids == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* actual search */
    a[0].type = CKA_CLASS;
    a[0].value = &class;
    a[0].value_len = sizeof class;

    rv = pakchois_find_objects_init(pks, a, 1);
    if (rv != CKR_OK) {
        gnutls_assert();
        return GNUTLS_E_PKCS11_ERROR;
    }

    current = 0;
    while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
           && count == 1) {

        a[0].type = CKA_ID;
        a[0].value = certid_tmp;
        a[0].value_len = sizeof(certid_tmp);

        _gnutls_string_init(&list->key_ids[current], gnutls_malloc, gnutls_realloc, gnutls_free);

        if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
            _gnutls_string_append_data(&list->key_ids[current], a[0].value, a[0].value_len);
            current++;
        }

        if (current > list->key_ids_size)
            break;
    }

    pakchois_find_objects_final(pks);

    list->key_ids_size = current-1;

    return 0;
}

/* Recover certificate list from tokens */


static int find_objs(pakchois_session_t *pks, struct token_info *info, void* input)
{
    struct crt_find_data_st* find_data = input;
    struct ck_attribute a[4];
    ck_object_class_t class;
    ck_certificate_type_t type;
    bool trusted;
    ck_rv_t rv;
    ck_object_handle_t obj;
    unsigned long count;
    opaque *cert_data;
    char certid_tmp[PKCS11_ID_SIZE];
    char label_tmp[PKCS11_LABEL_SIZE];
    int ret, i;
    struct pkey_list plist; /* private key holder */
    int tot_values = 0;

    if (info == NULL) { /* final call */
        if (find_data->current <= *find_data->n_list)
            ret = 0;
        else
            ret = GNUTLS_E_SHORT_MEMORY_BUFFER;

        *find_data->n_list = find_data->current;
        
        return ret;
    }

    /* do not bother reading the token if basic fields do not match
     */
    if (find_data->info.manufacturer[0] != 0) {
        if (strcmp(find_data->info.manufacturer, info->tinfo.manufacturer_id) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->info.token[0] != 0) {
        if (strcmp(find_data->info.token, info->tinfo.label) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->info.model[0] != 0) {
        if (strcmp(find_data->info.model, info->tinfo.model) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->info.serial[0] != 0) {
        if (strcmp(find_data->info.serial, info->tinfo.serial_number) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    memset(&plist, 0, sizeof(plist));
    if (find_data->flags==GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY) {
        ret = pkcs11_login(pks, info);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }

        ret = find_privkeys(pks, info, &plist);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }

        if (plist.key_ids_size == 0) {
            gnutls_assert();
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
        }
    } else if (find_data->flags==GNUTLS_PKCS11_OBJ_ATTR_ALL) {
        ret = pkcs11_login(pks, info);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }
    }

    cert_data = gnutls_malloc(MAX_CERT_SIZE);
    if (cert_data == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Find objects with cert class and X.509 cert type. */
    
    if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL || find_data->flags==GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY) {
        class = CKO_CERTIFICATE;
        type = CKC_X_509;
        trusted = 1;

        a[0].type = CKA_CLASS;
        a[0].value = &class;
        a[0].value_len = sizeof class;

        a[1].type = CKA_CERTIFICATE_TYPE;
        a[1].value = &type;
        a[1].value_len = sizeof type;
        
        tot_values = 2;
    } else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED) {
        class = CKO_CERTIFICATE;
        type = CKC_X_509;
        trusted = 1;

        a[0].type = CKA_CLASS;
        a[0].value = &class;
        a[0].value_len = sizeof class;

        a[1].type = CKA_TRUSTED;
        a[1].value = &trusted;
        a[1].value_len = sizeof trusted;
        
        tot_values = 2;
    } else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_PUBKEY) {
        class = CKO_PUBLIC_KEY;

        a[0].type = CKA_CLASS;
        a[0].value = &class;
        a[0].value_len = sizeof class;
        
        tot_values = 1;
    } else if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_ALL) {
        tot_values = 0;
    } else {
        gnutls_assert();
        return GNUTLS_E_INVALID_REQUEST;
    }

    rv = pakchois_find_objects_init(pks, a, tot_values);
    if (rv != CKR_OK) {
        gnutls_assert();
        _gnutls_debug_log("pk11: FindObjectsInit failed.\n");
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
           && count == 1) {
        gnutls_datum_t label, id, value;

        a[0].type = CKA_LABEL;
        a[0].value = label_tmp;
        a[0].value_len = sizeof label_tmp;

        if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
            label.data = a[0].value;
            label.size = a[0].value_len;
        } else {
            label.data = NULL;
            label.size = 0;
        }

        a[0].type = CKA_ID;
        a[0].value = certid_tmp;
        a[0].value_len = sizeof certid_tmp;
        if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
            id.data = a[0].value;
            id.size = a[0].value_len;
        } else {
            id.data = NULL;
            id.size = 0;
        }        

        a[0].type = CKA_VALUE;
        a[0].value = cert_data;
        a[0].value_len = MAX_CERT_SIZE;
        if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
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

            pakchois_get_attribute_value(pks, obj, a, 1);
        }

        if (find_data->flags == GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY) {
            for (i=0;i<plist.key_ids_size;i++) {
                if (plist.key_ids[i].length != a[1].value_len || memcmp(plist.key_ids[i].data, a[1].value, a[1].value_len)!=0) {
                    /* not found */
                    continue;
                }
            }
        }

        if (find_data->current < *find_data->n_list) {
            ret = gnutls_pkcs11_obj_init(&find_data->p_list[find_data->current]);
            if (ret < 0) {
                gnutls_assert();
                goto fail;
            }

           if (class == CKO_PUBLIC_KEY) {
                ret = pkcs11_obj_import_pubkey(pks, obj, find_data->p_list[find_data->current], &id, &label, &info->tinfo);
            } else {
                ret = pkcs11_obj_import(class, find_data->p_list[find_data->current], &value, &id, &label, &info->tinfo);
            }
            if (ret < 0) {
                gnutls_assert();
                goto fail;
            }
        }
                
        find_data->current++;

    }

    gnutls_free(cert_data);
    pakchois_find_objects_final(pks);
   
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE; /* continue until all tokens have been checked */

fail:
    gnutls_free(cert_data);
    pakchois_find_objects_final(pks);
    if (plist.key_ids != NULL) {
        for (i=0;i<plist.key_ids_size;i++) {
            _gnutls_string_clear(&plist.key_ids[i]);
        }
        gnutls_free( plist.key_ids);
    }
    for (i=0;i<find_data->current;i++) {
        gnutls_pkcs11_obj_deinit(find_data->p_list[i]);
    }
    find_data->current = 0;

    return ret;
}

/**
 * gnutls_pkcs11_obj_list_import_url:
 * @p_list: An uninitialized certificate list (may be NULL)
 * @n_list: initially should hold the maximum size of the list. Will contain the actual size.
 * @url: A PKCS 11 url identifying a set of certificates
 * @flags: Attributes of type #gnutls_pkcs11_obj_attr_t that can be used to limit output
 *
 * This function will initialize and set value to a certificate list
 * specified by a PKCS 11 URL.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs11_obj_list_import_url (gnutls_pkcs11_obj_t * p_list, unsigned int *n_list, const char* url, gnutls_pkcs11_obj_attr_t flags)
{
    int ret;
    struct crt_find_data_st find_data;

    /* fill in the find data structure */
    find_data.p_list = p_list;
    find_data.n_list = n_list;
    find_data.flags = flags;
    find_data.current = 0;

    if (url == NULL || url[0] == 0) {
        url = "pkcs11:";
    }

    ret = pkcs11_url_to_info(url, &find_data.info);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = _pkcs11_traverse_tokens(find_objs, &find_data, 0);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }
    
    return 0;
}

/**
 * gnutls_x509_crt_import_pkcs11_url:
 * @crt: A certificate of type #gnutls_x509_crt_t
 * @url: A PKCS 11 url
 *
 * This function will import a PKCS 11 certificate directly from a token
 * without involving the #gnutls_pkcs11_obj_t structure. This function will
 * fail if the certificate stored is not of X.509 type.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int gnutls_x509_crt_import_pkcs11_url( gnutls_x509_crt_t crt, const char* url)
{
    gnutls_pkcs11_obj_t pcrt;
    int ret;
    
    ret = gnutls_pkcs11_obj_init ( &pcrt);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = gnutls_pkcs11_obj_import_url (pcrt, url);
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
 * @pkcs11_obj: A PKCS 11 object that contains a certificate
 *
 * This function will import a PKCS 11 certificate to a #gnutls_x509_crt_t
 * structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int gnutls_x509_crt_import_pkcs11( gnutls_x509_crt_t crt, gnutls_pkcs11_obj_t pkcs11_crt)
{
    return gnutls_x509_crt_import(crt, &pkcs11_crt->raw, GNUTLS_X509_FMT_DER);
}

int gnutls_x509_crt_list_import_pkcs11 (gnutls_x509_crt_t * certs,
    unsigned int cert_max, gnutls_pkcs11_obj_t * const pkcs11_certs,
    unsigned int flags)
{
    int i, j;
    int ret;
    
    for (i=0;i<cert_max;i++) {
        ret = gnutls_x509_crt_init(&certs[i]);
        if (ret < 0) {
            gnutls_assert();
            goto cleanup;
        }
        
        ret = gnutls_x509_crt_import_pkcs11( certs[i], pkcs11_certs[i]);
        if (ret < 0) {
            gnutls_assert();
            goto cleanup;
        }
    }
    
    return 0;
    
cleanup:
    for (j=0;j<i;j++) {
        gnutls_x509_crt_deinit(certs[j]);
    }
    
    return ret;
}

static int find_flags(pakchois_session_t *pks, struct token_info *info, void* input)
{
    struct flags_find_data_st* find_data = input;

    if (info == NULL) { /* we don't support multiple calls */
        gnutls_assert();
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    /* do not bother reading the token if basic fields do not match
     */
    if (find_data->info.manufacturer[0] != 0) {
        if (strcmp(find_data->info.manufacturer, info->tinfo.manufacturer_id) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->info.token[0] != 0) {
        if (strcmp(find_data->info.token, info->tinfo.label) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->info.model[0] != 0) {
        if (strcmp(find_data->info.model, info->tinfo.model) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    if (find_data->info.serial[0] != 0) {
        if (strcmp(find_data->info.serial, info->tinfo.serial_number) != 0)
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    /* found token! */

    find_data->slot_flags = info->sinfo.flags;

    return 0;
}

/**
 * gnutls_pkcs11_token_get_flags:
 * @url: should contain a PKCS 11 URL
 * @flags: The output flags
 *
 * This function will return information about the PKCS 11 token flags.
 *
 * Returns: zero on success or a negative value on error.
 **/
int gnutls_pkcs11_token_get_flags(const char* url, unsigned int *flags)
{
    struct flags_find_data_st find_data;
    int ret;

    ret = pkcs11_url_to_info(url, &find_data.info);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = _pkcs11_traverse_tokens(find_flags, &find_data, 0);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    *flags = 0;
    if (find_data.slot_flags & CKF_HW_SLOT)
        *flags |= GNUTLS_PKCS11_TOKEN_HW;

    return 0;

}


const char* gnutls_pkcs11_type_get_name (gnutls_pkcs11_obj_type_t type)
{
    switch(type) {
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
