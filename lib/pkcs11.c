/*
   neon PKCS#11 support
   Copyright (C) 2008, Joe Orton <joe@manyfish.co.uk>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA
*/

#include <gnutls_int.h>
#include <pakchois/pakchois.h>
#include <gnutls/pkcs11.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>

#define MAX_PROVIDERS 16
#define ID_SIZE 128
#define LABEL_SIZE 128

/* XXX: try to eliminate this */
#define MAX_CERT_SIZE 8*1024

struct gnutls_pkcs11_provider_s {
    pakchois_module_t *module;
    unsigned long nslots;
    ck_slot_id_t *slots;
};


struct pkcs11_url_info
{
    /* everything here is null terminated strings */
    opaque id[ID_SIZE*3+1]; /* hex with delimiters */
    opaque type[16]; /* cert/key etc. */
    opaque manufacturer[sizeof (((struct ck_token_info *)NULL)->manufacturer_id)+1];
    opaque token[sizeof (((struct ck_token_info *)NULL)->label)+1];
    opaque serial[sizeof (((struct ck_token_info *)NULL)->serial_number)+1];
    opaque model[sizeof (((struct ck_token_info *)NULL)->model)+1];
    opaque label[LABEL_SIZE+1];
};

struct gnutls_pkcs11_crt_st {
    gnutls_datum_t raw;
    gnutls_certificate_type_t type;
    struct pkcs11_url_info info;
};

struct url_find_data_st {
    gnutls_pkcs11_crt_t crt;
    char certid_raw[ID_SIZE];
    size_t certid_raw_size;
};

struct crt_find_data_st {
    gnutls_pkcs11_crt_t *p_list;
    unsigned int* n_list;
    unsigned int current;
    gnutls_pkcs11_crt_attr_t flags;
    struct pkcs11_url_info info;
};

struct token_info {
    struct ck_token_info tinfo;
    struct ck_slot_info sinfo;
    ck_slot_id_t sid;
    struct gnutls_pkcs11_provider_s* prov;
};

/* thus function is called for every token in the traverse_tokens
 * function. Once everything is traversed it is called with NULL tinfo.
 * It should return 0 if found what it was looking for.
 */
typedef int (*find_func_t)(pakchois_session_t *pks, struct token_info* tinfo, void* input);

static struct gnutls_pkcs11_provider_s providers[MAX_PROVIDERS];
static int active_providers = 0;

static gnutls_pkcs11_pin_callback_t pin_func;
static void* pin_data;

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

/* returns strings of the PKCS#11 certificate structure.
 * Returns null terminated strings but output_size contains
 * the size of the actual data only.
 */
int gnutls_pkcs11_crt_get_info(gnutls_pkcs11_crt_t crt, gnutls_pkcs11_cert_info_t itype,
    void* output, size_t* output_size)
{
    const char* str;
    size_t len;

    switch(itype) {
        case GNUTLS_PKCS11_CRT_ID_HEX:
            str = crt->info.id;
            break;
        case GNUTLS_PKCS11_CRT_LABEL:
            str = crt->info.label;
            break;
        case GNUTLS_PKCS11_CRT_TOKEN_LABEL:
            str = crt->info.token;
            break;
        case GNUTLS_PKCS11_CRT_TOKEN_SERIAL:
            str = crt->info.serial;
            break;
        case GNUTLS_PKCS11_CRT_TOKEN_MANUFACTURER:
            str = crt->info.manufacturer;
            break;
        case GNUTLS_PKCS11_CRT_TOKEN_MODEL:
            str = crt->info.model;
            break;
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


int gnutls_pkcs11_init(unsigned int flags, const char* configfile)
{
    int ret;
    
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

void gnutls_pkcs11_deinit (void)
{
    int i;
    
    for (i=0;i<active_providers;i++) {
        pakchois_module_destroy(providers[i].module);
    }
    active_providers = 0;
}

void gnutls_pkcs11_set_pin_function(gnutls_pkcs11_pin_callback_t fn,
                                void *userdata)
{
    pin_func = fn;
    pin_data = userdata;
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

static int pkcs11_url_to_info(const char* url, struct pkcs11_url_info* info)
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


static int pkcs11_info_to_url(const struct pkcs11_url_info* info, char** url)
{
    gnutls_string str;
    int init = 0;
    int ret;
    char *s;
    
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

int gnutls_pkcs11_crt_init(gnutls_pkcs11_crt_t * crt)
{
    *crt = gnutls_malloc(sizeof(struct gnutls_pkcs11_crt_st));
    if (*crt == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }
 
}

void gnutls_pkcs11_crt_deinit(gnutls_pkcs11_crt_t crt)
{
    free(crt);
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


static int traverse_tokens (find_func_t find_func, void* input)
{
    struct ck_attribute a[3];
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
            
            pakchois_close_session(pks);
            pks = NULL;
            
            if (ret == 0) {
                found = 1;
                goto finish;
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

cleanup:
    if (pks != NULL) pakchois_close_session(pks);
   
    return ret;
}

/* imports a raw certificate from a token to a pkcs11_crt_t structure.
 */
static int pkcs11_crt_import(gnutls_pkcs11_crt_t crt, const gnutls_datum_t* data, 
   const gnutls_datum_t * id, const gnutls_datum_t * label, struct ck_token_info* tinfo)
{
    char *s;
    int ret;
    
    crt->type = GNUTLS_CRT_X509;
    ret = _gnutls_set_datum(&crt->raw, data->data, data->size);
    if (ret < 0) {
        gnutls_assert();
        return ret;
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

    memcpy(crt->info.label, label->data, label->size);
    crt->info.label[label->size] = 0;

    strcpy(crt->info.type, "cert");
    
    s = _gnutls_bin2hex(id->data, id->size, crt->info.id, sizeof(crt->info.id), ":");
    if (s == NULL) {
        gnutls_assert();
        return GNUTLS_E_PKCS11_ERROR;
    }

    return 0;
}


static int find_cert_url(pakchois_session_t *pks, struct token_info *info, void* input)
{
    struct url_find_data_st* find_data = input;
    struct ck_attribute a[4];
    ck_object_class_t class;
    ck_certificate_type_t type;
    ck_rv_t rv;
    ck_object_handle_t obj;
    unsigned long count;
    int found = 0, ret;
    unsigned char value[MAX_CERT_SIZE];
    char certid_tmp[ID_SIZE];
    char label_tmp[LABEL_SIZE];
    
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

    if (find_data->crt->info.type[0] != 0) {
        if (strcmp(find_data->crt->info.type, "cert") != 0) {
            gnutls_assert();
            return GNUTLS_E_UNIMPLEMENTED_FEATURE;
        }
    }

    /* search the token for the id */
    
    /* Find objects with cert class and X.509 cert type. */
    class = CKO_CERTIFICATE;
    type = CKC_X_509;

    a[0].type = CKA_CLASS;
    a[0].value = &class;
    a[0].value_len = sizeof class;
    a[1].type = CKA_CERTIFICATE_TYPE;
    a[1].value = &type;
    a[1].value_len = sizeof type;

        
    rv = pakchois_find_objects_init(pks, a, 2);
    if (rv != CKR_OK) {
        gnutls_assert();
        _gnutls_debug_log("pk11: FindObjectsInit failed.\n");
        ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
        goto cleanup;
    }

    while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
           && count == 1) {

        a[0].type = CKA_VALUE;
        a[0].value = value;
        a[0].value_len = sizeof value;
        a[1].type = CKA_ID;
        a[1].value = certid_tmp;
        a[1].value_len = sizeof(certid_tmp);
        a[2].type = CKA_LABEL;
        a[2].value = label_tmp;
        a[2].value_len = sizeof(label_tmp);

        if (pakchois_get_attribute_value(pks, obj, a, 3) == CKR_OK) {
            if (a[1].value_len == find_data->certid_raw_size && 
                memcmp(certid_tmp, find_data->certid_raw, find_data->certid_raw_size)==0) {
                gnutls_datum_t id = { a[1].value, a[1].value_len };
                gnutls_datum_t data = { a[0].value, a[0].value_len };
                gnutls_datum_t label = { a[2].value, a[2].value_len };
                
                ret = pkcs11_crt_import(find_data->crt, &data, &id, &label, &info->tinfo);
                if (ret < 0) {
                    gnutls_assert();
                    goto cleanup;
                }

                found = 1;
                break;
            }
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
    pakchois_find_objects_final(pks);
    
    return ret;
}

int gnutls_pkcs11_crt_import_url (gnutls_pkcs11_crt_t cert, const char * url)
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

    find_data.certid_raw_size = sizeof(find_data.certid_raw);
    
    ret = _gnutls_hex2bin(cert->info.id, strlen(cert->info.id), find_data.certid_raw, &find_data.certid_raw_size);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = traverse_tokens(find_cert_url, &find_data);
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

int gnutls_pkcs11_token_get_url (unsigned int seq, char** url)
{
    int ret;
    struct token_num tn;

    memset(&tn, 0, sizeof(tn));
    tn.seq = seq;

    ret = traverse_tokens(find_token_num, &tn);
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


int gnutls_pkcs11_crt_export_url (gnutls_pkcs11_crt_t cert, char ** url)
{
int ret;

    ret = pkcs11_info_to_url(&cert->info, url);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }
    
    return 0;
}

gnutls_certificate_type_t gnutls_pkcs11_crt_get_type (gnutls_pkcs11_crt_t certificate)
{
    return certificate->type;
}

struct pkey_list {
    gnutls_string *key_ids;
    size_t key_ids_size;
};

static int pk11_login(pakchois_session_t *pks, struct token_info *info)
{
    struct ck_token_info tinfo;
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
    if (!(info->sinfo.flags & CKF_HW_SLOT) && (tinfo.flags & CKF_LOGIN_REQUIRED) == 0) {
        gnutls_assert();
        _gnutls_debug_log( "pk11: No login required.\n");
        return 0;
    }

    /* For a token with a "protected" (out-of-band) authentication
     * path, calling login with a NULL username is all that is
     * required. */
    if (tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
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
    char certid_tmp[ID_SIZE];
    int ret;

    class = CKO_PRIVATE_KEY;

    ret = pk11_login(pks, info);
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


static int find_crts(pakchois_session_t *pks, struct token_info *info, void* input)
{
    struct crt_find_data_st* find_data = input;
    struct ck_attribute a[4];
    ck_object_class_t class;
    ck_certificate_type_t type;
    bool trusted;
    ck_rv_t rv;
    ck_object_handle_t obj;
    unsigned long count;
    unsigned char value[MAX_CERT_SIZE];
    char certid_tmp[ID_SIZE];
    char label_tmp[LABEL_SIZE];
    int ret, i;
    struct pkey_list plist; /* private key holder */

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

    if (find_data->info.type[0] != 0) {
        if (strcmp(find_data->info.type, "cert") != 0) {
            gnutls_assert();
            return GNUTLS_E_UNIMPLEMENTED_FEATURE;
        }
    }

    memset(&plist, 0, sizeof(plist));
    if (find_data->flags==GNUTLS_PKCS11_CRT_ATTR_WITH_PK) {
        ret = find_privkeys(pks, info, &plist);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }

        if (plist.key_ids_size == 0) {
            gnutls_assert();
            return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
        }
    }

    /* Find objects with cert class and X.509 cert type. */
    class = CKO_CERTIFICATE;
    type = CKC_X_509;
    trusted = 1;

    a[0].type = CKA_CLASS;
    a[0].value = &class;
    a[0].value_len = sizeof class;
    
    if (find_data->flags == GNUTLS_PKCS11_CRT_ATTR_ALL || find_data->flags==GNUTLS_PKCS11_CRT_ATTR_WITH_PK) {
        a[1].type = CKA_CERTIFICATE_TYPE;
        a[1].value = &type;
        a[1].value_len = sizeof type;
    }

    if (find_data->flags == GNUTLS_PKCS11_CRT_ATTR_TRUSTED) {
        a[1].type = CKA_TRUSTED;
        a[1].value = &trusted;
        a[1].value_len = sizeof trusted;
    }

    rv = pakchois_find_objects_init(pks, a, 2);
    if (rv != CKR_OK) {
        gnutls_assert();
        _gnutls_debug_log("pk11: FindObjectsInit failed.\n");
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

    while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
           && count == 1) {

        a[0].type = CKA_VALUE;
        a[0].value = value;
        a[0].value_len = sizeof value;
        a[1].type = CKA_ID;
        a[1].value = certid_tmp;
        a[1].value_len = sizeof(certid_tmp);
        a[2].type = CKA_LABEL;
        a[2].value = label_tmp;
        a[2].value_len = sizeof label_tmp;

        if (pakchois_get_attribute_value(pks, obj, a, 3) == CKR_OK) {
            gnutls_datum_t data = { a[0].value, a[0].value_len };
            gnutls_datum_t id = { a[1].value, a[1].value_len };
            gnutls_datum_t label = { a[2].value, a[2].value_len };

            /* XXX check also ID with find_data->info.id */

            if (find_data->flags == GNUTLS_PKCS11_CRT_ATTR_WITH_PK) {
                for (i=0;i<plist.key_ids_size;i++) {
                    if (plist.key_ids[i].length != a[1].value_len || memcmp(plist.key_ids[i].data, a[1].value, a[1].value_len)!=0) {
                        /* not found */
                        continue;
                    }
                }
            }

            if (find_data->current < *find_data->n_list) {

                ret = gnutls_pkcs11_crt_init(&find_data->p_list[find_data->current]);
                if (ret < 0) {
                    gnutls_assert();
                    goto fail;
                }

                ret = pkcs11_crt_import(find_data->p_list[find_data->current], &data, &id, &label, &info->tinfo);
                if (ret < 0) {
                    gnutls_assert();
                    goto fail;
                }
            }
            
            find_data->current++;

        }
        else {
            _gnutls_debug_log("pk11: Skipped cert, missing attrs.\n");
        }
    }

    pakchois_find_objects_final(pks);
   
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE; /* continue until all tokens have been checked */

fail:
    pakchois_find_objects_final(pks);
    if (plist.key_ids != NULL) {
        for (i=0;i<plist.key_ids_size;i++) {
            _gnutls_string_clear(&plist.key_ids[i]);
        }
        gnutls_free( plist.key_ids);
    }
    for (i=0;i<find_data->current;i++) {
        gnutls_pkcs11_crt_deinit(find_data->p_list[i]);
    }
    find_data->current = 0;

    return ret;
}

int gnutls_pkcs11_crt_list_import_url (gnutls_pkcs11_crt_t * p_list, unsigned int *n_list, const char* url, gnutls_pkcs11_crt_attr_t flags)
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

    ret = traverse_tokens(find_crts, &find_data);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }
    
    return 0;
}

int gnutls_x509_crt_import_pkcs11_url( gnutls_x509_crt_t crt, const char* url)
{
    gnutls_pkcs11_crt_t pcrt;
    int ret;

    ret = gnutls_pkcs11_crt_init ( &pcrt);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = gnutls_pkcs11_crt_import_url (pcrt, url);
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

    gnutls_pkcs11_crt_deinit(pcrt);

    return ret;
}



int gnutls_x509_crt_import_pkcs11( gnutls_x509_crt_t crt, gnutls_pkcs11_crt_t pkcs11_crt)
{
    return gnutls_x509_crt_import(crt, &pkcs11_crt->raw, GNUTLS_X509_FMT_DER);
}

int gnutls_x509_crt_list_import_pkcs11 (gnutls_x509_crt_t * certs,
    unsigned int cert_max, gnutls_pkcs11_crt_t * const pkcs11_certs,
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


/* To do list for PKCS#11 support:

   - propagate error strings back to ne_session; use new 
   pakchois_error() for pakchois API 0.2
   - add API to specify a particular slot number to use for clicert
   - add API to specify a particular cert ID for clicert
   - find a certificate which has an issuer matching the 
     CA dnames given by GnuTLS
   - make sure subject name matches between pubkey and privkey
   - check error handling & fail gracefully if the token is 
   ejected mid-session
   - add API to enumerate/search provided certs and allow 
     direct choice? (or just punt)
   - the session<->provider interface requires that 
   one clicert is used for all sessions.  remove this limitation
   - add API to import all CA certs as trusted
   (CKA_CERTIFICATE_CATEGORY seems to be unused unfortunately; 
    just add all X509 certs with CKA_TRUSTED set to true))
   - make DSA work

*/


#if 0
#define KEYTYPE_IS_DSA(kt) (kt == CKK_DSA)


static int find_client_cert(ne_ssl_pkcs11_provider *prov,
                            pakchois_session_t *pks)
{
    unsigned char certid[8192];
    unsigned long cid_len = sizeof certid;

    /* TODO: match cert subject too. */
    return pk11_find_x509(prov, pks, certid, &cid_len) 
        && pk11_find_pkey(prov, pks, certid, cid_len);
}

/* Callback invoked by GnuTLS to provide the signature.  The signature
 * operation is handled here by the PKCS#11 provider.  */
static int pk11_sign_callback(gnutls_session_t session,
                              void *userdata,
                              gnutls_certificate_type_t cert_type,
                              const gnutls_datum_t *cert,
                              const gnutls_datum_t *hash,
                              gnutls_datum_t *signature)
{
    ne_ssl_pkcs11_provider *prov = userdata;
    ck_rv_t rv;
    struct ck_mechanism mech;
    unsigned long siglen;

    if (!prov->session || prov->privkey == CK_INVALID_HANDLE) {
        NE_DEBUG(NE_DBG_SSL, "pk11: Cannot sign, no session/key.\n");
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

    mech.mechanism = prov->keytype == CKK_DSA ? CKM_DSA : CKM_RSA_PKCS;
    mech.parameter = NULL;
    mech.parameter_len = 0;

    /* Initialize signing operation; using the private key discovered
     * earlier. */
    rv = pakchois_sign_init(prov->session, &mech, prov->privkey);
    if (rv != CKR_OK) {
        NE_DEBUG(NE_DBG_SSL, "pk11: SignInit failed: %lx.\n", rv);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Work out how long the signature must be: */
    rv = pakchois_sign(prov->session, hash->data, hash->size, NULL, &siglen);
    if (rv != CKR_OK) {
        NE_DEBUG(NE_DBG_SSL, "pk11: Sign1 failed.\n");
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    signature->data = gnutls_malloc(siglen);
    signature->size = siglen;

    rv = pakchois_sign(prov->session, hash->data, hash->size, 
                       signature->data, &siglen);
    if (rv != CKR_OK) {
        NE_DEBUG(NE_DBG_SSL, "pk11: Sign2 failed.\n");
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    NE_DEBUG(NE_DBG_SSL, "pk11: Signed successfully.\n");

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


static void pk11_provide(void *userdata, ne_session *sess,
                         const ne_ssl_dname *const *dnames,
                         int dncount)
{
    ne_ssl_pkcs11_provider *prov = userdata;
    ck_slot_id_t *slots;
    unsigned long scount, n;

    if (prov->clicert) {
        NE_DEBUG(NE_DBG_SSL, "pk11: Using existing clicert.\n");
        ne_ssl_set_clicert(sess, prov->clicert);
        return;
    }

    if (pakchois_get_slot_list(prov->module, 1, NULL, &scount) != CKR_OK
        || scount == 0) {
        NE_DEBUG(NE_DBG_SSL, "pk11: No slots.\n");
        /* TODO: propagate error. */
        return;
    }

    slots = ne_malloc(scount * sizeof *slots);
    if (pakchois_get_slot_list(prov->module, 1, slots, &scount) != CKR_OK)  {
        ne_free(slots);
        NE_DEBUG(NE_DBG_SSL, "pk11: Really, no slots?\n");
        /* TODO: propagate error. */
        return;
    }

    NE_DEBUG(NE_DBG_SSL, "pk11: Found %ld slots.\n", scount);

    for (n = 0; n < scount; n++) {
        pakchois_session_t *pks;
        ck_rv_t rv;
        struct ck_slot_info sinfo;

        if (pakchois_get_slot_info(prov->module, slots[n], &sinfo) != CKR_OK) {
            NE_DEBUG(NE_DBG_SSL, "pk11: GetSlotInfo failed\n");
            continue;
        }

        if ((sinfo.flags & CKF_TOKEN_PRESENT) == 0) {
            NE_DEBUG(NE_DBG_SSL, "pk11: slot empty, ignoring\n");
            continue;
        }
        
        rv = pakchois_open_session(prov->module, slots[n], 
                                   CKF_SERIAL_SESSION,
                                   NULL, NULL, &pks);
        if (rv != CKR_OK) {
            NE_DEBUG(NE_DBG_SSL, "pk11: could not open slot, %ld (%ld: %ld)\n", 
                     rv, n, slots[n]);
            continue;
        }

        if (pk11_login(prov, slots[n], pks, &sinfo) == 0) {
            if (find_client_cert(prov, pks)) {
                NE_DEBUG(NE_DBG_SSL, "pk11: Setup complete.\n");
                prov->session = pks;
                ne_ssl_set_clicert(sess, prov->clicert);
                ne_free(slots);
                return;
            }
        }

        pakchois_close_session(pks);
    }

    ne_free(slots);
}



void ne_ssl_set_pkcs11_provider(ne_session *sess, 
                                ne_ssl_pkcs11_provider *provider)
{
    sess->ssl_context->sign_func = pk11_sign_callback;
    sess->ssl_context->sign_data = provider;

    ne_ssl_provide_clicert(sess, pk11_provide, provider);
}

void ne_ssl_pkcs11_provider_destroy(ne_ssl_pkcs11_provider *prov)
{
    if (prov->session) {
        pakchois_close_session(prov->session);
    }
    if (prov->clicert) {
        ne_ssl_clicert_free(prov->clicert);
    }
    pakchois_module_destroy(prov->module);
    ne_free(prov);
}

#endif


