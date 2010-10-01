/*
 * Copyright (C) 2010 Free Software Foundation, Inc.
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>
#include <stdio.h>
#include <stdlib.h>
#include "certtool-common.h"
#include "certtool-cfg.h"
#include <unistd.h>
#include <string.h>

#define MIN(x,y) ((x)<(y))?(x):(y)

static int pin_callback(void* user, int attempt, const char *token_url,
	const char *token_label, unsigned int flags, char* pin, size_t pin_max)
{
const char* password;
int len;
/* allow caching of PIN */
static char* cached_url = NULL;
static char cached_pin[32] = "";

	printf("PIN required for token '%s' with URL '%s'\n", token_label, token_url);
	if (flags & GNUTLS_PKCS11_PIN_FINAL_TRY)
		printf("*** This is the final try before locking!\n");
	if (flags & GNUTLS_PKCS11_PIN_COUNT_LOW)
		printf("*** Only few tries left before locking!\n");
	
	if (flags == 0 && cached_url != NULL) {
		if (strcmp(cached_url, token_url)==0) {
			strcpy(pin, cached_pin);
			return 0;
		}
	}
	
	password = getpass("Enter pin: ");
	if (password==NULL || password[0] == 0) {
		fprintf(stderr, "No password given\n");
		exit(1);
	}
	
	len = MIN(pin_max,strlen(password));
	memcpy(pin, password, len);
	pin[len] = 0;
	
	/* cache */
	strcpy(cached_pin, pin);
	free(cached_url);
	cached_url = strdup(token_url);
	
	return 0;
}

static void pkcs11_common(void)
{

	gnutls_pkcs11_set_pin_function (pin_callback, NULL);

}

void pkcs11_delete(FILE* outfile, const char* url, int batch, unsigned int login)
{
int ret;
unsigned int obj_flags = 0;

	if (login)
		obj_flags = GNUTLS_PKCS11_OBJ_FLAG_LOGIN;

	if (!batch) {
		pkcs11_list(outfile, url, PKCS11_TYPE_ALL, login, GNUTLS_PKCS11_URL_LIB);
		ret = read_yesno("Are you sure you want to delete those objects? (y/N): ");
		if (ret == 0) {
			exit(1);
		}
	}
	
	ret = gnutls_pkcs11_delete_url(url, obj_flags);
	if (ret < 0) {
		fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
		exit(1);
	}
	
	fprintf(outfile, "\n%d objects deleted\n", ret);
	
	return;
}
                                                                                                                                                
/* lists certificates from a token
 */
void pkcs11_list( FILE* outfile, const char* url, int type, unsigned int login, unsigned int detailed)
{
gnutls_pkcs11_obj_t *crt_list;
gnutls_x509_crt_t xcrt;
unsigned int crt_list_size = 0;
int ret;
char* output;
int i, attrs;
unsigned int obj_flags = 0;

	if (login)
		obj_flags = GNUTLS_PKCS11_OBJ_FLAG_LOGIN;

	pkcs11_common();

	if (url == NULL)
		url = "pkcs11:";

	if (type == PKCS11_TYPE_TRUSTED) {
		attrs = GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED;
	} else if (type == PKCS11_TYPE_PK) {
		attrs = GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY;
	} else if (type == PKCS11_TYPE_CRT_ALL) {
		attrs = GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL;
	} else if (type == PKCS11_TYPE_PRIVKEY) {
		attrs = GNUTLS_PKCS11_OBJ_ATTR_PRIVKEY;
	} else {
		attrs = GNUTLS_PKCS11_OBJ_ATTR_ALL;
	}
		
	/* give some initial value to avoid asking for the pkcs11 pin twice.
	 */
	crt_list_size = 128;
	crt_list = malloc(sizeof(*crt_list)*crt_list_size);
	if (crt_list == NULL) {
		fprintf(stderr, "Memory error\n");
		exit(1);
	}

	ret = gnutls_pkcs11_obj_list_import_url( crt_list, &crt_list_size, url, 
		attrs, obj_flags);
	if (ret < 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		fprintf(stderr, "Error in crt_list_import (1): %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	if (crt_list_size == 0) {
		fprintf(stderr, "No matching objects found\n");
		exit(0);
	}
	
	if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
		crt_list = realloc(crt_list, sizeof(*crt_list)*crt_list_size);
		if (crt_list == NULL) {
			fprintf(stderr, "Memory error\n");
			exit(1);
		}

		ret = gnutls_pkcs11_obj_list_import_url( crt_list, &crt_list_size, url, attrs, obj_flags);
		if (ret < 0) {
			fprintf(stderr, "Error in crt_list_import: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	}
	
	for (i=0;i<crt_list_size;i++) {
		char buf[128];
		size_t size;
		
		ret = gnutls_pkcs11_obj_export_url(crt_list[i], detailed, &output);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		fprintf(outfile, "Object %d:\n\tURL: %s\n", i, output);

		fprintf(outfile, "\tType: %s\n", gnutls_pkcs11_type_get_name(gnutls_pkcs11_obj_get_type( crt_list[i])));
		
		size = sizeof(buf);
		ret = gnutls_pkcs11_obj_get_info( crt_list[i], GNUTLS_PKCS11_OBJ_LABEL, buf, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}
		fprintf(outfile, "\tLabel: %s\n", buf);

		size = sizeof(buf);
		ret = gnutls_pkcs11_obj_get_info( crt_list[i], GNUTLS_PKCS11_OBJ_ID_HEX, buf, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}
		fprintf(outfile, "\tID: %s\n\n", buf);
		
		

		if (attrs == GNUTLS_PKCS11_OBJ_ATTR_ALL || attrs == GNUTLS_PKCS11_OBJ_ATTR_PRIVKEY)
			continue;

		ret = gnutls_x509_crt_init(&xcrt);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		ret = gnutls_x509_crt_import_pkcs11(xcrt, crt_list[i]);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

#if 0
		size = buffer_size;
		ret = gnutls_x509_crt_export (xcrt, GNUTLS_X509_FMT_PEM, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		fwrite (buffer, 1, size, outfile);
		fputs("\n\n", outfile);
#endif

		gnutls_x509_crt_deinit(xcrt);


	}
	
	return;
}

void pkcs11_export(FILE* outfile, const char* url, unsigned int login)
{
gnutls_pkcs11_obj_t crt;
gnutls_x509_crt_t xcrt;
gnutls_pubkey_t pubkey;
int ret;
size_t size;
unsigned int obj_flags = 0;

	if (login)
		obj_flags = GNUTLS_PKCS11_OBJ_FLAG_LOGIN;

	pkcs11_common();

	if (url == NULL)
		url = "pkcs11:";

	ret = gnutls_pkcs11_obj_init(&crt);
	if (ret < 0) {
		fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
		exit(1);
	}

	ret = gnutls_pkcs11_obj_import_url( crt, url, obj_flags);
	if (ret < 0) {
		fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
		exit(1);
	}

	switch(gnutls_pkcs11_obj_get_type(crt)) {
		case GNUTLS_PKCS11_OBJ_X509_CRT:
			ret = gnutls_x509_crt_init(&xcrt);
			if (ret < 0) {
				fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
				exit(1);
			}

			ret = gnutls_x509_crt_import_pkcs11(xcrt, crt);
			if (ret < 0) {
				fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
				exit(1);
			}

			size = buffer_size;
			ret = gnutls_x509_crt_export (xcrt, GNUTLS_X509_FMT_PEM, buffer, &size);
			if (ret < 0) {
				fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
				exit(1);
			}
			fwrite (buffer, 1, size, outfile);

			gnutls_x509_crt_deinit(xcrt);
			break;
		case GNUTLS_PKCS11_OBJ_PUBKEY:
			ret = gnutls_pubkey_init(&pubkey);
			if (ret < 0) {
				fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
				exit(1);
			}

			ret = gnutls_pubkey_import_pkcs11(pubkey, crt, 0);
			if (ret < 0) {
				fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
				exit(1);
			}

			size = buffer_size;
			ret = gnutls_pubkey_export (pubkey, GNUTLS_X509_FMT_PEM, buffer, &size);
			if (ret < 0) {
				fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
				exit(1);
			}
			fwrite (buffer, 1, size, outfile);

			gnutls_pubkey_deinit(pubkey);
			break;
		default: {
			gnutls_datum data, enc;

			size = buffer_size;
			ret = gnutls_pkcs11_obj_export (crt, buffer, &size);
			if (ret < 0) {
				break;
			}

			data.data = buffer;
			data.size = size;

			ret = gnutls_pem_base64_encode_alloc("DATA", &data, &enc);
			if (ret < 0) {
				fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
				exit(1);
			}

			fwrite (enc.data, 1, enc.size, outfile);

			gnutls_free(enc.data);
			break;
		}
	}
	fputs("\n\n", outfile);


	gnutls_pkcs11_obj_deinit(crt);

	return;

}

void pkcs11_token_list(FILE* outfile, unsigned int detailed)
{
int ret;
int i;
char *url;
char buf[128];
size_t size;

	pkcs11_common();

	for (i=0;;i++) {
		ret = gnutls_pkcs11_token_get_url(i, detailed, &url);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;

		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		fprintf(outfile, "Token %d:\n\tURL: %s\n", i, url);

		size = sizeof(buf);
		ret = gnutls_pkcs11_token_get_info(url, GNUTLS_PKCS11_TOKEN_LABEL, buf, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		fprintf(outfile, "\tLabel: %s\n", buf);

		size = sizeof(buf);
		ret = gnutls_pkcs11_token_get_info(url, GNUTLS_PKCS11_TOKEN_MANUFACTURER, buf, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		fprintf(outfile, "\tManufacturer: %s\n", buf);

		size = sizeof(buf);
		ret = gnutls_pkcs11_token_get_info(url, GNUTLS_PKCS11_TOKEN_MODEL, buf, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		fprintf(outfile, "\tModel: %s\n", buf);

		size = sizeof(buf);
		ret = gnutls_pkcs11_token_get_info(url, GNUTLS_PKCS11_TOKEN_SERIAL, buf, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		fprintf(outfile, "\tSerial: %s\n", buf);
		fprintf(outfile, "\n\n");

		gnutls_free(url);

	}

	return;
}

void pkcs11_write(FILE* outfile, const char* url, const char* label, int trusted, unsigned int login)
{
gnutls_x509_crt_t xcrt;
gnutls_x509_privkey_t xkey;
int ret;
unsigned int flags = 0;
unsigned int key_usage;

	if (login)
		flags = GNUTLS_PKCS11_OBJ_FLAG_LOGIN;

	pkcs11_common();

	if (url == NULL)
		url = "pkcs11:";

	xcrt = load_cert(0);
	if (xcrt != NULL) {
		if (trusted)
			flags |= GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED;
		ret = gnutls_pkcs11_copy_x509_crt(url, xcrt, label, flags);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}

		gnutls_x509_crt_get_key_usage(xcrt, &key_usage, NULL);
	}

	xkey = load_private_key(0);
	if (xkey != NULL) {
		ret = gnutls_pkcs11_copy_x509_privkey(url, xkey, label, key_usage, flags|GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE);
		if (ret < 0) {
			fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
			exit(1);
		}
	}

	if (xkey == NULL && xcrt == NULL) {
		fprintf(stderr, "You must use --load-privkey or --load-certificate to load the file to be copied\n");
		exit (1);
	}

	return;
}
