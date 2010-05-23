#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>
#include <stdio.h>
#include <stdlib.h>
#include "certtool-common.h"
#include "certtool-cfg.h"
#include <string.h>

#define MIN(x,y) ((x)<(y))?(x):(y)

static int pin_callback(void* user, int attempt, const char *slot_descr,
	const char *token_label, unsigned int flags, char* pin, size_t pin_max)
{
const char* password;
int len;

	printf("PIN required for token '%s' in slot '%s'\n", token_label, slot_descr);
	if (flags & GNUTLS_PKCS11_PIN_FINAL_TRY)
		printf("*** This is the final try before locking!\n");
	if (flags & GNUTLS_PKCS11_PIN_COUNT_LOW)
		printf("*** Only few tries left before locking!\n");

	password = get_pass();
	if (password==NULL) {
		fprintf(stderr, "No password given\n");
		exit(1);
	}

	len = MIN(pin_max,strlen(password));
	memcpy(pin, password, len);
	pin[len] = 0;
	
	return 0;
}

static void pkcs11_common(void)
{

	gnutls_pkcs11_set_pin_function (pin_callback, NULL);

}

void pkcs11_delete(FILE* outfile, const char* url, int batch)
{
int ret;
	if (!batch) {
		pkcs11_list(outfile, url, PKCS11_TYPE_ALL);
		ret = read_yesno("Are you sure you want to delete those objects? (Y/N): ");
		if (ret == 0) {
			exit(1);
		}
	}
	
	ret = gnutls_pkcs11_delete_url(url);
	if (ret < 0) {
		fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
		exit(1);
	}
	
	fprintf(outfile, "\n%d objects deleted\n", ret);
	
	return;
}
                                                                                                                                                
/* lists certificates from a token
 */
void pkcs11_list( FILE* outfile, const char* url, int type)
{
gnutls_pkcs11_obj_t *crt_list;
gnutls_x509_crt_t xcrt;
unsigned int crt_list_size = 0;
int ret;
char* output;
int i, flags;

	pkcs11_common();

	if (url == NULL)
		url = "pkcs11:";

	if (type == PKCS11_TYPE_TRUSTED) {
		flags = GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED;
	} else if (type == PKCS11_TYPE_PK) {
		flags = GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY;
	} else if (type == PKCS11_TYPE_CRT_ALL) {
		flags = GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL;
	} else {
		flags = GNUTLS_PKCS11_OBJ_ATTR_ALL;
	}
		
	/* give some initial value to avoid asking for the pkcs11 pin twice.
	 */
	crt_list_size = 128;
	crt_list = malloc(sizeof(*crt_list)*crt_list_size);
	if (crt_list == NULL) {
		fprintf(stderr, "Memory error\n");
		exit(1);
	}

	ret = gnutls_pkcs11_obj_list_import_url( crt_list, &crt_list_size, url, flags);
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

		ret = gnutls_pkcs11_obj_list_import_url( crt_list, &crt_list_size, url, flags);
		if (ret < 0) {
			fprintf(stderr, "Error in crt_list_import: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	}
	
	for (i=0;i<crt_list_size;i++) {
		char buf[128];
		size_t size;
		
		ret = gnutls_pkcs11_obj_export_url(crt_list[i], &output);
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
		
		

		if (flags == GNUTLS_PKCS11_OBJ_ATTR_ALL)
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

void pkcs11_export(FILE* outfile, const char* url)
{
gnutls_pkcs11_obj_t crt;
gnutls_x509_crt_t xcrt;
gnutls_pubkey_t pubkey;
int ret;
size_t size;

	pkcs11_common();

	if (url == NULL)
		url = "pkcs11:";

	ret = gnutls_pkcs11_obj_init(&crt);
	if (ret < 0) {
		fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
		exit(1);
	}

	ret = gnutls_pkcs11_obj_import_url( crt, url);
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

void pkcs11_token_list(FILE* outfile)
{
int ret;
int i;
char *url;
char buf[128];
size_t size;

	pkcs11_common();

	for (i=0;;i++) {
		ret = gnutls_pkcs11_token_get_url(i, &url);
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

void pkcs11_write(FILE* outfile, const char* url, const char* label, int trusted)
{
gnutls_x509_crt_t xcrt;
gnutls_x509_privkey_t xkey;
int ret;
unsigned int flags = 0;
unsigned int key_usage;

}

void pkcs11_export(FILE* outfile, const char* url)
{
gnutls_pkcs11_crt_t crt;
gnutls_x509_crt_t xcrt;
int ret;
size_t size;

	pkcs11_common();

	if (url == NULL)
		url = "pkcs11:";

	ret = gnutls_pkcs11_obj_init(&crt);
	if (ret < 0) {
		fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
		exit(1);
	}

	ret = gnutls_pkcs11_obj_import_url( crt, url);
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

void pkcs11_token_list(FILE* outfile)
{
int ret;
int i;
char *url;
char buf[128];
size_t size;

	pkcs11_common();

	for (i=0;;i++) {
		ret = gnutls_pkcs11_token_get_url(i, &url);
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

	if (xkey == NULL && xcrt == NULL) {
		fprintf(stderr, "You must use --load-privkey or --load-certificate to load the file to be copied\n");
		exit (1);
	}

	return;
}
