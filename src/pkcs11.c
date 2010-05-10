#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/pkcs11.h>
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
	memcpy(pin, password, MIN(pin_max,strlen(password)));

	return 0;
}

static void pkcs11_common(void)
{

	gnutls_pkcs11_set_pin_function (pin_callback, NULL);

}

/* lists certificates from a token
 */
void pkcs11_list( const char* url, int type)
{
gnutls_pkcs11_crt_t *crt_list;
unsigned int crt_list_size = 0;
int ret;
char* output;
int i, flags;

	pkcs11_common();

	if (url == NULL)
		url = "pkcs11:";

	ret = gnutls_pkcs11_crt_list_import( NULL, &crt_list_size, url, GNUTLS_PKCS11_CRT_ATTR_ALL);
	if (ret < 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		fprintf(stderr, "Error in crt_list_import (1): %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	if (crt_list_size == 0) {
		fprintf(stderr, "No matching certificates found\n");
		exit(0);
	}
	
	crt_list = malloc(sizeof(*crt_list)*crt_list_size);
	if (crt_list == NULL) {
		fprintf(stderr, "Memory error\n");
		exit(1);
	}

	if (type == PKCS11_TYPE_TRUSTED) {
		flags = GNUTLS_PKCS11_CRT_ATTR_TRUSTED;
	} else if (type == PKCS11_TYPE_PK) {
		flags = GNUTLS_PKCS11_CRT_ATTR_WITH_PK;
	} else {
		flags = GNUTLS_PKCS11_CRT_ATTR_ALL;
	}

	ret = gnutls_pkcs11_crt_list_import( crt_list, &crt_list_size, url, flags);
	if (ret < 0) {
		fprintf(stderr, "Error in crt_list_import: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	for (i=0;i<crt_list_size;i++) {
		gnutls_pkcs11_crt_export_url(crt_list[i], &output);
		fprintf(stderr, "cert[%d]: %s\n\n", i, output);
	}
	
	return;
}

void pkcs11_export(FILE* outfile, const char* url)
{
gnutls_pkcs11_crt_t crt;
gnutls_x509_crt_t xcrt;
int ret;

	pkcs11_common();

	if (url == NULL)
		url = "pkcs11:";

	ret = gnutls_pkcs11_crt_init(&crt);
	if (ret < 0) {
		fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
		exit(1);
	}

	ret = gnutls_pkcs11_crt_import_url( crt, url);
	if (ret < 0) {
		fprintf(stderr, "Error in %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
		exit(1);
	}

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

	print_certificate_info(xcrt, outfile, 1);

	gnutls_x509_crt_deinit(xcrt);
	gnutls_pkcs11_crt_deinit(crt);

	return;



}
