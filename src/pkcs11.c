#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include "certtool-common.h"

void pkcs11_list( const char* url)
{
gnutls_pkcs11_crt_t *crt_list;
unsigned int crt_list_size = 0;
int ret;
char* output;
int i;

	if (url == NULL)
		url = "pkcs11:";

	ret = gnutls_pkcs11_crt_list_import( NULL, &crt_list_size, url, GNUTLS_PKCS11_CRT_ATTR_ALL);
	if (ret != 0 && ret != GNUTLS_E_SHORT_MEMORY_BUFFER) {
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

	ret = gnutls_pkcs11_crt_list_import( crt_list, &crt_list_size, url, GNUTLS_PKCS11_CRT_ATTR_ALL);
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
