#include <stdio.h>
#include <gnutls_int.h>
#include <gnutls_x509.h>
#include <gnutls_cert.h>
#include <gnutls_errors.h>

#define MAX_FILE_SIZE 16*1024

struct file_res {
	char* test_file;
	int result;
};

static struct file_res test_files[] = {
	{ "test1.pem",  0 },
	{ "test2.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED },
	{ "test3.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED },
	{ "test10.pem", 0 },
	{ "test25.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED },
	{ NULL, 0 }
};

int _gnutls_verify_x509_file( char *cafile);


static void print_res( int x) {
	if (x&GNUTLS_CERT_INVALID)
		printf("- certificate is invalid\n");
	else
		printf("- certificate is valid\n");
	if (x&GNUTLS_CERT_NOT_TRUSTED)
		printf("- certificate is NOT trusted\n");
	else
		printf("- certificate is trusted\n");
	if (x==GNUTLS_CERT_CORRUPTED)
		printf("- Found a corrupted certificate.\n");
	return;
}

int main() {

int x;
char* file;
int i = 0, exp_result;

	gnutls_global_init();

	fprintf(stderr, "This program will perform some tests on X.509 certificate\n");
	fprintf(stderr, "verification functions.\n\n");

	for (;;) {
		exp_result = test_files[i].result;
		file = test_files[i++].test_file;

		if (file==NULL) break;
		x = _gnutls_verify_x509_file( file);

		if (x<0) {
			fprintf(stderr, "Unexpected error: %d\n", x);
			exit(1);
		}
		printf("Test %d, file %s: ", i, file);

		if ( x != exp_result) {
			printf("failed.");
			fprintf(stderr, "Unexpected error in verification.\n");
			fprintf(stderr, "Certificate was found to be: \n");
			print_res( x);
		}
		printf("ok.");
			
		printf("\n");
	}

	return 0;

}

/* Verifies a base64 encoded certificate list from memory 
 */
int _gnutls_verify_x509_mem( const char *ca, int ca_size)
{
	int siz, siz2, i;
	unsigned char *b64;
	const char *ptr;
	int ret;
	gnutls_datum tmp;
	gnutls_cert* x509_ca_list=NULL;
	int x509_ncas;

	siz = ca_size;

	ptr = ca;

	i = 1;

	do {
		siz2 = _gnutls_fbase64_decode(ptr, siz, &b64);
		siz -= siz2;	/* FIXME: this is not enough
				 */

		if (siz2 < 0) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}

		x509_ca_list =
		    (gnutls_cert *) gnutls_realloc( x509_ca_list,
						   i *
						   sizeof(gnutls_cert));
		if (x509_ca_list == NULL) {
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}

		tmp.data = b64;
		tmp.size = siz2;

		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&x509_ca_list[i - 1],
					     tmp)) < 0) {
			gnutls_assert();
			gnutls_free(b64);
			return ret;
		}
		gnutls_free(b64);

		/* now we move ptr after the pem header */
		ptr = strstr(ptr, PEM_CERT_SEP);
		if (ptr!=NULL)
			ptr++;

		i++;
	} while ((ptr = strstr(ptr, PEM_CERT_SEP)) != NULL);

	x509_ncas = i - 1;

	siz = _gnutls_x509_verify_certificate( x509_ca_list, x509_ncas-1,
		&x509_ca_list[x509_ncas-1], 1, NULL, 0);

	return siz;
}



/* Reads and verifies a base64 encoded certificate file 
 */
int _gnutls_verify_x509_file( char *cafile)
{
	int siz;
	char x[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(cafile, "rb");
	if (fd1 == NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	siz = fread(x, 1, sizeof(x)-1, fd1);
	fclose(fd1);

	x[siz] = 0;

	return _gnutls_verify_x509_mem( x, siz);
}

