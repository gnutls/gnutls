#include <stdio.h>
#include <gnutls_int.h>
#include <gnutls_x509.h>
#include <gnutls_cert.h>
#include <gnutls_errors.h>
#include <x509_b64.h>
#include <x509_verify.h>
#include <gnutls_global.h>

/* FIXME: This test uses gnutls internals. Rewrite it using
 * the exported stuff. (I leave it as an exercise to the reader :)
 */

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
	{ "test13.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED },
	{ "test22.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED },
	{ "test23.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED },
	{ "test24.pem", 0 },
	{ "test25.pem", GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED },
	{ "test26.pem", 0 },
	{ NULL, 0 }
};

#define CA_FILE "ca.pem"

int _gnutls_verify_x509_file( const char* certfile, const char *cafile);


static void print_res( int x) 
{
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

int main() 
{

int x;
char* file;
int i = 0, exp_result;

	gnutls_global_init();

	fprintf(stderr, "This test will perform some checks on X.509 certificate\n");
	fprintf(stderr, "verification functions.\n\n");

	for (;;) {
		exp_result = test_files[i].result;
		file = test_files[i++].test_file;

		if (file==NULL) break;
		x = _gnutls_verify_x509_file( file, CA_FILE);

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

	printf("\n");

	return 0;

}

/* Verifies a base64 encoded certificate list from memory 
 */
int _gnutls_verify_x509_mem( const char* cert, int cert_size,
	const char *ca, int ca_size)
{
	int siz, siz2, i;
	unsigned char *b64;
	const char *ptr;
	int ret;
	gnutls_datum tmp;
	gnutls_cert* x509_cert_list=NULL;
	gnutls_cert* x509_ca_list=NULL;
	int x509_ncerts, x509_ncas;

	/* Decode the CA certificate
	 */
	siz2 = _gnutls_fbase64_decode( NULL, ca, ca_size, &b64);

	if (siz2 < 0) {
		fprintf(stderr, "Error decoding CA certificate\n");
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	x509_ca_list =
	    (gnutls_cert *) gnutls_calloc( 1, sizeof(gnutls_cert));
	x509_ncas = 1;

	if (x509_ca_list == NULL) {
		fprintf(stderr, "memory error\n");
		gnutls_free(b64);
		return GNUTLS_E_MEMORY_ERROR;
	}

	tmp.data = b64;
	tmp.size = siz2;

	if ((ret =
	     _gnutls_x509_cert2gnutls_cert( x509_ca_list,
				     tmp, 0)) < 0) {
		fprintf(stderr, "Error parsing the CA certificate\n");
		gnutls_assert();
		gnutls_free(b64);
		return ret;
	}
	gnutls_free(b64);


	/* Decode the certificate chain. 
	 */
	siz = cert_size;
	ptr = cert;

	i = 1;

	do {
		siz2 = _gnutls_fbase64_decode( NULL, ptr, siz, &b64);
		siz -= siz2;	/* FIXME: this is not enough
				 */

		if (siz2 < 0) {
			gnutls_assert();
			return GNUTLS_E_PARSING_ERROR;
		}

		x509_cert_list =
		    (gnutls_cert *) gnutls_realloc( x509_cert_list,
						   i *
						   sizeof(gnutls_cert));
		if (x509_cert_list == NULL) {
			fprintf(stderr, "memory error\n");
			gnutls_assert();
			gnutls_free(b64);
			return GNUTLS_E_MEMORY_ERROR;
		}

		tmp.data = b64;
		tmp.size = siz2;

		if ((ret =
		     _gnutls_x509_cert2gnutls_cert( &x509_cert_list[i-1],
				     tmp, 0)) < 0) {
			fprintf(stderr, "Error parsing the certificate\n");
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

	x509_ncerts = i - 1;

	siz = _gnutls_x509_verify_certificate( x509_cert_list, x509_ncerts,
		x509_ca_list, 1, NULL, 0);

	_gnutls_free_cert( x509_ca_list[0]);
	for (i=0;i<x509_ncerts;i++) {
		_gnutls_free_cert( x509_cert_list[i]);
	}

	return siz;
}



/* Reads and verifies a base64 encoded certificate file 
 */
int _gnutls_verify_x509_file( const char* certfile, const char *cafile)
{
	int ca_size, cert_size;
	char ca[MAX_FILE_SIZE];
	char cert[MAX_FILE_SIZE];
	FILE *fd1;

	fd1 = fopen(certfile, "rb");
	if (fd1 == NULL) {
		fprintf(stderr, "error opening %s\n", certfile);
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	cert_size = fread(cert, 1, sizeof(cert)-1, fd1);
	fclose(fd1);

	cert[cert_size] = 0;


	fd1 = fopen(cafile, "rb");
	if (fd1 == NULL) {
		fprintf(stderr, "error opening %s\n", cafile);
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	ca_size = fread(ca, 1, sizeof(ca)-1, fd1);
	fclose(fd1);
	
	ca[ca_size] = 0;

	return _gnutls_verify_x509_mem( cert, cert_size, ca, ca_size);
}

