#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <time.h>
#include "certtool-gaa.h"

void certificate_info( void);
static void gaa_parser(int argc, char **argv);
void generate_self_signed( void);
static gaainfo info;

static unsigned char buffer[10*1024];
static const int buffer_size = sizeof(buffer);

static void tls_log_func( int level, const char* str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

int main(int argc, char** argv)
{
	gnutls_global_init();
	gnutls_global_set_log_function( tls_log_func);
	gnutls_global_set_log_level(2);

	gaa_parser(argc, argv);

	return 0;
}



static void read_set( gnutls_x509_crt crt, const char* input_str, const char* oid)
{
char input[128];
int ret;

	fputs( input_str, stderr);
	fgets( input, sizeof(input), stdin);
	
	if (strlen(input)==1) /* only newline */ return;

	ret = gnutls_x509_crt_set_dn_by_oid(crt, oid, input, strlen(input)-1);
	if (ret < 0) {
		fprintf(stderr, "set_dn: %s\n", gnutls_strerror(ret));
		exit(1);
	}
}

static int read_int( const char* input_str)
{
char input[128];

	fputs( input_str, stderr);
	fgets( input, sizeof(input), stdin);
	
	if (strlen(input)==1) /* only newline */ return 0;

	return atoi(input);
}

static const char* read_str( const char* input_str)
{
static char input[128];

	fputs( input_str, stderr);
	fgets( input, sizeof(input), stdin);
	
	input[strlen(input)-1] = 0;

	if (strlen(input)==0) return NULL;

	return input;
}

static int read_yesno( const char* input_str)
{
char input[128];

	fputs( input_str, stderr);
	fgets( input, sizeof(input), stdin);
	
	if (strlen(input)==1) /* only newline */ return 0;

	if (input[0] == 'y' || input[0] == 'Y') return 1;
	
	return 0;
}

static gnutls_x509_privkey generate_private_key_int( void)
{
gnutls_x509_privkey key;
int ret;

	ret = gnutls_x509_privkey_init(&key);
	if (ret < 0) {
		fprintf(stderr, "privkey_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	fprintf(stderr, "Generating a %d bit RSA private key...\n", info.bits);
	ret = gnutls_x509_privkey_generate( key, GNUTLS_PK_RSA, info.bits, 0);
	if (ret < 0) {
		fprintf(stderr, "privkey_generate: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	return key;

}

static void print_private_key( gnutls_x509_privkey key)
{
int size, ret;

	if (!info.pkcs8) {
		size = sizeof(buffer);
		ret = gnutls_x509_privkey_export( key, GNUTLS_X509_FMT_PEM, buffer, &size);	
		if (ret < 0) {
			fprintf(stderr, "privkey_export: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	} else {
		size = sizeof(buffer);
		ret = gnutls_x509_privkey_export_pkcs8( key, GNUTLS_X509_FMT_PEM, NULL, GNUTLS_PKCS8_PLAIN, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "privkey_export_pkcs8: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	}

	printf("Private key: \n%s\n", buffer);
}

void generate_private_key( void)
{
gnutls_x509_privkey key;
	
	key = generate_private_key_int();
	
	print_private_key( key);

	gnutls_x509_privkey_deinit(key);
}


void generate_self_signed( void)
{
	gnutls_x509_crt crt;
	gnutls_x509_privkey key;
	int size, serial;
	int days, result, ca_status;
	const char* str;

	size = gnutls_x509_crt_init(&crt);
	if (size < 0) {
		fprintf(stderr, "crt_init: %s\n", gnutls_strerror(size));
		exit(1);
	}

	key = generate_private_key_int();

	fprintf(stderr, "Please enter the details of the certificate's distinguished name. "
	"Just press enter to ignore a field.\n");

	read_set( crt, "Country name (2 chars): ", GNUTLS_OID_X520_COUNTRY_NAME);
	read_set( crt, "Organization name: ", GNUTLS_OID_X520_ORGANIZATION_NAME);
	read_set( crt, "Organizational unit name: ", GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME);
	read_set( crt, "Locality name: ", GNUTLS_OID_X520_LOCALITY_NAME);
	read_set( crt, "State or province name: ", GNUTLS_OID_X520_LOCALITY_NAME);
	read_set( crt, "Common name: ", GNUTLS_OID_X520_COMMON_NAME);
	
	fprintf(stderr, "This field should not be used in new certificates.\n");
	read_set( crt, "E-mail: ", GNUTLS_OID_PKCS9_EMAIL);

	size = gnutls_x509_crt_set_version( crt, 2);
	if (size < 0) {
		fprintf(stderr, "set_version: %s\n", gnutls_strerror(size));
		exit(1);
	}

	serial = read_int( "Enter the certificate's serial number: ");
	buffer[2] = serial & 0xff;
	buffer[1] = (serial >> 8) & 0xff;
	buffer[0] = (serial >> 16) & 0xff;

	result = gnutls_x509_crt_set_serial( crt, buffer, 3);
	if (result < 0) {
		fprintf(stderr, "serial: %s\n", gnutls_strerror(result));
		exit(1);
	}


	size = gnutls_x509_crt_set_key( crt, key);
	if (size < 0) {
		fprintf(stderr, "set_key: %s\n", gnutls_strerror(size));
		exit(1);
	}

	fprintf(stderr, "\n\nActivation/Expiration time.\n");	
	gnutls_x509_crt_set_activation_time( crt, time(NULL));
	
	do {
		days = read_int( "The generated certificate will expire in (days): ");
	} while( days==0);
	
	result = gnutls_x509_crt_set_expiration_time( crt, time(NULL)+days*24*60*60);
	if (result < 0) {
		fprintf(stderr, "serial: %s\n", gnutls_strerror(result));
		exit(1);
	}
	

	fprintf(stderr, "\n\nExtensions.\n");	

	ca_status = read_yesno( "Does the certificate belong to an authority? (Y/N): ");

	result = gnutls_x509_crt_set_ca_status( crt, ca_status);
	if (result < 0) {
		fprintf(stderr, "ca_status: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = read_yesno( "Is this a server certificate? (Y/N): ");
	if (result != 0) {
		str = read_str( "Enter the dnsName of the subject of the certificate: ");
		if (str != NULL) {
			result = gnutls_x509_crt_set_subject_alternative_name( crt, GNUTLS_SAN_DNSNAME, str);
			if (result < 0) {
				fprintf(stderr, "subject_alt_name: %s\n", gnutls_strerror(result));
				exit(1);
			}
		}
	} else {

		str = read_str( "Enter the e-mail of the subject of the certificate: ");
	
		if (str != NULL) {
			result = gnutls_x509_crt_set_subject_alternative_name( crt, GNUTLS_SAN_RFC822NAME, str);
			if (result < 0) {
				fprintf(stderr, "subject_alt_name: %s\n", gnutls_strerror(result));
				exit(1);
			}
		}
	}

	fprintf(stderr, "\n\nSigning certificate...\n");

	result = gnutls_x509_crt_sign( crt, crt, key);
	if (result < 0) {
		fprintf(stderr, "crt_sign: %s\n", gnutls_strerror(result));
		exit(1);
	}

	print_private_key( key);


	size = sizeof(buffer);
	result = gnutls_x509_crt_export( crt, GNUTLS_X509_FMT_PEM, buffer, &size);	
	if (result < 0) {
		fprintf(stderr, "crt_export: %s\n", gnutls_strerror(result));
		exit(1);
	}

	printf("Certificate: \n%s", buffer);


	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);

}

void gaa_parser(int argc, char **argv)
{
	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr,
			"Error in the arguments. Use the --help or -h parameters to get more information.\n");
		exit(1);
	}

	switch( info.action) {
		case 0:
			generate_self_signed();
			return;
		case 1:
			generate_private_key();
			return;
		case 2:
			certificate_info();
			return;
	}
}

void certtool_version(void)
{
	fprintf(stderr, "certtool, ");
	fprintf(stderr, "version %s. Libgnutls %s.\n", LIBGNUTLS_VERSION,
		gnutls_check_version(NULL));
}

void certificate_info( void)
{
	gnutls_x509_crt crt;
	int size, ret, i;
	time_t tim;
	gnutls_datum pem;
	char serial[40];
	size_t serial_size = sizeof(serial), dn_size;
	char printable[256];
	char *print;
	char dn[256];
		
	size = fread( buffer, 1, sizeof(buffer)-1, stdin);
	buffer[size] = 0;

	gnutls_x509_crt_init(&crt);
	
	pem.data = buffer;
	pem.size = size;
	
	ret = gnutls_x509_crt_import(crt, &pem, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		fprintf(stderr, "Decoding error: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	printf("Version: %d\n", gnutls_x509_crt_get_version(crt));

	/* serial number
	 */
	if (gnutls_x509_crt_get_serial(crt, serial, &serial_size) >= 0) {
		print = printable;
		for (i = 0; i < serial_size; i++) {
			sprintf(print, "%.2x ",
				(unsigned char) serial[i]);
			print += 3;
		}
		printf("Serial Number: %s\n", printable);
	}

	/* Issuer
	 */
	dn_size = sizeof(dn);

	ret = gnutls_x509_crt_get_issuer_dn(crt, dn, &dn_size);
	if (ret >= 0)
		printf("Issuer: %s\n", dn);

	printf("Signature Algorithm: ");
	ret = gnutls_x509_crt_get_signature_algorithm(crt);
	switch(ret) {
		case GNUTLS_PK_RSA:
			printf("RSA\n");
			break;
		case GNUTLS_PK_DSA:
			printf("DSA\n");
			break;
		default:
			printf("UNKNOWN\n");
			break;
	}

	/* Validity
	 */
	printf("Validity\n");

	tim = gnutls_x509_crt_get_activation_time(crt);
	printf("\tNot Before: %s", ctime(&tim));

	tim = gnutls_x509_crt_get_expiration_time(crt);
	printf("\tNot After: %s", ctime(&tim));

	/* Subject
	 */
	dn_size = sizeof(dn);
	ret = gnutls_x509_crt_get_dn(crt, dn, &dn_size);
	if (ret >= 0)
		printf("Subject: %s\n", dn);

	/* Public key algorithm
	 */
	printf("Subject Public Key Info:\n");
	ret = gnutls_x509_crt_get_pk_algorithm(crt, NULL);
	printf("\tPublic Key Algorithm: ");

	switch(ret) {
		case GNUTLS_PK_RSA:
			printf("RSA\n");
			break;
		case GNUTLS_PK_DSA:
			printf("DSA\n");
			break;
		default:
			printf("UNKNOWN\n");
			break;
	}

}
