#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <time.h>
#include "certtool-gaa.h"

void verify_chain(void);
gnutls_x509_privkey load_private_key(void);
gnutls_x509_privkey load_ca_private_key(void);
gnutls_x509_crt load_ca_cert(void);
void certificate_info( void);
static void gaa_parser(int argc, char **argv);
void generate_self_signed( void);
void generate_request(void);

static gaainfo info;

static unsigned char buffer[40*1024];
static const int buffer_size = sizeof(buffer);

static void tls_log_func( int level, const char* str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

int main(int argc, char** argv)
{
	gnutls_global_init();
	gnutls_global_set_log_function( tls_log_func);
	gnutls_global_set_log_level(1);

	gaa_parser(argc, argv);

	return 0;
}



static void read_crt_set( gnutls_x509_crt crt, const char* input_str, const char* oid)
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

static void read_crq_set( gnutls_x509_crq crq, const char* input_str, const char* oid)
{
char input[128];
int ret;

	fputs( input_str, stderr);
	fgets( input, sizeof(input), stdin);
	
	if (strlen(input)==1) /* only newline */ return;

	ret = gnutls_x509_crq_set_dn_by_oid(crq, oid, input, strlen(input)-1);
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

	if (info.privkey)
		return load_private_key();

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
	
	fprintf(stderr, "Generating a private key...\n");
	
	key = generate_private_key_int();
	
	print_private_key( key);

	gnutls_x509_privkey_deinit(key);
}


gnutls_x509_crt generate_certificate( gnutls_x509_privkey *ret_key)
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

	read_crt_set( crt, "Country name (2 chars): ", GNUTLS_OID_X520_COUNTRY_NAME);
	read_crt_set( crt, "Organization name: ", GNUTLS_OID_X520_ORGANIZATION_NAME);
	read_crt_set( crt, "Organizational unit name: ", GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME);
	read_crt_set( crt, "Locality name: ", GNUTLS_OID_X520_LOCALITY_NAME);
	read_crt_set( crt, "State or province name: ", GNUTLS_OID_X520_LOCALITY_NAME);
	read_crt_set( crt, "Common name: ", GNUTLS_OID_X520_COMMON_NAME);
	
	fprintf(stderr, "This field should not be used in new certificates.\n");
	read_crt_set( crt, "E-mail: ", GNUTLS_OID_PKCS9_EMAIL);

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

	*ret_key = key;
	return crt;

}

void generate_self_signed( void)
{
	gnutls_x509_crt crt;
	gnutls_x509_privkey key;
	int size;
	int result;

	fprintf(stderr, "Generating a self signed certificate...\n");

	crt = generate_certificate( &key);

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

void generate_signed_certificate( void)
{
	gnutls_x509_crt crt;
	gnutls_x509_privkey key;
	int size, result;
	gnutls_x509_privkey ca_key;
	gnutls_x509_crt ca_crt;

	fprintf(stderr, "Generating a signed certificate...\n");

	ca_key = load_ca_private_key();
	ca_crt = load_ca_cert();

	crt = generate_certificate( &key);
	
	fprintf(stderr, "\n\nSigning certificate...\n");

	result = gnutls_x509_crt_sign( crt, ca_crt, ca_key);
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
		case 3:
			generate_request();
			return;
		case 4:
			generate_signed_certificate();
			return;
		case 5:
			verify_chain();
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

gnutls_x509_privkey load_private_key()
{
FILE* fd;
gnutls_x509_privkey key;
int ret;
gnutls_datum dat;
size_t size;

	fd = fopen(info.privkey, "r");
	if (fd == NULL) {
		fprintf(stderr, "File %s does not exist.\n", info.privkey);
		exit(1);
	}

	size = fread(buffer, 1, sizeof(buffer)-1, fd);
	buffer[size] = 0;

	fclose(fd);

	ret = gnutls_x509_privkey_init(&key);
	if (ret < 0) {
		fprintf(stderr, "privkey_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	dat.data = buffer;
	dat.size = size;
	
	if (!info.pkcs8)
		ret = gnutls_x509_privkey_import( key, &dat, GNUTLS_X509_FMT_PEM);
	else
		ret = gnutls_x509_privkey_import_pkcs8( key, &dat, GNUTLS_X509_FMT_PEM,
			NULL, 0);
	
	if (ret < 0) {
		fprintf(stderr, "privkey_import: %s\n", gnutls_strerror(ret));
		exit(1);
	}	

	return key;
}

gnutls_x509_privkey load_ca_private_key()
{
FILE* fd;
gnutls_x509_privkey key;
int ret;
gnutls_datum dat;
size_t size;

	fprintf(stderr, "Loading CA's private key...\n");

	if (info.ca_privkey==NULL) {
		fprintf(stderr, "You must specify a private key of the CA.\n");
		exit(1);
	}

	fd = fopen(info.ca_privkey, "r");
	if (fd == NULL) {
		fprintf(stderr, "File %s does not exist.\n", info.ca_privkey);
		exit(1);
	}

	size = fread(buffer, 1, sizeof(buffer)-1, fd);
	buffer[size] = 0;

	fclose(fd);

	ret = gnutls_x509_privkey_init(&key);
	if (ret < 0) {
		fprintf(stderr, "privkey_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	dat.data = buffer;
	dat.size = size;
	
	if (!info.pkcs8)
		ret = gnutls_x509_privkey_import( key, &dat, GNUTLS_X509_FMT_PEM);
	else
		ret = gnutls_x509_privkey_import_pkcs8( key, &dat, GNUTLS_X509_FMT_PEM,
			NULL, 0);
	
	if (ret < 0) {
		fprintf(stderr, "privkey_import: %s\n", gnutls_strerror(ret));
		exit(1);
	}	

	return key;
}

/* Loads the CA's certificate
 */
gnutls_x509_crt load_ca_cert()
{
FILE* fd;
gnutls_x509_crt crt;
int ret;
gnutls_datum dat;
size_t size;

	fprintf(stderr, "Loading CA's certificate...\n");

	if (info.ca==NULL) {
		fprintf(stderr, "You must specify a certificate of the CA.\n");
		exit(1);
	}

	fd = fopen(info.ca, "r");
	if (fd == NULL) {
		fprintf(stderr, "File %s does not exist.\n", info.ca);
		exit(1);
	}

	size = fread(buffer, 1, sizeof(buffer)-1, fd);
	buffer[size] = 0;

	fclose(fd);

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		fprintf(stderr, "crt_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	dat.data = buffer;
	dat.size = size;
	
	ret = gnutls_x509_crt_import( crt, &dat, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		fprintf(stderr, "crt_import: %s\n", gnutls_strerror(ret));
		exit(1);
	}	

	return crt;
}


/* Generate a PKCS #10 certificate request.
 */
void generate_request(void)
{
	gnutls_x509_crq crq;
	gnutls_x509_privkey key;
	int ret;
	const char* pass;
	size_t size;

	fprintf(stderr, "Generating a PKCS #10 certificate request...\n");

	ret = gnutls_x509_crq_init(&crq);
	if (ret < 0) {
		fprintf(stderr, "crq_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	/* Load the private key.
	 */
	key = generate_private_key_int();

	read_crq_set( crq, "Country name (2 chars): ", GNUTLS_OID_X520_COUNTRY_NAME);
	read_crq_set( crq, "Organization name: ", GNUTLS_OID_X520_ORGANIZATION_NAME);
	read_crq_set( crq, "Organizational unit name: ", GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME);
	read_crq_set( crq, "Locality name: ", GNUTLS_OID_X520_LOCALITY_NAME);
	read_crq_set( crq, "State or province name: ", GNUTLS_OID_X520_LOCALITY_NAME);
	read_crq_set( crq, "Common name: ", GNUTLS_OID_X520_COMMON_NAME);

	ret = gnutls_x509_crq_set_version( crq, 0);
	if (ret < 0) {
		fprintf(stderr, "set_version: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	pass = read_str("Enter a challenge password: ");
	
	if (pass != NULL) {
		ret = gnutls_x509_crq_set_challenge_password( crq, pass);
		if (ret < 0) {
			fprintf(stderr, "set_pass: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	}

	ret = gnutls_x509_crq_set_key( crq, key);
	if (ret < 0) {
		fprintf(stderr, "set_key: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	ret = gnutls_x509_crq_sign( crq, key);
	if (ret < 0) {
		fprintf(stderr, "sign: %s\n", gnutls_strerror(ret));
		exit(1);
	}


	print_private_key( key);

	size = sizeof(buffer);	
	ret = gnutls_x509_crq_export( crq, GNUTLS_X509_FMT_PEM, buffer, &size);	
	if (ret < 0) {
		fprintf(stderr, "export: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	printf("Request: \n%s", buffer);

	gnutls_x509_crq_deinit(crq);
	gnutls_x509_privkey_deinit(key);

}



#define CERT_SEP "-----BEGIN CERT"
#define CRL_SEP "-----BEGIN X509 CRL"

int _verify_x509_mem( const char* cert, int cert_size)
{
	int siz, i;
	const char *ptr;
	int ret;
	unsigned int output;
	gnutls_datum tmp;
	gnutls_x509_crt *x509_cert_list = NULL;
	gnutls_x509_crl *x509_crl_list = NULL;
	int x509_ncerts, x509_ncrls;
	time_t now = time(0);

	/* Decode the CA certificate
	 */

	/* Decode the CRL list
	 */
	siz = cert_size;
	ptr = cert;

	i = 1;

	if (strstr(ptr, CRL_SEP)!=NULL) /* if CRLs exist */
	do {
		x509_crl_list =
		    (gnutls_x509_crl *) realloc( x509_crl_list,
						   i *
						   sizeof(gnutls_x509_crl));
		if (x509_crl_list == NULL) {
			fprintf(stderr, "memory error\n");
			exit(1);
		}

		tmp.data = (char*)ptr;
		tmp.size = siz;

		ret = gnutls_x509_crl_init( &x509_crl_list[i-1]);
		if (ret < 0) {
			fprintf(stderr, "Error parsing the CRL[%d]: %s\n", i, gnutls_strerror(ret));
			exit(1);
		}
	
		ret = gnutls_x509_crl_import( x509_crl_list[i-1], &tmp, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			fprintf(stderr, "Error parsing the CRL[%d]: %s\n", i, gnutls_strerror(ret));
			exit(1);
		}

		/* now we move ptr after the pem header */
		ptr = strstr(ptr, CRL_SEP);
		if (ptr!=NULL)
			ptr++;

		i++;
	} while ((ptr = strstr(ptr, CRL_SEP)) != NULL);

	x509_ncrls = i - 1;


	/* Decode the certificate chain. 
	 */
	siz = cert_size;
	ptr = cert;

	i = 1;

	do {
		x509_cert_list =
		    (gnutls_x509_crt *) realloc( x509_cert_list,
						   i *
						   sizeof(gnutls_x509_crt));
		if (x509_cert_list == NULL) {
			fprintf(stderr, "memory error\n");
			exit(1);
		}

		tmp.data = (char*)ptr;
		tmp.size = siz;

		ret = gnutls_x509_crt_init( &x509_cert_list[i-1]);
		if (ret < 0) {
			fprintf(stderr, "Error parsing the certificate[%d]: %s\n", i, gnutls_strerror(ret));
			exit(1);
		}
	
		ret = gnutls_x509_crt_import( x509_cert_list[i-1], &tmp, GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			fprintf(stderr, "Error parsing the certificate[%d]: %s\n", i, gnutls_strerror(ret));
			exit(1);
		}
		
		/* Check expiration dates.
		 */
		if (gnutls_x509_crt_get_activation_time(x509_cert_list[i-1]) > now)
			fprintf(stderr, "Warning: certificate %d has not been activated yet.\n", i);
		if (gnutls_x509_crt_get_expiration_time(x509_cert_list[i-1]) < now)
			fprintf(stderr, "Warning: certificate %d has been expired.\n", i);

		/* now we move ptr after the pem header */
		ptr = strstr(ptr, CERT_SEP);
		if (ptr!=NULL)
			ptr++;

		i++;
	} while ((ptr = strstr(ptr, CERT_SEP)) != NULL);

	x509_ncerts = i - 1;

	/* The last certificate in the list will be used as
	 * a CA (should be self signed).
	 */
	ret  = gnutls_x509_crt_list_verify( x509_cert_list, x509_ncerts,
		&x509_cert_list[x509_ncerts-1], 1, x509_crl_list, x509_ncrls, 0, &output);

	for (i=0;i<x509_ncerts;i++) {
		gnutls_x509_crt_deinit( x509_cert_list[i]);
	}

	for (i=0;i<x509_ncrls;i++) {
		gnutls_x509_crl_deinit( x509_crl_list[i]);
	}

	free( x509_cert_list);
	free( x509_crl_list);

	if ( ret < 0) {
		fprintf(stderr, "Error in verification: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	return output;
}

static void print_verification_res( unsigned int x) 
{
	printf( "Verification output:\n");
	if (x&GNUTLS_CERT_INVALID)
		printf("\tcertificate chain is invalid.\n");
	else
	 	printf("\tcertificate chain is valid.\n");
	if (x&GNUTLS_CERT_NOT_TRUSTED)
		printf("\tcertificate is NOT trusted\n");
	else
		printf("\tcertificate is trusted.\n");

	if (x&GNUTLS_CERT_CORRUPTED)
		printf("\tcertificate is corrupt.\n");

	if (x&GNUTLS_CERT_REVOKED)
		printf("\tcertificate is revoked.\n");
}

void verify_chain( void)
{
unsigned int output;
size_t size;

	size = fread( buffer, 1, sizeof(buffer)-1, stdin);

	output = _verify_x509_mem( buffer, size);
	
	print_verification_res( output);
}
