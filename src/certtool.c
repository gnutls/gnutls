#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <time.h>
#include "certtool-gaa.h"
#include <gnutls/pkcs12.h>
#include <unistd.h>

void generate_pkcs12( void);
void verify_chain(void);
gnutls_x509_privkey load_private_key(void);
gnutls_x509_crq load_request(void);
gnutls_x509_privkey load_ca_private_key(void);
gnutls_x509_crt load_ca_cert(void);
gnutls_x509_crt load_cert(void);
void certificate_info( void);
void privkey_info( void);
static void gaa_parser(int argc, char **argv);
void generate_self_signed( void);
void generate_request(void);

static gaainfo info;
FILE* outfile;
FILE* infile;
int in_cert_format;
int out_cert_format = GNUTLS_X509_FMT_PEM;

static unsigned char buffer[50*1024];
static const int buffer_size = sizeof(buffer);

static void tls_log_func( int level, const char* str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

int main(int argc, char** argv)
{
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

static void print_key_usage( unsigned int x) 
{
	if (x&GNUTLS_KEY_DIGITAL_SIGNATURE)
		fprintf(outfile,"\t\tDigital signature.\n");
	if (x&GNUTLS_KEY_NON_REPUDIATION)
		fprintf(outfile,"\t\tNon repudiation.\n");
	if (x&GNUTLS_KEY_KEY_ENCIPHERMENT)
		fprintf(outfile,"\t\tKey encipherment.\n");
	if (x&GNUTLS_KEY_DATA_ENCIPHERMENT)
		fprintf(outfile,"\t\tData encipherment.\n");
	if (x&GNUTLS_KEY_KEY_AGREEMENT)
		fprintf(outfile,"\t\tKey agreement.\n");
	if (x&GNUTLS_KEY_KEY_CERT_SIGN)
		fprintf(outfile,"\t\tCertificate signing.\n");
	if (x&GNUTLS_KEY_CRL_SIGN)
		fprintf(outfile,"\t\tCRL signing.\n");
	if (x&GNUTLS_KEY_ENCIPHER_ONLY)
		fprintf(outfile,"\t\tKey encipher only.\n");
	if (x&GNUTLS_KEY_DECIPHER_ONLY)
		fprintf(outfile,"\t\tKey decipher only.\n");
}

static void print_private_key( gnutls_x509_privkey key)
{
int size, ret;
	if (!key) return;

	if (!info.pkcs8) {
		size = sizeof(buffer);
		ret = gnutls_x509_privkey_export( key, out_cert_format, buffer, &size);	
		if (ret < 0) {
			fprintf(stderr, "privkey_export: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	} else {
		size = sizeof(buffer);
		ret = gnutls_x509_privkey_export_pkcs8( key, out_cert_format, NULL, GNUTLS_PKCS8_PLAIN, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "privkey_export_pkcs8: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	}

	fprintf(outfile,"Private key: \n%s\n", buffer);
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
	gnutls_x509_privkey key = NULL;
	int size, serial;
	int days, result, ca_status;
	const char* str;
	gnutls_x509_crq crq; /* request */

	size = gnutls_x509_crt_init(&crt);
	if (size < 0) {
		fprintf(stderr, "crt_init: %s\n", gnutls_strerror(size));
		exit(1);
	}


	crq = load_request();
	
	if (crq == NULL) {
		fprintf(stderr, "Please enter the details of the certificate's distinguished name. "
		"Just press enter to ignore a field.\n");

		key = generate_private_key_int();

		read_crt_set( crt, "Country name (2 chars): ", GNUTLS_OID_X520_COUNTRY_NAME);
		read_crt_set( crt, "Organization name: ", GNUTLS_OID_X520_ORGANIZATION_NAME);
		read_crt_set( crt, "Organizational unit name: ", GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME);
		read_crt_set( crt, "Locality name: ", GNUTLS_OID_X520_LOCALITY_NAME);
		read_crt_set( crt, "State or province name: ", GNUTLS_OID_X520_LOCALITY_NAME);
		read_crt_set( crt, "Common name: ", GNUTLS_OID_X520_COMMON_NAME);
	
		fprintf(stderr, "This field should not be used in new certificates.\n");
		read_crt_set( crt, "E-mail: ", GNUTLS_OID_PKCS9_EMAIL);

		result = gnutls_x509_crt_set_key( crt, key);
		if (result < 0) {
			fprintf(stderr, "set_key: %s\n", gnutls_strerror(result));
			exit(1);
		}

	} else {
		result = gnutls_x509_crt_set_crq( crt, crq);
		if (result < 0) {
			fprintf(stderr, "set_crq: %s\n", gnutls_strerror(result));
			exit(1);
		}
	}

	result = gnutls_x509_crt_set_version( crt, 2);
	if (result < 0) {
		fprintf(stderr, "set_version: %s\n", gnutls_strerror(result));
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

	result = read_yesno( "Is this a web server certificate? (Y/N): ");
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

gnutls_x509_crt update_certificate( void)
{
	gnutls_x509_crt crt;
	int size;
	int days, result;

	size = gnutls_x509_crt_init(&crt);
	if (size < 0) {
		fprintf(stderr, "crt_init: %s\n", gnutls_strerror(size));
		exit(1);
	}

	crt = load_cert();

	fprintf(stderr, "Activation/Expiration time.\n");	
	gnutls_x509_crt_set_activation_time( crt, time(NULL));
	
	do {
		days = read_int( "The updated certificate will expire in (days): ");
	} while( days==0);
	
	result = gnutls_x509_crt_set_expiration_time( crt, time(NULL)+days*24*60*60);
	if (result < 0) {
		fprintf(stderr, "serial: %s\n", gnutls_strerror(result));
		exit(1);
	}
	
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
	result = gnutls_x509_crt_export( crt, out_cert_format, buffer, &size);	
	if (result < 0) {
		fprintf(stderr, "crt_export: %s\n", gnutls_strerror(result));
		exit(1);
	}

	fprintf(outfile, "Certificate: \n%s", buffer);


	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);
	fclose(outfile);
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
	result = gnutls_x509_crt_export( crt, out_cert_format, buffer, &size);	
	if (result < 0) {
		fprintf(stderr, "crt_export: %s\n", gnutls_strerror(result));
		exit(1);
	}

	fprintf(outfile, "Certificate: \n%s", buffer);

	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);
}

void update_signed_certificate( void)
{
	gnutls_x509_crt crt;
	int size, result;
	gnutls_x509_privkey ca_key;
	gnutls_x509_crt ca_crt;

	fprintf(stderr, "Generating a signed certificate...\n");

	ca_key = load_ca_private_key();
	ca_crt = load_ca_cert();

	crt = update_certificate();
	
	fprintf(stderr, "\n\nSigning certificate...\n");

	result = gnutls_x509_crt_sign( crt, ca_crt, ca_key);
	if (result < 0) {
		fprintf(stderr, "crt_sign: %s\n", gnutls_strerror(result));
		exit(1);
	}

	size = sizeof(buffer);
	result = gnutls_x509_crt_export( crt, out_cert_format, buffer, &size);	
	if (result < 0) {
		fprintf(stderr, "crt_export: %s\n", gnutls_strerror(result));
		exit(1);
	}

	fprintf(outfile, "Certificate: \n%s", buffer);

	gnutls_x509_crt_deinit(crt);
}

void gaa_parser(int argc, char **argv)
{
	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr,
			"Error in the arguments. Use the --help or -h parameters to get more information.\n");
		exit(1);
	}
	
	if (info.outfile) {
		outfile = fopen(info.outfile, "w");
		if (outfile == NULL) {
			fprintf(stderr, "error: could not open %s.\n", info.outfile);
			exit(1);
		}
	} else outfile = stdout;

	if (info.infile) {
		infile = fopen(info.infile, "r");
		if (infile == NULL) {
			fprintf(stderr, "error: could not open %s.\n", info.infile);
			exit(1);
		}
	} else infile = stdin;
	
	if (info.incert_format) in_cert_format = GNUTLS_X509_FMT_DER;
	else in_cert_format = GNUTLS_X509_FMT_PEM;

	gnutls_global_init();
	gnutls_global_set_log_function( tls_log_func);
	gnutls_global_set_log_level(info.debug);

	switch( info.action) {
		case 0:
			generate_self_signed();
			break;
		case 1:
			generate_private_key();
			break;
		case 2:
			certificate_info();
			break;
		case 3:
			generate_request();
			break;
		case 4:
			generate_signed_certificate();
			break;
		case 5:
			verify_chain();
			break;
		case 6:
			privkey_info();
			break;
		case 7:
			update_signed_certificate();
			break;
		case 8:
			generate_pkcs12();
			break;
	}
	fclose(outfile);
}

void certtool_version(void)
{
	fprintf(stderr, "certtool, ");
	fprintf(stderr, "version %s. Libgnutls %s.\n", LIBGNUTLS_VERSION,
		gnutls_check_version(NULL));
}

const char* get_algorithm( int a) 
{
	switch (a) {
		case GNUTLS_PK_RSA:
			return "RSA";
		case GNUTLS_PK_DSA:
			return "DSA";
			break;
		default:
			return "UNKNOWN";
	}
}

void certificate_info( void)
{
	gnutls_x509_crt crt;
	int size, ret, i;
	unsigned int critical, key_usage;
	time_t tim;
	gnutls_datum pem;
	char serial[40];
	size_t serial_size = sizeof(serial), dn_size;
	char printable[256];
	char *print;
	const char* cprint;
	char dn[256];
		
	size = fread( buffer, 1, sizeof(buffer)-1, infile);
	buffer[size] = 0;

	gnutls_x509_crt_init(&crt);
	
	pem.data = buffer;
	pem.size = size;
	
	ret = gnutls_x509_crt_import(crt, &pem, in_cert_format);
	if (ret < 0) {
		fprintf(stderr, "Decoding error: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	fprintf(outfile, "Version: %d\n", gnutls_x509_crt_get_version(crt));

	/* serial number
	 */
	if (gnutls_x509_crt_get_serial(crt, serial, &serial_size) >= 0) {
		print = printable;
		for (i = 0; i < serial_size; i++) {
			sprintf(print, "%.2x ",
				(unsigned char) serial[i]);
			print += 3;
		}
		fprintf(outfile, "Serial Number: %s\n", printable);
	}
	


	/* Issuer
	 */
	dn_size = sizeof(dn);

	ret = gnutls_x509_crt_get_issuer_dn(crt, dn, &dn_size);
	if (ret >= 0)
		fprintf(outfile, "Issuer: %s\n", dn);

	fprintf(outfile, "Signature Algorithm: ");
	ret = gnutls_x509_crt_get_signature_algorithm(crt);

	cprint = get_algorithm( ret);
	fprintf(outfile,  "%s\n", cprint);

	/* Validity
	 */
	fprintf(outfile, "Validity:\n");

	tim = gnutls_x509_crt_get_activation_time(crt);
	fprintf(outfile, "\tNot Before: %s", ctime(&tim));

	tim = gnutls_x509_crt_get_expiration_time(crt);
	fprintf(outfile, "\tNot After: %s", ctime(&tim));

	/* Subject
	 */
	dn_size = sizeof(dn);
	ret = gnutls_x509_crt_get_dn(crt, dn, &dn_size);
	if (ret >= 0)
		fprintf(outfile, "Subject: %s\n", dn);

	/* Public key algorithm
	 */
	fprintf(outfile, "Subject Public Key Info:\n");
	ret = gnutls_x509_crt_get_pk_algorithm(crt, NULL);
	fprintf(outfile, "\tPublic Key Algorithm: ");

	cprint = get_algorithm( ret);
	fprintf(outfile,  "%s\n", cprint);


	
	fprintf(outfile, "\nX.509 Extensions:\n");
	
	/* subject alternative name
	 */
	for (i = 0; !(ret < 0); i++) {
		size = sizeof(buffer);
		ret = gnutls_x509_crt_get_subject_alt_name(crt, i, buffer, &size, &critical);

		if (i==0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			fprintf(outfile, "\tSubject Alternative name:");
			if (critical) fprintf(outfile, " (critical)");
			fprintf(outfile, "\n");
		}
		
		if (ret < 0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			fprintf(outfile, "\t\tFound unsupported alternative name.\n");
		} else switch (ret) {
			case GNUTLS_SAN_DNSNAME:
				fprintf(outfile, "\t\tDNSname: %s\n", buffer);
				break;
			case GNUTLS_SAN_RFC822NAME:
				fprintf(outfile, "\t\tRFC822name: %s\n", buffer);
				break;
			case GNUTLS_SAN_URI:
				fprintf(outfile, "\t\tURI: %s\n", buffer);
				break;
			case GNUTLS_SAN_IPADDRESS:
				fprintf(outfile, "\t\tIPAddress: %s\n", buffer);
				break;
		}
	}
	
	/* check for basicConstraints
	 */
	ret = gnutls_x509_crt_get_ca_status( crt, &critical);
	
	if (ret >= 0) {
		fprintf(outfile, "\tBasic Constraints:");
		if (critical) fprintf(outfile, " (critical)");
		fprintf(outfile, "\n");		

		if (ret==0) fprintf(outfile, "\t\tCA:FALSE\n");
		else fprintf(outfile, "\t\tCA:TRUE\n");
		
	}

	/* Key Usage.
	 */
	ret = gnutls_x509_crt_get_key_usage( crt, &key_usage, &critical);
	
	if (ret >= 0) {
		fprintf(outfile, "\tKey usage:\n");
		print_key_usage(key_usage);
	}


	/* fingerprint
	 */
	size = sizeof(buffer);
	if ((ret=gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_MD5, buffer, &size)) < 0) 
	{
		const char* str = gnutls_strerror(ret);
		if (str == NULL) str = "unknown error";
	    	fprintf(stderr, "Error in fingerprint calculation: %s\n", str);
	} else {
		print = printable;
		for (i = 0; i < size; i++) {
			sprintf(print, "%.2x ", (unsigned char) buffer[i]);
			print += 3;
		}
		fprintf(outfile, "\nFingerprint: %s\n", printable);
	}

	size = sizeof(buffer);
	if ((ret=gnutls_x509_crt_get_key_id(crt, 0, buffer, &size)) < 0) 
	{
		const char* str = gnutls_strerror(ret);
		if (str == NULL) str = "unknown error";
	    	fprintf(stderr, "Error in key id calculation: %s\n", str);
	} else {
		print = printable;
		for (i = 0; i < size; i++) {
			sprintf(print, "%.2x ", (unsigned char) buffer[i]);
			print += 3;
		}
		fprintf(outfile, "Public Key ID: %s\n", printable);
	}

	fprintf(outfile, "\n");
}

void privkey_info( void)
{
	gnutls_x509_privkey key;
	int size, ret, i;
	gnutls_datum pem;
	char printable[256];
	char *print;
	const char* cprint;
		
	size = fread( buffer, 1, sizeof(buffer)-1, infile);
	buffer[size] = 0;

	gnutls_x509_privkey_init(&key);
	
	pem.data = buffer;
	pem.size = size;
	
	if (!info.pkcs8) {
		ret = gnutls_x509_privkey_import(key, &pem, in_cert_format);
	} else {
		ret = gnutls_x509_privkey_import_pkcs8(key, &pem, in_cert_format, NULL, GNUTLS_PKCS8_PLAIN);
	}

	if (ret < 0) {
		fprintf(stderr, "Decoding error: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	/* Public key algorithm
	 */
	fprintf(outfile, "Public Key Info:\n");
	ret = gnutls_x509_privkey_get_pk_algorithm(key);
	fprintf(outfile, "\tPublic Key Algorithm: ");

	cprint = get_algorithm( ret);
	fprintf(outfile,  "%s\n", cprint);


	size = sizeof(buffer);
	if ((ret=gnutls_x509_privkey_get_key_id(key, 0, buffer, &size)) < 0) 
	{
		const char* str = gnutls_strerror(ret);
		if (str == NULL) str = "unknown error";
	    	fprintf(stderr, "Error in key id calculation: %s\n", str);
	} else {
		print = printable;
		for (i = 0; i < size; i++) {
			sprintf(print, "%.2x ", (unsigned char) buffer[i]);
			print += 3;
		}
		fprintf(outfile, "Public Key ID: %s\n", printable);
	}

	fprintf(outfile, "\n");
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
		ret = gnutls_x509_privkey_import( key, &dat, in_cert_format);
	else
		ret = gnutls_x509_privkey_import_pkcs8( key, &dat, in_cert_format,
			NULL, 0);
	
	if (ret < 0) {
		fprintf(stderr, "privkey_import: %s\n", gnutls_strerror(ret));
		exit(1);
	}	

	return key;
}

gnutls_x509_crq load_request()
{
FILE* fd;
gnutls_x509_crq crq;
int ret;
gnutls_datum dat;
size_t size;

	if (!info.request) return NULL;

	fd = fopen(info.request, "r");
	if (fd == NULL) {
		fprintf(stderr, "File %s does not exist.\n", info.request);
		exit(1);
	}

	size = fread(buffer, 1, sizeof(buffer)-1, fd);
	buffer[size] = 0;

	fclose(fd);

	ret = gnutls_x509_crq_init(&crq);
	if (ret < 0) {
		fprintf(stderr, "crq_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	dat.data = buffer;
	dat.size = size;
	
	ret = gnutls_x509_crq_import( crq, &dat, in_cert_format);
	
	if (ret < 0) {
		fprintf(stderr, "crq_import: %s\n", gnutls_strerror(ret));
		exit(1);
	}	

	return crq;
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
		ret = gnutls_x509_privkey_import( key, &dat, in_cert_format);
	else
		ret = gnutls_x509_privkey_import_pkcs8( key, &dat, in_cert_format,
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
	
	ret = gnutls_x509_crt_import( crt, &dat, in_cert_format);
	if (ret < 0) {
		fprintf(stderr, "crt_import: %s\n", gnutls_strerror(ret));
		exit(1);
	}	

	return crt;
}

/* Loads the certificate
 */
gnutls_x509_crt load_cert()
{
FILE* fd;
gnutls_x509_crt crt;
int ret;
gnutls_datum dat;
size_t size;

	fprintf(stderr, "Loading certificate...\n");

	if (info.cert==NULL) {
		fprintf(stderr, "You must specify a certificate.\n");
		exit(1);
	}

	fd = fopen(info.cert, "r");
	if (fd == NULL) {
		fprintf(stderr, "File %s does not exist.\n", info.cert);
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
	
	ret = gnutls_x509_crt_import( crt, &dat, in_cert_format);
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
	ret = gnutls_x509_crq_export( crq, out_cert_format, buffer, &size);	
	if (ret < 0) {
		fprintf(stderr, "export: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	fprintf(outfile, "Request: \n%s", buffer);

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
	fprintf(outfile,  "Verification output:\n");
	if (x&GNUTLS_CERT_INVALID)
		fprintf(outfile, "\tcertificate chain is invalid.\n");
	else
	 	fprintf(outfile, "\tcertificate chain is valid.\n");

	if (x&GNUTLS_CERT_NOT_TRUSTED)
		fprintf(outfile, "\tThe certificate chain was NOT verified.\n");
	else
		fprintf(outfile, "\tThe certificate chain was verified.\n");

	if (x&GNUTLS_CERT_CORRUPTED)
		fprintf(outfile, "\tA certificate is corrupt.\n");

	if (x&GNUTLS_CERT_REVOKED)
		fprintf(outfile, "\tA certificate has been revoked.\n");
}

void verify_chain( void)
{
unsigned int output;
size_t size;

	size = fread( buffer, 1, sizeof(buffer)-1, infile);

	output = _verify_x509_mem( buffer, size);
	
	print_verification_res( output);
}

#include <gnutls/pkcs12.h>
#include <unistd.h>

void generate_pkcs12( void)
{
	gnutls_pkcs12 pkcs12;
	gnutls_pkcs12_bag bag, kbag;
	gnutls_x509_crt crt;
	gnutls_x509_privkey key;
	int result;
	size_t size;
	gnutls_datum data;
	char* password;
	const char* name;
	gnutls_datum key_id;
	unsigned char _key_id[20];
	int index;
	
	fprintf(stderr, "Generating a PKCS #12 structure...\n");
	
	if (outfile == stdout) {
		fprintf(stderr, "Sorry, will not output DER data to stdout.\n");
		exit(1);
	}
	
	key = load_private_key();
	crt = load_cert();
	
	do {
		name = read_str("Enter a name for the key: ");
	} while( name == NULL);

	password = getpass( "Enter password: ");
	
	result = gnutls_pkcs12_bag_init( &bag);
	if (result < 0) {
		fprintf(stderr, "bag_init: %s\n", gnutls_strerror(result));
		exit(1);
	}

	size = sizeof(_key_id);
	result = gnutls_x509_privkey_get_key_id( key, 0, _key_id, &size);
	if (result < 0) {
		fprintf(stderr, "key_id: %s\n", gnutls_strerror(result));
		exit(1);
	}
	
	key_id.data = _key_id;
	key_id.size = size;
		
	size = sizeof(buffer);
	result = gnutls_x509_crt_export( crt, GNUTLS_X509_FMT_DER, buffer, &size);
	if (result < 0) {
		fprintf(stderr, "crt_export: %s\n", gnutls_strerror(result));
		exit(1);
	}

	data.data = buffer;
	data.size = size;
	result = gnutls_pkcs12_bag_set_data( bag, GNUTLS_BAG_CERTIFICATE, &data);
	if (result < 0) {
		fprintf(stderr, "bag_set_data: %s\n", gnutls_strerror(result));
		exit(1);
	}
	
	index = result;

	result = gnutls_pkcs12_bag_set_friendly_name( bag, index, name);
	if (result < 0) {
		fprintf(stderr, "bag_set_key_id: %s\n", gnutls_strerror(result));
		exit(1);
	}
	

	result = gnutls_pkcs12_bag_set_key_id( bag, index, &key_id);
	if (result < 0) {
		fprintf(stderr, "bag_set_key_id: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = gnutls_pkcs12_bag_encrypt( bag, password, 0);
	if (result < 0) {
		fprintf(stderr, "bag_encrypt: %s\n", gnutls_strerror(result));
		exit(1);
	}
	
	/* Key BAG */

	result = gnutls_pkcs12_bag_init( &kbag);
	if (result < 0) {
		fprintf(stderr, "bag_init: %s\n", gnutls_strerror(result));
		exit(1);
	}

	size = sizeof(buffer);
	result = gnutls_x509_privkey_export_pkcs8( key, GNUTLS_X509_FMT_DER, password,
		GNUTLS_PKCS8_USE_PKCS12_3DES, buffer, &size);
	if (result < 0) {
		fprintf(stderr, "key_export: %s\n", gnutls_strerror(result));
		exit(1);
	}

	data.data = buffer;
	data.size = size;
	result = gnutls_pkcs12_bag_set_data( kbag, GNUTLS_BAG_PKCS8_ENCRYPTED_KEY, &data);
	if (result < 0) {
		fprintf(stderr, "bag_set_data: %s\n", gnutls_strerror(result));
		exit(1);
	}

	index = result;

	result = gnutls_pkcs12_bag_set_friendly_name( kbag, index, name);
	if (result < 0) {
		fprintf(stderr, "bag_set_key_id: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = gnutls_pkcs12_bag_set_key_id( kbag, result, &key_id);
	if (result < 0) {
		fprintf(stderr, "bag_set_key_id: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = gnutls_pkcs12_bag_encrypt( kbag, password, 0);
	if (result < 0) {
		fprintf(stderr, "bag_encrypt: %s\n", gnutls_strerror(result));
		exit(1);
	}

	/* write the PKCS #12 structure.
	 */
	result = gnutls_pkcs12_init(&pkcs12);
	if (result < 0) {
		fprintf(stderr, "crt_sign: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = gnutls_pkcs12_set_bag( pkcs12, bag);
	if (result < 0) {
		fprintf(stderr, "set_bag: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = gnutls_pkcs12_set_bag( pkcs12, kbag);
	if (result < 0) {
		fprintf(stderr, "set_bag: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = gnutls_pkcs12_generate_mac( pkcs12, password);
	if (result < 0) {
		fprintf(stderr, "generate_mac: %s\n", gnutls_strerror(result));
		exit(1);
	}

	size = sizeof(buffer);
	result = gnutls_pkcs12_export( pkcs12, GNUTLS_X509_FMT_DER, buffer, &size);
	if (result < 0) {
		fprintf(stderr, "pkcs12_export: %s\n", gnutls_strerror(result));
		exit(1);
	}
	
	fwrite( buffer, 1, size, outfile);
	
}
