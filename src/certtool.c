/*
 * Copyright (C) 2003 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <gnutls/gnutls.h>

#ifdef ENABLE_PKI

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/x509.h>
#include <time.h>
#include "certtool-gaa.h"
#include <gnutls/pkcs12.h>
#include <unistd.h>

int generate_prime(int bits);
void pkcs12_info( void);
void generate_pkcs12( void);
void verify_chain(void);
gnutls_x509_privkey load_private_key(int mand);
gnutls_x509_crq load_request(void);
gnutls_x509_privkey load_ca_private_key(void);
gnutls_x509_crt load_ca_cert(void);
gnutls_x509_crt load_cert(int mand);
void certificate_info( void);
void crl_info( void);
void privkey_info( void);
static void print_certificate_info( gnutls_x509_crt crt);
static void gaa_parser(int argc, char **argv);
void generate_self_signed( void);
void generate_request(void);

static gaainfo info;
FILE* outfile;
FILE* infile;
int in_cert_format;
int out_cert_format;

unsigned char buffer[50*1024];
const int buffer_size = sizeof(buffer);

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

	ret = gnutls_x509_crt_set_dn_by_oid(crt, oid, 0, input, strlen(input)-1);
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

	ret = gnutls_x509_crq_set_dn_by_oid(crq, oid, 0, input, strlen(input)-1);
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

static const char* read_pass( const char* input_str)
{
static char input[128];
const char* pass;

	if (info.pass) return info.pass;

#ifdef _WIN32

	fputs( input_str, stderr);
	fgets( input, sizeof(input), stdin);
	
	input[strlen(input)-1] = 0;

	if (strlen(input)==0 || input[0]=='\n') return NULL;

	return input;
#else
	pass = getpass(input_str);
	if (pass == NULL || strlen(pass)==0 || pass[0]=='\n') return NULL;

	return pass;
#endif
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
		return load_private_key(1);

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
int ret;
size_t size;

	if (!key) return;

	if (!info.pkcs8) {
		size = sizeof(buffer);
		ret = gnutls_x509_privkey_export( key, out_cert_format, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "privkey_export: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	} else {
		unsigned int flags;
		const char* pass;
		
		if (info.export) flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
		else flags = GNUTLS_PKCS_USE_PKCS12_3DES;
		if ((pass=read_pass("Enter password: ")) == NULL) flags = GNUTLS_PKCS_PLAIN;

		size = sizeof(buffer);
		ret = gnutls_x509_privkey_export_pkcs8( key, out_cert_format, pass, flags, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "privkey_export_pkcs8: %s\n", gnutls_strerror(ret));
			exit(1);
		}
	}

	fwrite(buffer, 1, size, outfile);
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

		key = load_private_key(1);

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

	serial = read_int( "Enter the certificate's serial number (decimal): ");
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

	crt = load_cert(1);

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
	size_t size;
	int result;

	fprintf(stderr, "Generating a self signed certificate...\n");

	crt = generate_certificate( &key);

	print_certificate_info( crt);

	fprintf(stderr, "\n\nSigning certificate...\n");

	result = gnutls_x509_crt_sign( crt, crt, key);
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

	fwrite( buffer, 1, size, outfile);

	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);
}

void generate_signed_certificate( void)
{
	gnutls_x509_crt crt;
	gnutls_x509_privkey key;
	size_t size;
	int result;
	gnutls_x509_privkey ca_key;
	gnutls_x509_crt ca_crt;

	fprintf(stderr, "Generating a signed certificate...\n");

	ca_key = load_ca_private_key();
	ca_crt = load_ca_cert();

	crt = generate_certificate( &key);

	print_certificate_info( crt);
	
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

	fwrite( buffer, 1, size, outfile);

	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);
}

void update_signed_certificate( void)
{
	gnutls_x509_crt crt;
	size_t size;
	int result;
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

	fwrite( buffer, 1, size, outfile);

	gnutls_x509_crt_deinit(crt);
}

void gaa_parser(int argc, char **argv)
{
int ret;

	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr,
			"Error in the arguments. Use the --help or -h parameters to get more information.\n");
		exit(1);
	}
	
	if (info.outfile) {
		outfile = fopen(info.outfile, "w");
		if (outfile == NULL) {
			fprintf(stderr, "error: could not open '%s'.\n", info.outfile);
			exit(1);
		}
	} else outfile = stdout;

	if (info.infile) {
		infile = fopen(info.infile, "r");
		if (infile == NULL) {
			fprintf(stderr, "error: could not open '%s'.\n", info.infile);
			exit(1);
		}
	} else infile = stdin;
	
	if (info.incert_format) in_cert_format = GNUTLS_X509_FMT_DER;
	else in_cert_format = GNUTLS_X509_FMT_PEM;

	if (info.outcert_format) out_cert_format = GNUTLS_X509_FMT_DER;
	else out_cert_format = GNUTLS_X509_FMT_PEM;

	if ((ret=gnutls_global_init()) < 0) {
		fprintf(stderr, "global_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}

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
		case 9:
			pkcs12_info();
			break;
		case 10:
			generate_prime( info.bits);
			break;
		case 11:
			crl_info();
			break;
		default:
			fprintf(stderr, "GnuTLS' certtool utility.\n");
			fprintf(stderr, "Please use the --help to get help on this program.\n");
			exit(0);
	}
	fclose(outfile);
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

static inline int known_oid( const char* oid)
{
	if (strcmp(oid, "2.5.29.17") == 0 ||
		strcmp( oid, "2.5.29.19") == 0 ||
		strcmp( oid, "2.5.29.15") == 0)
			return 1;
	
	return 0;
}

void certificate_info( void)
{
	gnutls_x509_crt crt;
	int ret;
	unsigned int i, indx, j;
	unsigned int critical, key_usage;
	time_t tim;
	gnutls_datum pem;
	char serial[40];
	size_t serial_size = sizeof(serial), dn_size, size;
	char printable[256];
	char *print;
	const char* cprint;
	char dn[256];
	char oid[128] = "";
	char old_oid[128] = "";
		
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

	fprintf(outfile, "X.509 certificate info:\n\n");
	
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
		fprintf(outfile, "Serial Number (hex): %s\n", printable);
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
	ret = 0;
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

	/* other extensions:
	 */
	indx = 0;
	ret = 0;
	for (i = 0; !(ret < 0); i++) {

		size = sizeof(oid);
		ret = gnutls_x509_crt_get_extension_oid( crt, i, oid, &size);

		if (ret >= 0) {
			if (known_oid( oid)) continue;

			if (strcmp( oid, old_oid) == 0) {
				indx++;
			} else {
				indx = 0;
			}

			fprintf( outfile, "\t%s: ", oid);
			
			size = sizeof(buffer);
			ret = gnutls_x509_crt_get_extension_by_oid( crt, oid, indx, buffer, &size, &critical);
			if (ret >= 0) {
				if (critical)
					fprintf(outfile, "(critical)\n");
				else
					fprintf(outfile, "\n");

				print = printable;
				for (j = 0; j < size; j++) {
					sprintf(print, "%.2x ", (unsigned char) buffer[j]);
					print += 3;
				}
				fprintf(outfile, "\t\tDER Data: %s\n", printable);
			
			}
	
			ret = 0;
			strcpy( old_oid, oid);
		}
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

static void print_certificate_info( gnutls_x509_crt crt)
{
	int ret;
	unsigned int i;
	unsigned int critical, key_usage;
	time_t tim;
	char serial[40];
	size_t serial_size = sizeof(serial), dn_size, size;
	char printable[256];
	char *print;
	const char* cprint;
	char dn[256];
	
	fprintf( stderr, "\n\nX.509 certificate info:\n\n");
	
	fprintf(stderr, "Version: %d\n", gnutls_x509_crt_get_version(crt));

	/* serial number
	 */
	if (gnutls_x509_crt_get_serial(crt, serial, &serial_size) >= 0) {
		print = printable;
		for (i = 0; i < serial_size; i++) {
			sprintf(print, "%.2x ",
				(unsigned char) serial[i]);
			print += 3;
		}
		fprintf(stderr, "Serial Number (hex): %s\n", printable);
	}
	
	/* Validity
	 */
	fprintf(stderr, "Validity:\n");

	tim = gnutls_x509_crt_get_activation_time(crt);
	fprintf(stderr, "\tNot Before: %s", ctime(&tim));

	tim = gnutls_x509_crt_get_expiration_time(crt);
	fprintf(stderr, "\tNot After: %s", ctime(&tim));

	/* Subject
	 */
	dn_size = sizeof(dn);
	ret = gnutls_x509_crt_get_dn(crt, dn, &dn_size);
	if (ret >= 0)
		fprintf(stderr, "Subject: %s\n", dn);

	/* Public key algorithm
	 */
	fprintf(stderr, "Subject Public Key Info:\n");
	ret = gnutls_x509_crt_get_pk_algorithm(crt, NULL);
	fprintf(stderr, "\tPublic Key Algorithm: ");

	cprint = get_algorithm( ret);
	fprintf(stderr,  "%s\n", cprint);


	
	fprintf(stderr, "\nX.509 Extensions:\n");
	
	/* subject alternative name
	 */
	for (i = 0; !(ret < 0); i++) {
		size = sizeof(buffer);
		ret = gnutls_x509_crt_get_subject_alt_name(crt, i, buffer, &size, &critical);

		if (i==0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			fprintf(stderr, "\tSubject Alternative name:");
			if (critical) fprintf(stderr, " (critical)");
			fprintf(stderr, "\n");
		}
		
		if (ret < 0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			fprintf(stderr, "\t\tFound unsupported alternative name.\n");
		} else switch (ret) {
			case GNUTLS_SAN_DNSNAME:
				fprintf(stderr, "\t\tDNSname: %s\n", buffer);
				break;
			case GNUTLS_SAN_RFC822NAME:
				fprintf(stderr, "\t\tRFC822name: %s\n", buffer);
				break;
			case GNUTLS_SAN_URI:
				fprintf(stderr, "\t\tURI: %s\n", buffer);
				break;
			case GNUTLS_SAN_IPADDRESS:
				fprintf(stderr, "\t\tIPAddress: %s\n", buffer);
				break;
		}
	}
	
	/* check for basicConstraints
	 */
	ret = gnutls_x509_crt_get_ca_status( crt, &critical);
	
	if (ret >= 0) {
		fprintf(stderr, "\tBasic Constraints:");
		if (critical) fprintf(stderr, " (critical)");
		fprintf(stderr, "\n");		

		if (ret==0) fprintf(stderr, "\t\tCA:FALSE\n");
		else fprintf(stderr, "\t\tCA:TRUE\n");
		
	}

	/* Key Usage.
	 */
	ret = gnutls_x509_crt_get_key_usage( crt, &key_usage, &critical);
	
	if (ret >= 0) {
		fprintf(stderr, "\tKey usage:\n");
		print_key_usage(key_usage);
	}

	fprintf(stderr, "\n");

	if (read_yesno( "Is the above information ok? (Y/N): ")==0) {
		exit(1);
	}
}

void crl_info(void)
{
	gnutls_x509_crl crl;
	int ret, rc;
	size_t size;
	time_t tim;
	unsigned int i;
	gnutls_datum pem;
	unsigned char serial[40];
	size_t serial_size = sizeof(serial), dn_size;
	char printable[256];
	char *print, dn[256];
	const char* cprint;
		
	size = fread( buffer, 1, sizeof(buffer)-1, infile);
	buffer[size] = 0;

	gnutls_x509_crl_init(&crl);
	
	pem.data = buffer;
	pem.size = size;
	
	ret = gnutls_x509_crl_import(crl, &pem, in_cert_format);
	if (ret < 0) {
		fprintf(stderr, "Decoding error: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	fprintf(outfile, "Version: %d\n", gnutls_x509_crl_get_version(crl));

	/* Issuer
	 */
	dn_size = sizeof(dn);

	ret = gnutls_x509_crl_get_issuer_dn(crl, dn, &dn_size);
	if (ret >= 0)
		fprintf(outfile, "Issuer: %s\n", dn);

	fprintf(outfile, "Signature Algorithm: ");
	ret = gnutls_x509_crl_get_signature_algorithm(crl);

	cprint = get_algorithm( ret);
	fprintf(outfile,  "%s\n", cprint);

	/* Validity
	 */
	fprintf(outfile, "Update dates:\n");

	tim = gnutls_x509_crl_get_this_update(crl);
	fprintf(outfile, "\tIssued at: %s", ctime(&tim));

	tim = gnutls_x509_crl_get_next_update(crl);
	fprintf(outfile, "\tNext at: %s", ctime(&tim));

	fprintf(outfile, "\n");
	
	/* Count the certificates.
	 */
	 
	rc = gnutls_x509_crl_get_crt_count( crl);
	fprintf(outfile, "Revoked certificates: %d\n", rc);

	for (i=0;i<(unsigned int)rc;i++) {
		/* serial number
		 */
		serial_size = sizeof(serial);
		if (gnutls_x509_crl_get_crt_serial(crl, i, serial, &serial_size, &tim) >= 0) {
			print = printable;
			for (i = 0; i < serial_size; i++) {
				sprintf(print, "%.2x ",
					(unsigned char) serial[i]);
				print += 3;
			}
			fprintf(outfile, "\tCertificate SN: %s\n", printable);
			fprintf(outfile, "\tRevoked at: %s\n", ctime( &tim));
		}
	
	}
}

void privkey_info( void)
{
	gnutls_x509_privkey key;
	size_t size;
	int ret;
	unsigned int i;
	gnutls_datum pem;
	char printable[256];
	char *print;
	const char* cprint;
	const char* pass;
		
	size = fread( buffer, 1, sizeof(buffer)-1, infile);
	buffer[size] = 0;

	gnutls_x509_privkey_init(&key);
	
	pem.data = buffer;
	pem.size = size;
	
	pass = read_pass("Enter password: ");

	if (!info.pkcs8) {
		ret = gnutls_x509_privkey_import(key, &pem, in_cert_format);
	} else {
		ret = gnutls_x509_privkey_import_pkcs8(key, &pem, in_cert_format, pass, 0);
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

/* mand should be non zero if it is required to read a private key.
 */
gnutls_x509_privkey load_private_key(int mand)
{
FILE* fd;
gnutls_x509_privkey key;
int ret;
gnutls_datum dat;
size_t size;
const char* pass;

	if (!info.privkey && !mand) return NULL;

	if (!info.privkey) {
		fprintf(stderr, "error: a private key was not specified\n");
		exit(1);
	}

	fd = fopen(info.privkey, "r");
	if (fd == NULL) {
		fprintf(stderr, "error: could not load key file '%s'.\n", info.privkey);
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
	else {
		pass = read_pass("Enter password: ");
		ret = gnutls_x509_privkey_import_pkcs8( key, &dat, in_cert_format,
			pass, 0);
	}
	
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
const char* pass;
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
	else {
		pass = read_pass("Enter password: ");
		ret = gnutls_x509_privkey_import_pkcs8( key, &dat, in_cert_format,
			pass, 0);
	}
	
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
 * If mand is non zero then a certificate is mandatory. Otherwise
 * null will be returned if the certificate loading fails.
 */
gnutls_x509_crt load_cert(int mand)
{
FILE* fd;
gnutls_x509_crt crt;
int ret;
gnutls_datum dat;
size_t size;

	fprintf(stderr, "Loading certificate...\n");

	if (info.cert==NULL) {
		fprintf(stderr, "You must specify a certificate.\n");
		if (mand) exit(1);
		else return NULL;
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

	pass = read_pass("Enter a challenge password: ");
	
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

	size = sizeof(buffer);	
	ret = gnutls_x509_crq_export( crq, out_cert_format, buffer, &size);	
	if (ret < 0) {
		fprintf(stderr, "export: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	fwrite( buffer, 1, size, outfile);

	gnutls_x509_crq_deinit(crq);
	gnutls_x509_privkey_deinit(key);

}

static void print_verification_res( gnutls_x509_crt crt, gnutls_x509_crt issuer,
	gnutls_x509_crl *crl_list, int crl_list_size);

#define CERT_SEP "-----BEGIN CERT"
#define CRL_SEP "-----BEGIN X509 CRL"
int _verify_x509_mem( const void* cert, int cert_size)
{
	int siz, i;
	const char *ptr;
	int ret;
	unsigned int output;
	char name[256];
	char issuer_name[256];
	size_t name_size;
	size_t issuer_name_size;
	gnutls_datum tmp;
	gnutls_x509_crt *x509_cert_list = NULL;
	gnutls_x509_crl *x509_crl_list = NULL;
	int x509_ncerts, x509_ncrls;
	

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
		

		if (i-1 != 0) {
			/* verify the previous certificate using this one 
			 * as CA.
			 */

			name_size = sizeof(name);
			ret = gnutls_x509_crt_get_dn( x509_cert_list[i-2], name, &name_size);
			if (ret < 0) {
				fprintf(stderr, "Error in get_dn: %s\n", gnutls_strerror(ret));
				exit(1);
			}

			fprintf( outfile, "Certificate[%d]: %s\n", i-2, name);

			/* print issuer 
			 */
			issuer_name_size = sizeof(issuer_name);
			ret = gnutls_x509_crt_get_issuer_dn( x509_cert_list[i-2], issuer_name, &issuer_name_size);
			if (ret < 0) {
				fprintf(stderr, "Error in get_dn: %s\n", gnutls_strerror(ret));
				exit(1);
			}

			fprintf( outfile, "\tIssued by: %s\n", name);
			
			/* Get the Issuer's name
			 */
			name_size = sizeof(name);
			ret = gnutls_x509_crt_get_dn( x509_cert_list[i-1], name, &name_size);
			if (ret < 0) {
				fprintf(stderr, "Error in get_dn: %s\n", gnutls_strerror(ret));
				exit(1);
			}

			fprintf( outfile, "\tVerifying against certificate[%d].\n", i-1);

			if (strcmp( issuer_name, name) != 0) {
				fprintf(stderr, "Error: Issuer's name: %s\n", name);
				fprintf(stderr, "Error: Issuer's name does not match the next certificate.\n");
				exit(1);
			}

			fprintf( outfile, "\tVerification output: ");
			print_verification_res( x509_cert_list[i-2], x509_cert_list[i-1], 
				x509_crl_list, x509_ncrls);
			fprintf( outfile, ".\n\n");

		}


		/* now we move ptr after the pem header 
		 */
		ptr = strstr(ptr, CERT_SEP);
		if (ptr!=NULL)
			ptr++;

		i++;
	} while ((ptr = strstr(ptr, CERT_SEP)) != NULL);

	x509_ncerts = i - 1;

	/* The last certificate in the list will be used as
	 * a CA (should be self signed).
	 */
	name_size = sizeof(name);
	ret = gnutls_x509_crt_get_dn( x509_cert_list[x509_ncerts-1], name, &name_size);
	if (ret < 0) {
		fprintf(stderr, "Error in get_dn: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	fprintf( outfile, "Certificate[%d]: %s\n", x509_ncerts-1, name);

	/* print issuer 
	 */
	issuer_name_size = sizeof(issuer_name);
	ret = gnutls_x509_crt_get_issuer_dn( x509_cert_list[x509_ncerts-1], issuer_name, &issuer_name_size);
	if (ret < 0) {
		fprintf(stderr, "Error in get_dn: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	fprintf( outfile, "\tIssued by: %s\n", name);
			
	if (strcmp( issuer_name, name) != 0) {
		fprintf(stderr, "Error: The last certificate is not self signed.\n");
		exit(1);
	}

	fprintf( outfile, "\tVerification output: ");
	print_verification_res( x509_cert_list[x509_ncerts-1], x509_cert_list[x509_ncerts-1], 
				x509_crl_list, x509_ncrls);

	fprintf( outfile, ".\n\n");

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

static void print_verification_res( gnutls_x509_crt crt, gnutls_x509_crt issuer,
	gnutls_x509_crl *crl_list, int crl_list_size)
{
unsigned int output;
int comma=0;
int ret;
time_t now = time(0);

	ret = gnutls_x509_crt_verify( crt, &issuer, 1, 0, &output);
	if (ret < 0) {
		fprintf(stderr, "Error in verification: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	if (output&GNUTLS_CERT_NOT_TRUSTED) {
		fprintf(outfile, "Not verified");
		comma = 1;
	} else {
		fprintf(outfile, "Verified");
		comma = 1;
	}

	if (output&GNUTLS_CERT_SIGNER_NOT_CA) {
		if (comma) fprintf(outfile, ", ");
		fprintf(outfile, "Issuer is not a CA");
		comma = 1;
	}

	/* Check expiration dates.
	 */
	
	if (gnutls_x509_crt_get_activation_time(crt) > now) {
		if (comma) fprintf(outfile, ", ");
		comma = 1;
		fprintf(outfile, "Not activated");
	}
	
	if (gnutls_x509_crt_get_expiration_time(crt) < now) {
		if (comma) fprintf(outfile, ", ");
		comma = 1;
		fprintf(outfile, "Expired");
	}
	
	ret = gnutls_x509_crt_check_revocation( crt, crl_list, crl_list_size);
	if (ret < 0) {
		fprintf(stderr, "Error in verification: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	
	if (ret == 1) { /* revoked */
		if (comma) fprintf(outfile, ", ");
		comma = 1;
		fprintf(outfile, "Revoked");
	}
	

}

void verify_chain( void)
{
size_t size;

	size = fread( buffer, 1, sizeof(buffer)-1, infile);

	_verify_x509_mem( buffer, size);
	
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
	const char* password;
	const char* name;
	unsigned int flags;
	gnutls_datum key_id;
	unsigned char _key_id[20];
	int index;

	fprintf(stderr, "Generating a PKCS #12 structure...\n");
	
	key = load_private_key(1);
	crt = load_cert(0);
	
	do {
		name = read_str("Enter a name for the key: ");
	} while( name == NULL);

	password = read_pass( "Enter password: ");

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
		
	if (crt) { /* add the certificate only if it was specified.
		    */
		result = gnutls_pkcs12_bag_set_crt( bag, crt);
		if (result < 0) {
			fprintf(stderr, "set_crt: %s\n", gnutls_strerror(result));
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

		if (info.export) flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
		else flags = GNUTLS_PKCS8_USE_PKCS12_3DES;

		result = gnutls_pkcs12_bag_encrypt( bag, password, flags);
		if (result < 0) {
			fprintf(stderr, "bag_encrypt: %s\n", gnutls_strerror(result));
			exit(1);
		}
	}
	
	/* Key BAG */

	result = gnutls_pkcs12_bag_init( &kbag);
	if (result < 0) {
		fprintf(stderr, "bag_init: %s\n", gnutls_strerror(result));
		exit(1);
	}

	if (info.export) flags = GNUTLS_PKCS_USE_PKCS12_RC2_40;
	else flags = GNUTLS_PKCS_USE_PKCS12_3DES;

	size = sizeof(buffer);
	result = gnutls_x509_privkey_export_pkcs8( key, GNUTLS_X509_FMT_DER, password,
		flags, buffer, &size);
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

	/* write the PKCS #12 structure.
	 */
	result = gnutls_pkcs12_init(&pkcs12);
	if (result < 0) {
		fprintf(stderr, "crt_sign: %s\n", gnutls_strerror(result));
		exit(1);
	}

	if (crt) {
		result = gnutls_pkcs12_set_bag( pkcs12, bag);
		if (result < 0) {
			fprintf(stderr, "set_bag: %s\n", gnutls_strerror(result));
			exit(1);
		}
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
	result = gnutls_pkcs12_export( pkcs12, out_cert_format, buffer, &size);
	if (result < 0) {
		fprintf(stderr, "pkcs12_export: %s\n", gnutls_strerror(result));
		exit(1);
	}
	
	fwrite( buffer, 1, size, outfile);
	
}

const char* BAGTYPE( gnutls_pkcs12_bag_type x)
{
	switch (x) {
		case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
			return "PKCS #8 Encrypted key";
		case GNUTLS_BAG_EMPTY:
			return "Empty";
		case GNUTLS_BAG_PKCS8_KEY:
			return "PKCS #8 Key";
		case GNUTLS_BAG_CERTIFICATE:
			return "Certificate";
		case GNUTLS_BAG_ENCRYPTED:
			return "Encrypted";
		case GNUTLS_BAG_CRL:
			return "CRL";
		default:
			return "Unknown";
	}
}

void print_bag_data(gnutls_pkcs12_bag bag)
{
int result;
int count, i, type;
gnutls_const_datum cdata;
const char* str;
gnutls_datum out, data;

	count = gnutls_pkcs12_bag_get_count( bag);
	if (count < 0) {
		fprintf(stderr, "get_count: %s\n", gnutls_strerror(count));
		exit(1);
	}

	fprintf( outfile, "\tElements: %d\n", count);
	
	for (i=0;i<count;i++) {
		type = gnutls_pkcs12_bag_get_type( bag, i);
		if (type < 0) {
			fprintf(stderr, "get_type: %s\n", gnutls_strerror(type));
			exit(1);
		}

		fprintf( outfile, "\tType: %s\n", BAGTYPE( type));
		
		result = gnutls_pkcs12_bag_get_data( bag, i, &cdata);
		if (result < 0) {
			fprintf(stderr, "get_data: %s\n", gnutls_strerror(result));
			exit(1);
		}
		
		switch (type) {
		case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
			str = "ENCRYPTED PRIVATE KEY";
			break;
		case GNUTLS_BAG_PKCS8_KEY:
			str = "PRIVATE KEY";
			break;
		case GNUTLS_BAG_CERTIFICATE:
			str = "CERTIFICATE";
			break;
		case GNUTLS_BAG_CRL:
			str = "CRL";
			break;
		case GNUTLS_BAG_ENCRYPTED:
		case GNUTLS_BAG_EMPTY:
		default:
			str = NULL;
		}		
	
		/* we have to cast gnutls_const_datum to a
		 * plain datum.
		 */
		data.data = (unsigned char*)cdata.data;
		data.size = cdata.size;

		if (str != NULL) {
			gnutls_pem_base64_encode_alloc( str, &data, &out);
			fprintf( outfile, "%s\n", out.data);
		
			gnutls_free(out.data);
		}
	
	}
}

void pkcs12_info( void)
{
	gnutls_pkcs12 pkcs12;
	gnutls_pkcs12_bag bag;
	int result, ret;
	size_t size;
	gnutls_datum data;
	const char* password;
	int index;
	
	size = fread( buffer, 1, sizeof(buffer)-1, infile);
	buffer[size] = 0;
	
	data.data = buffer;
	data.size = size;

	password = read_pass( "Enter password: ");
	
	result = gnutls_pkcs12_init(&pkcs12);
	if (result < 0) {
		fprintf(stderr, "p12_init: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = gnutls_pkcs12_import( pkcs12, &data, in_cert_format, 0);
	if (result < 0) {
		fprintf(stderr, "p12_import: %s\n", gnutls_strerror(result));
		exit(1);
	}

	result = gnutls_pkcs12_verify_mac( pkcs12, password);
	if (result < 0) {
		fprintf(stderr, "verify_mac: %s\n", gnutls_strerror(result));
		exit(1);
	}



	index = 0;

	do {
		result = gnutls_pkcs12_bag_init( &bag);
		if (result < 0) {
			fprintf(stderr, "bag_init: %s\n", gnutls_strerror(result));
			exit(1);
		}

		ret = gnutls_pkcs12_get_bag( pkcs12, index, bag);
		if (ret < 0) {
			break;
		}
		
		result = gnutls_pkcs12_bag_get_count( bag);
		if (result < 0) {
			fprintf(stderr, "bag_init: %s\n", gnutls_strerror(result));
			exit(1);
		}
	
		fprintf( outfile, "BAG #%d\n", index);
		
		result = gnutls_pkcs12_bag_get_type( bag, 0);
		if (result < 0) {
			fprintf(stderr, "bag_init: %s\n", gnutls_strerror(result));
			exit(1);
		}

		
		if (result == GNUTLS_BAG_ENCRYPTED) {
			fprintf( stderr, "\tType: %s\n", BAGTYPE( result));
			fprintf( stderr, "\n\tDecrypting...\n");

			result = gnutls_pkcs12_bag_decrypt( bag, password);

			if (result < 0) {
				fprintf(stderr, "bag_decrypt: %s\n", gnutls_strerror(result));
				exit(1);
			}

			result = gnutls_pkcs12_bag_get_count( bag);
			if (result < 0) {
				fprintf(stderr, "get_count: %s\n", gnutls_strerror(result));
				exit(1);
			}
	
		}

		print_bag_data( bag);
		
		gnutls_pkcs12_bag_deinit(bag);
		
		index++;
	} while( ret == 0);

	
}

#else /* ENABLE_PKI */

#include <stdio.h>

int main (int argc, char **argv)
{
    printf ("\nX.509 PKI not supported. This program is a dummy.\n\n");
    return 1;
};

#endif

void certtool_version(void)
{
	fprintf(stderr, "certtool, ");
	fprintf(stderr, "version %s. Libgnutls %s.\n", LIBGNUTLS_VERSION,
		gnutls_check_version(NULL));
}

void print_license(void)
{
	fprintf(stdout,
		"\nCopyright (C) 2001-2003 Nikos Mavroyanopoulos\n"
		"This program is free software; you can redistribute it and/or modify \n"
		"it under the terms of the GNU General Public License as published by \n"
		"the Free Software Foundation; either version 2 of the License, or \n"
		"(at your option) any later version. \n" "\n"
		"This program is distributed in the hope that it will be useful, \n"
		"but WITHOUT ANY WARRANTY; without even the implied warranty of \n"
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the \n"
		"GNU General Public License for more details. \n" "\n"
		"You should have received a copy of the GNU General Public License \n"
		"along with this program; if not, write to the Free Software \n"
		"Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n");
}
