#include <stdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <time.h>

#define PRINTX(x,y) if (y[0]!=0) printf(" #   %s %s\n", x, y)
#define PRINT_DN(X) PRINTX( "CN:", X.common_name); \
	PRINTX( "OU:", X.organizational_unit_name); \
	PRINTX( "O:", X.organization); \
	PRINTX( "L:", X.locality_name); \
	PRINTX( "S:", X.state_or_province_name); \
	PRINTX( "C:", X.country); \
	PRINTX( "E:", X.email)
#define PRINT_PGP_NAME(X) PRINTX( "NAME:", X.name); \
	PRINTX( "EMAIL:", X.email)

static const char* my_ctime( time_t* tv) {
static char buf[256];
struct tm* tp;

tp = localtime(tv);
strftime(buf, sizeof buf, "%a %b %e %H:%M:%S %Z %Y\n", tp);

return buf;

}

void print_x509_info(GNUTLS_STATE state)
{

	gnutls_x509_dn dn;
	const gnutls_datum *cert_list;
	int cert_list_size = 0;
	char digest[20];
	char serial[40];
	size_t digest_size = sizeof(digest);
	int i;
	int serial_size = sizeof(serial);
	char printable[120];
	char *print;
	int bits, algo;
	time_t expiret = gnutls_certificate_expiration_time_peers(state);
	time_t activet = gnutls_certificate_activation_time_peers(state);

	cert_list = gnutls_certificate_get_peers(state, &cert_list_size);

	if (cert_list_size <= 0)
		return;

	printf(" - Certificate info:\n");

	printf(" # Certificate is valid since: %s", my_ctime( &activet));
	printf(" # Certificate expires: %s", my_ctime( &expiret));

	/* Print the fingerprint of the certificate
	 */
	if (gnutls_x509_fingerprint
	    (GNUTLS_DIG_MD5, &cert_list[0], digest, &digest_size) >= 0) {
		print = printable;
		for (i = 0; i < digest_size; i++) {
			sprintf(print, "%.2x ", (unsigned char) digest[i]);
			print += 3;
		}
		printf(" # Certificate fingerprint: %s\n", printable);
	}

	/* Print the serial number of the certificate.
	 */

	if (gnutls_x509_extract_certificate_serial
	    (&cert_list[0], serial, &serial_size) >= 0) {
		print = printable;
		for (i = 0; i < serial_size; i++) {
			sprintf(print, "%.2x ", (unsigned char) serial[i]);
			print += 3;
		}
		printf(" # Certificate serial number: %s\n", printable);
	}

	/* Print the version of the X.509 
	 * certificate.
	 */
	printf(" # Certificate version: #%d\n",
	       gnutls_x509_extract_certificate_version(&cert_list[0]));

	algo = gnutls_x509_extract_certificate_pk_algorithm( &cert_list[0], &bits);
	printf(" # Certificate public key algorithm: ");

	if (algo==GNUTLS_PK_RSA) {
		printf("RSA\n");
		printf(" #   Modulus: %d bits\n", bits);
	} else if (algo==GNUTLS_PK_DSA) {
		printf("DSA\n");
		printf(" #   Exponent: %d bits\n", bits);
	} else {
		printf("UNKNOWN\n");
	}

	gnutls_x509_extract_certificate_dn(&cert_list[0], &dn);
	PRINT_DN(dn);

	gnutls_x509_extract_certificate_issuer_dn(&cert_list[0], &dn);
	printf(" # Certificate Issuer's info:\n");
	PRINT_DN(dn);

}

void print_openpgp_info(GNUTLS_STATE state)
{

	gnutls_openpgp_name pgp_name;
	char digest[20];
	int digest_size = sizeof(digest), i;
	char printable[120];
	char *print;
	const gnutls_datum *cert_list;
	int cert_list_size = 0;
	time_t expiret = gnutls_certificate_expiration_time_peers(state);
	time_t activet = gnutls_certificate_activation_time_peers(state);

	cert_list = gnutls_certificate_get_peers(state, &cert_list_size);

	if (cert_list_size > 0) {
		int algo, bits;

		printf(" # Key was created at: %s", my_ctime( &activet));
		printf(" # Key expires: ");
		if (expiret != 0)
			printf("%s", my_ctime( &expiret));
		else
			printf("Never\n");
		
		if (gnutls_openpgp_fingerprint
		    (&cert_list[0], digest, &digest_size) >= 0) {
			print = printable;
			for (i = 0; i < digest_size; i++) {
				sprintf(print, "%.2x ",
					(unsigned char) digest[i]);
				print += 3;
			}

			printf(" # PGP Key version: %d\n", 
				gnutls_openpgp_extract_key_version(&cert_list[0]));

			algo = gnutls_openpgp_extract_key_pk_algorithm( &cert_list[0], &bits);
		
			printf(" # PGP Key public key algorithm: ");

			if (algo==GNUTLS_PK_RSA) {
				printf("RSA\n");
				printf(" #   Modulus: %d bits\n", bits);
			} else if (algo==GNUTLS_PK_DSA) {
				printf("DSA\n");
				printf(" #   Exponent: %d bits\n", bits);
			} else {
				printf("UNKNOWN\n");
			}

			printf(" # PGP Key fingerprint: %s\n",
			       printable);

			gnutls_openpgp_extract_key_name(&cert_list
							      [0], 0, &pgp_name);
			PRINT_PGP_NAME(pgp_name);

		}

	}
}

void print_cert_vrfy(GNUTLS_STATE state)
{

	int status;
	status = gnutls_certificate_verify_peers(state);
	printf("\n");

	if (status == GNUTLS_E_NO_CERTIFICATE_FOUND) {
		printf("- Peer did not send any certificate.\n");
		return;
	}
	if (status < 0) {
		printf("- Could not verify certificate (err %d)\n", status);
		return;
	}

	if (status & GNUTLS_CERT_INVALID)
		printf("- Peer's certificate is invalid\n");
	if (status & GNUTLS_CERT_NOT_TRUSTED)
		printf("- Peer's certificate is NOT trusted\n");
	else
		printf("- Peer's certificate is trusted\n");
	if (status & GNUTLS_CERT_CORRUPTED)
		printf("- Peer's certificate is corrupted\n");

}

int print_info(GNUTLS_STATE state)
{
	const char *tmp;
	GNUTLS_CredType cred;
	GNUTLS_KXAlgorithm kx;


	/* print the key exchange's algorithm name
	 */
	kx = gnutls_kx_get(state);

	cred = gnutls_auth_get_type(state);
	switch (cred) {
	case GNUTLS_CRD_ANON:
		printf("- Anonymous DH using prime of %d bits, secret key "
			"of %d bits, and peer's public key is %d bits.\n",
		       gnutls_dh_get_prime_bits(state), gnutls_dh_get_secret_bits(state),
		       gnutls_dh_get_peers_public_bits(state));
		break;
	case GNUTLS_CRD_SRP:
		/* This should be only called in server
		 * side.
		 */
		if (gnutls_srp_server_get_username(state) != NULL)
			printf("- SRP authentication. Connected as '%s'\n",
			       gnutls_srp_server_get_username(state));
		break;
	case GNUTLS_CRD_CERTIFICATE:
		switch (gnutls_cert_type_get(state)) {
		case GNUTLS_CRT_X509:
			printf
			    ("- Peer requested X.509 certificate authentication.\n");

			print_x509_info(state);

			break;
		case GNUTLS_CRT_OPENPGP:{
				printf
				    ("- Peer requested OpenPGP certificate authentication.\n");

				print_openpgp_info(state);

				break;
			}
		}

		print_cert_vrfy(state);

		/* Check if we have been using ephemeral Diffie Hellman.
		 */
		if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS) {
			printf("- Ephemeral DH using prime of %d bits, secret key "
				"of %d bits, and peer's public key is %d bits.\n",
			       gnutls_dh_get_prime_bits(state), gnutls_dh_get_secret_bits(state),
			       gnutls_dh_get_peers_public_bits(state));
		}
	}

	tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(state));
	printf("- Version: %s\n", tmp);

	tmp = gnutls_kx_get_name(kx);
	printf("- Key Exchange: %s\n", tmp);

	tmp = gnutls_cipher_get_name(gnutls_cipher_get(state));
	printf("- Cipher: %s\n", tmp);

	tmp = gnutls_mac_get_name(gnutls_mac_get(state));
	printf("- MAC: %s\n", tmp);

	tmp = gnutls_compression_get_name(gnutls_compression_get(state));
	printf("- Compression: %s\n", tmp);

	return 0;
}

void print_list(void)
{
	/* FIXME: This is hard coded. Make it print all the supported
	 * algorithms.
	 */
	printf("\n");
	printf("Certificate types:");
	printf(" X.509");
	printf(", OPENPGP\n");

	printf("Protocols:");
	printf(" TLS1.0");
	printf(", SSL3.0\n");

	printf("Ciphers:");
	printf(" RIJNDAEL_128_CBC");
	printf(", TWOFISH_128_CBC");
	printf(", 3DES_CBC");
	printf(", ARCFOUR\n");

	printf("MACs:");
	printf(" MD5");
	printf(", SHA-1\n");

	printf("Key exchange algorithms:");
	printf(" RSA");
	printf(", DHE_DSS");
	printf(", DHE_RSA");
	printf(", SRP");
	printf(", ANON_DH\n");

	printf("Compression methods:");
	printf(" ZLIB");
	printf(", NULL\n");

	return;
}

void print_license(void)
{
   fprintf(stdout,
	   "\nCopyright (C) 2001-2002 Nikos Mavroyanopoulos\n"
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
