#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/x509.h>
#include <time.h>

#define TEST_STRING

int xml = 0;
void print_cert_info(gnutls_session session);

#define PRINTX(x,y) if (y[0]!=0) printf(" #   %s %s\n", x, y)
#define PRINT_PGP_NAME(X) PRINTX( "NAME:", X.name); \
	PRINTX( "EMAIL:", X.email)

static const char *my_ctime(time_t * tv)
{
	static char buf[256];
	struct tm *tp;

	tp = localtime(tv);
	strftime(buf, sizeof buf, "%a %b %e %H:%M:%S %Z %Y\n", tp);

	return buf;

}

void print_x509_info(gnutls_session session)
{
	gnutls_x509_crt crt;
	const gnutls_datum *cert_list;
	int cert_list_size = 0, ret;
	char digest[20];
	char serial[40];
	char dn[256];
	int dn_size;
	size_t digest_size = sizeof(digest);
	int i, j;
	int serial_size = sizeof(serial);
	char printable[256];
	char *print;
	int bits, algo;
	time_t expiret, activet;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);


	if (cert_list_size <= 0) {
		fprintf(stderr, "No certificates found!\n");
		return;
	}

	printf(" - Got a certificate list of %d certificates.\n\n",
	       cert_list_size);

	for (j = 0; j < cert_list_size; j++) {

		gnutls_x509_crt_init(&crt);
		ret =
		    gnutls_x509_crt_import(crt, &cert_list[j],
					   GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			fprintf(stderr, "Decoding error: %s\n",
				gnutls_strerror(ret));
			return;
		}


		printf(" - Certificate[%d] info:\n", j);

		if (xml) {
			gnutls_datum xml_data;

			ret = gnutls_x509_crt_to_xml( crt, &xml_data, 0);
			if (ret < 0) {
				fprintf(stderr, "XML encoding error: %s\n",
					gnutls_strerror(ret));
				return;
			}
			
			printf("%s", xml_data.data);
			gnutls_free( xml_data.data);

		} else {

			expiret = gnutls_x509_crt_get_expiration_time(crt);
			activet = gnutls_x509_crt_get_activation_time(crt);

			printf(" # valid since: %s", my_ctime(&activet));
			printf(" # expires at: %s", my_ctime(&expiret));


			/* Print the serial number of the certificate.
			 */
			if (gnutls_x509_crt_get_serial(crt, serial, &serial_size)
			    >= 0) {
				print = printable;
				for (i = 0; i < serial_size; i++) {
					sprintf(print, "%.2x ",
						(unsigned char) serial[i]);
					print += 3;
				}
				printf(" # serial number: %s\n", printable);
			}

			/* Print the fingerprint of the certificate
			 */
			digest_size = sizeof(digest);
			if ((ret=gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_MD5, digest, &digest_size))
			    < 0) {
			    	fprintf(stderr, "Error in fingerprint calculation: %s\n", gnutls_strerror(ret));
			} else {
				print = printable;
				for (i = 0; i < digest_size; i++) {
					sprintf(print, "%.2x ",
						(unsigned char) digest[i]);
					print += 3;
				}
				printf(" # fingerprint: %s\n", printable);
			}

			/* Print the version of the X.509 
			 * certificate.
			 */
			printf(" # version: #%d\n",
			       gnutls_x509_crt_get_version(crt));

			algo = gnutls_x509_crt_get_pk_algorithm(crt, &bits);
			printf(" # public key algorithm: ");
			if (algo == GNUTLS_PK_RSA) {
				printf("RSA\n");
				printf(" #   Modulus: %d bits\n", bits);
			} else if (algo == GNUTLS_PK_DSA) {
				printf("DSA\n");
				printf(" #   Exponent: %d bits\n", bits);
			} else {
				printf("UNKNOWN\n");
			}

			dn_size = sizeof(dn);
			ret = gnutls_x509_crt_get_dn(crt, dn, &dn_size);
			if (ret >= 0)
				printf(" # Subject's DN: %s\n", dn);
	
			dn_size = sizeof(dn);
			ret = gnutls_x509_crt_get_issuer_dn(crt, dn, &dn_size);
			if (ret >= 0)
				printf(" # Issuer's DN: %s\n", dn);
		}

		gnutls_x509_crt_deinit(crt);
		
		printf("\n");

	}

}

void print_openpgp_info(gnutls_session session)
{

	gnutls_openpgp_name pgp_name;
	char digest[20];
	int digest_size = sizeof(digest), i;
	char printable[120];
	char *print;
	const gnutls_datum *cert_list;
	int cert_list_size = 0;
	time_t expiret = gnutls_certificate_expiration_time_peers(session);
	time_t activet = gnutls_certificate_activation_time_peers(session);

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

	if (cert_list_size > 0) {
		int algo, bits;

#if 0
		if (xml) {
			gnutls_datum res;

			gnutls_openpgp_key_to_xml(&cert_list[0], &res, 0);
			puts(res.data);

			free(res.data);

			return;
		}
#endif

		printf(" # Key was created at: %s", my_ctime(&activet));
		printf(" # Key expires: ");
		if (expiret != 0)
			printf("%s", my_ctime(&expiret));
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
			       gnutls_openpgp_extract_key_version
			       (&cert_list[0]));

			algo =
			    gnutls_openpgp_extract_key_pk_algorithm
			    (&cert_list[0], &bits);

			printf(" # PGP Key public key algorithm: ");

			if (algo == GNUTLS_PK_RSA) {
				printf("RSA\n");
				printf(" #   Modulus: %d bits\n", bits);
			} else if (algo == GNUTLS_PK_DSA) {
				printf("DSA\n");
				printf(" #   Exponent: %d bits\n", bits);
			} else {
				printf("UNKNOWN\n");
			}

			printf(" # PGP Key fingerprint: %s\n", printable);

			if (gnutls_openpgp_extract_key_name(&cert_list[0],
							    0,
							    &pgp_name) <
			    0) {
				fprintf(stderr,
					"Could not extract name\n");
			} else {
				PRINT_PGP_NAME(pgp_name);
			}

		}

	}
}

void print_cert_vrfy(gnutls_session session)
{

	int status;
	status = gnutls_certificate_verify_peers(session);
	printf("\n");

	if (status == GNUTLS_E_NO_CERTIFICATE_FOUND) {
		printf("- Peer did not send any certificate.\n");
		return;
	}
	if (status < 0) {
		printf("- Could not verify certificate (err %d)\n",
		       status);
		return;
	}

	if (status & GNUTLS_CERT_INVALID)
		printf("- Peer's certificate chain is broken\n");
	if (status & GNUTLS_CERT_NOT_TRUSTED)
		printf("- Peer's certificate is NOT trusted\n");
	else
		printf("- Peer's certificate is trusted\n");
	if (status & GNUTLS_CERT_CORRUPTED)
		printf("- Peer's certificate is corrupted\n");

}

int print_info(gnutls_session session)
{
	const char *tmp;
	gnutls_credentials_type cred;
	gnutls_kx_algorithm kx;


	/* print the key exchange's algorithm name
	 */
	kx = gnutls_kx_get(session);

	cred = gnutls_auth_get_type(session);
	switch (cred) {
	case GNUTLS_CRD_ANON:
		printf("- Anonymous DH using prime of %d bits, secret key "
		       "of %d bits, and peer's public key is %d bits.\n",
		       gnutls_dh_get_prime_bits(session),
		       gnutls_dh_get_secret_bits(session),
		       gnutls_dh_get_peers_public_bits(session));
		break;
	case GNUTLS_CRD_SRP:
		/* This should be only called in server
		 * side.
		 */
		if (gnutls_srp_server_get_username(session) != NULL)
			printf("- SRP authentication. Connected as '%s'\n",
			       gnutls_srp_server_get_username(session));
		break;
	case GNUTLS_CRD_CERTIFICATE:
		{
			char dns[256];
			int dns_size = sizeof(dns);
			int type;

			/* This fails in client side */
			if (gnutls_get_server_name
			    (session, dns, &dns_size, &type, 0) == 0) {
				printf("- Given server name[%d]: %s\n",
				       type, dns);
			}
		}

		print_cert_info(session);

		print_cert_vrfy(session);

		/* Check if we have been using ephemeral Diffie Hellman.
		 */
		if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS) {
			printf
			    ("- Ephemeral DH using prime of %d bits, secret key "
			     "of %d bits, and peer's public key is %d bits.\n",
			     gnutls_dh_get_prime_bits(session),
			     gnutls_dh_get_secret_bits(session),
			     gnutls_dh_get_peers_public_bits(session));
		}
	}

	tmp =
	    gnutls_protocol_get_name(gnutls_protocol_get_version(session));
	printf("- Version: %s\n", tmp);

	tmp = gnutls_kx_get_name(kx);
	printf("- Key Exchange: %s\n", tmp);

	tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
	printf("- Cipher: %s\n", tmp);

	tmp = gnutls_mac_get_name(gnutls_mac_get(session));
	printf("- MAC: %s\n", tmp);

	tmp = gnutls_compression_get_name(gnutls_compression_get(session));
	printf("- Compression: %s\n", tmp);

	return 0;
}

void print_cert_info(gnutls_session session)
{

	printf("- Certificate type: ");
	switch (gnutls_certificate_type_get(session)) {
	case GNUTLS_CRT_X509:
		printf("X.509\n");
		print_x509_info(session);
		break;
	case GNUTLS_CRT_OPENPGP:
		printf("OpenPGP\n");
		print_openpgp_info(session);
		break;
	}

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
	printf(" RIJNDAEL-128-CBC");
	printf(", TWOFISH-128-CBC");
	printf(", 3DES-CBC");
	printf(", ARCFOUR\n");
	printf(", ARCFOUR-40\n");

	printf("MACs:");
	printf(" MD5");
	printf(", SHA-1\n");

	printf("Key exchange algorithms:");
	printf(" RSA");
	printf(", RSA-EXPORT");
	printf(", DHE-DSS");
	printf(", DHE-RSA");
	printf(", SRP");
	printf(", SRP-RSA");
	printf(", SRP-DSS");
	printf(", ANON-DH\n");

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

void parse_protocols(char **protocols, int protocols_size,
		     int *protocol_priority)
{
	int i, j;

	if (protocols != NULL && protocols_size > 0) {
		for (j = i = 0; i < protocols_size; i++) {
			if (strncasecmp(protocols[i], "SSL", 3) == 0)
				protocol_priority[j++] = GNUTLS_SSL3;
			if (strncasecmp(protocols[i], "TLS", 3) == 0)
				protocol_priority[j++] = GNUTLS_TLS1;
		}
		protocol_priority[j] = 0;
	}
}

void parse_ciphers(char **ciphers, int nciphers, int *cipher_priority)
{
	int j, i;

	if (ciphers != NULL && nciphers > 0) {
		for (j = i = 0; i < nciphers; i++) {
			if (strncasecmp(ciphers[i], "RIJ", 3) == 0)
				cipher_priority[j++] =
				    GNUTLS_CIPHER_RIJNDAEL_128_CBC;
			if (strncasecmp(ciphers[i], "TWO", 3) == 0)
				cipher_priority[j++] =
				    GNUTLS_CIPHER_TWOFISH_128_CBC;
			if (strncasecmp(ciphers[i], "3DE", 3) == 0)
				cipher_priority[j++] =
				    GNUTLS_CIPHER_3DES_CBC;
			if (strcasecmp(ciphers[i], "ARCFOUR-40") == 0)
				cipher_priority[j++] =
				    GNUTLS_CIPHER_ARCFOUR_40;
			if (strcasecmp(ciphers[i], "ARCFOUR") == 0)
				cipher_priority[j++] =
				    GNUTLS_CIPHER_ARCFOUR_128;
			if (strncasecmp(ciphers[i], "NUL", 3) == 0)
				cipher_priority[j++] = GNUTLS_CIPHER_NULL;
		}
		cipher_priority[j] = 0;
	}
}

void parse_macs(char **macs, int nmacs, int *mac_priority)
{
	int i, j;
	if (macs != NULL && nmacs > 0) {
		for (j = i = 0; i < nmacs; i++) {
			if (strncasecmp(macs[i], "MD5", 3) == 0)
				mac_priority[j++] = GNUTLS_MAC_MD5;
			if (strncasecmp(macs[i], "SHA", 3) == 0)
				mac_priority[j++] = GNUTLS_MAC_SHA;
		}
		mac_priority[j] = 0;
	}
}

void parse_ctypes(char **ctype, int nctype, int *cert_type_priority)
{
	int i, j;
	if (ctype != NULL && nctype > 0) {
		for (j = i = 0; i < nctype; i++) {
			if (strncasecmp(ctype[i], "OPE", 3) == 0)
				cert_type_priority[j++] =
				    GNUTLS_CRT_OPENPGP;
			if (strncasecmp(ctype[i], "X", 1) == 0)
				cert_type_priority[j++] = GNUTLS_CRT_X509;
		}
		cert_type_priority[j] = 0;
	}
}

void parse_kx(char **kx, int nkx, int *kx_priority)
{
	int i, j;
	if (kx != NULL && nkx > 0) {
		for (j = i = 0; i < nkx; i++) {
			if (strcasecmp(kx[i], "SRP") == 0)
				kx_priority[j++] = GNUTLS_KX_SRP;
			if (strcasecmp(kx[i], "SRP-RSA") == 0)
				kx_priority[j++] = GNUTLS_KX_SRP_RSA;
			if (strcasecmp(kx[i], "SRP-DSS") == 0)
				kx_priority[j++] = GNUTLS_KX_SRP_DSS;
			if (strcasecmp(kx[i], "RSA") == 0)
				kx_priority[j++] = GNUTLS_KX_RSA;
			if (strcasecmp(kx[i], "RSA-EXPORT") == 0)
				kx_priority[j++] = GNUTLS_KX_RSA_EXPORT;
			if (strncasecmp(kx[i], "DHE-RSA", 7) == 0)
				kx_priority[j++] = GNUTLS_KX_DHE_RSA;
			if (strncasecmp(kx[i], "DHE-DSS", 7) == 0)
				kx_priority[j++] = GNUTLS_KX_DHE_DSS;
			if (strncasecmp(kx[i], "ANON", 4) == 0)
				kx_priority[j++] = GNUTLS_KX_ANON_DH;
		}
		kx_priority[j] = 0;
	}
}

void parse_comp(char **comp, int ncomp, int *comp_priority)
{
	int i, j;
	if (comp != NULL && ncomp > 0) {
		for (j = i = 0; i < ncomp; i++) {
			if (strncasecmp(comp[i], "NUL", 3) == 0)
				comp_priority[j++] = GNUTLS_COMP_NULL;
			if (strncasecmp(comp[i], "ZLI", 3) == 0)
				comp_priority[j++] = GNUTLS_COMP_ZLIB;
			if (strncasecmp(comp[i], "LZO", 3) == 0)
				comp_priority[j++] = GNUTLS_COMP_LZO;
		}
		comp_priority[j] = 0;
	}

}
