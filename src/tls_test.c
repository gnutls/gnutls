/*
 * Copyright (C) 2000,2001,2002,2003 Nikos Mavroyanopoulos
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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <sys/time.h>
#include <tests.h>
#include <common.h>
#include <tls_test-gaa.h>

#ifndef SHUT_WR
# define SHUT_WR 1
#endif

#ifndef SHUT_RDWR
# define SHUT_RDWR 2
#endif

#define SA struct sockaddr
#define ERR(err,s) if (err==-1) {perror(s);return(1);}
#define MAX_BUF 4096

/* global stuff here */
int resume;
char *hostname=NULL;
int port;
int record_max_size;
int fingerprint;
static int debug;

gnutls_srp_client_credentials srp_cred;
gnutls_anon_client_credentials anon_cred;
gnutls_certificate_credentials xcred;

/* end of global stuff */


int more_info = 0;

int tls1_ok = 0;
int ssl3_ok = 0;

static void tls_log_func( int level, const char* str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

typedef int (*TEST_FUNC)( gnutls_session);

typedef struct {
	char* test_name;
	TEST_FUNC func;
	char* suc_str;
	char* fail_str;
	char* unsure_str;
} TLS_TEST;

static const TLS_TEST tls_tests[] = {
	{ "for TLS 1.0 support", test_tls1, "yes", "no", "dunno" },
	{ "for SSL 3.0 support", test_ssl3, "yes", "no", "dunno" },
	{ "for version rollback bug in RSA PMS", test_rsa_pms, "no", "yes", "dunno" },
	{ "for version rollback bug in Client Hello", test_version_rollback, "no", "yes", "dunno" },

	/* this test will disable TLS 1.0 if the server is 
	 * buggy */
	{ "whether we need to disable TLS 1.0", test_tls1_2, "no", "yes", "dunno" },

	{ "whether the server ignores the RSA PMS version", test_rsa_pms_version_check, "yes", "no", "dunno"},
	{ "whether the server can accept Hello Extensions", test_hello_extension, "yes", "no", "dunno"},
	{ "whether the server can accept cipher suites not in SSL 3.0 spec", test_unknown_ciphersuites, "yes", "no", "dunno"},
	{ "whether the server can accept a bogus TLS record version in the client hello", test_version_oob, "yes", "no", "dunno"},
	{ "for certificate information", test_certificate, "", "", "" },
	{ "for trusted CAs", test_server_cas, "", "", "" },
	{ "whether the server understands TLS closure alerts", test_bye, "yes", "no", "partially"},
	/* the fact that is after the closure alert test does matter.
	 */
	{ "whether the server supports session resumption", test_session_resume2, "yes", "no", "dunno"},
	{ "for export-grade ciphersuite support", test_export, "yes", "no", "dunno" },
#ifdef ENABLE_ANON
	{ "for anonymous authentication support", test_anonymous, "yes", "no", "dunno"},
	{ "for anonymous Diffie Hellman prime size", test_dhe_bits, "", "N/A", "N/A" },
#endif
	{ "for ephemeral Diffie Hellman support", test_dhe, "yes", "no", "dunno" },
	{ "for ephemeral Diffie Hellman prime size", test_dhe_bits, "", "N/A", "N/A" },
	{ "for AES cipher support", test_aes, "yes", "no", "dunno"},
	{ "for 3DES cipher support", test_3des, "yes", "no", "dunno"},
	{ "for ARCFOUR cipher support", test_arcfour, "yes", "no", "dunno"},
	{ "for MD5 MAC support", test_md5, "yes", "no", "dunno"},
	{ "for SHA1 MAC support", test_sha, "yes", "no", "dunno"},
	{ "for max record size (TLS extension)", test_max_record_size, "yes", "no", "dunno" },
#ifdef ENABLE_SRP
	{ "for SRP authentication support (TLS extension)", test_srp, "yes", "no", "dunno" },
#endif
	{ "for OpenPGP authentication support (TLS extension)", test_openpgp1, "yes", "no", "dunno" },
	{ NULL }
};

static int tt = 0;
const char* ip;

#define CONNECT() \
		sd = socket(AF_INET, SOCK_STREAM, 0); \
		ERR(sd, "socket"); \
		memset(&sa, '\0', sizeof(sa)); \
		sa.sin_family = AF_INET; \
		sa.sin_port = htons(port); \
		sa.sin_addr.s_addr = *((unsigned int *) server_host->h_addr); \
		ip = inet_ntop(AF_INET, &sa.sin_addr, buffer, MAX_BUF); \
		if (tt++ == 0) printf("Connecting to '%s:%d'...\n", ip, port); \
		err = connect(sd, (SA *) & sa, sizeof(sa)); \
		ERR(err, "connect")

static void gaa_parser(int argc, char **argv);

int main(int argc, char **argv)
{
	int err, ret;
	int sd, i;
	struct sockaddr_in sa;
	gnutls_session state;
	char buffer[MAX_BUF + 1];
	struct hostent *server_host;
	int ssl3_ok = 0;
	int tls1_ok = 0;

	gaa_parser(argc, argv);

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

        sockets_init();

	if (gnutls_global_init() < 0) {
		fprintf(stderr, "global state initialization error\n");
		exit(1);
	}

	gnutls_global_set_log_function( tls_log_func);
	gnutls_global_set_log_level(debug);

	if (gnutls_global_init_extra() < 0) {
		fprintf(stderr, "global state initialization error\n");
		exit(1);
	}

	printf("Resolving '%s'...\n", hostname);
	/* get server name */
	server_host = gethostbyname(hostname);
	if (server_host == NULL) {
		fprintf(stderr, "Cannot resolve %s\n", hostname);
		exit(1);
	}

	/* X509 stuff */
	if (gnutls_certificate_allocate_credentials(&xcred) < 0) {	/* space for 2 certificates */
		fprintf(stderr, "memory error\n");
		exit(1);
	}

	/* SRP stuff */
#ifdef ENABLE_SRP
	if (gnutls_srp_allocate_client_credentials(&srp_cred) < 0) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}
	gnutls_srp_set_client_credentials( srp_cred, "guest", "guest");
#endif

#ifdef ENABLE_ANON
	/* ANON stuff */
	if (gnutls_anon_allocate_client_credentials(&anon_cred) < 0) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}
#endif

	i = 0;

	do {

		if (tls_tests[i].test_name==NULL) break; /* finished */

		/* if neither of SSL3 and TLSv1 are supported, exit
		 */
		if (i > 1 && tls1_ok == 0 && ssl3_ok == 0) break;

		CONNECT();
		gnutls_init(&state, GNUTLS_CLIENT);
		gnutls_transport_set_ptr(state, (gnutls_transport_ptr)sd);

		printf("Checking %s...", tls_tests[i].test_name);

		if ((ret=tls_tests[i].func( state)) == SUCCEED) {
			printf(" %s\n", tls_tests[i].suc_str);
			if (i==0) tls1_ok = 1;
			if (i==1) ssl3_ok = 1;
		} else if (ret==GFAILED)
			printf(" %s\n", tls_tests[i].fail_str);
		else printf(" %s\n", tls_tests[i].unsure_str);

		gnutls_deinit(state);

		shutdown(sd, SHUT_RDWR);	/* no more receptions */
		close(sd);

		i++;
	} while(1);

#ifdef ENABLE_SRP
	gnutls_srp_free_client_credentials(srp_cred);
#endif
	gnutls_certificate_free_credentials(xcred);
#ifdef ENABLE_ANON
	gnutls_anon_free_client_credentials(anon_cred);
#endif
	gnutls_global_deinit();

	return 0;
}

static gaainfo info;
void gaa_parser(int argc, char **argv)
{
	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr, "Error in the arguments. Use the -h or --help parameters to get more info.\n");
		exit(1);
	}

	port = info.pp;
	if (info.rest_args==NULL) hostname="localhost";
	else hostname = info.rest_args;

	debug = info.debug;

	more_info = info.more_info;
	
}

