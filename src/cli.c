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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/x509.h>
#include <sys/time.h>
#include <signal.h>
#include <netdb.h>
#include <common.h>
#include "cli-gaa.h"

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
int resume, starttls;
char *hostname = NULL;
int port;
int record_max_size;
int fingerprint;
int crlf;
int quiet = 0;
extern int xml;

char *srp_passwd = NULL;
char *srp_username;
char *pgp_keyfile;
char *pgp_certfile;
char *pgp_keyring;
char *pgp_trustdb;
char *x509_keyfile;
char *x509_certfile;
char *x509_cafile;
char *x509_crlfile = NULL;
static int x509ctype;
static int disable_extensions;
static int debug;

static gnutls_srp_client_credentials srp_cred;
static gnutls_anon_client_credentials anon_cred;
static gnutls_certificate_credentials xcred;

int protocol_priority[16] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
int kx_priority[16] =
    { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_SRP,
	/* Do not use anonymous authentication, unless you know what that means */
	GNUTLS_KX_ANON_DH, GNUTLS_KX_RSA_EXPORT, 0
};
int cipher_priority[16] =
    { GNUTLS_CIPHER_ARCFOUR_128, GNUTLS_CIPHER_RIJNDAEL_128_CBC,
	GNUTLS_CIPHER_3DES_CBC,
	GNUTLS_CIPHER_ARCFOUR_40, 0
};
int comp_priority[16] = { GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
int mac_priority[16] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
int cert_type_priority[16] = { GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0 };

/* end of global stuff */

/* prototypes */
typedef struct {
	int fd;
	gnutls_session session;
	int secure;
} socket_st;

ssize_t socket_recv(socket_st socket, void *buffer, int buffer_size);
ssize_t socket_send(socket_st socket, void *buffer, int buffer_size);
void socket_bye(socket_st * socket);
static void check_rehandshake(socket_st socket, int ret);
static int do_handshake(socket_st * socket);
static void init_global_tls_stuff(void);


#define MAX(X,Y) (X >= Y ? X : Y);

/* A callback function to be used at the certificate selection time.
 */
static int cert_callback(gnutls_session session,
			 const gnutls_datum * client_certs,
			 int client_certs_num,
			 const gnutls_datum * req_ca_rdn, int nreqs)
{
	char issuer_dn[256];
	int len, i, ret;

	/* Print the server's trusted CAs
	 */
	if (nreqs > 0)
		printf("- Server's trusted authorities:\n");
	else
		printf
		    ("- Server did not send us any trusted authorities names.\n");

//	gnutls_alert_send(session, GNUTLS_AL_WARNING, GNUTLS_A_BAD_CERTIFICATE);
	/* print the names (if any) */
	for (i = 0; i < nreqs; i++) {
		len = sizeof(issuer_dn);
		ret = gnutls_x509_rdn_get(&req_ca_rdn[i], issuer_dn, &len);
		if (ret >= 0) {
			printf("   [%d]: ", i);
			printf("%s\n", issuer_dn);
		}
	}

	if (client_certs_num > 0)
		return 0;	/* use the first one */

	return -1;

}


/* initializes a gnutls_session with some defaults.
 */
static gnutls_session init_tls_session(const char *hostname)
{
	gnutls_session session;

	gnutls_init(&session, GNUTLS_CLIENT);

	/* allow the use of private ciphersuites.
	 */
	if (disable_extensions == 0)
		gnutls_handshake_set_private_extensions(session, 1);

	if (disable_extensions == 0)
		gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname,
				       strlen(hostname));

	gnutls_cipher_set_priority(session, cipher_priority);
	gnutls_compression_set_priority(session, comp_priority);
	gnutls_kx_set_priority(session, kx_priority);
	gnutls_protocol_set_priority(session, protocol_priority);
	gnutls_mac_set_priority(session, mac_priority);
	gnutls_certificate_type_set_priority(session, cert_type_priority);

	gnutls_dh_set_prime_bits(session, 512);

	gnutls_credentials_set(session, GNUTLS_CRD_ANON, anon_cred);
	gnutls_credentials_set(session, GNUTLS_CRD_SRP, srp_cred);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	gnutls_certificate_client_set_select_function(session,
						      cert_callback);

	/* send the fingerprint */
	if (fingerprint != 0)
		gnutls_openpgp_send_key(session,
					GNUTLS_OPENPGP_KEY_FINGERPRINT);

	/* use the max record size extension */
	if (record_max_size > 0 && disable_extensions == 0) {
		if (gnutls_record_set_max_size(session, record_max_size) <
		    0) {
			fprintf(stderr,
				"Cannot set the maximum record size to %d.\n",
				record_max_size);
			exit(1);
		}
	}

	return session;
}

static void gaa_parser(int argc, char **argv);

/* Returns zero if the error code was successfully handled.
 */
static int handle_error(socket_st hd, int err)
{
	int alert, ret;
	const char *err_type;

	if (err >= 0) return 0;

	if (gnutls_error_is_fatal(err) == 0) {
		ret = 0;
		err_type = "Non fatal";
	} else {
		ret = err;
		err_type = "Fatal";
	}

	fprintf(stderr,
		"*** %s error: %s\n", err_type, gnutls_strerror(err));

	if (err == GNUTLS_E_WARNING_ALERT_RECEIVED
	    || err == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		alert = gnutls_alert_get(hd.session);
		printf("*** Received alert [%d]: %s\n",
		       alert, gnutls_alert_get_name(alert));

	}

	check_rehandshake(hd, ret);

	return ret;
}


int main(int argc, char **argv)
{
	int err, ret;
	int sd, ii, i;
	struct sockaddr_in sa;
	char buffer[MAX_BUF + 1];
	char *session_data = NULL;
	char *session_id = NULL;
	int session_data_size;
	int session_id_size;
	fd_set rset;
	int maxfd;
	struct timeval tv;
	int user_term = 0;
	struct hostent *server_host;
	socket_st hd;

	gaa_parser(argc, argv);

	signal(SIGPIPE, SIG_IGN);

	init_global_tls_stuff();


	printf("Resolving '%s'...\n", hostname);
	/* get server name */
	server_host = gethostbyname(hostname);
	if (server_host == NULL) {
		fprintf(stderr, "Cannot resolve %s\n", hostname);
		exit(1);
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);

	sa.sin_addr.s_addr = *((unsigned int *) server_host->h_addr);

	inet_ntop(AF_INET, &sa.sin_addr, buffer, MAX_BUF);
	fprintf(stderr, "Connecting to '%s:%d'...\n", buffer, port);

	err = connect(sd, (SA *) & sa, sizeof(sa));
	ERR(err, "connect");

	hd.secure = 0;
	hd.fd = sd;

	hd.session = init_tls_session(hostname);
	if (starttls)
		goto after_handshake;

	for (i = 0; i < 2; i++) {


		if (i == 1) {
			hd.session = init_tls_session(hostname);
			gnutls_session_set_data(hd.session, session_data,
						session_data_size);
			free(session_data);
		}

		ret = do_handshake(&hd);

		/* Note that every error on handshake is fatal.
		 */
		if (ret < 0) {
			fprintf(stderr, "*** Handshake has failed\n");
			gnutls_perror(ret);
			gnutls_deinit(hd.session);
			return 1;
		} else {
			printf("- Handshake was completed\n");
			if (gnutls_session_is_resumed(hd.session) != 0)
				printf("*** This is a resumed session\n");
		}



		if (resume != 0 && i == 0) {

			gnutls_session_get_data(hd.session, NULL,
						&session_data_size);
			session_data = malloc(session_data_size);

			gnutls_session_get_data(hd.session, session_data,
						&session_data_size);

			gnutls_session_get_id(hd.session, NULL,
					      &session_id_size);
			session_id = malloc(session_id_size);
			gnutls_session_get_id(hd.session, session_id,
					      &session_id_size);

			/* print some information */
			print_info(hd.session);

			printf("- Disconnecting\n");
			socket_bye(&hd);

			printf
			    ("\n\n- Connecting again- trying to resume previous session\n");
			sd = socket(AF_INET, SOCK_STREAM, 0);
			ERR(sd, "socket");

			err = connect(sd, (SA *) & sa, sizeof(sa));
			ERR(err, "connect");

			hd.fd = sd;
			hd.secure = 0;
		} else {
			break;
		}
	}


      after_handshake:

	printf("\n- Simple Client Mode:\n\n");

	FD_ZERO(&rset);
	for (;;) {
		FD_SET(fileno(stdin), &rset);
		FD_SET(sd, &rset);

		maxfd = MAX(fileno(stdin), sd);
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		select(maxfd + 1, &rset, NULL, NULL, &tv);

		if (FD_ISSET(sd, &rset)) {
			bzero(buffer, MAX_BUF + 1);
			ret = socket_recv(hd, buffer, MAX_BUF);

			if (ret == 0) {
				printf
				    ("- Peer has closed the GNUTLS connection\n");
				break;
			} else if (handle_error(hd, ret) < 0
				   && user_term == 0) {
				fprintf(stderr,
					"*** Server has terminated the connection abnormally.\n");
				break;
			} else if (ret > 0) {
				if (quiet != 0)
					printf("- Received[%d]: ", ret);
				for (ii = 0; ii < ret; ii++) {
					fputc(buffer[ii], stdout);
				}
				fflush(stdout);
			}

			if (user_term != 0)
				break;
		}

		if (FD_ISSET(fileno(stdin), &rset)) {
			if (fgets(buffer, MAX_BUF, stdin) == NULL) {
				if (hd.secure == 0) {
					fprintf(stderr,
						"*** Starting TLS handshake\n");
					ret = do_handshake(&hd);
					if (ret < 0) {
						fprintf(stderr,
							"*** Handshake has failed\n");
						socket_bye(&hd);
						user_term = 1;
					}
					continue;
				} else {
					user_term = 1;
					continue;
				}
			}

			if (crlf != 0) {
				char *b = strchr(buffer, '\n');
				if (b != NULL)
					strcpy(b, "\r\n");
			}

			ret = socket_send(hd, buffer, strlen(buffer));

			if (ret > 0) {
				if (quiet != 0)
					printf("- Sent: %d bytes\n", ret);
			} else
				handle_error(hd, ret);

		}
	}

	if (user_term != 0)
		socket_bye(&hd);


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
		fprintf(stderr,
			"Error in the arguments. Use the --help or -h parameters to get more information.\n");
		exit(1);
	}

	debug = info.debug;
	disable_extensions = info.disable_extensions;
	xml = info.xml;
	starttls = info.starttls;
	resume = info.resume;
	port = info.port;
	record_max_size = info.record_size;
	fingerprint = info.fingerprint;

	if (info.fmtder == 0)
		x509ctype = GNUTLS_X509_FMT_PEM;
	else
		x509ctype = GNUTLS_X509_FMT_DER;

	srp_username = info.srp_username;
	srp_passwd = info.srp_passwd;
	x509_cafile = info.x509_cafile;
	x509_crlfile = info.x509_crlfile;
	x509_keyfile = info.x509_keyfile;
	x509_certfile = info.x509_certfile;
	pgp_keyfile = info.pgp_keyfile;
	pgp_certfile = info.pgp_certfile;

	pgp_keyring = info.pgp_keyring;
	pgp_trustdb = info.pgp_trustdb;

	crlf = info.crlf;

	if (info.rest_args == NULL)
		hostname = "localhost";
	else
		hostname = info.rest_args;

	parse_protocols(info.proto, info.nproto, protocol_priority);
	parse_ciphers(info.ciphers, info.nciphers, cipher_priority);
	parse_macs(info.macs, info.nmacs, mac_priority);
	parse_ctypes(info.ctype, info.nctype, cert_type_priority);
	parse_kx(info.kx, info.nkx, kx_priority);
	parse_comp(info.comp, info.ncomp, comp_priority);


}

void cli_version(void)
{
	fprintf(stderr, "GNU TLS test client, ");
	fprintf(stderr, "version %s. Libgnutls %s.\n", LIBGNUTLS_VERSION,
		gnutls_check_version(NULL));
}



/* Functions to manipulate sockets
 */

ssize_t socket_recv(socket_st socket, void *buffer, int buffer_size)
{
	int ret;

	if (socket.secure)
		do {
			ret =
			    gnutls_record_recv(socket.session, buffer,
					       buffer_size);
		} while (ret == GNUTLS_E_INTERRUPTED
			 || ret == GNUTLS_E_AGAIN);
	else
		do {
			ret = recv(socket.fd, buffer, buffer_size, 0);
		} while (ret == -1 && errno == EINTR);

	return ret;
}

ssize_t socket_send(socket_st socket, void *buffer, int buffer_size)
{
	int ret;

	if (socket.secure)
		do {
			ret =
			    gnutls_record_send(socket.session, buffer,
					       buffer_size);
		} while (ret == GNUTLS_E_AGAIN
			 || ret == GNUTLS_E_INTERRUPTED);
	else
		do {
			ret = send(socket.fd, buffer, buffer_size, 0);
		} while (ret == -1 && errno == EINTR);


	return ret;
}

void socket_bye(socket_st * socket)
{
	int ret;
	if (socket->secure) {
		do
			ret =
			    gnutls_bye(socket->session, GNUTLS_SHUT_RDWR);
		while (ret == GNUTLS_E_INTERRUPTED
		       || ret == GNUTLS_E_AGAIN);
		gnutls_deinit(socket->session);
		socket->session = NULL;
	}

	shutdown(socket->fd, SHUT_RDWR);	/* no more receptions */
	close(socket->fd);

	socket->fd = -1;
	socket->secure = 0;
}

static void check_rehandshake(socket_st socket, int ret)
{
	if (socket.secure && ret == GNUTLS_E_REHANDSHAKE) {
		/* There is a race condition here. If application
		 * data is sent after the rehandshake request,
		 * the server thinks we ignored his request.
		 * This is a bad design of this client.
		 */
		printf("* Received rehandshake request\n");
		/* gnutls_alert_send( session, GNUTLS_AL_WARNING, GNUTLS_A_NO_RENEGOTIATION); */

		ret = do_handshake(&socket);

		if (ret == 0) {
			printf("* Rehandshake was performed.\n");
		} else {
			printf("* Rehandshake Failed.\n");
		}
	}
}


static int do_handshake(socket_st * socket)
{
	int ret;
	gnutls_transport_set_ptr(socket->session,
				 (gnutls_transport_ptr) socket->fd);
	do {
		ret = gnutls_handshake(socket->session);

		if (ret < 0) {
			handle_error(*socket, ret);
		}
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret == 0) {
		socket->secure = 1;
		/* print some information */
		print_info(socket->session);
	}
	return ret;
}


static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

static void init_global_tls_stuff()
{
	int ret;

	if (gnutls_global_init() < 0) {
		fprintf(stderr, "global state initialization error\n");
		exit(1);
	}
	gnutls_global_set_log_function(tls_log_func);
	gnutls_global_set_log_level(debug);

	if (gnutls_global_init_extra() < 0) {
		fprintf(stderr,
			"global state (extra) initialization error\n");
		exit(1);
	}

	/* X509 stuff */
	if (gnutls_certificate_allocate_credentials(&xcred) < 0) {
		fprintf(stderr, "Certificate allocation memory error\n");
		exit(1);
	}

	/* there are some intermediate CAs that have a v1 certificate *%&@#*%&
	 */
	gnutls_certificate_set_verify_flags(xcred,
					    GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

	if (x509_cafile != NULL) {
		ret =
		    gnutls_certificate_set_x509_trust_file(xcred,
							   x509_cafile,
							   x509ctype);
		if (ret < 0) {
			fprintf(stderr,
				"Error setting the x509 trust file\n");
		} else {
			printf("Processed %d CA certificate(s).\n", ret);
		}
	}
#ifdef ENABLE_PKI
	if (x509_crlfile != NULL) {
		ret =
		    gnutls_certificate_set_x509_crl_file(xcred,
							 x509_crlfile,
							 x509ctype);
		if (ret < 0) {
			fprintf(stderr,
				"Error setting the x509 CRL file\n");
		} else {
			printf("Processed %d CRL(s).\n", ret);
		}
	}
#endif

	if (x509_certfile != NULL) {
		ret =
		    gnutls_certificate_set_x509_key_file(xcred,
							 x509_certfile,
							 x509_keyfile,
							 x509ctype);
		if (ret < 0) {
			fprintf(stderr,
				"Error setting the x509 key files ('%s', '%s')\n",
				x509_certfile, x509_keyfile);
		}
	}

	if (pgp_certfile != NULL) {
		ret =
		    gnutls_certificate_set_openpgp_key_file(xcred,
							    pgp_certfile,
							    pgp_keyfile);
		if (ret < 0) {
			fprintf(stderr,
				"Error setting the x509 key files ('%s', '%s')\n",
				pgp_certfile, pgp_keyfile);
		}
	}

	if (pgp_keyring != NULL) {
		ret =
		    gnutls_certificate_set_openpgp_keyring_file(xcred,
								pgp_keyring);
		if (ret < 0) {
			fprintf(stderr,
				"Error setting the OpenPGP keyring file\n");
		}
	}

	if (pgp_trustdb != NULL) {
		ret =
		    gnutls_certificate_set_openpgp_trustdb(xcred,
							   pgp_trustdb);
		if (ret < 0) {
			fprintf(stderr,
				"Error setting the OpenPGP trustdb file\n");
		}
	}
#ifdef ENABLE_SRP
	/* SRP stuff */
	if (gnutls_srp_allocate_client_credentials(&srp_cred) < 0) {
		fprintf(stderr, "SRP authentication error\n");
	}

	if (srp_username != NULL) {
		if ((ret =
		     gnutls_srp_set_client_credentials(srp_cred,
						       srp_username,
						       srp_passwd)) < 0) {
			fprintf(stderr, "SRP credentials set error [%d]\n",
				ret);
		}
	}
#endif


#ifdef ENABLE_ANON
	/* ANON stuff */
	if (gnutls_anon_allocate_client_credentials(&anon_cred) < 0) {
		fprintf(stderr, "Anonymous authentication error\n");
	}
#endif

}
