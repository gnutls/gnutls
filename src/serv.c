/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "../lib/gnutls.h"
#include <common.h>
#include <signal.h>

#define KEYFILE1 "x509/key.pem"
#define CERTFILE1 "x509/cert.pem"

#define KEYFILE2 "x509/key-dsa.pem"
#define CERTFILE2 "x509/cert-dsa.pem"

#define CAFILE "x509/ca.pem"
#define CRLFILE NULL

#define SRP_PASSWD "srp/tpasswd"
#define SRP_PASSWD_CONF "srp/tpasswd.conf"

/* konqueror cannot handle sending the page in multiple
 * pieces.
 */
static char http_buffer[16*1024];

/* This is a sample TCP echo server.
 * This will behave as an http server if any argument in the
 * command line is present
 */


#define SA struct sockaddr
#define ERR(err,s) if(err==-1) {perror(s);return(1);}
#define MAX_BUF 1024

#define HTTP_BEGIN "HTTP/1.0 200 OK\n" \
		"Content-Type: text/html\n" \
		"\n" \
		"<HTML><BODY>\n" \
		"<CENTER><H1>This is <a href=\"http://www.gnu.org/software/gnutls\">" \
		"GNUTLS</a></H1>\n\n"

#define HTTP_END  "</BODY></HTML>\n\n"

#define RENEGOTIATE

/* These are global */
GNUTLS_SRP_SERVER_CREDENTIALS srp_cred;
GNUTLS_ANON_SERVER_CREDENTIALS dh_cred;
GNUTLS_CERTIFICATE_SERVER_CREDENTIALS x509_cred;


GNUTLS_STATE initialize_state(void)
{
	GNUTLS_STATE state;
	int ret;
	int protocol_priority[] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
	int kx_priority[] = { GNUTLS_KX_DHE_DSS, GNUTLS_KX_RSA, GNUTLS_KX_DHE_RSA, GNUTLS_KX_SRP, GNUTLS_KX_ANON_DH, 0 };
	int cipher_priority[] = { GNUTLS_CIPHER_RIJNDAEL_128_CBC, GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR, 0};
	int comp_priority[] = { GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
	int mac_priority[] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };

	gnutls_init(&state, GNUTLS_SERVER);
	if ((ret = gnutls_db_set_name(state, "gnutls-rsm.db")) < 0)
		fprintf(stderr, "*** DB error (%d). Resuming will not be possible.\n\n", ret);

	/* null cipher is here only for debuging 
	 * purposes.
	 */
	gnutls_cipher_set_priority(state, cipher_priority);
	gnutls_compression_set_priority(state, comp_priority);
	gnutls_kx_set_priority(state, kx_priority);
	gnutls_protocol_set_priority( state, protocol_priority);
	gnutls_mac_set_priority(state, mac_priority);
	
	gnutls_cred_set(state, GNUTLS_CRD_ANON, dh_cred);
	gnutls_cred_set(state, GNUTLS_CRD_SRP, srp_cred);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, x509_cred);

	gnutls_mac_set_priority(state, mac_priority);

	gnutls_certificate_server_set_request( state, GNUTLS_CERT_REQUEST);

	return state;
}

/* Creates html with the current state information.
 */
#define tmp2 &http_buffer[strlen(http_buffer)]
void peer_print_info( GNUTLS_STATE state)
{
	const char *tmp;
	unsigned char sesid[32];
	int sesid_size, i;
	
	/* print session_id */
	gnutls_session_get_id( state, sesid, &sesid_size);
	sprintf(tmp2, "\n<p>Session ID: <i>");
	for(i=0;i<sesid_size;i++)
		sprintf(tmp2, "%.2X", sesid[i]);
	sprintf(tmp2, "</i></p>\n");

	/* Here unlike print_info() we use the kx algorithm to distinguish
	 * the functions to call.
	 */ 

	/* print srp specific data */
	if (gnutls_kx_get(state) == GNUTLS_KX_SRP) {
		sprintf(tmp2, "<p>Connected as user '%s'.</p>\n",
		       gnutls_srp_server_get_username( state));
	}

	if (gnutls_kx_get(state) == GNUTLS_KX_ANON_DH) {
		sprintf(tmp2, "<p> Connect using anonymous DH (prime of %d bits)</p>\n",
		       gnutls_dh_get_bits( state));
	}

	/* print state information */
	strcat( http_buffer, "<P>\n");

	tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(state));
	sprintf(tmp2, "Protocol version: <b>%s</b><br>\n", tmp);

	tmp = gnutls_kx_get_name(gnutls_kx_get(state));
	sprintf(tmp2, "Key Exchange: <b>%s</b><br>\n", tmp);

	if (gnutls_kx_get(state) == GNUTLS_KX_DHE_RSA || gnutls_kx_get(state) == GNUTLS_KX_DHE_DSS) {
		sprintf(tmp2, "Ephemeral DH using prime of <b>%d</b> bits.<br>\n",
			        gnutls_dh_get_bits( state));
	}
			
	tmp =
	    gnutls_compression_get_name
	    (gnutls_compression_get(state));
	sprintf(tmp2, "Compression: <b>%s</b><br>\n", tmp);
	
	tmp = gnutls_cipher_get_name(gnutls_cipher_get(state));
	sprintf(tmp2, "Cipher: <b>%s</b><br>\n", tmp);
	
	tmp = gnutls_mac_get_name(gnutls_mac_get(state));
	sprintf(tmp2, "MAC: <b>%s</b><br>\n", tmp);

	strcat( http_buffer, "</P>\n");

	return;
}

/* actually something like readline.
 * if rnl!=1 then reads an http request in the form REQ\n\n
 */
int read_request( GNUTLS_STATE state, char *data, int data_size, int rnl)
{
	int n, rc, nl = 0;
	char c, *ptr, p1=0, p2=0;

	ptr = data;
	for (n = 1; n < data_size; n++) {
		do {
			rc = gnutls_read( state, &c, 1);
		} while( rc==GNUTLS_E_INTERRUPTED || rc==GNUTLS_E_AGAIN);

		if ( rc == 1) {
			*ptr++ = c;
			if (c == '\n' && rnl==1) break;

			if (c=='\n' && p1=='\r' && p2=='\n') {
				nl++;
				if (nl == 1)
					break;
			}
			p2 = p1;
			p1 = c;

		} else if (rc == 0) {
			if (n == 1)
				return 0;
			else
				break;
		} else {
			return rc;
		}
	}

	*ptr = 0;
	return n;
}

void check_alert( GNUTLS_STATE state, int ret) {
int last_alert;

	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		last_alert = gnutls_alert_get_last(state);
		if (last_alert == GNUTLS_A_NO_RENEGOTIATION &&
			ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
			printf("* Received NO_RENEGOTIATION alert. Client Does not support renegotiation.\n");
		else
			printf("* Received alert '%d'.\n", ret);
	}
}

int main(int argc, char **argv)
{
	int err, listen_sd, i;
	int sd, ret;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	int client_len;
	char topbuf[512];
	GNUTLS_STATE state;
	char buffer[MAX_BUF + 1];
	int optval = 1;
	int http = 0;
	char name[256];

	signal(SIGPIPE, SIG_IGN);
	
	if (argc != 2) {
		fprintf(stderr, "Usage: serv [-e] [-h]\n");
		exit(1);
	} else {
		if (argv[1][strlen(argv[1])-1]=='h') {
			http = 1;
			strcpy(name, "HTTP Server");
		} else {
			strcpy(name, "Echo Server");
		}
	}
	
	if (gnutls_global_init() < 0) {
		fprintf(stderr, "global state initialization error\n");
		exit(1);
	}

	if (gnutls_certificate_allocate_server_sc(&x509_cred, 2) < 0) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}

	if (gnutls_x509pki_set_trust_file( x509_cred, CAFILE, CRLFILE) < 0) {
		fprintf(stderr, "X509 PARSE ERROR\nDid you have ca.pem?\n");
		exit(1);
	}

	if (gnutls_x509pki_set_key_file( x509_cred, CERTFILE1, KEYFILE1) < 0) {
		fprintf(stderr, "X509 PARSE ERROR\nDid you have key.pem and cert.pem?\n");
		exit(1);
	}

	if (gnutls_x509pki_set_key_file( x509_cred, CERTFILE2, KEYFILE2) < 0) {
		fprintf(stderr, "X509 PARSE ERROR\nDid you have key.pem and cert.pem?\n");
		exit(1);
	}

	/* this is a password file (created with the included srpcrypt utility) 
	 * Read README.crypt prior to using SRP.
	 */
	gnutls_srp_allocate_server_sc( &srp_cred);
	gnutls_srp_set_server_cred_file( srp_cred, SRP_PASSWD, SRP_PASSWD_CONF);

	gnutls_anon_allocate_server_sc( &dh_cred);

	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	ERR(listen_sd, "socket");

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(PORT);	/* Server Port number */

	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &optval,
		   sizeof(int));
	err = bind(listen_sd, (SA *) & sa_serv, sizeof(sa_serv));
	ERR(err, "bind");
	err = listen(listen_sd, 1024);
	ERR(err, "listen");

	printf("%s ready. Listening to port '%d'.\n\n", name, PORT);

	client_len = sizeof(sa_cli);
	
	for (;;) {
		state = initialize_state();

		sd = accept(listen_sd, (SA *) & sa_cli, &client_len);

		printf("- connection from %s, port %d\n",
		       inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
				 sizeof(topbuf)), ntohs(sa_cli.sin_port));


		gnutls_transport_set_ptr( state, sd);
		do {
			ret = gnutls_handshake( state);
		} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);

		if (ret < 0) {
			close(sd);
			gnutls_deinit(state);
			fprintf(stderr, "*** Handshake has failed (%s)\n\n",
				gnutls_strerror(ret));
			check_alert( state, ret);
			continue;
		}
		printf("- Handshake was completed\n");

		print_info(state);

		i = 0;
		for (;;) {
			bzero(buffer, MAX_BUF + 1);
			ret = read_request( state, buffer, MAX_BUF, (http==0)?1:2);

			if (gnutls_error_is_fatal(ret) == 1 || ret == 0) {
				fflush(stdout);
				if (ret == 0) {
					printf
					    ("\n- Peer has closed the GNUTLS connection\n");
					fflush(stdout);
					break;
				} else {
					fprintf(stderr,
						"\n*** Received corrupted data(%d). Closing the connection.\n\n",
						ret);
					break;
				}

			}

			if (ret > 0) {
				if (http == 0) {
					printf( "* Read %d bytes from client.\n", strlen(buffer));
					do {
						ret = gnutls_write( state, buffer, strlen(buffer));
					} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);
					printf( "* Wrote %d bytes to client.\n", ret);
				} else {
					strcpy( http_buffer, HTTP_BEGIN);
					peer_print_info( state);
					strcat( http_buffer, HTTP_END);
					do {
						ret = gnutls_write( state, http_buffer, strlen(http_buffer));
					} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);

					printf("- Served request. Closing connection.\n");
					break;
				}
			}
			i++;
#ifdef RENEGOTIATE
			if (i == 20) {
				do {
					ret = gnutls_rehandshake( state);
				} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);

				printf("* Requesting rehandshake.\n");
				/* continue handshake proccess */
				do {
					ret = gnutls_handshake( state);
				} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);
				printf("* Rehandshake returned %d\n", ret);
			}
#endif
			
			check_alert( state, ret);

			if (http != 0) {
				break;	/* close the connection */
			}
		}
		printf("\n");
		do {
			ret = gnutls_bye( state, GNUTLS_SHUT_WR); 
		} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);
		/* do not wait for
		 * the peer to close the connection.
		 */
		close(sd);
		gnutls_deinit(state);

	}
	close(listen_sd);

	gnutls_certificate_free_server_sc(x509_cred);
	gnutls_srp_free_server_sc(srp_cred);
	gnutls_anon_free_server_sc(dh_cred);

	gnutls_global_deinit();
	
	return 0;

}
