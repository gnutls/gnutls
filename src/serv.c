/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
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
#include <port.h>

#define KEYFILE "x509/key.pem"
#define CERTFILE "x509/cert.pem"
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
SRP_SERVER_CREDENTIALS srp_cred;
ANON_SERVER_CREDENTIALS dh_cred;
X509PKI_SERVER_CREDENTIALS x509_cred;


GNUTLS_STATE initialize_state()
{
	GNUTLS_STATE state;
	int ret;


	/* this is a password file (created with the included crypt utility) 
	 * Read README.crypt prior to using SRP.
	 */
	gnutls_allocate_srp_server_sc( &srp_cred);
	gnutls_set_srp_server_cred( srp_cred, SRP_PASSWD, SRP_PASSWD_CONF);

	gnutls_allocate_anon_server_sc( &dh_cred);
	gnutls_set_anon_server_cred( dh_cred, 1024);

	gnutls_init(&state, GNUTLS_SERVER);
	if ((ret = gnutls_set_db_name(state, "gnutls-rsm.db")) < 0)
		fprintf(stderr, "*** DB error (%d)\n\n", ret);

	/* null cipher is here only for debuging 
	 * purposes.
	 */
	gnutls_set_cipher_priority(state, GNUTLS_NULL_CIPHER, 
				   GNUTLS_RIJNDAEL_CBC, GNUTLS_3DES_CBC, 0);
	gnutls_set_compression_priority(state, GNUTLS_ZLIB, GNUTLS_NULL_COMPRESSION, 0);
	gnutls_set_kx_priority(state, GNUTLS_KX_DHE_RSA, GNUTLS_KX_RSA, GNUTLS_KX_SRP,
			       GNUTLS_KX_DH_ANON, 0);
	gnutls_set_cred(state, GNUTLS_ANON, dh_cred);
	gnutls_set_cred(state, GNUTLS_SRP, srp_cred);
	gnutls_set_cred(state, GNUTLS_X509PKI, x509_cred);

	gnutls_set_mac_priority(state, GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0);

	return state;
}

void print_info(GNUTLS_STATE state)
{
	const SRP_SERVER_AUTH_INFO *srp_info;
	const ANON_SERVER_AUTH_INFO *dh_info;
	const char *tmp;
	unsigned char sesid[32];
	int sesid_size, i;
	
	/* print session_id specific data */
	gnutls_get_current_session_id( state, sesid, &sesid_size);
	printf("\n- Session ID: ");
	for(i=0;i<sesid_size;i++)
		printf("%.2X", sesid[i]);
	printf("\n");

	if ( gnutls_ext_get_dnsname(state) != NULL) {
		printf("- DNSNAME: ");
		printf("%s\n", gnutls_ext_get_dnsname(state));
	}
	
	/* print srp specific data */
	if (gnutls_get_auth_info_type(state) == GNUTLS_SRP) {
		srp_info = gnutls_get_auth_info(state);
		if (srp_info != NULL)
			printf("\n- User '%s' connected\n",
			       srp_info->username);
	}
	if (gnutls_get_auth_info_type(state) == GNUTLS_ANON) {
		dh_info = gnutls_get_auth_info(state);
		if (dh_info != NULL)
			printf("\n- Anonymous DH using prime of %d bits\n",
			       dh_info->dh_bits);
	}

	/* print state information */

	tmp = gnutls_version_get_name(gnutls_get_current_version(state));
	printf("- Version: %s\n", tmp);

	tmp = gnutls_kx_get_name(gnutls_get_current_kx(state));
	printf("- Key Exchange: %s\n", tmp);

	tmp =
	    gnutls_compression_get_name
	    (gnutls_get_current_compression_method(state));
	printf("- Compression: %s\n", tmp);

	tmp = gnutls_cipher_get_name(gnutls_get_current_cipher(state));
	printf("- Cipher: %s\n", tmp);

	tmp = gnutls_mac_get_name(gnutls_get_current_mac_algorithm(state));
	printf("- MAC: %s\n", tmp);


}

/* Creates html with the current state information.
 */
#define tmp2 &http_buffer[strlen(http_buffer)]
void peer_print_info(int cd, GNUTLS_STATE state)
{
	const SRP_SERVER_AUTH_INFO *srp_info;
	const ANON_SERVER_AUTH_INFO *dh_info;
	const char *tmp;
	unsigned char sesid[32];
	int sesid_size, i;
	
	/* print session_id */
	gnutls_get_current_session_id( state, sesid, &sesid_size);
	sprintf(tmp2, "\n<p>Session ID: <i>");
	for(i=0;i<sesid_size;i++)
		sprintf(tmp2, "%.2X", sesid[i]);
	sprintf(tmp2, "</i></p>\n");

	/* if the client supports dnsname extension then
	 * print the hostname he connected to.
	 */
	if (gnutls_ext_get_dnsname(state)!=NULL) {
		printf("\n<p>DNSNAME: ");
		printf("<b>%s</b></p>\n", gnutls_ext_get_dnsname(state));
	}

	/* print srp specific data */
	if (gnutls_get_current_kx(state) == GNUTLS_KX_SRP) {
		srp_info = gnutls_get_auth_info(state);
		if (srp_info != NULL) {
			sprintf(tmp2, "<p>Connected as user '%s'.</p>\n",
			       srp_info->username);
		}
	}
	if (gnutls_get_current_kx(state) == GNUTLS_KX_DH_ANON) {
		dh_info = gnutls_get_auth_info(state);
		if (dh_info != NULL) {
			sprintf(tmp2, "<p> Connect using anonymous DH (prime of %d bits)</p>\n",
			       dh_info->dh_bits);
		}

	}

	/* print state information */
	strcat( http_buffer, "<P>\n");

	tmp = gnutls_version_get_name(gnutls_get_current_version(state));
	sprintf(tmp2, "Protocol version: <b>%s</b><br>\n", tmp);

	tmp = gnutls_kx_get_name(gnutls_get_current_kx(state));
	sprintf(tmp2, "Key Exchange: <b>%s</b><br>\n", tmp);

	tmp =
	    gnutls_compression_get_name
	    (gnutls_get_current_compression_method(state));
	sprintf(tmp2, "Compression: <b>%s</b><br>\n", tmp);
	
	tmp = gnutls_cipher_get_name(gnutls_get_current_cipher(state));
	sprintf(tmp2, "Cipher: <b>%s</b><br>\n", tmp);
	
	tmp = gnutls_mac_get_name(gnutls_get_current_mac_algorithm(state));
	sprintf(tmp2, "MAC: <b>%s</b><br>\n", tmp);

	strcat( http_buffer, "</P>\n");

	return;
}

/* actually something like readline.
 * if rnl!=1 then reads an http request in the form REQ\n\n
 */
int read_request(int cd, GNUTLS_STATE state, char *data, int data_size, int rnl)
{
	int n, rc, nl = 0;
	char c, *ptr, p1=0, p2=0;

	ptr = data;
	for (n = 1; n < data_size; n++) {
		if ((rc = gnutls_read(cd, state, &c, 1)) == 1) {

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
fprintf(stderr, "\n");
	*ptr = 0;
	return n;
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
	
	if (gnutls_global_init("pkix.asn", "pkcs1.asn") < 0) {
		fprintf(stderr, "global state initialization error\n");
		exit(1);
	}

	if (gnutls_allocate_x509_server_sc(&x509_cred, 1) < 0) {
		exit(1);
	}

	if (gnutls_set_x509_server_key( x509_cred, CERTFILE, KEYFILE) < 0) {
		fprintf(stderr, "X509 PARSE ERROR\nDid you have key.pem and cert.pem?\n");
		exit(1);
	}

	if (gnutls_set_x509_server_trust( x509_cred, CAFILE, CRLFILE) < 0) {
		fprintf(stderr, "X509 PARSE ERROR\nDid you have ca.pem?\n");
		exit(1);
	}


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


		ret = gnutls_handshake(sd, state);
		if (ret < 0) {
			close(sd);
			gnutls_deinit(state);
			fprintf(stderr, "*** Handshake has failed (%s)\n\n",
				gnutls_strerror(ret));
			continue;
		}
		printf("- Handshake was completed\n");

		print_info(state);

		i = 0;
		for (;;) {
			bzero(buffer, MAX_BUF + 1);
			ret = read_request(sd, state, buffer, MAX_BUF, (http==0)?1:2);

			if (gnutls_is_fatal_error(ret) == 1) {
				if (ret == GNUTLS_E_CLOSURE_ALERT_RECEIVED) {
					printf
					    ("\n- Peer has closed the GNUTLS connection\n");
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
					gnutls_write(sd, state, buffer,
						     strlen(buffer));
				} else {
					strcpy( http_buffer, HTTP_BEGIN);
					peer_print_info(sd, state);
					strcat( http_buffer, HTTP_END);
					gnutls_write(sd, state, http_buffer, strlen(http_buffer));
					printf("- Served request. Closing connection.\n");
					break;
				}
			}
			i++;
#ifdef RENEGOTIATE
			if (i == 10)
				ret = gnutls_rehandshake(sd, state);
#endif
			if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
			    || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
				ret = gnutls_get_last_alert(state);
				if (ret == GNUTLS_NO_RENEGOTIATION)
					printf
					    ("* Received NO_RENEGOTIATION alert. Client Does not support renegotiation.\n");
				else
					printf("* Received alert '%d'.\n",
					       ret);
			}

			if (http != 0) {
				break;	/* close the connection */
			}
		}
		printf("\n");
		gnutls_bye_nowait(sd, state);
		close(sd);
		gnutls_deinit(state);
	}
	close(listen_sd);

	gnutls_free_x509_server_sc(x509_cred);
	gnutls_free_srp_server_sc(x509_cred);
	gnutls_free_anon_server_sc(x509_cred);

	gnutls_global_deinit();
	
	return 0;

}
