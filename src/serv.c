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
#include <signal.h>

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

	gnutls_init(&state, GNUTLS_SERVER);
	if ((ret = gnutls_set_db_name(state, "gnutls-rsm.db")) < 0)
		fprintf(stderr, "*** DB error (%d). Resuming will not be possible.\n\n", ret);

	/* null cipher is here only for debuging 
	 * purposes.
	 */
	gnutls_set_cipher_priority(state, GNUTLS_NULL_CIPHER, 
				   GNUTLS_RIJNDAEL_CBC, GNUTLS_3DES_CBC, GNUTLS_ARCFOUR, 0);
	gnutls_set_compression_priority(state, GNUTLS_ZLIB, GNUTLS_NULL_COMPRESSION, 0);
	gnutls_set_kx_priority(state, GNUTLS_KX_RSA, GNUTLS_KX_DHE_RSA, GNUTLS_KX_SRP, GNUTLS_KX_DH_ANON, 0);
	gnutls_set_protocol_priority( state, GNUTLS_TLS1, GNUTLS_SSL3, 0);
	
	gnutls_set_cred(state, GNUTLS_ANON, dh_cred);
	gnutls_set_cred(state, GNUTLS_SRP, srp_cred);
	gnutls_set_cred(state, GNUTLS_X509PKI, x509_cred);

	gnutls_set_mac_priority(state, GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0);

	gnutls_x509pki_set_cert_request( state, GNUTLS_CERT_REQUEST);

	return state;
}

#define PRINTX(x,y) if (y[0]!=0) printf(" -   %s %s\n", x, y)
#define PRINT_DN(X) PRINTX( "CN:", X->common_name); \
	PRINTX( "OU:", X->organizational_unit_name); \
	PRINTX( "O:", X->organization); \
	PRINTX( "L:", X->locality_name); \
	PRINTX( "S:", X->state_or_province_name); \
	PRINTX( "C:", X->country); \
	PRINTX( "E:", X->email); \
	PRINTX( "SAN:", gnutls_x509pki_client_get_subject_dns_name(state))

void print_info(GNUTLS_STATE state)
{
	const char *tmp;
	unsigned char sesid[32];
	int sesid_size, i;
	const gnutls_DN* dn;
	CredType cred;
	CertificateStatus status;
	
	/* print session_id specific data */
	gnutls_get_current_session_id( state, sesid, &sesid_size);
	printf("\n- Session ID: ");
	for(i=0;i<sesid_size;i++)
		printf("%.2X", sesid[i]);
	printf("\n");

	if ( gnutls_ext_get_name_ind(state, GNUTLS_DNSNAME) != NULL) {
		printf("- DNSNAME: ");
		printf("%s\n", (char*)gnutls_ext_get_name_ind(state, GNUTLS_DNSNAME));
	}
	
	/* we could also use the KX algorithm to distinguish the functions
	 * to call, but this is easier.
	 */
	cred = gnutls_get_auth_type(state);

	switch(cred) {
		case GNUTLS_SRP:
			/* print srp specific data */
			printf("\n- User '%s' connected\n",
			       gnutls_srp_server_get_username( state));
			break;
		case GNUTLS_ANON:
			printf("\n- Anonymous DH using prime of %d bits\n",
			        gnutls_anon_server_get_dh_bits( state));
			break;

		case GNUTLS_X509PKI: 
			status = gnutls_x509pki_client_get_peer_certificate_status( state);
			switch( status) {
			case GNUTLS_CERT_NOT_TRUSTED:
				printf("- Peer's X509 Certificate was NOT verified\n");
				break;
			case GNUTLS_CERT_EXPIRED:
				printf("- Peer's X509 Certificate was verified but is expired\n");
				break;
			case GNUTLS_CERT_TRUSTED:
				printf("- Peer's X509 Certificate was verified\n");
				break;
			case GNUTLS_CERT_NONE:
				printf("- Peer did not send any certificate.\n");
				break;
			case GNUTLS_CERT_INVALID:
				printf("- Peer's X509 Certificate was invalid\n");
				break;
			}
		
			if (gnutls_get_current_kx(state) == GNUTLS_KX_DHE_RSA || gnutls_get_current_kx(state) == GNUTLS_KX_DHE_DSS) {
				printf("\n- Ephemeral DH using prime of %d bits\n",
			        gnutls_x509pki_server_get_dh_bits( state));
			}
			
			if (status!=GNUTLS_CERT_NONE && status!=GNUTLS_CERT_INVALID) {
				printf(" - Certificate info:\n");
				printf(" - Certificate version: #%d\n", gnutls_x509pki_client_get_peer_certificate_version(state));

				dn = gnutls_x509pki_client_get_peer_dn( state);
				if (dn!=NULL)
					PRINT_DN( dn);

				dn = gnutls_x509pki_client_get_issuer_dn( state);
				if (dn!=NULL) {
					printf(" - Certificate Issuer's info:\n");
					PRINT_DN( dn);
				}
			}
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
	if (gnutls_ext_get_name_ind(state, GNUTLS_DNSNAME)!=NULL) {
		sprintf(tmp2, "\n<p>DNSNAME: ");
		sprintf(tmp2, "<b>%s</b></p>\n", (char*)gnutls_ext_get_name_ind(state, GNUTLS_DNSNAME));
	}

	/* Here unlike print_info() we use the kx algorithm to distinguish
	 * the functions to call.
	 */ 

	/* print srp specific data */
	if (gnutls_get_current_kx(state) == GNUTLS_KX_SRP) {
		sprintf(tmp2, "<p>Connected as user '%s'.</p>\n",
		       gnutls_srp_server_get_username( state));
	}

	if (gnutls_get_current_kx(state) == GNUTLS_KX_DH_ANON) {
		sprintf(tmp2, "<p> Connect using anonymous DH (prime of %d bits)</p>\n",
		       gnutls_anon_server_get_dh_bits( state));
	}

	/* print state information */
	strcat( http_buffer, "<P>\n");

	tmp = gnutls_version_get_name(gnutls_get_current_version(state));
	sprintf(tmp2, "Protocol version: <b>%s</b><br>\n", tmp);

	tmp = gnutls_kx_get_name(gnutls_get_current_kx(state));
	sprintf(tmp2, "Key Exchange: <b>%s</b><br>\n", tmp);

	if (gnutls_get_current_kx(state) == GNUTLS_KX_DHE_RSA || gnutls_get_current_kx(state) == GNUTLS_KX_DHE_DSS) {
		sprintf(tmp2, "Ephemeral DH using prime of <b>%d</b> bits.<br>\n",
			        gnutls_x509pki_server_get_dh_bits( state));
	}
			
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
		do {
			rc = gnutls_read(cd, state, &c, 1);
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
	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		ret = gnutls_get_last_alert(state);
		if (ret == GNUTLS_NO_RENEGOTIATION)
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

	if (gnutls_allocate_x509_server_sc(&x509_cred, 1) < 0) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}

	if (gnutls_set_x509_server_trust( x509_cred, CAFILE, CRLFILE) < 0) {
		fprintf(stderr, "X509 PARSE ERROR\nDid you have ca.pem?\n");
		exit(1);
	}

	if (gnutls_set_x509_server_key( x509_cred, CERTFILE, KEYFILE) < 0) {
		fprintf(stderr, "X509 PARSE ERROR\nDid you have key.pem and cert.pem?\n");
		exit(1);
	}

	/* this is a password file (created with the included srpcrypt utility) 
	 * Read README.crypt prior to using SRP.
	 */
	gnutls_allocate_srp_server_sc( &srp_cred);
	gnutls_set_srp_server_cred( srp_cred, SRP_PASSWD, SRP_PASSWD_CONF);

	gnutls_allocate_anon_server_sc( &dh_cred);
	gnutls_set_anon_server_cred( dh_cred, 1024);

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


		do {
			ret = gnutls_handshake(sd, state);
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
			ret = read_request(sd, state, buffer, MAX_BUF, (http==0)?1:2);

			if (gnutls_is_fatal_error(ret) == 1 || ret == 0) {
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
						ret = gnutls_write(sd, state, buffer, strlen(buffer));
					} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);
					printf( "* Wrote %d bytes to client.\n", ret);
				} else {
					strcpy( http_buffer, HTTP_BEGIN);
					peer_print_info(sd, state);
					strcat( http_buffer, HTTP_END);
					do {
						ret = gnutls_write(sd, state, http_buffer, strlen(http_buffer));
					} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);

					printf("- Served request. Closing connection.\n");
					break;
				}
			}
			i++;
#ifdef RENEGOTIATE
			if (i == 20) {
				do {
					ret = gnutls_rehandshake(sd, state);
				} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);

				if (gnutls_get_last_alert(state)!=GNUTLS_NO_RENEGOTIATION) {
					printf("* Requesting rehandshake.\n");
					/* continue handshake proccess */
					do {
						ret = gnutls_handshake(sd, state);
					} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);
					printf("* Rehandshake returned %d\n", ret);
				}
			}
#endif
			
			check_alert( state, ret);

			if (http != 0) {
				break;	/* close the connection */
			}
		}
		printf("\n");
		do {
			ret = gnutls_bye(sd, state, GNUTLS_SHUT_WR); 
		} while( ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);
		/* do not wait for
		 * the peer to close the connection.
		 */
		close(sd);
		gnutls_deinit(state);

	}
	close(listen_sd);

	gnutls_free_x509_server_sc(x509_cred);
	gnutls_free_srp_server_sc(srp_cred);
	gnutls_free_anon_server_sc(dh_cred);

	gnutls_global_deinit();
	
	return 0;

}
