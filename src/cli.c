/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "../lib/gnutls.h"
#include <signal.h>
#include "port.h"
#include <sys/time.h>

#define SA struct sockaddr
#define ERR(err,s) if (err==-1) {perror(s);return(1);}
#define MAX_BUF 100

#define MAX(X,Y) (X >= Y ? X : Y);

int main()
{
	int err, ret;
	int sd;
	struct sockaddr_in sa;
	GNUTLS_STATE state;
	char buffer[MAX_BUF];
	char *session;
	int session_size;
	fd_set rset;
	int maxfd;
	struct timeval tv;
	int user_term = 0;
	
//	signal(SIGPIPE, SIG_IGN);

	sd = socket(AF_INET, SOCK_STREAM, 0);
	ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(SERVER);
	sa.sin_port = htons(PORT);

	err = connect(sd, (SA *) & sa, sizeof(sa));
	ERR(err, "connect");

	gnutls_init(&state, GNUTLS_CLIENT);
	gnutls_set_current_version( state, GNUTLS_TLS1);

	gnutls_set_cipher_priority( state, 2, GNUTLS_ARCFOUR, GNUTLS_3DES);
	gnutls_set_compression_priority( state, 1, GNUTLS_COMPRESSION_NULL);
	gnutls_set_kx_priority( state, 3, GNUTLS_KX_ANON_DH, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA);
	gnutls_set_mac_priority( state, 2, GNUTLS_MAC_SHA, GNUTLS_MAC_MD5);
	ret = gnutls_handshake(sd, state);

	if (ret < 0) {
		fprintf(stderr, "Handshake has failed\n");
		gnutls_perror(ret);
		gnutls_deinit(&state);
		return 1;
	} else {
		fprintf(stderr, "Handshake was completed\n");
	}
	gnutls_get_current_session( state, NULL, &session_size);
	session = malloc(session_size);
	gnutls_get_current_session( state, session, &session_size);
	
	fprintf(stderr, "Disconnecting\n");
	gnutls_close(sd, state);
	shutdown( sd, SHUT_WR);
	close(sd);	
	gnutls_deinit( &state);	
	
	fprintf(stderr, "\n\nConnecting again- trying to resume previous session\n");
	sd = socket(AF_INET, SOCK_STREAM, 0);
	ERR(sd, "socket");

	err = connect(sd, (SA *) & sa, sizeof(sa));
	ERR(err, "connect");
	
	/* Begin handshake again */
	gnutls_init(&state, GNUTLS_CLIENT);
	
	gnutls_set_current_version( state, GNUTLS_TLS1);

	gnutls_set_cipher_priority( state, 2, GNUTLS_ARCFOUR, GNUTLS_3DES);
	gnutls_set_compression_priority( state, 2, GNUTLS_ZLIB, GNUTLS_COMPRESSION_NULL);
	gnutls_set_kx_priority( state, 3, GNUTLS_KX_ANON_DH, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA);
	gnutls_set_mac_priority( state, 2, GNUTLS_MAC_SHA, GNUTLS_MAC_MD5);

	gnutls_set_current_session( state, session, session_size);
	free(session);
	
	ret = gnutls_handshake(sd, state);

	if (ret < 0) {
		fprintf(stderr, "Handshake failed\n");
		gnutls_perror(ret);
		gnutls_deinit(&state);
		return 1;
	} else {
		fprintf(stderr, "Handshake was completed\n");
	}

	FD_ZERO(&rset);
	for(;;) {
		FD_SET(fileno(stdin), &rset);
		FD_SET(sd, &rset);
		
		maxfd = MAX(fileno(stdin), sd);
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		select(maxfd+1, &rset, NULL, NULL, &tv);

		if (FD_ISSET(sd, &rset)) {
			bzero(buffer, MAX_BUF);

			ret = gnutls_recv(sd, state, buffer, MAX_BUF);
			/* remove new line */
			if (buffer[strlen(buffer)-1]=='\n') buffer[strlen(buffer)-1]='\0';
			if (ret==0) {
				fprintf(stderr,
					"Peer has abnormaly closed the GNUTLS connection\n");
				break;
			}
			if (gnutls_is_fatal_error(ret) == 1) {
				if (ret == GNUTLS_E_CLOSURE_ALERT_RECEIVED || ret == GNUTLS_E_INVALID_SESSION) {
					fprintf(stderr,
						"Peer has closed the GNUTLS connection\n");
					break;
				} else {
					fprintf(stderr, "Received corrupted data(%d)\n",
						ret);
					break;
				}
			} else {
				fprintf(stdout, "Received: %s\n", buffer);
			}
			if (user_term!=0) break;
		}
		if (FD_ISSET(fileno(stdin), &rset)) {
	
			if( fgets(buffer, MAX_BUF, stdin) == NULL) {
				gnutls_close(sd, state);
				user_term = 1;
				continue;
			}
			gnutls_send( sd, state, buffer, strlen(buffer));
		}
	}
	if (user_term!=0) gnutls_close(sd, state);
	
	shutdown( sd, SHUT_RDWR); /* no more receptions */
	close(sd);
	
	gnutls_deinit(&state);
	return 0;
}
