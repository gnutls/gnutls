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
#include <port.h>

#define SA struct sockaddr
#define ERR(err,s) if (err==-1) {perror(s);return(1);}
#define MAX_BUF 100

int main()
{
	int err, ret;
	int sd, pid;
	struct sockaddr_in sa;
	GNUTLS_STATE state;
	char buffer[MAX_BUF];

//      signal(SIGPIPE, SIG_IGN);

	sd = socket(AF_INET, SOCK_STREAM, 0);
	ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	sa.sin_port = htons(PORT);

	err = connect(sd, (SA *) & sa, sizeof(sa));
	ERR(err, "connect");

	gnutls_init(&state, GNUTLS_CLIENT);
	gnutls_set_current_version( state, GNUTLS_TLS1); /* SSL3 */

	gnutls_set_cipher_priority( 3, GNUTLS_ARCFOUR, GNUTLS_DES, GNUTLS_3DES);
//	gnutls_set_kx_priority( 1, GNUTLS_KX_ANON_DH);
	gnutls_set_kx_priority( 3, GNUTLS_KX_ANON_DH, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA);
	gnutls_set_mac_priority(2, GNUTLS_MAC_SHA, GNUTLS_MAC_MD5);
	ret = gnutls_handshake(sd, state);

	if (ret < 0) {
		fprintf(stderr, "Handshake has failed\n");
		gnutls_perror(ret);
		gnutls_deinit(&state);
		return 1;
	} else {
		fprintf(stderr, "Handshake was completed\n\n");
	}

	if ( pid = fork() == 0) {
		for(;;) {
			bzero(buffer, MAX_BUF);
			ret=gnutls_recv(sd, state, buffer, MAX_BUF);
			if (gnutls_is_fatal_error(ret) == 1) {
				if (ret == GNUTLS_E_CLOSURE_ALERT_RECEIVED) {
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
		}
		kill(getppid(), SIGTERM);
		return 0;
	}
	/* parent */
	
	while( fgets(buffer, MAX_BUF, stdin) != NULL) {
		buffer[strlen(buffer)-1] = '\0';
		gnutls_send( sd, state, buffer, strlen(buffer));
	}
	gnutls_close(sd, state);
	
	shutdown( sd, SHUT_WR);

	gnutls_deinit(&state);
	return 0;
}
