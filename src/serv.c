#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../lib/gnutls.h"
#include <port.h>

#define SA struct sockaddr
#define ERR(err,s) if(err==-1) {perror(s);return(1);}

int main()
{
	int err, listen_sd;
	int sd, ret;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	int client_len, i;
	char topbuf[512];
	GNUTLS_STATE state;
	char *str;
	char buf[4096];


	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	ERR(listen_sd, "socket");

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(PORT);	/* Server Port number */

	err = bind(listen_sd, (SA *) & sa_serv, sizeof(sa_serv));
	ERR(err, "bind");
	err = listen(listen_sd, 1024);
	ERR(err, "listen");

	client_len = sizeof(sa_cli);
	for (;;) {
		gnutls_init(&state, GNUTLS_SERVER);
		sd = accept(listen_sd, (SA *) & sa_cli, &client_len);


		fprintf(stderr, "connection from %s, port %d\n",
			inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
				  sizeof(topbuf)), ntohs(sa_cli.sin_port));



		ret = gnutls_handshake(sd, state);
		if (ret<0) {
			close(sd);
			gnutls_deinit(&state);
			fprintf(stderr, "Handshake has failed\n", ret);
			gnutls_perror(ret);
			continue;
		}
		fprintf(stderr, "Handshake was completed\n");

		ret = gnutls_send(sd, state, "hello world\n", sizeof("hello world\n"));
		if (ret<0) {
			close(sd);
			gnutls_deinit(&state);
			gnutls_perror(ret);
			continue;
		}
		fprintf(stderr, "Data was send (%d)\n", ret);
		fprintf(stderr, "\n");
		gnutls_close(sd, state);
		close(sd);
		gnutls_deinit(&state);
	}
	close(listen_sd);
	return 0;

}
