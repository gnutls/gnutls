#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "gnutls.h"

#define SA struct sockaddr
#define ERR(err,s) if(err==-1) {perror(s);exit(1);}

int main()
{
	int err;
	int listen_sd;
	int sd;
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
	sa_serv.sin_port = htons(6666);	/* Server Port number */

	err = bind(listen_sd, (SA*) &sa_serv,
		   sizeof(sa_serv)); ERR(err, "bind");
	err = listen(listen_sd, 1024);
	ERR(err, "listen");

	client_len = sizeof(sa_cli);
	for (;;) {
		gnutls_init(&state, GNUTLS_SERVER);
		sd =
		    accept(listen_sd, (SA*) &sa_cli,
			   &client_len);


		fprintf(stderr, "connection from %s, port %d\n",
			inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
				  sizeof(topbuf)), ntohs(sa_cli.sin_port));



//		gnutls_handshake(sd, state);
//		fprintf(stderr, "Handshake was completed\n");
//		gnutls_send(sd, state, "hello\n", 5);
		gnutls_recv(sd, state, buf, 10);
//		fprintf(stderr, "buf: %s\n", bin2hex(buf,100));
		_print_TLSCiphertext( buf);
		fprintf(stderr, "Data was send\n");
		close(sd);
		gnutls_deinit(&state);
	}
	close(listen_sd);
	return 0;

}
