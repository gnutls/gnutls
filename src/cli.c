#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gnutls.h>

#define SA struct sockaddr
#define ERR(err,s) if (err==-1) {perror(s);exit(1);}

int main ()
{
  int err;
  int sd;
  struct sockaddr_in sa;
  GNUTLS_STATE state;
  char buffer[100];

  sd = socket (AF_INET, SOCK_STREAM, 0);       ERR(sd, "socket");
 
  memset (&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr ("127.0.0.1");
  sa.sin_port        = htons     (6666);
  
  err = connect(sd, (SA*) &sa,
		sizeof(sa));                   ERR(err, "connect");

  gnutls_init(&state, GNUTLS_CLIENT);
  gnutls_handshake( sd, state);
  
  gnutls_recv( sd, state, buffer, 10);
  fprintf(stderr, "Received: %s\n", buffer);


  close (sd);
  gnutls_deinit(&state);
  return 0;
}
