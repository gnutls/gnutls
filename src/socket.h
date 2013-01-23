#include <gnutls/gnutls.h>

typedef struct
{
  int fd;
  gnutls_session_t session;
  int secure;
  char *hostname;
  char *ip;
  char *service;
  struct addrinfo *ptr;
  struct addrinfo *addr_info;
} socket_st;

ssize_t socket_recv (const socket_st * socket, void *buffer, int buffer_size);
ssize_t socket_send (const socket_st * socket, const void *buffer,
                     int buffer_size);
ssize_t socket_send_range(const socket_st * socket, const void *buffer,
        		  int buffer_size, gnutls_range_st *range);
void socket_open (socket_st * hd, const char *hostname, const char *service, int udp);
void socket_bye (socket_st * socket);

void sockets_init (void);
