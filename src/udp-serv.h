#include <gnutls/dtls.h>

int udp_server(const char* name, int port, int mtu);
gnutls_session_t initialize_session (int dtls);
const char * human_addr (const struct sockaddr *sa, socklen_t salen,
            char *buf, size_t buflen);
int wait_for_connection(void);
int listen_socket (const char *name, int listen_port, int socktype);
