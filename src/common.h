#define PORT 5556
#define SERVER "127.0.0.1"

#include <gnutls/gnutls.h>

int print_info( gnutls_session state);
void print_cert_info( gnutls_session state);
int print_list(void);
