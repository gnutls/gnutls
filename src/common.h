#define PORT 5556
#define SERVER "127.0.0.1"

#include <config.h>
#include <gnutls/gnutls.h>

#ifdef _WIN32
# include <winsock.h>
# include <io.h>
# include <winbase.h>
# define socklen_t int
# define close closesocket
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <netdb.h>
# include <signal.h>
#endif

/* the number of elements in the priority structures.
 */
#define PRI_MAX 16

extern const char str_unknown[];

int print_info( gnutls_session state, const char* hostname);
void print_cert_info( gnutls_session state, const char* hostname);
void print_list(void);

void parse_comp( char** comp, int ncomp, int* comp_priority);
void parse_kx( char** kx, int nkx, int* kx_priority);
void parse_ctypes( char** ctype, int nctype, int * cert_type_priority);
void parse_macs( char** macs, int nmacs, int *mac_priority);
void parse_ciphers( char** ciphers, int nciphers, int* cipher_priority);
void parse_protocols( char** protocols, int protocols_size, int* protocol_priority);

void sockets_init( void);
#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src,
                             char *dst, size_t cnt);
#endif
