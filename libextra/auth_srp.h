#ifndef AUTH_SRP_H
# define AUTH_SRP_H

#include <gnutls_auth.h>


typedef int gnutls_srp_server_credentials_function(gnutls_session,
   const char *username, gnutls_datum * salt, gnutls_datum * verifier,
   gnutls_datum * generator, gnutls_datum * prime);

typedef int gnutls_srp_client_credentials_function(gnutls_session,
   unsigned int times, char **username, char** password);


typedef struct {
   char *username;
   char *password;
   gnutls_srp_client_credentials_function *get_function;
} SRP_CLIENT_CREDENTIALS_INT;

#define gnutls_srp_client_credentials SRP_CLIENT_CREDENTIALS_INT*

typedef struct {
   char *password_file;
   char *password_conf_file;
   /* callback function, instead of reading the
    * password files.
    */
   gnutls_srp_server_credentials_function *pwd_callback;
} SRP_SERVER_CREDENTIALS_INT;

#define gnutls_srp_server_credentials SRP_SERVER_CREDENTIALS_INT*

/* these structures should not use allocated data */
typedef struct SRP_SERVER_AUTH_INFO_INT {
   char username[MAX_SRP_USERNAME];
} *SRP_SERVER_AUTH_INFO;

#ifdef ENABLE_SRP

int _gnutls_proc_srp_server_hello(gnutls_session state,
				  const opaque * data, size_t data_size);
int _gnutls_gen_srp_server_hello(gnutls_session state, opaque * data,
				 size_t data_size);

int _gnutls_gen_srp_server_kx(gnutls_session, opaque **);
int _gnutls_gen_srp_client_kx(gnutls_session, opaque **);

int _gnutls_proc_srp_server_kx(gnutls_session, opaque *, size_t);
int _gnutls_proc_srp_client_kx(gnutls_session, opaque *, size_t);

typedef struct SRP_SERVER_AUTH_INFO_INT SRP_SERVER_AUTH_INFO_INT;

#endif				/* ENABLE_SRP */

#endif
