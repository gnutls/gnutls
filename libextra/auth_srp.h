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
} srp_client_credentials_st;

#define gnutls_srp_client_credentials srp_client_credentials_st*

typedef struct {
   char *password_file;
   char *password_conf_file;
   /* callback function, instead of reading the
    * password files.
    */
   gnutls_srp_server_credentials_function *pwd_callback;
} srp_server_cred_st;

#define gnutls_srp_server_credentials srp_server_cred_st*

/* these structures should not use allocated data */
typedef struct srp_server_auth_info_st {
   char username[MAX_SRP_USERNAME];
} *srp_server_auth_info_t;

#ifdef ENABLE_SRP

int _gnutls_proc_srp_server_hello(gnutls_session state,
				  const opaque * data, size_t data_size);
int _gnutls_gen_srp_server_hello(gnutls_session state, opaque * data,
				 size_t data_size);

int _gnutls_gen_srp_server_kx(gnutls_session, opaque **);
int _gnutls_gen_srp_client_kx(gnutls_session, opaque **);

int _gnutls_proc_srp_server_kx(gnutls_session, opaque *, size_t);
int _gnutls_proc_srp_client_kx(gnutls_session, opaque *, size_t);

typedef struct srp_server_auth_info_st srp_server_auth_info_st;

#endif				/* ENABLE_SRP */

#endif
