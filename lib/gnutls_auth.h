#ifndef GNUTLS_AUTH_H
 #define GNUTLS_AUTH_H
typedef struct {
	char* name; /* null terminated */
	int (*gnutls_generate_server_kx)( GNUTLS_KEY, opaque**);
	int (*gnutls_generate_server_kx2)( GNUTLS_KEY, opaque**); /* used in SRP */
	int (*gnutls_generate_client_kx0)( GNUTLS_KEY, opaque**);
	int (*gnutls_generate_client_kx)( GNUTLS_KEY, opaque**); /* used in SRP */
	int (*gnutls_generate_client_cert_vrfy) ( GNUTLS_KEY, opaque**);
	int (*gnutls_generate_server_cert_vrfy) ( GNUTLS_KEY, opaque**);
	
	int (*gnutls_process_server_kx)( GNUTLS_KEY, opaque*, int);
	int (*gnutls_process_server_kx2)( GNUTLS_KEY, opaque*, int);
	int (*gnutls_process_client_kx0)( GNUTLS_KEY, opaque*, int);
	int (*gnutls_process_client_kx)( GNUTLS_KEY, opaque*, int);
	int (*gnutls_process_client_cert_vrfy) ( GNUTLS_KEY, opaque*, int);
	int (*gnutls_process_server_cert_vrfy) ( GNUTLS_KEY, opaque*, int);
} MOD_AUTH_STRUCT;
#endif
