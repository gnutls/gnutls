#ifndef GNUTLS_AUTH_H
# define GNUTLS_AUTH_H

typedef struct MOD_AUTH_STRUCT_INT {
	char* name; /* null terminated */
	int (*gnutls_generate_server_certificate)( GNUTLS_STATE, opaque**);
	int (*gnutls_generate_client_certificate)( GNUTLS_STATE, opaque**);
	int (*gnutls_generate_server_kx)( GNUTLS_STATE, opaque**);
	int (*gnutls_generate_server_kx2)( GNUTLS_STATE, opaque**); /* used in SRP */
	int (*gnutls_generate_client_kx0)( GNUTLS_STATE, opaque**);
	int (*gnutls_generate_client_kx)( GNUTLS_STATE, opaque**); /* used in SRP */
	int (*gnutls_generate_client_cert_vrfy) ( GNUTLS_STATE, opaque**);
	int (*gnutls_generate_server_certificate_request) ( GNUTLS_STATE, opaque**);
	
	int (*gnutls_process_server_certificate)( GNUTLS_STATE, opaque*, int);
	int (*gnutls_process_client_certificate)( GNUTLS_STATE, opaque*, int);
	int (*gnutls_process_server_kx)( GNUTLS_STATE, opaque*, int);
	int (*gnutls_process_server_kx2)( GNUTLS_STATE, opaque*, int);
	int (*gnutls_process_client_kx0)( GNUTLS_STATE, opaque*, int);
	int (*gnutls_process_client_kx)( GNUTLS_STATE, opaque*, int);
	int (*gnutls_process_client_cert_vrfy) ( GNUTLS_STATE, opaque*, int);
	int (*gnutls_process_server_certificate_request) ( GNUTLS_STATE, opaque*, int);
} MOD_AUTH_STRUCT;

#endif
