#ifndef GNUTLS_AUTH_H
# define GNUTLS_AUTH_H

typedef struct MOD_AUTH_STRUCT_INT {
	const char* name; /* null terminated */
	int (*gnutls_generate_server_certificate)( gnutls_session, opaque**);
	int (*gnutls_generate_client_certificate)( gnutls_session, opaque**);
	int (*gnutls_generate_server_kx)( gnutls_session, opaque**);
	int (*gnutls_generate_server_kx2)( gnutls_session, opaque**); /* used in SRP */
	int (*gnutls_generate_client_kx0)( gnutls_session, opaque**);
	int (*gnutls_generate_client_kx)( gnutls_session, opaque**); /* used in SRP */
	int (*gnutls_generate_client_cert_vrfy) ( gnutls_session, opaque**);
	int (*gnutls_generate_server_certificate_request) ( gnutls_session, opaque**);
	
	int (*gnutls_process_server_certificate)( gnutls_session, opaque*, int);
	int (*gnutls_process_client_certificate)( gnutls_session, opaque*, int);
	int (*gnutls_process_server_kx)( gnutls_session, opaque*, int);
	int (*gnutls_process_server_kx2)( gnutls_session, opaque*, int);
	int (*gnutls_process_client_kx0)( gnutls_session, opaque*, int);
	int (*gnutls_process_client_kx)( gnutls_session, opaque*, int);
	int (*gnutls_process_client_cert_vrfy) ( gnutls_session, opaque*, int);
	int (*gnutls_process_server_certificate_request) ( gnutls_session, opaque*, int);
} MOD_AUTH_STRUCT;

#endif
