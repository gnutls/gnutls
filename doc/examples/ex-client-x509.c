/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "examples.h"

/* A very basic TLS client, with X.509 authentication and server certificate
 * verification. Note that error checking for missing files etc. is omitted
 * for simplicity.
 */

#define MAX_BUF 1024
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define MSG "GET / HTTP/1.0\r\n\r\n"

extern int tcp_connect(void);
extern void tcp_close(int sd);

int main(void)
{
        int ret, sd, ii;
        gnutls_session_t session;
        char buffer[MAX_BUF + 1];
        gnutls_datum_t out;
        int type;
        unsigned status;
#if 0
        const char *err;
#endif
        gnutls_certificate_credentials_t xcred;

        if (gnutls_check_version("3.4.6") == NULL) {
                fprintf(stderr, "GnuTLS 3.4.6 or later is required for this example\n");
                exit(1);
        }

        /* for backwards compatibility with gnutls < 3.3.0 */
        gnutls_global_init();

        /* X509 stuff */
        gnutls_certificate_allocate_credentials(&xcred);

        /* sets the trusted cas file
         */
        gnutls_certificate_set_x509_trust_file(xcred, CAFILE,
                                               GNUTLS_X509_FMT_PEM);

        /* If client holds a certificate it can be set using the following:
         *
         gnutls_certificate_set_x509_key_file (xcred, 
         "cert.pem", "key.pem", 
         GNUTLS_X509_FMT_PEM); 
         */

        /* Initialize TLS session 
         */
        gnutls_init(&session, GNUTLS_CLIENT);

        gnutls_session_set_ptr(session, (void *) "my_host_name");

        gnutls_server_name_set(session, GNUTLS_NAME_DNS, "my_host_name",
                               strlen("my_host_name"));

        /* It is recommended to use the default priorities */
        gnutls_set_default_priority(session);
#if 0
	/* if more fine-graned control is required */
        ret = gnutls_priority_set_direct(session, 
                                         "NORMAL", &err);
        if (ret < 0) {
                if (ret == GNUTLS_E_INVALID_REQUEST) {
                        fprintf(stderr, "Syntax error at: %s\n", err);
                }
                exit(1);
        }
#endif

        /* put the x509 credentials to the current session
         */
        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
        gnutls_session_set_verify_cert(session, "my_host_name", 0);

        /* connect to the peer
         */
        sd = tcp_connect();

        gnutls_transport_set_int(session, sd);
        gnutls_handshake_set_timeout(session,
                                     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        /* Perform the TLS handshake
         */
        do {
                ret = gnutls_handshake(session);
        }
        while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
        if (ret < 0) {
                fprintf(stderr, "*** Handshake failed\n");
                gnutls_perror(ret);
                goto end;
        } else {
                char *desc;

                desc = gnutls_session_get_desc(session);
                printf("- Session info: %s\n", desc);
                gnutls_free(desc);
        }

        /* check certificate verification status */
        type = gnutls_certificate_type_get(session);
        status = gnutls_session_get_verify_cert_status(session);
        ret =
            gnutls_certificate_verification_status_print(status, type,
                                                         &out, 0);
        if (ret < 0) {
                printf("Error\n");
                return GNUTLS_E_CERTIFICATE_ERROR;
        }

        printf("%s", out.data);
        gnutls_free(out.data);

	/* send data */
        gnutls_record_send(session, MSG, strlen(MSG));

        ret = gnutls_record_recv(session, buffer, MAX_BUF);
        if (ret == 0) {
                printf("- Peer has closed the TLS connection\n");
                goto end;
        } else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
                fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
        } else if (ret < 0) {
                fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
                goto end;
        }

        if (ret > 0) {
                printf("- Received %d bytes: ", ret);
                for (ii = 0; ii < ret; ii++) {
                        fputc(buffer[ii], stdout);
                }
                fputs("\n", stdout);
        }

        gnutls_bye(session, GNUTLS_SHUT_RDWR);

      end:

        tcp_close(sd);

        gnutls_deinit(session);

        gnutls_certificate_free_credentials(xcred);

        gnutls_global_deinit();

        return 0;
}
