/*
 * Copyright (C) 2001,2002 Paul Sheer
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* This server is heavily modified for GNUTLS by Nikos Mavroyanopoulos
 * (which means it is quite unreadable)
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include "common.h"
#include <signal.h>
#include "serv-gaa.h"
#include <sys/time.h>
#include <fcntl.h>
#include <config.h>
#include <list.h>

/* konqueror cannot handle sending the page in multiple
 * pieces.
 */
/* global stuff */
static int generate = 0;
static int http = 0;
static int port = 0;
static int x509ctype;

static int quiet;
static int nodb;

char *srp_passwd;
char *srp_passwd_conf;
char *pgp_keyring;
char *pgp_trustdb;
char *pgp_keyserver;
char *pgp_keyfile;
char *pgp_certfile;
char *x509_keyfile;
char *x509_certfile;
char *x509_cafile;
char *x509_crlfile = NULL;

/* end of globals */

/* This is a sample TCP echo server.
 * This will behave as an http server if any argument in the
 * command line is present
 */

#define SMALL_READ_TEST (2147483647)

#define SA struct sockaddr
#define ERR(err,s) if(err==-1) {perror(s);return(1);}
#define GERR(ret, where) fprintf(stdout, "*** gnutls error[%d]: %s (%s)\n", ret, gnutls_strerror(ret), where)
#define MAX_BUF 1024

#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))
#undef min
#define min(x,y) ((x) < (y) ? (x) : (y))


#define HTTP_END  "</BODY></HTML>\n\n"

#define HTTP_UNIMPLEMENTED "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>501 Method Not Implemented</TITLE>\r\n</HEAD><BODY>\r\n<H1>Method Not Implemented</H1>\r\n<HR>\r\n</BODY></HTML>\r\n"
#define HTTP_OK "HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n"

#define HTTP_BEGIN HTTP_OK \
		"\n" \
		"<HTML><BODY>\n" \
		"<CENTER><H1>This is <a href=\"http://www.gnu.org/software/gnutls\">" \
		"GNUTLS</a></H1>\n\n"

#define RENEGOTIATE

/* These are global */
GNUTLS_SRP_SERVER_CREDENTIALS srp_cred;
GNUTLS_ANON_SERVER_CREDENTIALS dh_cred;
GNUTLS_CERTIFICATE_SERVER_CREDENTIALS cert_cred;


#ifdef HAVE_LIBGDBM

# include <gdbm.h>

# define DB_FILE "gnutls-rsm.db"

 static void wrap_gdbm_init(void);
 static void wrap_gdbm_deinit(void);
 static int wrap_gdbm_store( void* dbf, gnutls_datum key, gnutls_datum data);
 static gnutls_datum wrap_gdbm_fetch( void* dbf, gnutls_datum key);
 static int wrap_gdbm_delete( void* dbf, gnutls_datum key);

#endif

#define HTTP_STATE_REQUEST	1
#define HTTP_STATE_RESPONSE	2
#define HTTP_STATE_CLOSING	3

LIST_TYPE_DECLARE (listener_item, char *http_request;
		   char *http_response;
		   int request_length; int response_length; int response_written; int http_state; int fd;
		   GNUTLS_STATE tstate;
		   int handshake_ok;
    );

static void listener_free (listener_item * j)
{
    if (j->http_request)
	free (j->http_request);
    if (j->http_response)
	free (j->http_response);
    if (j->fd >= 0) {
	gnutls_bye ( j->tstate, GNUTLS_SHUT_WR);
	shutdown (j->fd, 2);
	close (j->fd);
	gnutls_deinit (j->tstate);
    }
}



#define DEFAULT_PRIME_BITS 1024

/* we use primes up to 1024 in this server.
 * otherwise we should add them here.
 */
static int prime_nums[] = { 768, 1024, 0 };

GNUTLS_DH_PARAMS dh_params;

static int generate_dh_primes(void)
{
   gnutls_datum prime, generator;
   int i = 0;

   if (gnutls_dh_params_init(&dh_params) < 0) {
      fprintf(stderr, "Error in dh parameter initialization\n");
      exit(1);
   }

   do {
      /* Generate Diffie Hellman parameters - for use with DHE
       * kx algorithms. These should be discarded and regenerated
       * once a day, once a week or once a month. Depends on the
       * security requirements.
       */
      printf
	  ("Generating Diffie Hellman parameters [%d]. Please wait...",
	   prime_nums[i]);
      fflush(stdout);

      if (gnutls_dh_params_generate(&prime, &generator, prime_nums[i]) < 0) {
	 fprintf(stderr, "Error in prime generation\n");
	 exit(1);
      }

      if (gnutls_dh_params_set
	  (dh_params, prime, generator, prime_nums[i]) < 0) {
	 fprintf(stderr, "Error in prime replacement\n");
	 exit(1);
      }
      free(prime.data);
      free(generator.data);

   } while (prime_nums[++i] != 0);

   return 0;
}

int protocol_priority[16] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
int kx_priority[16] =
    { GNUTLS_KX_DHE_DSS, GNUTLS_KX_RSA, GNUTLS_KX_DHE_RSA, GNUTLS_KX_SRP,
  /* Do not use anonymous authentication, unless you know what that means */ 
  GNUTLS_KX_ANON_DH, 0
};
int cipher_priority[16] =
    { GNUTLS_CIPHER_RIJNDAEL_128_CBC, GNUTLS_CIPHER_3DES_CBC,
   GNUTLS_CIPHER_ARCFOUR, 0
};

int comp_priority[16] = { GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
int mac_priority[16] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
int cert_type_priority[16] = { GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0 };

LIST_DECLARE_INIT (listener_list, listener_item, listener_free);

GNUTLS_STATE initialize_state (void)
{
    GNUTLS_STATE state;

    gnutls_init (&state, GNUTLS_SERVER);

   /* allow the use of private ciphersuites.
    */
   gnutls_handshake_set_private_extensions( state, 1);

#ifdef HAVE_LIBGDBM
   if (nodb==0) {
    gnutls_db_set_retrieve_function( state, wrap_gdbm_fetch);
    gnutls_db_set_remove_function( state, wrap_gdbm_delete);
    gnutls_db_set_store_function( state, wrap_gdbm_store);
    gnutls_db_set_ptr( state, NULL);
   }
#endif

    gnutls_cipher_set_priority(state, cipher_priority);
    gnutls_compression_set_priority(state, comp_priority);
    gnutls_kx_set_priority(state, kx_priority);
    gnutls_protocol_set_priority( state, protocol_priority);
    gnutls_mac_set_priority(state, mac_priority);
    gnutls_cert_type_set_priority(state, cert_type_priority);

    gnutls_cred_set(state, GNUTLS_CRD_ANON, dh_cred);
    gnutls_cred_set(state, GNUTLS_CRD_SRP, srp_cred);
    gnutls_cred_set (state, GNUTLS_CRD_CERTIFICATE, cert_cred);

    gnutls_certificate_server_set_request (state, GNUTLS_CERT_REQUEST);

    return state;
}

static char DEFAULT_DATA[] = "This is the default message reported "
	"by GnuTLS TLS version 1.0 implementation. For more information "
	"please visit http://www.gnutls.org or even http://www.gnu.org/software/gnutls.";

/* Creates html with the current state information.
 */
#define tmp2 &http_buffer[strlen(http_buffer)]
char* peer_print_info(GNUTLS_STATE state, int *ret_length)
{
   const char *tmp;
   unsigned char sesid[32];
   int sesid_size, i;
   char* http_buffer = malloc(5*1024);

   if (http_buffer==NULL) return NULL;
   if (quiet != 0) {
   
   	strcpy( http_buffer, HTTP_BEGIN);
   	strcpy( &http_buffer[sizeof(HTTP_BEGIN)-1], DEFAULT_DATA);
   	strcpy( &http_buffer[sizeof(HTTP_BEGIN)+sizeof(DEFAULT_DATA)-2], HTTP_END);
   	*ret_length = sizeof(DEFAULT_DATA) + sizeof(HTTP_BEGIN) +
   		sizeof(HTTP_END) - 3;
   	return http_buffer;
   
   }

   strcpy( http_buffer, HTTP_BEGIN);
   
   /* print session_id */
   gnutls_session_get_id(state, sesid, &sesid_size);
   sprintf(tmp2, "\n<p>Session ID: <i>");
   for (i = 0; i < sesid_size; i++)
      sprintf(tmp2, "%.2X", sesid[i]);
   sprintf(tmp2, "</i></p>\n");

   /* Here unlike print_info() we use the kx algorithm to distinguish
    * the functions to call.
    */

   /* print srp specific data */
   if (gnutls_kx_get(state) == GNUTLS_KX_SRP) {
      sprintf(tmp2, "<p>Connected as user '%s'.</p>\n",
	      gnutls_srp_server_get_username(state));
   }

   if (gnutls_kx_get(state) == GNUTLS_KX_ANON_DH) {
      sprintf(tmp2,
	      "<p> Connect using anonymous DH (prime of %d bits)</p>\n",
	      gnutls_dh_get_prime_bits(state));
   }

   /* print state information */
   strcat(http_buffer, "<P>\n");

   tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(state));
   sprintf(tmp2, "Protocol version: <b>%s</b><br>\n", tmp);

   if (gnutls_auth_get_type(state) == GNUTLS_CRD_CERTIFICATE) {
      tmp = gnutls_cert_type_get_name(gnutls_cert_type_get(state));
      sprintf(tmp2, "Certificate Type: <b>%s</b><br>\n", tmp);
   }

   tmp = gnutls_kx_get_name(gnutls_kx_get(state));
   sprintf(tmp2, "Key Exchange: <b>%s</b><br>\n", tmp);

   if (gnutls_kx_get(state) == GNUTLS_KX_DHE_RSA
       || gnutls_kx_get(state) == GNUTLS_KX_DHE_DSS) {
      sprintf(tmp2,
	      "Ephemeral DH using prime of <b>%d</b> bits.<br>\n",
	      gnutls_dh_get_prime_bits(state));
   }

   tmp = gnutls_compression_get_name(gnutls_compression_get(state));
   sprintf(tmp2, "Compression: <b>%s</b><br>\n", tmp);

   tmp = gnutls_cipher_get_name(gnutls_cipher_get(state));
   sprintf(tmp2, "Cipher: <b>%s</b><br>\n", tmp);

   tmp = gnutls_mac_get_name(gnutls_mac_get(state));
   sprintf(tmp2, "MAC: <b>%s</b><br>\n", tmp);

   strcat(http_buffer, "</P>\n"HTTP_END);

   *ret_length = strlen(http_buffer);

   return http_buffer;
}

static int listen_socket (char* name, int listen_port)
{
    struct sockaddr_in a;
    int s;
    int yes;

    if ((s = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
	perror ("socket() failed");
	return -1;
    }
    yes = 1;

    if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof (yes)) < 0) {
	perror ("setsockopt() failed");
	close (s);
	return -1;
    }
    memset (&a, 0, sizeof (a));
    a.sin_port = htons (listen_port);
    a.sin_family = AF_INET;
    if (bind (s, (struct sockaddr *) &a, sizeof (a)) < 0) {
	perror ("bind() failed");
	close (s);
	return -1;
    }

    printf("%s ready. Listening to port '%d'.\n\n", name, listen_port);
    listen (s, 10);
    return s;
}

static void get_response(GNUTLS_STATE state, char *request, char **response, int *response_length)
{
    char *p, *h;

    if (http!=0) {
	    if (strncmp (request, "GET ", 4))
		goto unimplemented;

	    if (!(h = strchr (request, '\r')))
		goto unimplemented;

	    *h++ = '\0';
	    while (*h == '\r' || *h == '\n')
		h++;

	    if (!(p = strchr (request + 4, ' ')))
		goto unimplemented;
	    *p = '\0';
    }
    
//    *response = peer_print_info(state, request+4, h, response_length);
    if (http!=0) {
	*response = peer_print_info(state, response_length);
    } else {
    	*response = strdup( request);
    	*response_length = strlen( *response);
    }
    return;

  unimplemented:
    *response = strdup(HTTP_UNIMPLEMENTED);
    *response_length = strlen (*response);
}

void terminate( int sig) {
	fprintf(stderr, "Exiting via signal %d\n", sig);
	exit(0);
}


void check_alert(GNUTLS_STATE state, int ret)
{
   int last_alert;

   if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
       || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
      last_alert = gnutls_alert_get(state);
      if (last_alert == GNUTLS_A_NO_RENEGOTIATION &&
	  ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
	 printf
	     ("* Received NO_RENEGOTIATION alert. Client Does not support renegotiation.\n");
      else
	 printf("* Received alert '%d'.\n", ret);
   }
}

static void gaa_parser(int argc, char **argv);

int main(int argc, char **argv)
{
   int ret, n, h;
   char topbuf[512];
//   int optval = 1;
   char name[256];

   signal(SIGPIPE, SIG_IGN);
   signal( SIGHUP, SIG_IGN);
   signal( SIGTERM, terminate);
   signal( SIGINT, terminate);

   gaa_parser(argc, argv);

#ifdef HAVE_LIBGDBM
   if (nodb==0) wrap_gdbm_init();
#endif

   if (http == 1) {
      strcpy(name, "HTTP Server");
   } else {
      strcpy(name, "Echo Server");
   }

   if (gnutls_global_init() < 0) {
      fprintf(stderr, "global state initialization error\n");
      exit(1);
   }

   if (gnutls_global_init_extra() < 0) {
      fprintf(stderr, "global state initialization error\n");
      exit(1);
   }

   /* Note that servers must generate parameters for
    * Diffie Hellman. See gnutls_dh_params_generate(), and
    * gnutls_dh_params_set().
    */
   if (generate != 0)
      generate_dh_primes();

   if (gnutls_certificate_allocate_cred(&cert_cred) < 0) {
      fprintf(stderr, "memory error\n");
      exit(1);
   }

   if (x509_cafile != NULL) {
      if ((ret=gnutls_certificate_set_x509_trust_file
	  (cert_cred, x509_cafile, x509ctype)) < 0) {
	 fprintf(stderr, "Error reading '%s'\n", x509_cafile);
	 exit(1);
      } else {
      	 printf("Processed %d CA certificate(s).\n", ret);
      }
   }

   if (pgp_keyring != NULL) {
      ret =
	  gnutls_certificate_set_openpgp_keyring_file(cert_cred, pgp_keyring);
      if (ret < 0) {
	 fprintf(stderr, "Error setting the OpenPGP keyring file\n");
      }
   }

   if (pgp_trustdb != NULL) {
      ret = gnutls_certificate_set_openpgp_trustdb(cert_cred, pgp_trustdb);
      if (ret < 0) {
	 fprintf(stderr, "Error setting the OpenPGP trustdb file\n");
      }
   }

   if (pgp_certfile != NULL)
      if (gnutls_certificate_set_openpgp_key_file
	  (cert_cred, pgp_certfile, pgp_keyfile) < 0) {
	 fprintf(stderr,
		 "Error while reading the OpenPGP key pair ('%s', '%s')\n",
		 pgp_certfile, pgp_keyfile);
      }

   gnutls_certificate_set_openpgp_keyserver(cert_cred, pgp_keyserver, 0);

   if (x509_certfile != NULL)
      if (gnutls_certificate_set_x509_key_file
	  (cert_cred, x509_certfile, x509_keyfile, x509ctype) < 0) {
	 fprintf(stderr,
		 "Error reading '%s' or '%s'\n", x509_certfile,
		 x509_keyfile);
	 exit(1);
      }

   if (generate != 0)
      if (gnutls_certificate_set_dh_params(cert_cred, dh_params) < 0) {
	 fprintf(stderr, "Error while setting DH parameters\n");
	 exit(1);
      }

   /* this is a password file (created with the included srpcrypt utility) 
    * Read README.crypt prior to using SRP.
    */
   gnutls_srp_allocate_server_cred(&srp_cred);

   if (srp_passwd!=NULL)
   if ((ret=gnutls_srp_set_server_cred_file(srp_cred, srp_passwd, srp_passwd_conf)) < 0) {
	/* only exit is this function is not disabled 
	 */
   	fprintf(stderr, "Error while setting SRP parameters\n");
   }


   gnutls_anon_allocate_server_cred(&dh_cred);
   if (generate != 0)
      gnutls_anon_set_server_dh_params(dh_cred, dh_params);


    h = listen_socket ( name, port);
    if (h < 0)
	exit (1);

    for (;;) {
	listener_item *j;
	fd_set rd, wr;
	int val;

	FD_ZERO (&rd);
	FD_ZERO (&wr);
	n = 0;

/* check for new incoming connections */
	FD_SET (h, &rd);
	n = max (n, h);

/* flag which connections we are reading or writing to within the fd sets */
	lloopstart (listener_list, j) {

	    val = fcntl (j->fd, F_GETFL, 0);
	    if (fcntl (j->fd, F_SETFL, val | O_NONBLOCK) < 0) {
	    	perror("fcntl()");
	    	exit(1);
	    }

	    if (j->http_state == HTTP_STATE_REQUEST) {
		FD_SET (j->fd, &rd);
		n = max (n, j->fd);
	    }
	    if (j->http_state == HTTP_STATE_RESPONSE) {
		FD_SET (j->fd, &wr);
		n = max (n, j->fd);
	    }
	}
	lloopend (listener_list, j);

/* core operation */
	n = select (n + 1, &rd, &wr, 0, 0);
	if (n == -1 && errno == EINTR)
	    continue;
	if (n < 0) {
	    perror ("select()");
	    exit (1);
	}

/* a new connection has arrived */
	if (FD_ISSET (h, &rd)) {
	    unsigned int l;
	    GNUTLS_STATE tstate;
	    int accept_fd;
	    struct sockaddr_in client_address;

	    tstate = initialize_state ();

	    memset (&client_address, 0, l = sizeof (client_address));
	    accept_fd = accept (h, (struct sockaddr *) &client_address, &l);

	    if (accept_fd < 0) {
		perror ("accept()");
	    } else {
	    	time_t tt;
	    	char* ctt;

/* new list entry for the connection */
		lappend (listener_list);
		j = listener_list.tail;
		j->http_request = (char *) strdup ("");
		j->http_state = HTTP_STATE_REQUEST;
		j->fd = accept_fd;

		j->tstate = tstate;
                gnutls_transport_set_ptr( tstate, accept_fd);
		j->handshake_ok = 0;

		if (quiet==0) {
			tt = time(0);
			ctt = ctime(&tt);
			ctt[strlen(ctt)-1] = 0;

//		printf ("- %s: connection from %s\n", ctt, inet_ntoa (client_address.sin_addr));

		        printf("- connection from %s, port %d\n",
			     inet_ntop(AF_INET, &client_address.sin_addr, topbuf,
			       sizeof(topbuf)), ntohs(client_address.sin_port));

			fflush(stdout);
		}
	    }
	}

/* read or write to each connection as indicated by select()'s return argument */
	lloopstart (listener_list, j) {
	    if (FD_ISSET (j->fd, &rd)) {
/* read partial GET request */
		char buf[1024];
		int r, ret;

		if (j->handshake_ok == 0) {
		    r = gnutls_handshake ( j->tstate);
		    if (r < 0 && gnutls_error_is_fatal (r) == 0) {
			check_alert(j->tstate, r);
			/* nothing */
		    } else if (r < 0 && gnutls_error_is_fatal (r) == 1) {
			GERR( r, "handshake");

		    	do {
		    	ret = gnutls_alert_send_appropriate( j->tstate, r);
		    	} while(ret==GNUTLS_E_AGAIN);
			j->http_state = HTTP_STATE_CLOSING;
		    } else if (r == 0) {
		        if ( gnutls_session_is_resumed( j->tstate)!=0 && quiet==0)
        	 	  printf("*** This is a resumed session\n");
//		        print_info(j->tstate);

			j->handshake_ok = 1;
		    }
		}

		if (j->handshake_ok == 1) {
		    r = gnutls_record_recv ( j->tstate, buf, min (1024, SMALL_READ_TEST));
		    if (r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN) {
			/* do nothing */
		    } else if (r < 0 || r == 0) {
			j->http_state = HTTP_STATE_CLOSING;
			if (r<0 && r!=GNUTLS_E_UNEXPECTED_PACKET_LENGTH) {
				check_alert(j->tstate, r);
				GERR(r, "recv");
			}

		    } else {
			j->http_request = realloc (j->http_request, j->request_length + r + 1);
			if (j->http_request!=NULL) {
			 memcpy (j->http_request + j->request_length, buf, r);
			 j->request_length += r;
			 j->http_request[j->request_length] = '\0';
			} else j->http_state = HTTP_STATE_CLOSING;
			
		    }
/* check if we have a full HTTP header */
		    if (j->http_request!=NULL) {
		        if ( (http==0 && strchr(j->http_request, '\n')) || strstr (j->http_request, "\r\n\r\n")) {
			  get_response (j->tstate, j->http_request, &j->http_response, &j->response_length);
			  j->http_state = HTTP_STATE_RESPONSE;
			  j->response_written = 0;
		        }
		    }
		}
	    }
	    if (FD_ISSET (j->fd, &wr)) {
/* write partial response request */
		int r;

		if (j->handshake_ok == 0) {
		    r = gnutls_handshake ( j->tstate);
		    if (r < 0 && gnutls_error_is_fatal (r) == 0) {
			check_alert(j->tstate, r);
			/* nothing */
		    } else if (r < 0 && gnutls_error_is_fatal (r) == 1) {
		    	int ret;
		    	
			j->http_state = HTTP_STATE_CLOSING;
		    	GERR(r, "handshake");

		    	do {
		    		ret=gnutls_alert_send_appropriate( j->tstate, r);
		    	} while(ret==GNUTLS_E_AGAIN);
		    } else if (r == 0) {
		        if ( gnutls_session_is_resumed( j->tstate)!=0 && quiet == 0)
        	 	  printf("*** This is a resumed session\n");
//		        print_info(j->tstate);

			j->handshake_ok = 1;
		    }
		}

		if (j->handshake_ok == 1) {
		    r =
			gnutls_record_send ( j->tstate, j->http_response + j->response_written,
				      min (j->response_length - j->response_written, SMALL_READ_TEST));
		    if (r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN) {
			/* do nothing */
		    } else if (r < 0 || r == 0) {
			if (http!=0) j->http_state = HTTP_STATE_CLOSING;
			else {
				j->http_state = HTTP_STATE_REQUEST;
				free( j->http_response);
				j->response_length = 0;
				j->request_length = 0;
				j->http_request[0] = 0;
			}
			
			if (r<0) GERR(r, "send");
			check_alert(j->tstate, r);
		    } else {
			j->response_written += r;
/* check if we have written a complete response */
			if (j->response_written == j->response_length) {
				if (http!=0) j->http_state = HTTP_STATE_CLOSING;
				else {
					j->http_state = HTTP_STATE_REQUEST;
					free( j->http_response);
					j->response_length = 0;
					j->request_length = 0;
					j->http_request[0] = 0;
				}
			}
		    }
		}
	    }
	}
	lloopend (listener_list, j);

/* loop through all connections, closing those that are in error */
	lloopstart (listener_list, j) {
	    if (j->http_state == HTTP_STATE_CLOSING) {
		ldeleteinc (listener_list, j);
	    }
	}
	lloopend (listener_list, j);
    }


   gnutls_certificate_free_cred(cert_cred);
   gnutls_srp_free_server_cred(srp_cred);
   gnutls_anon_free_server_cred(dh_cred);

#ifdef HAVE_LIBGDBM
   if (nodb==0) wrap_gdbm_deinit();
#endif
   gnutls_global_deinit();

   return 0;

}

#define DEFAULT_X509_KEYFILE "x509/key.pem"
#define DEFAULT_X509_CERTFILE "x509/cert.pem"

#define DEFAULT_X509_KEYFILE2 "x509/key-dsa.pem"
#define DEFAULT_X509_CERTFILE2 "x509/cert-dsa.pem"

#define DEFAULT_PGP_KEYFILE "openpgp/sec.asc"
#define DEFAULT_PGP_CERTFILE "openpgp/pub.asc"

#define DEFAULT_X509_CAFILE "x509/ca.pem"
#define DEFAULT_X509_CRLFILE NULL;

#define DEFAULT_SRP_PASSWD "srp/tpasswd"
#define DEFAULT_SRP_PASSWD_CONF "srp/tpasswd.conf"

#undef DEBUG

static gaainfo info;
void gaa_parser(int argc, char **argv)
{
   int i, j;

   if (gaa(argc, argv, &info) != -1) {
      fprintf(stderr,
	      "Error in the arguments. Use the --help or -h parameters to get more information.\n");
      exit(1);
   }
 
   quiet = info.quiet;
   nodb = info.nodb;

   if (info.http == 0)
      http = 0;
   else
      http = 1;

   if (info.fmtder == 0)
      x509ctype = GNUTLS_X509_FMT_PEM;
   else
      x509ctype = GNUTLS_X509_FMT_DER;

   if (info.generate == 0)
      generate = 0;
   else
      generate = 1;

   port = info.port;

#ifdef DEBUG
   if (info.x509_certfile != NULL)
      x509_certfile = info.x509_certfile;
   else
      x509_certfile = DEFAULT_X509_CERTFILE;

   if (info.x509_keyfile != NULL)
      x509_keyfile = info.x509_keyfile;
   else
      x509_keyfile = DEFAULT_X509_KEYFILE;

   if (info.x509_cafile != NULL)
      x509_cafile = info.x509_certfile;
   else
      x509_cafile = DEFAULT_X509_CAFILE;

   if (info.pgp_certfile != NULL)
      pgp_certfile = info.pgp_certfile;
   else
      pgp_certfile = DEFAULT_PGP_CERTFILE;

   if (info.pgp_keyfile != NULL)
      pgp_keyfile = info.pgp_keyfile;
   else
      pgp_keyfile = DEFAULT_PGP_KEYFILE;

   if (info.srp_passwd != NULL)
      srp_passwd = info.srp_passwd;
   else
      srp_passwd = DEFAULT_SRP_PASSWD;

   if (info.srp_passwd_conf != NULL)
      srp_passwd_conf = info.srp_passwd_conf;
   else
      srp_passwd_conf = DEFAULT_SRP_PASSWD_CONF;
#else
      x509_certfile = info.x509_certfile;
      x509_keyfile = info.x509_keyfile;
      x509_cafile = info.x509_cafile;
      pgp_certfile = info.pgp_certfile;
      pgp_keyfile = info.pgp_keyfile;
      srp_passwd = info.srp_passwd;
      srp_passwd_conf = info.srp_passwd_conf;
#endif

   pgp_keyserver = info.pgp_keyserver;
   pgp_keyring = info.pgp_keyring;
   pgp_trustdb = info.pgp_trustdb;

   if (info.proto != NULL && info.nproto > 0) {
      for (j = i = 0; i < info.nproto; i++) {
	 if (strncasecmp(info.proto[i], "SSL", 3) == 0)
	    protocol_priority[j++] = GNUTLS_SSL3;
	 if (strncasecmp(info.proto[i], "TLS", 3) == 0)
	    protocol_priority[j++] = GNUTLS_TLS1;
      }
      protocol_priority[j] = 0;
   }

   if (info.ciphers != NULL && info.nciphers > 0) {
      for (j = i = 0; i < info.nciphers; i++) {
	 if (strncasecmp(info.ciphers[i], "RIJ", 3) == 0)
	    cipher_priority[j++] = GNUTLS_CIPHER_RIJNDAEL_128_CBC;
	 if (strncasecmp(info.ciphers[i], "TWO", 3) == 0)
	    cipher_priority[j++] = GNUTLS_CIPHER_TWOFISH_128_CBC;
	 if (strncasecmp(info.ciphers[i], "3DE", 3) == 0)
	    cipher_priority[j++] = GNUTLS_CIPHER_3DES_CBC;
	 if (strncasecmp(info.ciphers[i], "ARC", 3) == 0)
	    cipher_priority[j++] = GNUTLS_CIPHER_ARCFOUR;
      }
      cipher_priority[j] = 0;
   }

   if (info.macs != NULL && info.nmacs > 0) {
      for (j = i = 0; i < info.nmacs; i++) {
	 if (strncasecmp(info.macs[i], "MD5", 3) == 0)
	    mac_priority[j++] = GNUTLS_MAC_MD5;
	 if (strncasecmp(info.macs[i], "SHA", 3) == 0)
	    mac_priority[j++] = GNUTLS_MAC_SHA;
      }
      mac_priority[j] = 0;
   }

   if (info.ctype != NULL && info.nctype > 0) {
      for (j = i = 0; i < info.nctype; i++) {
	 if (strncasecmp(info.ctype[i], "OPE", 3) == 0)
	    cert_type_priority[j++] = GNUTLS_CRT_OPENPGP;
	 if (strncasecmp(info.ctype[i], "X", 1) == 0)
	    cert_type_priority[j++] = GNUTLS_CRT_X509;
      }
      cert_type_priority[j] = 0;
   }

   if (info.kx != NULL && info.nkx > 0) {
      for (j = i = 0; i < info.nkx; i++) {
	 if (strncasecmp(info.kx[i], "SRP", 3) == 0)
	    kx_priority[j++] = GNUTLS_KX_SRP;
	 if (strncasecmp(info.kx[i], "RSA", 3) == 0)
	    kx_priority[j++] = GNUTLS_KX_RSA;
	 if (strncasecmp(info.kx[i], "DHE_RSA", 7) == 0)
	    kx_priority[j++] = GNUTLS_KX_DHE_RSA;
	 if (strncasecmp(info.kx[i], "DHE_DSS", 7) == 0)
	    kx_priority[j++] = GNUTLS_KX_DHE_DSS;
	 if (strncasecmp(info.kx[i], "ANON", 4) == 0)
	    kx_priority[j++] = GNUTLS_KX_ANON_DH;
      }
      kx_priority[j] = 0;
   }

   if (info.comp != NULL && info.ncomp > 0) {
      for (j = i = 0; i < info.ncomp; i++) {
	 if (strncasecmp(info.comp[i], "NUL", 3) == 0)
	    comp_priority[j++] = GNUTLS_COMP_NULL;
	 if (strncasecmp(info.comp[i], "ZLI", 1) == 0)
	    comp_priority[j++] = GNUTLS_COMP_ZLIB;
      }
      comp_priority[j] = 0;
   }
}

void serv_version(void) {
	fprintf(stderr, "GNU TLS test server, ");
	fprintf(stderr, "version %s.\n", LIBGNUTLS_VERSION);
}

#ifdef HAVE_LIBGDBM

static void wrap_gdbm_init(void) {
	GDBM_FILE tmpdbf;

	/* create db */
	tmpdbf = gdbm_open(DB_FILE, 0, GDBM_NEWDB, 0600, NULL);
	if (tmpdbf==NULL) {
		fprintf(stderr, "Error opening gdbm database\n");
		exit(1);
	}
	gdbm_close( tmpdbf);
}

static void wrap_gdbm_deinit(void) {
	return;
}

static int wrap_gdbm_store( void* dbf, gnutls_datum key, gnutls_datum data) {
	datum _key, _data;
	int res;
	GDBM_FILE write_dbf;

	write_dbf = gdbm_open(DB_FILE, 0, GDBM_WRITER, 0600, NULL);
	if (write_dbf==NULL) {
		fprintf(stderr, "Error opening gdbm database\n");
		exit(1);
	}
	
	_key.dptr = key.data;
	_key.dsize = key.size;

	_data.dptr = data.data;
	_data.dsize = data.size;

	res = gdbm_store( write_dbf, _key, _data, GDBM_INSERT);

	gdbm_close( write_dbf);
	return res;
}

static gnutls_datum wrap_gdbm_fetch( void* dbf, gnutls_datum key) {
	datum _key, _res;
	gnutls_datum res2;
	GDBM_FILE read_dbf;

	_key.dptr = key.data;
	_key.dsize = key.size;

	read_dbf = gdbm_open(DB_FILE, 0, GDBM_READER, 0600, NULL);
	if (read_dbf==NULL) {
		fprintf(stderr, "Error opening gdbm database\n");
		exit(1);
	}

	_res = gdbm_fetch( read_dbf, _key);

	gdbm_close( read_dbf);
	
	res2.data = _res.dptr;
	res2.size = _res.dsize;

	return res2;
}

static int wrap_gdbm_delete( void* dbf, gnutls_datum key) {
	datum _key;
	int res;
	GDBM_FILE write_dbf;

	write_dbf = gdbm_open(DB_FILE, 0, GDBM_WRITER, 0600, NULL);
	if (write_dbf==NULL) {
		fprintf(stderr, "Error opening gdbm database\n");
		exit(1);
	}
	
	_key.dptr = key.data;
	_key.dsize = key.size;

	res = gdbm_delete( write_dbf, _key);
	gdbm_close( write_dbf);

	return res;
}

#endif /* HAVE LIBGDBM */
