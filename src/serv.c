/*
 * Copyright (C) 2001,2002 Paul Sheer
 * Portions Copyright (C) 2002,2003 Nikos Mavroyanopoulos
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

#ifdef HAVE_LIBOPENCDK
#include <opencdk.h>

static int
recv_openpgp_key(gnutls_session session, const unsigned char *keyfpr,
		 unsigned int keyfpr_length, gnutls_datum * key);
#endif


/* konqueror cannot handle sending the page in multiple
 * pieces.
 */
/* global stuff */
static int generate = 0;
static int http = 0;
static int port = 0;
static int x509ctype;
static int debug;

static int quiet;
static int nodb;

char *srp_passwd;
char *srp_passwd_conf;
char *pgp_keyring;
char *pgp_trustdb;
char *pgp_keyfile;
char *pgp_certfile;
char *x509_keyfile;
char *x509_certfile;
char *x509_cafile;
char *dh_params_file;
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
		"GNUTLS</a></H1></CENTER>\n\n"

#define RENEGOTIATE

/* These are global */
gnutls_srp_server_credentials srp_cred;
gnutls_anon_server_credentials dh_cred;
gnutls_certificate_credentials cert_cred;

const int ssl_session_cache = 40;

static void wrap_db_init(void);
static void wrap_db_deinit(void);
static int wrap_db_store(void *dbf, gnutls_datum key, gnutls_datum data);
static gnutls_datum wrap_db_fetch(void *dbf, gnutls_datum key);
static int wrap_db_delete(void *dbf, gnutls_datum key);


#define HTTP_STATE_REQUEST	1
#define HTTP_STATE_RESPONSE	2
#define HTTP_STATE_CLOSING	3

LIST_TYPE_DECLARE(listener_item, char *http_request;
		  char *http_response; int request_length;
		  int response_length;
		  int response_written;
		  int http_state;
		  int fd; gnutls_session tls_session; int handshake_ok;);

static void listener_free(listener_item * j)
{
   if (j->http_request)
      free(j->http_request);
   if (j->http_response)
      free(j->http_response);
   if (j->fd >= 0) {
      gnutls_bye(j->tls_session, GNUTLS_SHUT_WR);
      shutdown(j->fd, 2);
      close(j->fd);
      gnutls_deinit(j->tls_session);
   }
}


/* we use primes up to 1024 in this server.
 * otherwise we should add them here.
 */

gnutls_dh_params dh_params;
gnutls_rsa_params rsa_params;

static int generate_dh_primes(void)
{
   int prime_bits = 768;

   if (gnutls_dh_params_init(&dh_params) < 0) {
      fprintf(stderr, "Error in dh parameter initialization\n");
      exit(1);
   }

      /* Generate Diffie Hellman parameters - for use with DHE
       * kx algorithms. These should be discarded and regenerated
       * once a day, once a week or once a month. Depends on the
       * security requirements.
       */
      printf
	  ("Generating Diffie Hellman parameters [%d]. Please wait...\n",
	   prime_bits);
      fflush(stdout);

      if (gnutls_dh_params_generate2( dh_params, prime_bits) < 0) {
	 fprintf(stderr, "Error in prime generation\n");
	 exit(1);
      }

   return 0;
}

static void read_dh_params(void)
{
   char tmpdata[2048];
   int size;
   gnutls_datum params;
   FILE* fd;
   
   if (gnutls_dh_params_init(&dh_params) < 0) {
      fprintf(stderr, "Error in dh parameter initialization\n");
      exit(1);
   }

   /* read the params file
    */
   fd = fopen(dh_params_file, "r");
   if (fd==NULL) {
   	fprintf(stderr, "Could not open %s\n", dh_params_file);
   	exit(1);
   }

   size = fread( tmpdata, 1, sizeof(tmpdata)-1, fd);
   tmpdata[size] = 0;
   fclose(fd);

   params.data = tmpdata;
   params.size = size;

   size = gnutls_dh_params_import_pkcs3( dh_params, &params, GNUTLS_X509_FMT_PEM);

   if (size < 0) {
   	fprintf(stderr, "Error parsing dh params: %s\n", gnutls_strerror(size));
   	exit(1);
   }

   printf("Read Diffie Hellman parameters.\n");
   fflush(stdout);
   
}

static int generate_rsa_params(void)
{
   if (gnutls_rsa_params_init(&rsa_params) < 0) {
      fprintf(stderr, "Error in rsa parameter initialization\n");
      exit(1);
   }

   /* Generate RSA parameters - for use with RSA-export
    * cipher suites. These should be discarded and regenerated
    * once a day, once every 500 transactions etc. Depends on the
    * security requirements.
    */
   printf("Generating temporary RSA parameters. Please wait...\n");
   fflush(stdout);

   if (gnutls_rsa_params_generate2( rsa_params, 512) < 0) {
      fprintf(stderr, "Error in rsa parameter generation\n");
      exit(1);
   }

   return 0;
}

int protocol_priority[16] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
int kx_priority[16] =
    { GNUTLS_KX_DHE_DSS, GNUTLS_KX_RSA, GNUTLS_KX_DHE_RSA, GNUTLS_KX_SRP,
   /* Do not use anonymous authentication, unless you know what that means */
   GNUTLS_KX_ANON_DH, GNUTLS_KX_RSA_EXPORT, 0
};
int cipher_priority[16] =
    { GNUTLS_CIPHER_RIJNDAEL_128_CBC, GNUTLS_CIPHER_3DES_CBC,
   GNUTLS_CIPHER_ARCFOUR_128, GNUTLS_CIPHER_ARCFOUR_40, 0
};

int comp_priority[16] =
    { GNUTLS_COMP_ZLIB, GNUTLS_COMP_LZO, GNUTLS_COMP_NULL, 0 };
int mac_priority[16] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
int cert_type_priority[16] = { GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0 };

LIST_DECLARE_INIT(listener_list, listener_item, listener_free);

gnutls_session initialize_session(void)
{
   gnutls_session session;

   gnutls_init(&session, GNUTLS_SERVER);

   /* allow the use of private ciphersuites.
    */
   gnutls_handshake_set_private_extensions(session, 1);

#if HAVE_LIBOPENCDK
   gnutls_openpgp_set_recv_key_function(session, recv_openpgp_key);
#endif

   if (nodb == 0) {
      gnutls_db_set_retrieve_function(session, wrap_db_fetch);
      gnutls_db_set_remove_function(session, wrap_db_delete);
      gnutls_db_set_store_function(session, wrap_db_store);
      gnutls_db_set_ptr(session, NULL);
   }

/*   gnutls_dh_set_prime_bits( session, prime_bits); */
   gnutls_cipher_set_priority(session, cipher_priority);
   gnutls_compression_set_priority(session, comp_priority);
   gnutls_kx_set_priority(session, kx_priority);
   gnutls_protocol_set_priority(session, protocol_priority);
   gnutls_mac_set_priority(session, mac_priority);
   gnutls_certificate_type_set_priority(session, cert_type_priority);

   gnutls_credentials_set(session, GNUTLS_CRD_ANON, dh_cred);
   gnutls_credentials_set(session, GNUTLS_CRD_SRP, srp_cred);
   gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cert_cred);

   gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

   return session;
}

static char DEFAULT_DATA[] = "This is the default message reported "
    "by GnuTLS TLS version 1.0 implementation. For more information "
    "please visit http://www.gnutls.org or even http://www.gnu.org/software/gnutls.";

/* Creates html with the current session information.
 */
#define tmp2 &http_buffer[strlen(http_buffer)]
char *peer_print_info(gnutls_session session, int *ret_length,
		      const char *header)
{
   const char *tmp;
   unsigned char sesid[32];
   int sesid_size, i;
   char *http_buffer = malloc(5 * 1024 + strlen(header));

   if (http_buffer == NULL)
      return NULL;
   if (quiet != 0) {

      strcpy(http_buffer, HTTP_BEGIN);
      strcpy(&http_buffer[sizeof(HTTP_BEGIN) - 1], DEFAULT_DATA);
      strcpy(&http_buffer[sizeof(HTTP_BEGIN) + sizeof(DEFAULT_DATA) - 2],
	     HTTP_END);
      *ret_length =
	  sizeof(DEFAULT_DATA) + sizeof(HTTP_BEGIN) + sizeof(HTTP_END) - 3;
      return http_buffer;

   }

   strcpy(http_buffer, HTTP_BEGIN);

   /* print session_id */
   gnutls_session_get_id(session, sesid, &sesid_size);
   sprintf(tmp2, "\n<p>Session ID: <i>");
   for (i = 0; i < sesid_size; i++)
      sprintf(tmp2, "%.2X", sesid[i]);
   sprintf(tmp2, "</i></p>\n");
   sprintf(tmp2,
	   "<h5>If your browser supports session resuming, then you should see the "
	   "same session ID, when you press the <b>reload</b> button.</h5>\n");

   /* Here unlike print_info() we use the kx algorithm to distinguish
    * the functions to call.
    */
   {
      char dns[256];
      int dns_size = sizeof(dns);
      int type;

      if (gnutls_server_name_get(session, dns, &dns_size, &type, 0) == 0) {
	 sprintf(tmp2, "\n<p>Server Name: %s</p>\n", dns);
      }

   }

   /* print srp specific data */
#ifdef ENABLE_SRP
   if (gnutls_kx_get(session) == GNUTLS_KX_SRP) {
      sprintf(tmp2, "<p>Connected as user '%s'.</p>\n",
	      gnutls_srp_server_get_username(session));
   }
#endif

#ifdef ENABLE_ANON
   if (gnutls_kx_get(session) == GNUTLS_KX_ANON_DH) {
      sprintf(tmp2,
	      "<p> Connect using anonymous DH (prime of %d bits)</p>\n",
	      gnutls_dh_get_prime_bits(session));
   }
#endif

   if (gnutls_kx_get(session) == GNUTLS_KX_DHE_RSA
       || gnutls_kx_get(session) == GNUTLS_KX_DHE_DSS) {
      sprintf(tmp2,
	      "Ephemeral DH using prime of <b>%d</b> bits.<br>\n",
	      gnutls_dh_get_prime_bits(session));
   }

   /* print session information */
   strcat(http_buffer, "<P>\n");

   tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
   sprintf(tmp2,
	   "<TABLE border=1><TR><TD>Protocol version:</TD><TD>%s</TD></TR>\n",
	   tmp);

   if (gnutls_auth_get_type(session) == GNUTLS_CRD_CERTIFICATE) {
      tmp =
	  gnutls_certificate_type_get_name(gnutls_certificate_type_get
					   (session));
      sprintf(tmp2, "<TR><TD>Certificate Type:</TD><TD>%s</TD></TR>\n",
	      tmp);
   }

   tmp = gnutls_kx_get_name(gnutls_kx_get(session));
   sprintf(tmp2, "<TR><TD>Key Exchange:</TD><TD>%s</TD></TR>\n", tmp);

   tmp = gnutls_compression_get_name(gnutls_compression_get(session));
   sprintf(tmp2, "<TR><TD>Compression</TD><TD>%s</TD></TR>\n", tmp);

   tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
   sprintf(tmp2, "<TR><TD>Cipher</TD><TD>%s</TD></TR>\n", tmp);

   tmp = gnutls_mac_get_name(gnutls_mac_get(session));
   sprintf(tmp2, "<TR><TD>MAC</TD><TD>%s</TD></TR>\n", tmp);

   tmp = gnutls_cipher_suite_get_name(gnutls_kx_get(session),
				      gnutls_cipher_get(session),
				      gnutls_mac_get(session));
   sprintf(tmp2, "<TR><TD>Ciphersuite</TD><TD>%s</TD></TR></p></TABLE>\n",
	   tmp);

   strcat(http_buffer, "<hr><P>Your header was:<PRE>");
   strcat(http_buffer, header);
   strcat(http_buffer, "</PRE></P>");

   strcat(http_buffer, "</P>\n" HTTP_END);

   *ret_length = strlen(http_buffer);

   return http_buffer;
}

static int listen_socket(char *name, int listen_port)
{
   struct sockaddr_in a;
   int s;
   int yes;

   if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket() failed");
      return -1;
   }
   yes = 1;

   if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof(yes))
       < 0) {
      perror("setsockopt() failed");
      close(s);
      return -1;
   }
   memset(&a, 0, sizeof(a));
   a.sin_port = htons(listen_port);
   a.sin_family = AF_INET;
   if (bind(s, (struct sockaddr *) &a, sizeof(a)) < 0) {
      perror("bind() failed");
      close(s);
      return -1;
   }

   printf("%s ready. Listening to port '%d'.\n\n", name, listen_port);
   listen(s, 10);
   return s;
}

static void get_response(gnutls_session session, char *request,
			 char **response, int *response_length)
{
   char *p, *h;

   if (http != 0) {
      if (strncmp(request, "GET ", 4))
	 goto unimplemented;

      if (!(h = strchr(request, '\n')))
	 goto unimplemented;

      *h++ = '\0';
      while (*h == '\r' || *h == '\n')
	 h++;

      if (!(p = strchr(request + 4, ' ')))
	 goto unimplemented;
      *p = '\0';
   }
//    *response = peer_print_info(session, request+4, h, response_length);
   if (http != 0) {
      *response = peer_print_info(session, response_length, h);
   } else {
      *response = strdup(request);
      *response_length = strlen(*response);
   }

   return;

 unimplemented:
   *response = strdup(HTTP_UNIMPLEMENTED);
   *response_length = strlen(*response);
}

void terminate(int sig)
{
   fprintf(stderr, "Exiting via signal %d\n", sig);
   exit(0);
}


void check_alert(gnutls_session session, int ret)
{
   int last_alert;

   if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
       || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
      last_alert = gnutls_alert_get(session);
      if (last_alert == GNUTLS_A_NO_RENEGOTIATION &&
	  ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
	 printf
	     ("* Received NO_RENEGOTIATION alert. Client Does not support renegotiation.\n");
      else
	 printf("* Received alert '%d': %s.\n", last_alert,
		gnutls_alert_get_name(last_alert));
   }
}

static void tls_log_func( int level, const char* str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

static void gaa_parser(int argc, char **argv);

int main(int argc, char **argv)
{
   int ret, n, h;
   char topbuf[512];
//   int optval = 1;
   char name[256];
   int accept_fd;
   struct sockaddr_in client_address;

   signal(SIGPIPE, SIG_IGN);
   signal(SIGHUP, SIG_IGN);
   signal(SIGTERM, terminate);
   signal(SIGINT, terminate);

   gaa_parser(argc, argv);

   if (nodb == 0)
      wrap_db_init();

   if (http == 1) {
      strcpy(name, "HTTP Server");
   } else {
      strcpy(name, "Echo Server");
   }

   if (gnutls_global_init() < 0) {
      fprintf(stderr, "global state initialization error\n");
      exit(1);
   }
   gnutls_global_set_log_function( tls_log_func);
   gnutls_global_set_log_level(debug);

   if (gnutls_global_init_extra() < 0) {
      fprintf(stderr, "global state (extra) initialization error\n");
      exit(1);
   }

   /* Note that servers must generate parameters for
    * Diffie Hellman. See gnutls_dh_params_generate(), and
    * gnutls_dh_params_set().
    */
   if (generate != 0) {
      generate_rsa_params();
      generate_dh_primes();
   }
   
   if (dh_params_file) {
      read_dh_params();
   }

   if (gnutls_certificate_allocate_credentials(&cert_cred) < 0) {
      fprintf(stderr, "memory error\n");
      exit(1);
   }

   if (x509_cafile != NULL) {
      if ((ret = gnutls_certificate_set_x509_trust_file
	   (cert_cred, x509_cafile, x509ctype)) < 0) {
	 fprintf(stderr, "Error reading '%s'\n", x509_cafile);
	 fprintf(stderr, "Error: '%s'\n", gnutls_strerror(ret));
	 exit(1);
      } else {
	 printf("Processed %d CA certificate(s).\n", ret);
      }
   }

#ifdef ENABLE_PKI
   if (x509_crlfile != NULL) {
      if ((ret = gnutls_certificate_set_x509_crl_file
	   (cert_cred, x509_crlfile, x509ctype)) < 0) {
	 fprintf(stderr, "Error reading '%s'\n", x509_crlfile);
	 fprintf(stderr, "Error: '%s'\n", gnutls_strerror(ret));
	 exit(1);
      } else {
	 printf("Processed %d CRL(s).\n", ret);
      }
   }
#endif

   if (pgp_keyring != NULL) {
      ret =
	  gnutls_certificate_set_openpgp_keyring_file(cert_cred,
						      pgp_keyring);
      if (ret < 0) {
	 fprintf(stderr, "Error setting the OpenPGP keyring file\n");
	 fprintf(stderr, "Error: '%s'\n", gnutls_strerror(ret));
      }
   }

   if (pgp_trustdb != NULL) {
      ret = gnutls_certificate_set_openpgp_trustdb(cert_cred, pgp_trustdb);
      if (ret < 0) {
	 fprintf(stderr, "Error setting the OpenPGP trustdb file\n");
	 fprintf(stderr, "Error: '%s'\n", gnutls_strerror(ret));
      }
   }

   if (pgp_certfile != NULL)
      if ((ret = gnutls_certificate_set_openpgp_key_file
	   (cert_cred, pgp_certfile, pgp_keyfile)) < 0) {
	 fprintf(stderr,
		 "Error[%d] while reading the OpenPGP key pair ('%s', '%s')\n",
		 ret, pgp_certfile, pgp_keyfile);
	 fprintf(stderr, "Error: '%s'\n", gnutls_strerror(ret));
      }

   if (x509_certfile != NULL)
      if ((ret = gnutls_certificate_set_x509_key_file
	  (cert_cred, x509_certfile, x509_keyfile, x509ctype)) < 0) {
	 fprintf(stderr,
		 "Error reading '%s' or '%s'\n", x509_certfile,
		 x509_keyfile);
	 fprintf(stderr, "Error: '%s'\n", gnutls_strerror(ret));
	 exit(1);
      }

   if (generate != 0 || read_dh_params != NULL) {
      gnutls_certificate_set_dh_params(cert_cred, dh_params);
      gnutls_certificate_set_rsa_params(cert_cred, rsa_params);
   }

   /* this is a password file (created with the included srpcrypt utility) 
    * Read README.crypt prior to using SRP.
    */
#ifdef ENABLE_SRP
   gnutls_srp_allocate_server_credentials(&srp_cred);

   if (srp_passwd != NULL)
      if ((ret =
	   gnutls_srp_set_server_credentials_file(srp_cred, srp_passwd,
						  srp_passwd_conf)) < 0) {
	 /* only exit is this function is not disabled 
	  */
	 fprintf(stderr, "Error while setting SRP parameters\n");
	 fprintf(stderr, "Error: '%s'\n", gnutls_strerror(ret));
      }
#endif

#ifdef ENABLE_ANON
   gnutls_anon_allocate_server_credentials(&dh_cred);
   if (generate != 0)
      gnutls_anon_set_server_dh_params(dh_cred, dh_params);
#endif

   h = listen_socket(name, port);
   if (h < 0)
      exit(1);

   for (;;) {
      listener_item *j;
      fd_set rd, wr;
      int val;

      FD_ZERO(&rd);
      FD_ZERO(&wr);
      n = 0;

/* check for new incoming connections */
      FD_SET(h, &rd);
      n = max(n, h);

/* flag which connections we are reading or writing to within the fd sets */
      lloopstart(listener_list, j) {

	 val = fcntl(j->fd, F_GETFL, 0);
	 if (fcntl(j->fd, F_SETFL, val | O_NONBLOCK) < 0) {
	    perror("fcntl()");
	    exit(1);
	 }

	 if (j->http_state == HTTP_STATE_REQUEST) {
	    FD_SET(j->fd, &rd);
	    n = max(n, j->fd);
	 }
	 if (j->http_state == HTTP_STATE_RESPONSE) {
	    FD_SET(j->fd, &wr);
	    n = max(n, j->fd);
	 }
      }
      lloopend(listener_list, j);

/* core operation */
      n = select(n + 1, &rd, &wr, 0, 0);
      if (n == -1 && errno == EINTR)
	 continue;
      if (n < 0) {
	 perror("select()");
	 exit(1);
      }

/* a new connection has arrived */
      if (FD_ISSET(h, &rd)) {
	 unsigned int l;
	 gnutls_session tls_session;

	 tls_session = initialize_session();

	 memset(&client_address, 0, l = sizeof(client_address));
	 accept_fd = accept(h, (struct sockaddr *) &client_address, &l);

	 if (accept_fd < 0) {
	    perror("accept()");
	 } else {
	    time_t tt;
	    char *ctt;

/* new list entry for the connection */
	    lappend(listener_list);
	    j = listener_list.tail;
	    j->http_request = (char *) strdup("");
	    j->http_state = HTTP_STATE_REQUEST;
	    j->fd = accept_fd;

	    j->tls_session = tls_session;
	    gnutls_transport_set_ptr(tls_session, accept_fd);
	    j->handshake_ok = 0;

	    if (quiet == 0) {
	       tt = time(0);
	       ctt = ctime(&tt);
	       ctt[strlen(ctt) - 1] = 0;

/*
		        printf("\n* connection from %s, port %d\n",
			     inet_ntop(AF_INET, &client_address.sin_addr, topbuf,
			       sizeof(topbuf)), ntohs(client_address.sin_port));
      */

	    }
	 }
      }

/* read or write to each connection as indicated by select()'s return argument */
      lloopstart(listener_list, j) {
	 if (FD_ISSET(j->fd, &rd)) {
/* read partial GET request */
	    char buf[1024];
	    int r, ret;

	    if (j->handshake_ok == 0) {
	       r = gnutls_handshake(j->tls_session);
	       if (r < 0 && gnutls_error_is_fatal(r) == 0) {
		  check_alert(j->tls_session, r);
		  /* nothing */
	       } else if (r < 0 && gnutls_error_is_fatal(r) == 1) {
		  GERR(r, "handshake");

		  do {
		     ret =
			 gnutls_alert_send_appropriate(j->tls_session, r);
		  } while (ret == GNUTLS_E_AGAIN);
		  j->http_state = HTTP_STATE_CLOSING;
	       } else if (r == 0) {
		  if (gnutls_session_is_resumed(j->tls_session) != 0
		      && quiet == 0)
		     printf("*** This is a resumed session\n");

		  if (quiet == 0) {
		     printf("\n* connection from %s, port %d\n",
			    inet_ntop(AF_INET, &client_address.sin_addr,
				      topbuf, sizeof(topbuf)),
			    ntohs(client_address.sin_port));
		     print_info(j->tls_session);
		  }
		  j->handshake_ok = 1;
	       }
	    }

	    if (j->handshake_ok == 1) {
	       r = gnutls_record_recv(j->tls_session, buf,
				      min(1024, SMALL_READ_TEST));
	       if (r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN) {
		  /* do nothing */
	       } else if (r < 0 || r == 0) {
		  j->http_state = HTTP_STATE_CLOSING;
		  if (r < 0 && r != GNUTLS_E_UNEXPECTED_PACKET_LENGTH) {
		     check_alert(j->tls_session, r);
		     GERR(r, "recv");
		  }

	       } else {
		  j->http_request =
		      realloc(j->http_request, j->request_length + r + 1);
		  if (j->http_request != NULL) {
		     memcpy(j->http_request + j->request_length, buf, r);
		     j->request_length += r;
		     j->http_request[j->request_length] = '\0';
		  } else
		     j->http_state = HTTP_STATE_CLOSING;

	       }
/* check if we have a full HTTP header */

	       j->http_response = NULL;
	       if (j->http_request != NULL) {
		  if ((http == 0 && strchr(j->http_request, '\n'))
		      || strstr(j->http_request, "\r\n\r\n")
		      || strstr(j->http_request, "\n\n")) {
		     get_response(j->tls_session, j->http_request,
				  &j->http_response, &j->response_length);
		     j->http_state = HTTP_STATE_RESPONSE;
		     j->response_written = 0;
		  }
	       }
	    }
	 }
	 if (FD_ISSET(j->fd, &wr)) {
/* write partial response request */
	    int r;

	    if (j->handshake_ok == 0) {
	       r = gnutls_handshake(j->tls_session);
	       if (r < 0 && gnutls_error_is_fatal(r) == 0) {
		  check_alert(j->tls_session, r);
		  /* nothing */
	       } else if (r < 0 && gnutls_error_is_fatal(r) == 1) {
		  int ret;

		  j->http_state = HTTP_STATE_CLOSING;
		  GERR(r, "handshake");

		  do {
		     ret =
			 gnutls_alert_send_appropriate(j->tls_session, r);
		  } while (ret == GNUTLS_E_AGAIN);
	       } else if (r == 0) {
		  if (gnutls_session_is_resumed(j->tls_session) != 0
		      && quiet == 0)
		     printf("*** This is a resumed session\n");
		  if (quiet == 0) {
		     printf("- connection from %s, port %d\n",
			    inet_ntop(AF_INET, &client_address.sin_addr,
				      topbuf, sizeof(topbuf)),
			    ntohs(client_address.sin_port));
		     print_info(j->tls_session);
		  }
		  j->handshake_ok = 1;
	       }
	    }

	    if (j->handshake_ok == 1) {
	       r = gnutls_record_send(j->tls_session,
				      j->http_response +
				      j->response_written,
				      min(j->response_length -
					  j->response_written,
					  SMALL_READ_TEST));
	       if (r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN) {
		  /* do nothing */
	       } else if (r < 0 || r == 0) {
		  if (http != 0)
		     j->http_state = HTTP_STATE_CLOSING;
		  else {
		     j->http_state = HTTP_STATE_REQUEST;
		     free(j->http_response);
		     j->response_length = 0;
		     j->request_length = 0;
		     j->http_request[0] = 0;
		  }

		  if (r < 0)
		     GERR(r, "send");
		  check_alert(j->tls_session, r);
	       } else {
		  j->response_written += r;
/* check if we have written a complete response */
		  if (j->response_written == j->response_length) {
		     if (http != 0)
			j->http_state = HTTP_STATE_CLOSING;
		     else {
			j->http_state = HTTP_STATE_REQUEST;
			free(j->http_response);
			j->response_length = 0;
			j->request_length = 0;
			j->http_request[0] = 0;
		     }
		  }
	       }
	    }
	 }
      }
      lloopend(listener_list, j);

/* loop through all connections, closing those that are in error */
      lloopstart(listener_list, j) {
	 if (j->http_state == HTTP_STATE_CLOSING) {
	    ldeleteinc(listener_list, j);
	 }
      }
      lloopend(listener_list, j);
   }


   gnutls_certificate_free_credentials(cert_cred);

#ifdef ENABLE_SRP
   gnutls_srp_free_server_credentials(srp_cred);
#endif

#ifdef ENABLE_ANON
   gnutls_anon_free_server_credentials(dh_cred);
#endif

   if (nodb == 0)
      wrap_db_deinit();
   gnutls_global_deinit();

   return 0;

}

static gaainfo info;
void gaa_parser(int argc, char **argv)
{
   if (gaa(argc, argv, &info) != -1) {
      fprintf(stderr,
	      "Error in the arguments. Use the --help or -h parameters to get more information.\n");
      exit(1);
   }

   debug = info.debug;
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
   
   dh_params_file = info.dh_params_file;

   port = info.port;

   x509_certfile = info.x509_certfile;
   x509_keyfile = info.x509_keyfile;
   x509_cafile = info.x509_cafile;
   x509_crlfile = info.x509_crlfile;
   pgp_certfile = info.pgp_certfile;
   pgp_keyfile = info.pgp_keyfile;
   srp_passwd = info.srp_passwd;
   srp_passwd_conf = info.srp_passwd_conf;

   pgp_keyring = info.pgp_keyring;
   pgp_trustdb = info.pgp_trustdb;

   parse_protocols(info.proto, info.nproto, protocol_priority);
   parse_ciphers(info.ciphers, info.nciphers, cipher_priority);
   parse_macs(info.macs, info.nmacs, mac_priority);
   parse_ctypes(info.ctype, info.nctype, cert_type_priority);
   parse_kx(info.kx, info.nkx, kx_priority);
   parse_comp(info.comp, info.ncomp, comp_priority);
}

void serv_version(void)
{
   fprintf(stderr, "GNU TLS test server, ");
   fprintf(stderr, "version %s. Libgnutls %s.\n", LIBGNUTLS_VERSION, gnutls_check_version(NULL));
}

/* session resuming support */

#define SESSION_ID_SIZE 32
#define SESSION_DATA_SIZE 1024

typedef struct {
   char session_id[SESSION_ID_SIZE];
   int session_id_size;

   char session_data[SESSION_DATA_SIZE];
   int session_data_size;
} CACHE;

static CACHE *cache_db;
int cache_db_ptr = 0;

static void wrap_db_init(void)
{

   /* allocate cache_db */
   cache_db = calloc(1, ssl_session_cache * sizeof(CACHE));
}

static void wrap_db_deinit(void)
{
   return;
}

static int wrap_db_store(void *dbf, gnutls_datum key, gnutls_datum data)
{

   if (cache_db == NULL)
      return -1;

   if (key.size > SESSION_ID_SIZE)
      return -1;
   if (data.size > SESSION_DATA_SIZE)
      return -1;

   memcpy(cache_db[cache_db_ptr].session_id, key.data, key.size);
   cache_db[cache_db_ptr].session_id_size = key.size;

   memcpy(cache_db[cache_db_ptr].session_data, data.data, data.size);
   cache_db[cache_db_ptr].session_data_size = data.size;

   cache_db_ptr++;
   cache_db_ptr %= ssl_session_cache;

   return 0;
}

static gnutls_datum wrap_db_fetch(void *dbf, gnutls_datum key)
{
   gnutls_datum res = { NULL, 0 };
   int i;

   if (cache_db == NULL)
      return res;

   for (i = 0; i < ssl_session_cache; i++) {
      if (key.size == cache_db[i].session_id_size &&
	  memcmp(key.data, cache_db[i].session_id, key.size) == 0) {


	 res.size = cache_db[i].session_data_size;

	 res.data = gnutls_malloc(res.size);
	 if (res.data == NULL)
	    return res;

	 memcpy(res.data, cache_db[i].session_data, res.size);

	 return res;
      }
   }
   return res;
}

static int wrap_db_delete(void *dbf, gnutls_datum key)
{
   int i;

   if (cache_db == NULL)
      return -1;

   for (i = 0; i < ssl_session_cache; i++) {
      if (key.size == (unsigned int)cache_db[i].session_id_size &&
	  memcmp(key.data, cache_db[i].session_id, key.size) == 0) {

	 cache_db[i].session_id_size = 0;
	 cache_db[i].session_data_size = 0;

	 return 0;
      }
   }

   return -1;

}

#ifdef HAVE_LIBOPENCDK

static int
recv_openpgp_key(gnutls_session session, const unsigned char *keyfpr,
		 unsigned int keyfpr_length, gnutls_datum * key)
{
   static const char *hostname = "hkp://wwwkeys.pgp.net";
   static const short port = 11371;
   int rc;
   CDK_KBNODE knode = NULL;
   unsigned int i;

   fprintf(stderr, "must recv: ");
   for (i = 0; i < keyfpr_length; i++) {
      fprintf(stderr, "%x", (unsigned char)keyfpr[i]);
   }
   fprintf(stderr, "\n");

   /* The key fingerprint should be 20 bytes
    * in v4 keys.
    */
   if (keyfpr_length != 20)
      return -1;

   rc = cdk_keyserver_recv_key(hostname, port, keyfpr,
			       CDK_DBSEARCH_FPR, &knode);

   if (!rc) {
      size_t len;

      cdk_kbnode_write_to_mem(knode, NULL, &len);

      key->data = gnutls_malloc(len);
      if (key->data == NULL) {
	 rc = -1;
	 goto finish;
      }

      key->size = len;
      cdk_kbnode_write_to_mem(knode, key->data, &len);

      rc = 0;			/* success */

   } else {
      rc = -1;
   }

 finish:

   cdk_kbnode_release(knode);
   return rc;

}

#endif
