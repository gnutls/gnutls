/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "../lib/gnutls.h"
#include "common.h"
#include <signal.h>
#include "serv-gaa.h"


/* konqueror cannot handle sending the page in multiple
 * pieces.
 */
/* global stuff */
static char http_buffer[16 * 1024];
static int generate = 0;
static int http = 0;
static int port = 0;

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


#define SA struct sockaddr
#define ERR(err,s) if(err==-1) {perror(s);return(1);}
#define MAX_BUF 1024

#define HTTP_BEGIN "HTTP/1.0 200 OK\n" \
		"Content-Type: text/html\n" \
		"\n" \
		"<HTML><BODY>\n" \
		"<CENTER><H1>This is <a href=\"http://www.gnu.org/software/gnutls\">" \
		"GNUTLS</a></H1>\n\n"

#define HTTP_END  "</BODY></HTML>\n\n"

#define RENEGOTIATE

/* These are global */
GNUTLS_SRP_SERVER_CREDENTIALS srp_cred;
GNUTLS_ANON_SERVER_CREDENTIALS dh_cred;
GNUTLS_CERTIFICATE_SERVER_CREDENTIALS cert_cred;


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
   GNUTLS_KX_ANON_DH, 0
};
int cipher_priority[16] =
    { GNUTLS_CIPHER_RIJNDAEL_128_CBC, GNUTLS_CIPHER_3DES_CBC,
   GNUTLS_CIPHER_ARCFOUR, 0
};
int comp_priority[16] = { GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
int mac_priority[16] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
int cert_type_priority[16] = { GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0 };

GNUTLS_STATE initialize_state(void)
{
   GNUTLS_STATE state;
   int ret;

   gnutls_init(&state, GNUTLS_SERVER);
   if ((ret = gnutls_db_set_name(state, "gnutls-rsm.db")) < 0)
      fprintf(stderr,
	      "*** DB error (%d). Resuming will not be possible.\n\n",
	      ret);

   /* null cipher is here only for debuging 
    * purposes.
    */
   gnutls_cipher_set_priority(state, cipher_priority);
   gnutls_compression_set_priority(state, comp_priority);
   gnutls_kx_set_priority(state, kx_priority);
   gnutls_protocol_set_priority(state, protocol_priority);
   gnutls_mac_set_priority(state, mac_priority);
   gnutls_cert_type_set_priority(state, cert_type_priority);

   gnutls_dh_set_prime_bits(state, DEFAULT_PRIME_BITS);

   gnutls_cred_set(state, GNUTLS_CRD_ANON, dh_cred);
   gnutls_cred_set(state, GNUTLS_CRD_SRP, srp_cred);
   gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, cert_cred);

   gnutls_mac_set_priority(state, mac_priority);

   gnutls_certificate_server_set_request(state, GNUTLS_CERT_REQUEST);

   return state;
}

/* Creates html with the current state information.
 */
#define tmp2 &http_buffer[strlen(http_buffer)]
void peer_print_info(GNUTLS_STATE state)
{
   const char *tmp;
   unsigned char sesid[32];
   int sesid_size, i;

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

   strcat(http_buffer, "</P>\n");

   return;
}

/* actually something like readline.
 * if rnl!=1 then reads an http request in the form REQ\n\n
 */
int read_request(GNUTLS_STATE state, char *data, int data_size, int rnl)
{
   int n, rc, nl = 0;
   char c, *ptr, p1 = 0, p2 = 0;

   ptr = data;
   for (n = 1; n < data_size; n++) {
      do {
	 rc = gnutls_record_recv(state, &c, 1);
      } while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);

      if (rc == 1) {
	 *ptr++ = c;
	 if (c == '\n' && rnl == 1)
	    break;

	 if (c == '\n' && p1 == '\r' && p2 == '\n') {
	    nl++;
	    if (nl == 1)
	       break;
	 }
	 p2 = p1;
	 p1 = c;

      } else if (rc == 0) {
	 if (n == 1)
	    return 0;
	 else
	    break;
      } else {
	 return rc;
      }
   }

   *ptr = 0;
   return n;
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
   int err, listen_sd, i;
   int sd, ret;
   struct sockaddr_in sa_serv;
   struct sockaddr_in sa_cli;
   int client_len;
   char topbuf[512];
   GNUTLS_STATE state;
   char buffer[MAX_BUF + 1];
   int optval = 1;
   char name[256];

   signal(SIGPIPE, SIG_IGN);

   gaa_parser(argc, argv);

   if (http == 1) {
      strcpy(name, "HTTP Server");
   } else {
      strcpy(name, "Echo Server");
   }

   if (gnutls_global_init() < 0) {
      fprintf(stderr, "global state initialization error\n");
      exit(1);
   }

   /* Note that servers must generate parameters for
    * Diffie Hellman. See gnutls_dh_params_generate(), and
    * gnutls_dh_params_set().
    */
   if (generate != 0)
      generate_dh_primes();

   if (gnutls_certificate_allocate_sc(&cert_cred) < 0) {
      fprintf(stderr, "memory error\n");
      exit(1);
   }

   if (x509_cafile != NULL)
      if (gnutls_certificate_set_x509_trust_file
	  (cert_cred, x509_cafile, x509_crlfile) < 0) {
	 fprintf(stderr, "Error reading '%s'\n", x509_cafile);
	 exit(1);
      }

   if (pgp_keyring != NULL) {
      ret =
	  gnutls_certificate_set_openpgp_keyring_file(cert_cred, pgp_keyring);
      if (ret < 0) {
	 fprintf(stderr, "Error setting the OpenPGP keyring file\n");
      }
   }

   if (pgp_trustdb != NULL) {
      gnutls_certificate_set_openpgp_trustdb(cert_cred, pgp_trustdb);
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
	  (cert_cred, x509_certfile, x509_keyfile) < 0) {
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
   gnutls_srp_allocate_server_sc(&srp_cred);
   gnutls_srp_set_server_cred_file(srp_cred, srp_passwd, srp_passwd_conf);

   gnutls_anon_allocate_server_sc(&dh_cred);
   if (generate != 0)
      gnutls_anon_set_server_dh_params(dh_cred, dh_params);

   listen_sd = socket(AF_INET, SOCK_STREAM, 0);
   ERR(listen_sd, "socket");

   memset(&sa_serv, '\0', sizeof(sa_serv));
   sa_serv.sin_family = AF_INET;
   sa_serv.sin_addr.s_addr = INADDR_ANY;
   sa_serv.sin_port = htons(port);	/* Server Port number */

   setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
   err = bind(listen_sd, (SA *) & sa_serv, sizeof(sa_serv));
   ERR(err, "bind");
   err = listen(listen_sd, 1024);
   ERR(err, "listen");

   printf("%s ready. Listening to port '%d'.\n\n", name, port);

   client_len = sizeof(sa_cli);

   for (;;) {
      state = initialize_state();

      sd = accept(listen_sd, (SA *) & sa_cli, &client_len);

      printf("- connection from %s, port %d\n",
	     inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
		       sizeof(topbuf)), ntohs(sa_cli.sin_port));


      gnutls_transport_set_ptr(state, sd);
      do {
	 ret = gnutls_handshake(state);
      } while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

      if (ret < 0) {
	 close(sd);
	 gnutls_deinit(state);
	 fprintf(stderr,
		 "*** Handshake has failed (%s)\n\n",
		 gnutls_strerror(ret));
	 check_alert(state, ret);
	 continue;
      }
      printf("- Handshake was completed\n");

      print_info(state);

      i = 0;
      for (;;) {
	 bzero(buffer, MAX_BUF + 1);
	 ret = read_request(state, buffer, MAX_BUF, (http == 0) ? 1 : 2);

	 if (gnutls_error_is_fatal(ret) == 1 || ret == 0) {
	    fflush(stdout);
	    if (ret == 0) {
	       printf("\n- Peer has closed the GNUTLS connection\n");
	       fflush(stdout);
	       break;
	    } else {
	       fprintf(stderr,
		       "\n*** Received corrupted data(%d). Closing the connection.\n\n",
		       ret);
	       break;
	    }

	 }

	 if (ret > 0) {
	    if (http == 0) {
	       printf("* Read %d bytes from client.\n", strlen(buffer));
	       do {
		  ret = gnutls_record_send(state, buffer, strlen(buffer));
	       } while (ret ==
			GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
	       printf("* Wrote %d bytes to client.\n", ret);
	    } else {
	       strcpy(http_buffer, HTTP_BEGIN);
	       peer_print_info(state);
	       strcat(http_buffer, HTTP_END);
	       do {
		  ret =
		      gnutls_record_send(state,
					 http_buffer, strlen(http_buffer));
	       } while (ret ==
			GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

	       printf("- Served request. Closing connection.\n");
	       break;
	    }
	 }
	 i++;
#ifdef RENEGOTIATE
	 if (i == 20) {
	    do {
	       ret = gnutls_rehandshake(state);
	    } while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

	    printf("* Requesting rehandshake.\n");
	    /* continue handshake proccess */
	    do {
	       ret = gnutls_handshake(state);
	    } while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
	    printf("* Rehandshake returned %d\n", ret);
	 }
#endif

	 check_alert(state, ret);

	 if (http != 0) {
	    break;		/* close the connection */
	 }
      }
      printf("\n");
      do {
	 ret = gnutls_bye(state, GNUTLS_SHUT_WR);
      } while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
      /* do not wait for
       * the peer to close the connection.
       */
      close(sd);
      gnutls_deinit(state);

   }
   close(listen_sd);

   gnutls_certificate_free_sc(cert_cred);
   gnutls_srp_free_server_sc(srp_cred);
   gnutls_anon_free_server_sc(dh_cred);

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

static gaainfo info;
void gaa_parser(int argc, char **argv)
{
   int i, j;

   if (gaa(argc, argv, &info) != -1) {
      fprintf(stderr,
	      "Error in the arguments. Use the --help or -h parameters to get more information.\n");
      exit(1);
   }

   if (info.http == 0)
      http = 0;
   else
      http = 1;

   if (info.generate == 0)
      generate = 0;
   else
      generate = 1;

   port = info.port;

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

   pgp_keyserver = info.pgp_keyserver;

   if (info.srp_passwd != NULL)
      srp_passwd = info.srp_passwd;
   else
      srp_passwd = DEFAULT_SRP_PASSWD;

   if (info.srp_passwd_conf != NULL)
      srp_passwd_conf = info.srp_passwd_conf;
   else
      srp_passwd_conf = DEFAULT_SRP_PASSWD_CONF;

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
