/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Tests for the xssl interface */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)

int main()
{
  exit(77);
}

#else

#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/xssl.h>
#include <signal.h>

#include "utils.h"

#define TOFU_DB_FILE "tofu.tmp.db"

static void terminate(void);

/* This program tests the robustness of record
 * decoding.
 */

static time_t mytime (time_t * t)
{
  time_t then = 1359304177;

  if (t)
    *t = then;

  return then;
}


static void
server_log_func (int level, const char *str)
{
//  fprintf (stderr, "server|<%d>| %s", level, str);
}

static void
client_log_func (int level, const char *str)
{
  fprintf (stderr, "client|<%d>| %s", level, str);
}

static unsigned char ca_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDUDCCAgigAwIBAgIBADANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDEw5HbnVU\n"
  "TFMgVGVzdCBDQTAeFw0xMTA1MjgwODM2MzBaFw0zODEwMTIwODM2MzNaMBkxFzAV\n"
  "BgNVBAMTDkdudVRMUyBUZXN0IENBMIIBUjANBgkqhkiG9w0BAQEFAAOCAT8AMIIB\n"
  "OgKCATEAnORCsX1unl//fy2d1054XduIg/3CqVBaT3Hca65SEoDwh0KiPtQoOgZL\n"
  "dKY2cobGs/ojYtOjcs0KnlPYdmtjEh6WEhuJU95v4TQdC4OLMiE56eIGq252hZAb\n"
  "HoTL84Q14DxQWGuzQK830iml7fbw2WcIcRQ8vFGs8SzfXw63+MI6Fq6iMAQIqP08\n"
  "WzGmRRzL5wvCiPhCVkrPmwbXoABub6AAsYwWPJB91M9/lx5gFH5k9/iPfi3s2Kg3\n"
  "F8MOcppqFYjxDSnsfiz6eMh1+bYVIAo367vGVYHigXMEZC2FezlwIHaZzpEoFlY3\n"
  "a7LFJ00yrjQ910r8UE+CEMTYzE40D0olCMo7FA9RCjeO3bUIoYaIdVTUGWEGHWSe\n"
  "oxGei9Gkm6u+ASj8f+i0jxdD2qXsewIDAQABo0MwQTAPBgNVHRMBAf8EBTADAQH/\n"
  "MA8GA1UdDwEB/wQFAwMHBgAwHQYDVR0OBBYEFE1Wt2oAWPFnkvSmdVUbjlMBA+/P\n"
  "MA0GCSqGSIb3DQEBCwUAA4IBMQAesOgjGFi1zOYpA/N3gkUVRcBHDxmN7g2yOcqH\n"
  "VfhFc+e4zhOehR11WCt2RgzNlnYVmV5zBmQBdTAt8Po/MVhLCDW1BULHlLvL0DFc\n"
  "4sB1RlcGeQcCKQa4b+Q9VWf4f6TfuEWZQC5j5stiXjVgOqrOMrzKZ2eKWA4JsL9s\n"
  "V+7ANSZE+hOt1X1mA8moyqe95U2Ecih+nFJSWSBd1WFiEzVnXv4FVWPXbH9HERDK\n"
  "VbasjofWWmQO1YlQPishLgm1IbwqOkOk4sDgoLuUZ4GgP0DDeN6EmRDOzByrv+9u\n"
  "f45Bl9IQf4IJNPLU9lEqjyMOydqT6kBi7fjV5ICuQZ4EeVJsOGuX7PqNyoDzJHLv\n"
  "ferRfNLr6eQSHSxBhS0cVyDjb5gCawK6u7xTU+b7xikEie9k\n"
  "-----END CERTIFICATE-----\n";

const gnutls_datum_t ca_cert = { ca_pem,
  sizeof (ca_pem)-1
};

static unsigned char server_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIICsDCCAWigAwIBAgIETeC0kjANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDEw5H\n"
  "bnVUTFMgVGVzdCBDQTAeFw0xMTA1MjgwODM4NDNaFw0zODEwMTIwODM4NDZaMDEx\n"
  "LzAtBgNVBAMTJkdudVRMUyBUZXN0IHNlcnZlciAoRUNEU0EgY2VydGlmaWNhdGUp\n"
  "ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE0vMmf/W0rRoUqBxH5Uq+c/sR76ElmyZM\n"
  "e2zj3U9PRJ0maKstEOHkpaDaSU6s2Hyi9L88wS1ZX0ijgY0wgYowDAYDVR0TAQH/\n"
  "BAIwADAUBgNVHREEDTALgglsb2NhbGhvc3QwEwYDVR0lBAwwCgYIKwYBBQUHAwEw\n"
  "DwYDVR0PAQH/BAUDAweAADAdBgNVHQ4EFgQUJ97Q83IFpLgqeOnT1rX/JzCvlTQw\n"
  "HwYDVR0jBBgwFoAUTVa3agBY8WeS9KZ1VRuOUwED788wDQYJKoZIhvcNAQELBQAD\n"
  "ggExAErP9z8CCwt7YwA+SHoulNjqcXsngeKAKN9fVgV/XuspG6L2nU1WZvCjjFj6\n"
  "jggMbJSElyCuLZJKlTC/DihXUgRXyswOzg9qQ7dDv+V/Qi95XH5slXNzYxMQSdoA\n"
  "IaULVVDZcMFMVSc+TyAchJ6XwUY9umiysz3lSOioMQCch4MA366ZNqqnq5OD4moH\n"
  "1SUX8CbRjA6SLpvffexLTB2Af+mFi8ReTkXCwB1LGEH1HRp/XzBc+/F9mavy3g/6\n"
  "Hnjf2E1h2GDYXcJCVfE+ArjNS+R94jJwRMFBvwD/x2hsvpSajDpO0+GIxlGGKdyh\n"
  "7o4puz/BqHwSzX9h7I7RvFEogDUNUzLgHMdcjq5usnmQpdWNUP8Xs/WqLjML+/PT\n"
  "+jyCwmll0lPlC2RqAx3pM1XrjjQ=\n"
  "-----END CERTIFICATE-----\n";

const gnutls_datum_t server_cert = { server_cert_pem,
  sizeof (server_cert_pem)-1
};

static unsigned char server_key_pem[] =
   "-----BEGIN EC PRIVATE KEY-----\n"
   "MGgCAQEEHHX3xeBOGgIxxtuhhpbwdwZnJztR7+uZTHnYuL+gBwYFK4EEACGhPAM6\n"
   "AATS8yZ/9bStGhSoHEflSr5z+xHvoSWbJkx7bOPdT09EnSZoqy0Q4eSloNpJTqzY\n"
   "fKL0vzzBLVlfSA==\n"
   "-----END EC PRIVATE KEY-----\n";

const gnutls_datum_t server_key = { server_key_pem,
  sizeof (server_key_pem)-1
};

#define LINE1 "hello there people\n"
#define LINE2 "how are you doing today, all well?\n"

static const char* test = NULL;

#define err_quit(r) {fail("%s: Error in line %d: %s\n", test, __LINE__, gnutls_strerror(r)); exit(1);}

static void
client (int fd, unsigned int vmethod, unsigned use_cert)
{
  int ret;
  char *line = NULL;
  size_t line_len;
  xssl_cred_t cred;
  xssl_t sb;
  gnutls_cinput_st aux[2];
  unsigned int status;
  unsigned aux_size = 0;

  gnutls_global_init ();
  gnutls_global_set_time_function (mytime);

  if (debug)
    {
      gnutls_global_set_log_function (client_log_func);
      gnutls_global_set_log_level (7);
    }

  if (vmethod & GNUTLS_VMETHOD_GIVEN_CAS)
    {
      aux[aux_size].type = GNUTLS_CINPUT_TYPE_MEM;
      aux[aux_size].contents = GNUTLS_CINPUT_CAS;
      aux[aux_size].fmt = GNUTLS_X509_FMT_PEM;
      aux[aux_size].i1.mem = ca_cert;
      aux_size++;
    }

  if (use_cert != 0)
    {
      aux[aux_size].type = GNUTLS_CINPUT_TYPE_MEM;
      aux[aux_size].contents = GNUTLS_CINPUT_KEYPAIR;
      aux[aux_size].fmt = GNUTLS_X509_FMT_PEM;
      aux[aux_size].i1.mem = server_cert;
      aux[aux_size].i2.mem = server_key;
      aux_size++;
    }

  if (vmethod & GNUTLS_VMETHOD_TOFU)
    {
      aux[aux_size].type = GNUTLS_CINPUT_TYPE_FILE;
      aux[aux_size].contents = GNUTLS_CINPUT_TOFU_DB;
      aux[aux_size].i1.file = TOFU_DB_FILE;
      aux_size++;
    }

  ret = xssl_cred_init(&cred, vmethod, aux, aux_size);
  if (ret < 0)
    err_quit(ret);

  /* Initialize TLS session
   */
  ret = xssl_client_init(&sb, "localhost", NULL, (gnutls_transport_ptr_t)fd,
                                NULL, cred, &status, 0);
  if (ret < 0)
    {
      if (ret == GNUTLS_E_AUTH_ERROR)
        {
          gnutls_datum_t txt;
          
          gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509,
            &txt, 0);
          
          fprintf(stderr, "auth[%x]: %s\n", status, txt.data);
          gnutls_free(txt.data);
        }
      err_quit(ret);
    }
    
  ret = xssl_getline(sb, &line, &line_len);
  if (ret < 0)
    err_quit(ret);
  
  if (strcmp(line, LINE1) != 0)
    {
      fail("Error comparing first line\n");
      exit(1);
    }

  ret = xssl_getline(sb, &line, &line_len);
  if (ret < 0)
    err_quit(ret);
  
  if (strcmp(line, LINE2) != 0)
    {
      fail("Error comparing first line\n");
      exit(1);
    }
  
  gnutls_free(line);

  xssl_deinit(sb);

  close (fd);

  xssl_cred_deinit (cred);

  gnutls_global_deinit ();
}


/* These are global */
pid_t child;

static void terminate(void)
{
  kill(child, SIGTERM);
  exit(1);
}

static void
server (int fd, unsigned vmethod)
{
  int ret;
  xssl_cred_t cred;
  xssl_t sb;
  gnutls_cinput_st aux[2];
  unsigned aux_size = 0;

  gnutls_global_init ();

  if (debug)
    {
      gnutls_global_set_log_function (client_log_func);
      gnutls_global_set_log_level (7);
    }


  aux[aux_size].type = GNUTLS_CINPUT_TYPE_MEM;
  aux[aux_size].contents = GNUTLS_CINPUT_KEYPAIR;
  aux[aux_size].fmt = GNUTLS_X509_FMT_PEM;
  aux[aux_size].i1.mem = server_cert;
  aux[aux_size].i2.mem = server_key;
  aux_size++;

  if (vmethod & GNUTLS_VMETHOD_GIVEN_CAS)
    {
      aux[aux_size].type = GNUTLS_CINPUT_TYPE_MEM;
      aux[aux_size].contents = GNUTLS_CINPUT_CAS;
      aux[aux_size].fmt = GNUTLS_X509_FMT_PEM;
      aux[aux_size].i1.mem = ca_cert;
      aux_size++;
    }

  ret = xssl_cred_init(&cred, vmethod, aux, aux_size);
  if (ret < 0)
    err_quit(ret);

  /* Initialize TLS session
   */
  ret = xssl_server_init(&sb, (gnutls_transport_ptr_t)fd,
                                NULL, cred, NULL, 0);
  if (ret < 0)
    err_quit(ret);

  ret = xssl_write(sb, LINE1, sizeof(LINE1)-1);
  if (ret < 0)
    err_quit(ret);
  
  ret = xssl_write(sb, LINE2, sizeof(LINE2)-1);
  if (ret < 0)
    err_quit(ret);
    
  ret = xssl_flush(sb);
  if (ret < 0)
    err_quit(ret);
  
  xssl_deinit(sb);

  close (fd);

  xssl_cred_deinit (cred);

  gnutls_global_deinit ();

}

static void start (unsigned vc, unsigned vs, unsigned ccert)
{
  int fd[2];
  int ret;
  
  ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
  if (ret < 0)
    {
      perror("socketpair");
      exit(1);
    }

  child = fork ();
  if (child < 0)
    {
      perror ("fork");
      fail ("fork");
      exit(1);
    }

  if (child)
    {
      /* parent */
      close(fd[1]);
      server (fd[0], vs);
      waitpid(-1, NULL, 0);
      //kill(child, SIGTERM);
    }
  else 
    {
      close(fd[0]);
      client (fd[1], vc, ccert);
      exit(0);
    }
}

static void ch_handler(int sig)
{
int status = 0;

  waitpid(-1, &status, 0);
  if (WEXITSTATUS(status) != 0 ||
      (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV))
    {
      if (WIFSIGNALED(status))
        fail("Child died with sigsegv\n");
      else
        fail("Child died with status %d\n", WEXITSTATUS(status));
      terminate();
    }
  return;
}

void
doit (void)
{
  signal(SIGCHLD, ch_handler);

  test = "test1: no auth";
  start(GNUTLS_VMETHOD_NO_AUTH, GNUTLS_VMETHOD_NO_AUTH, 0);

  test = "test2: server auth";
  start(GNUTLS_VMETHOD_GIVEN_CAS, GNUTLS_VMETHOD_NO_AUTH, 0);

  test = "test3: mutual auth";
  start(GNUTLS_VMETHOD_GIVEN_CAS, GNUTLS_VMETHOD_GIVEN_CAS, 1);

  remove(TOFU_DB_FILE);
  test = "test4: trust on first use p1";
  start(GNUTLS_VMETHOD_TOFU, GNUTLS_VMETHOD_NO_AUTH, 0);

  test = "test5: trust on first use p2";
  start(GNUTLS_VMETHOD_TOFU, GNUTLS_VMETHOD_NO_AUTH, 0);
  remove(TOFU_DB_FILE);

}

#endif /* _WIN32 */
