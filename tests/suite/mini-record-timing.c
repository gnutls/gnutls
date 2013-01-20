/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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
#include <signal.h>
#include <errno.h>

#include <time.h>
#include <timespec.h>
#include <sys/time.h>

#ifdef DEBUG
static void
server_log_func (int level, const char *str)
{
  fprintf (stderr, "server|<%d>| %s", level, str);
}

static void
client_log_func (int level, const char *str)
{
  fprintf (stderr, "client|<%d>| %s", level, str);
}
#endif

static void terminate(void);

/* This program tests the robustness of record
 * decoding.
 */

static unsigned char server_cert_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBeTCCASWgAwIBAgIBBzANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwROb25l\n"
"MCIYDzIwMTMwMTE5MTA0MDAwWhgPMjA0MDA2MDUxMDQwMDBaMA8xDTALBgNVBAMT\n"
"BE5vbmUwWTANBgkqhkiG9w0BAQEFAANIADBFAj4Bh52/b3FNXDdICg1Obqu9ivW+\n"
"PGJ89mNsX3O9S/aclnx5Ozw9MC1UJuZ2UEHl27YVmm4xG/y3nKUNevZjKwIDAQAB\n"
"o2swaTAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDATBgNVHSUE\n"
"DDAKBggrBgEFBQcDATAPBgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQWBBRhEgmVCi6c\n"
"hhRQvMzfEXqLKTRxcTANBgkqhkiG9w0BAQsFAAM/AADMi31wr0Tp2SJUCuQjFVCb\n"
"JDleomTayOWVS/afCyAUxYjqFfUFSZ8sYN3zAgnXt5DYO3VclIlax4n6iXOg\n"
"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_cert = { server_cert_pem,
  sizeof (server_cert_pem)
};

static unsigned char server_key_pem[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIBLAIBAAI+AYedv29xTVw3SAoNTm6rvYr1vjxifPZjbF9zvUv2nJZ8eTs8PTAt\n"
"VCbmdlBB5du2FZpuMRv8t5ylDXr2YysCAwEAAQI9EPt8Q77sFeWn0BfHoPD9pTsG\n"
"5uN2e9DP8Eu6l8K4AcOuEsEkqZzvxgqZPA68pw8BZ5xKINMFdRPHmrX/cQIfHsdq\n"
"aMDYR/moqgj8MbupqOr/48iorTk/D//2lgAMnwIfDLk3UWGvPiv6fNTlEnTgVn6o\n"
"TdL0mvpkixebQ5RR9QIfHDjkRGtXph+xXUBh50RZXE8nFfl/WV7diVE+DOq8pwIf\n"
"BxdOwjdsAH1oLBxG0sN6qBoM2NrCYoE8edydNsu55QIfEWsrlJnO/t0GzHy7qWdV\n"
"zi9JMPu9MTDhOGmqPQO7Xw==\n"
"-----END RSA PRIVATE KEY-----\n";


const gnutls_datum_t server_key = { server_key_pem,
  sizeof (server_key_pem)
};


/* A very basic TLS client, with anonymous authentication.
 */

#define MAX_BUF 1024

#define MAX_PER_POINT (16*1024)
#define MAX_MEASUREMENTS (MAX_PER_POINT*(sizeof(points)/sizeof(points[0])))

struct point_st {
  unsigned char byte1;
  unsigned char byte2;
  unsigned midx;
  unsigned long measurements[MAX_PER_POINT];
};

static struct point_st points[] = {
  { 0, 0, 0 },
//  { 1, 1, 0 },
//  { 14, 14, 0 },
  { 253, 253, 0 },
};

struct point_st *prev_point_ptr = &points[0];
unsigned int point_idx = 0;


static ssize_t
push(gnutls_transport_ptr_t tr, const void *_data, size_t len)
{
int fd = (long int)tr;
    
  return send(fd, _data, len, 0);
}

static ssize_t
push_crippled (gnutls_transport_ptr_t tr, const void *_data, size_t len)
{
int fd = (long int)tr;
unsigned char* data = (void*)_data;
struct point_st * p = &points[point_idx];

  memcpy(&data[len-32], data+5, 32);

//fprintf(stderr, "sending: %d.%d: %d\n", (unsigned)p->byte1, (unsigned)p->byte2, (int)len);
  data[len-17] ^= p->byte1;
  data[len-18] ^= p->byte2;

  prev_point_ptr = p;
  point_idx++;
  if (point_idx >= (sizeof(points)/sizeof(points[0])))
    point_idx = 0;
    
  return send(fd, data, len, 0);
}


static unsigned long timespec_sub_us(struct timespec *a, struct timespec *b)
{
  return (a->tv_sec*1000*1000 + a->tv_nsec/1000 - (b->tv_sec *1000*1000 + 
          b->tv_nsec/1000));
}

static
double calc_avg(unsigned long *diffs, unsigned int diffs_size)
{
double avg = 0;
unsigned int i;

  for(i=0;i<diffs_size;i++)
    avg += diffs[i];
    
  avg /= diffs_size;

  return avg;
}

static int compar(const void* _a, const void* _b)
{
  unsigned long a, b;
  
  a = *((unsigned long*)_a);
  b = *((unsigned long*)_b);
  
  if (a < b)
    return -1;
  else if (a==b)
    return 0;
  else
    return 1;
}

static
double calc_median(unsigned long *diffs, unsigned int diffs_size)
{
double med;

  qsort(diffs, diffs_size, sizeof(diffs[0]), compar);
    
  med = diffs[diffs_size/2];

  return med;
}

static
double calc_var(unsigned long *diffs, unsigned int diffs_size, double avg)
{
double sum = 0, d;
unsigned int i;

  for (i=0;i<diffs_size;i++) {
    d = ((double)diffs[i] - avg);
    d *= d;
    
    sum += d;
  }
  sum /= diffs_size - 1;
  
  return sum;
}


static void
client (int fd, const char* prio, unsigned int text_size)
{
  int ret;
  char buffer[MAX_BUF + 1];
  char text[text_size];
  gnutls_certificate_credentials_t x509_cred;
  gnutls_session_t session;
  struct timespec start, stop;
  static unsigned int taken = 0;
  static unsigned long *measurements;
  static unsigned long min = 0, max = 0;
  const char* err;

  measurements = malloc(sizeof(measurements[0])*MAX_MEASUREMENTS);
  if (measurements == NULL)
    exit(1);

  gnutls_global_init ();
  
  setpriority(PRIO_PROCESS, getpid(), -15);
  
  memset(text, 0, text_size);

#ifdef DEBUG
  gnutls_global_set_log_function (client_log_func);
  gnutls_global_set_log_level (6);
#endif

  gnutls_certificate_allocate_credentials (&x509_cred);

  /* Initialize TLS session
   */
restart:
  gnutls_init (&session, GNUTLS_CLIENT);

  /* Use default priorities */
  if (gnutls_priority_set_direct (session, prio, &err) < 0) {
    fprintf(stderr, "Error in %s\n", err);
    exit(1);
  }

  /* put the anonymous credentials to the current session
   */
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) fd);

  /* Perform the TLS handshake
   */
  do 
    {
      ret = gnutls_handshake (session);
    }
  while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

  if (ret < 0)
    {
      fprintf (stderr, "client: Handshake failed\n");
      gnutls_perror (ret);
      exit(1);
    }
    
  if (gnutls_protocol_get_version(session) != GNUTLS_TLS1_1)
    {
      fprintf (stderr, "client: Handshake didn't negotiate TLS 1.1\n");
      exit(1);
    }

  gnutls_transport_set_push_function (session, push_crippled);
  do {
    ret = gnutls_record_send (session, text, sizeof(text));
  } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
  /* measure peer's processing time */
  gettime(&start);

#define TLS_RECV
#ifdef TLS_RECV
  do {
    ret = gnutls_record_recv(session, buffer, sizeof(buffer));
  } while(ret < 0 && (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED));
#else
  do {
    ret = recv(fd, buffer, sizeof(buffer), 0);
  } while(ret == -1 && errno == EAGAIN);
#endif

  if (taken < MAX_MEASUREMENTS)
    {
      gettime(&stop);
      measurements[taken] = timespec_sub_us(&stop, &start);

      if (min > measurements[taken] || min == 0)
        min = measurements[taken];
      if (max < measurements[taken])
        max = measurements[taken];

//fprintf(stderr, "(%u,%u): %lu\n", (unsigned) prev_point_ptr->byte1,
// (unsigned) prev_point_ptr->byte2, measurements[taken]);
      prev_point_ptr->measurements[prev_point_ptr->midx++] = measurements[taken];
      taken++;
      
      gnutls_deinit(session);
      
      goto restart;
    }
#ifndef TLS_RECV
  else if (ret < 0)
    {
      fprintf(stderr, "Error in recv()\n");
      exit(1);
    }
#endif

  gnutls_transport_set_push_function (session, push);
    
  gnutls_bye (session, GNUTLS_SHUT_WR);
  
  {
    double avg1, avg2, var, med;
    unsigned i;
    
    printf("Taken %u measurements\n", taken);
    avg1 = calc_avg(measurements, taken);
    med = calc_median(measurements, taken);
    
    var = calc_var(measurements, taken, avg1);
    
    printf("Average processing time: %.3f microsec, Median: %.3f Variance: %.3f\n", avg1, med, var);
    printf("(Min,Max)=(%lu,%lu)\n\n", min, max);

    for (i=0;i<sizeof(points)/sizeof(points[0]);i++)
      {
        avg2 = calc_avg( points[i].measurements, points[i].midx);
        var = calc_var(points[i].measurements, points[i].midx, avg2);
        med = calc_median(points[i].measurements, points[i].midx);
        printf("(%u,%u) Avg: %.3f microsec, Median: %.3f, Variance: %.3f\n", (unsigned)points[i].byte2, (unsigned)points[i].byte1, 
               avg2, med, var);
        if (i > 0)
          {
            printf("Avg diff (%u,%u)-(%u,%u)=%.3f\n", 
                   (unsigned)points[0].byte2, (unsigned)points[0].byte1,
                   (unsigned)points[i].byte2, (unsigned)points[i].byte1,
                   avg1-avg2);
          
          }
        else
          avg1 = avg2;
      }
  }

  close (fd);

  gnutls_deinit (session);

  gnutls_certificate_free_credentials (x509_cred);

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
server (int fd, const char* prio)
{
int ret;
char buffer[MAX_BUF + 1];
gnutls_session_t session;
gnutls_certificate_credentials_t x509_cred;
const char* err;

  setpriority(PRIO_PROCESS, getpid(), -15);

  /* this must be called once in the program
   */
  gnutls_global_init ();
  memset(buffer, 0, sizeof(buffer));

#ifdef DEBUG
  gnutls_global_set_log_function (server_log_func);
  gnutls_global_set_log_level (6);
#endif

  gnutls_certificate_allocate_credentials (&x509_cred);
  ret = gnutls_certificate_set_x509_key_mem (x509_cred, &server_cert, &server_key,
                                       GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    {
      fprintf(stderr, "Could not set certificate\n");
      terminate();
    }

restart:
  gnutls_init (&session, GNUTLS_SERVER);

  /* avoid calling all the priority functions, since the defaults
   * are adequate.
   */
  if (gnutls_priority_set_direct (session, prio, &err) < 0) {
    fprintf(stderr, "Error in %s\n", err);
    terminate();
  }

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) fd);

  do 
    {
      ret = gnutls_handshake (session);
    }
  while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
  if (ret < 0)
    {
#ifdef GNUTLS_E_PREMATURE_TERMINATION
      if (ret != GNUTLS_E_PREMATURE_TERMINATION && ret != GNUTLS_E_UNEXPECTED_PACKET_LENGTH)
#else
      if (ret != GNUTLS_E_UNEXPECTED_PACKET_LENGTH)
#endif
        {
          close (fd);
          gnutls_deinit (session);
          fprintf( stderr, "server: Handshake has failed (%s)\n\n", gnutls_strerror (ret));
          terminate();
        }
      goto finish;
    }

  do {
    ret = gnutls_record_recv (session, buffer, sizeof (buffer));
  } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

  if (ret < 0)
    {
      do {
        ret = gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_RECORD_MAC);
      } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
      gnutls_deinit(session);
      goto restart;
    }

  /* do not wait for the peer to close the connection.
   */
  gnutls_bye (session, GNUTLS_SHUT_WR);

finish:
  close (fd);
  gnutls_deinit (session);

  gnutls_certificate_free_credentials (x509_cred);

  gnutls_global_deinit ();

}

static void start (const char* prio, unsigned int text_size)
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
      fprintf( stderr, "fork");
      exit(1);
    }

  if (child)
    {
      /* parent */
      close(fd[1]);
      server (fd[0], prio);
      kill(child, SIGTERM);
    }
  else 
    {
      close(fd[0]);
      client (fd[1], prio, text_size);
      exit(0);
    }
}

static void ch_handler(int sig)
{
int status;
  wait(&status);
  if (WEXITSTATUS(status) != 0 ||
      (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV))
    {
      if (WIFSIGNALED(status))
        fprintf(stderr, "Child died with sigsegv\n");
      else
        fprintf(stderr, "Child died with status %d\n", WEXITSTATUS(status));
      terminate();
    }
  return;
}

int main(int argc, char** argv)
{
  signal(SIGCHLD, ch_handler);

  printf("\nAES-SHA1 (GnuTLS attack)\n");
  start("NONE:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:%COMPAT:+VERS-TLS1.1:+VERS-TLS1.0:+VERS-SSL3.0", 18*16);
//  start("PERFORMANCE:-CIPHER-ALL:+AES-128-CBC:-MAC-ALL:+SHA1:%COMPAT", 18*16);

//  printf("\nAES-SHA1 (full plaintext recovery)\n");
//  start("PERFORMANCE:-CIPHER-ALL:+AES-128-CBC:-MAC-ALL:+SHA1:%COMPAT", 2*16);

//  printf("\nAES-SHA256\n");
//  start("PERFORMANCE:-CIPHER-ALL:+AES-128-CBC:-MAC-ALL:+SHA256:%COMPAT");
}

#endif /* _WIN32 */

