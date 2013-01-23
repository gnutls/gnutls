/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#elif HAVE_WS2TCPIP_H
# include <ws2tcpip.h>
#endif
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef _WIN32
# include <signal.h>
#endif
#include <socket.h>
#include "sockets.h"

#define MAX_BUF 4096

extern unsigned int verbose;
/* Functions to manipulate sockets
 */

ssize_t
socket_recv (const socket_st * socket, void *buffer, int buffer_size)
{
  int ret;

  if (socket->secure)
    {
      do
        {
          ret = gnutls_record_recv (socket->session, buffer, buffer_size);
          if (ret == GNUTLS_E_HEARTBEAT_PING_RECEIVED)
            gnutls_heartbeat_pong(socket->session, 0);
        }
      while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_HEARTBEAT_PING_RECEIVED);

    }
  else
    do
      {
        ret = recv (socket->fd, buffer, buffer_size, 0);
      }
    while (ret == -1 && errno == EINTR);

  return ret;
}

ssize_t
socket_send (const socket_st * socket, const void *buffer, int buffer_size)
{
  return socket_send_range(socket, buffer, buffer_size, NULL);
}


ssize_t
socket_send_range (const socket_st * socket, const void *buffer, int buffer_size, gnutls_range_st *range)
{
  int ret;

  if (socket->secure)
    do
      {
   	if (range == NULL)
          ret = gnutls_record_send (socket->session, buffer, buffer_size);
    	else
          ret = gnutls_record_send_range(socket->session, buffer, buffer_size, range);
      }
    while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
  else
    do
      {
        ret = send (socket->fd, buffer, buffer_size, 0);
      }
    while (ret == -1 && errno == EINTR);

  if (ret > 0 && ret != buffer_size && verbose)
    fprintf (stderr,
             "*** Only sent %d bytes instead of %d.\n", ret, buffer_size);

  return ret;
}

void
socket_bye (socket_st * socket)
{
  int ret;
  if (socket->secure)
    {
      do
        ret = gnutls_bye (socket->session, GNUTLS_SHUT_WR);
      while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
      if (ret < 0)
        fprintf (stderr, "*** gnutls_bye() error: %s\n",
                 gnutls_strerror (ret));
      gnutls_deinit (socket->session);
      socket->session = NULL;
    }

  freeaddrinfo (socket->addr_info);
  socket->addr_info = socket->ptr = NULL;

  free (socket->ip);
  free (socket->hostname);
  free (socket->service);

  shutdown (socket->fd, SHUT_RDWR);     /* no more receptions */
  close (socket->fd);

  socket->fd = -1;
  socket->secure = 0;
}

void
socket_open (socket_st * hd, const char *hostname, const char *service, int udp)
{
  struct addrinfo hints, *res, *ptr;
  int sd, err;
  char buffer[MAX_BUF + 1];
  char portname[16] = { 0 };

  printf ("Resolving '%s'...\n", hostname);
  /* get server name */
  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
  if ((err = getaddrinfo (hostname, service, &hints, &res)))
    {
      fprintf (stderr, "Cannot resolve %s:%s: %s\n", hostname, service,
               gai_strerror (err));
      exit (1);
    }

  sd = -1;
  for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
      sd = socket (ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
      if (sd == -1)
        continue;

      if ((err = getnameinfo (ptr->ai_addr, ptr->ai_addrlen, buffer, MAX_BUF,
                              portname, sizeof (portname),
                              NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
        {
          fprintf (stderr, "getnameinfo(): %s\n", gai_strerror (err));
          continue;
        }

      if (hints.ai_socktype == SOCK_DGRAM)
        {
#if defined(IP_DONTFRAG)
          int yes = 1;
          if (setsockopt (sd, IPPROTO_IP, IP_DONTFRAG,
                        (const void *) &yes, sizeof (yes)) < 0)
            perror ("setsockopt(IP_DF) failed");
#elif defined(IP_MTU_DISCOVER)
          int yes = IP_PMTUDISC_DO;
          if (setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER, 
                         (const void*) &yes, sizeof (yes)) < 0)
            perror ("setsockopt(IP_DF) failed");
#endif
        }


      printf ("Connecting to '%s:%s'...\n", buffer, portname);

      err = connect (sd, ptr->ai_addr, ptr->ai_addrlen);
      if (err < 0)
        {
          fprintf (stderr, "Cannot connect to %s:%s: %s\n", buffer,
                   portname, strerror (errno));
          continue;
        }
      break;
    }

  if (err != 0)
    exit(1);

  if (sd == -1)
    {
      fprintf (stderr, "Could not find a supported socket\n");
      exit (1);
    }

  hd->secure = 0;
  hd->fd = sd;
  hd->hostname = strdup (hostname);
  hd->ip = strdup (buffer);
  hd->service = strdup (portname);
  hd->ptr = ptr;
  hd->addr_info = res;

  return;
}

void
sockets_init (void)
{
#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;

    wVersionRequested = MAKEWORD (1, 1);
    if (WSAStartup (wVersionRequested, &wsaData) != 0)
      {
          perror ("WSA_STARTUP_ERROR");
      }
#else
  signal (SIGPIPE, SIG_IGN);
#endif

}
