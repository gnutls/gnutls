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
#include <sys/socket.h>
#elif HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
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
# include <arpa/inet.h>
# include <signal.h>
#else
# undef endservent
# define endservent()
#endif
#include <socket.h>
#include <c-ctype.h>
#include "sockets.h"

#ifdef HAVE_LIBIDN
#include <idna.h>
#include <idn-free.h>
#endif

#define MAX_BUF 4096

/* Functions to manipulate sockets
 */

ssize_t
socket_recv(const socket_st * socket, void *buffer, int buffer_size)
{
	int ret;

	if (socket->secure) {
		do {
			ret =
			    gnutls_record_recv(socket->session, buffer,
					       buffer_size);
			if (ret == GNUTLS_E_HEARTBEAT_PING_RECEIVED)
				gnutls_heartbeat_pong(socket->session, 0);
		}
		while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN
		       || ret == GNUTLS_E_HEARTBEAT_PING_RECEIVED);

	} else
		do {
			ret = recv(socket->fd, buffer, buffer_size, 0);
		}
		while (ret == -1 && errno == EINTR);

	return ret;
}

ssize_t
socket_recv_timeout(const socket_st * socket, void *buffer, int buffer_size, unsigned ms)
{
	int ret;

	if (socket->secure)
		gnutls_record_set_timeout(socket->session, ms);
	ret = socket_recv(socket, buffer, buffer_size);

	if (socket->secure)
		gnutls_record_set_timeout(socket->session, 0);

	return ret;
}

ssize_t
socket_send(const socket_st * socket, const void *buffer, int buffer_size)
{
	return socket_send_range(socket, buffer, buffer_size, NULL);
}


ssize_t
socket_send_range(const socket_st * socket, const void *buffer,
		  int buffer_size, gnutls_range_st * range)
{
	int ret;

	if (socket->secure)
		do {
			if (range == NULL)
				ret =
				    gnutls_record_send(socket->session,
						       buffer,
						       buffer_size);
			else
				ret =
				    gnutls_record_send_range(socket->
							     session,
							     buffer,
							     buffer_size,
							     range);
		}
		while (ret == GNUTLS_E_AGAIN
		       || ret == GNUTLS_E_INTERRUPTED);
	else
		do {
			ret = send(socket->fd, buffer, buffer_size, 0);
		}
		while (ret == -1 && errno == EINTR);

	if (ret > 0 && ret != buffer_size && socket->verbose)
		fprintf(stderr,
			"*** Only sent %d bytes instead of %d.\n", ret,
			buffer_size);

	return ret;
}

static
ssize_t send_line(socket_st * socket, const char *txt)
{
	int len = strlen(txt);
	int ret;

	if (socket->verbose)
		fprintf(stderr, "starttls: sending: %s\n", txt);

	ret = send(socket->fd, txt, len, 0);

	if (ret == -1) {
		fprintf(stderr, "error sending \"%s\"\n", txt);
		exit(1);
	}

	return ret;
}

static
ssize_t wait_for_text(socket_st * socket, const char *txt, unsigned txt_size)
{
	char buf[1024];
	char *p;
	int ret;
	fd_set read_fds;
	struct timeval tv;

	if (socket->verbose && txt != NULL)
		fprintf(stderr, "starttls: waiting for: \"%.*s\"\n", txt_size, txt);

	do {
		FD_ZERO(&read_fds);
		FD_SET(socket->fd, &read_fds);
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		ret = select(socket->fd + 1, &read_fds, NULL, NULL, &tv);
		if (ret <= 0)
			ret = -1;
		else
			ret = recv(socket->fd, buf, sizeof(buf)-1, 0);
		if (ret == -1) {
			fprintf(stderr, "error receiving %s\n", txt);
			exit(1);
		}
		buf[ret] = 0;

		if (txt == NULL)
			break;

		if (socket->verbose)
			fprintf(stderr, "starttls: received: %s\n", buf);

		p = memmem(buf, ret, txt, txt_size);
		if (p != NULL && p != buf) {
			p--;
			if (*p == '\n')
				break;
		}
	} while(ret < (int)txt_size || strncmp(buf, txt, txt_size) != 0);

	return ret;
}

void
socket_starttls(socket_st * socket, const char *app_proto)
{
	char buf[512];

	if (socket->secure)
		return;

	if (app_proto == NULL || strcasecmp(app_proto, "https") == 0)
		return;

	if (strcasecmp(app_proto, "smtp") == 0 || strcasecmp(app_proto, "submission") == 0) {
		if (socket->verbose)
			printf("Negotiating SMTP STARTTLS\n");

		wait_for_text(socket, "220 ", 4);
		snprintf(buf, sizeof(buf), "EHLO %s\n", socket->hostname);
		send_line(socket, buf);
		wait_for_text(socket, "250 ", 4);
		send_line(socket, "STARTTLS\n");
		wait_for_text(socket, "220 ", 4);
	} else if (strcasecmp(app_proto, "imap") == 0 || strcasecmp(app_proto, "imap2") == 0) {
		if (socket->verbose)
			printf("Negotiating IMAP STARTTLS\n");

		send_line(socket, "a CAPABILITY\r\n");
		wait_for_text(socket, "a OK", 4);
		send_line(socket, "a STARTTLS\r\n");
		wait_for_text(socket, "a OK", 4);
	} else if (strcasecmp(app_proto, "xmpp") == 0) {
		if (socket->verbose)
			printf("Negotiating XMPP STARTTLS\n");

		snprintf(buf, sizeof(buf), "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\n", socket->hostname);
		send_line(socket, buf);
		wait_for_text(socket, "<?", 2);
		send_line(socket, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
		wait_for_text(socket, "<proceed", 8);
	} else if (strcasecmp(app_proto, "ldap") == 0) {
		if (socket->verbose)
			printf("Negotiating LDAP STARTTLS\n");
#define LDAP_STR "\x30\x1d\x02\x01\x01\x77\x18\x80\x16\x31\x2e\x33\x2e\x36\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37"
		send(socket->fd, LDAP_STR, sizeof(LDAP_STR)-1, 0);
		wait_for_text(socket, NULL, 0);
	} else if (strcasecmp(app_proto, "ftp") == 0 || strcasecmp(app_proto, "ftps") == 0) {
		if (socket->verbose)
			printf("Negotiating FTP STARTTLS\n");

		send_line(socket, "FEAT\r\n");
		wait_for_text(socket, "211 ", 4);
		send_line(socket, "AUTH TLS\r\n");
		wait_for_text(socket, "234", 3);
	} else {
		if (!c_isdigit(app_proto[0])) {
			static int warned = 0;
			if (warned == 0) {
				fprintf(stderr, "unknown protocol '%s'\n", app_proto);
				warned = 1;
			}
		}
	}

	return;
}

#define CANON_SERVICE(app_proto) \
	if (strcasecmp(app_proto, "xmpp") == 0) \
		app_proto = "xmpp-server"; \

int
starttls_proto_to_port(const char *app_proto)
{
	struct servent *s;

	CANON_SERVICE(app_proto);

	s = getservbyname(app_proto, NULL);
	if (s != NULL) {
		return s->s_port;
	}
	endservent();

	return 443;
}

const char *starttls_proto_to_service(const char *app_proto)
{
	struct servent *s;

	CANON_SERVICE(app_proto);

	s = getservbyname(app_proto, NULL);
	if (s != NULL) {
		return s->s_name;
	}
	endservent();

	return "443";
}

void socket_bye(socket_st * socket)
{
	int ret;
	if (socket->secure) {
		do
			ret = gnutls_bye(socket->session, GNUTLS_SHUT_WR);
		while (ret == GNUTLS_E_INTERRUPTED
		       || ret == GNUTLS_E_AGAIN);
		if (ret < 0)
			fprintf(stderr, "*** gnutls_bye() error: %s\n",
				gnutls_strerror(ret));
		gnutls_deinit(socket->session);
		socket->session = NULL;
	}

	freeaddrinfo(socket->addr_info);
	socket->addr_info = socket->ptr = NULL;

	free(socket->ip);
	free(socket->hostname);
	free(socket->service);

	shutdown(socket->fd, SHUT_RDWR);	/* no more receptions */
	close(socket->fd);

	socket->fd = -1;
	socket->secure = 0;
}

void
socket_open(socket_st * hd, const char *hostname, const char *service,
	    int udp, const char *msg)
{
	struct addrinfo hints, *res, *ptr;
	int sd, err = 0;
	char buffer[MAX_BUF + 1];
	char portname[16] = { 0 };
	char *a_hostname = (char*)hostname;

	memset(hd, 0, sizeof(*hd));

#ifdef HAVE_LIBIDN
	err = idna_to_ascii_8z(hostname, &a_hostname, IDNA_ALLOW_UNASSIGNED);
	if (err != IDNA_SUCCESS) {
		fprintf(stderr, "Cannot convert %s to IDNA: %s\n", hostname,
			idna_strerror(err));
		exit(1);
	}
#endif

	if (msg != NULL)
		printf("Resolving '%s'...\n", a_hostname);

	/* get server name */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
	if ((err = getaddrinfo(a_hostname, service, &hints, &res))) {
		fprintf(stderr, "Cannot resolve %s:%s: %s\n", hostname,
			service, gai_strerror(err));
		exit(1);
	}

	sd = -1;
	for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
		sd = socket(ptr->ai_family, ptr->ai_socktype,
			    ptr->ai_protocol);
		if (sd == -1)
			continue;

		if ((err =
		     getnameinfo(ptr->ai_addr, ptr->ai_addrlen, buffer,
				 MAX_BUF, portname, sizeof(portname),
				 NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
			fprintf(stderr, "getnameinfo(): %s\n",
				gai_strerror(err));
			continue;
		}

		if (hints.ai_socktype == SOCK_DGRAM) {
#if defined(IP_DONTFRAG)
			int yes = 1;
			if (setsockopt(sd, IPPROTO_IP, IP_DONTFRAG,
				       (const void *) &yes,
				       sizeof(yes)) < 0)
				perror("setsockopt(IP_DF) failed");
#elif defined(IP_MTU_DISCOVER)
			int yes = IP_PMTUDISC_DO;
			if (setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER,
				       (const void *) &yes,
				       sizeof(yes)) < 0)
				perror("setsockopt(IP_DF) failed");
#endif
		}


		if (msg)
			printf("%s '%s:%s'...\n", msg, buffer, portname);

		err = connect(sd, ptr->ai_addr, ptr->ai_addrlen);
		if (err < 0) {
			continue;
		}
		break;
	}

	if (err != 0) {
		int e = errno;
		fprintf(stderr, "Could not connect to %s:%s: %s\n",
				buffer, portname, strerror(e));
		exit(1);
	}

	if (sd == -1) {
		fprintf(stderr, "Could not find a supported socket\n");
		exit(1);
	}

	hd->secure = 0;
	hd->fd = sd;
	hd->hostname = strdup(hostname);
	hd->ip = strdup(buffer);
	hd->service = strdup(portname);
	hd->ptr = ptr;
	hd->addr_info = res;
#ifdef HAVE_LIBIDN
	idn_free(a_hostname);
#endif
	return;
}

void sockets_init(void)
{
#ifdef _WIN32
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(1, 1);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		perror("WSA_STARTUP_ERROR");
	}
#else
	signal(SIGPIPE, SIG_IGN);
#endif

}

/* converts a textual service or port to
 * a service.
 */
const char *port_to_service(const char *sport, const char *proto)
{
	unsigned int port;
	struct servent *sr;

	if (!c_isdigit(sport[0]))
		return sport;

	port = atoi(sport);
	if (port == 0)
		return sport;

	port = htons(port);

	sr = getservbyport(port, proto);
	if (sr == NULL) {
		fprintf(stderr,
			"Warning: getservbyport(%s) failed. Using port number as service.\n", sport);
		return sport;
	}

	return sr->s_name;
}

int service_to_port(const char *service, const char *proto)
{
	unsigned int port;
	struct servent *sr;

	port = atoi(service);
	if (port != 0)
		return port;

	sr = getservbyname(service, proto);
	if (sr == NULL) {
		fprintf(stderr, "Warning: getservbyname() failed.\n");
		exit(1);
	}

	return ntohs(sr->s_port);
}
