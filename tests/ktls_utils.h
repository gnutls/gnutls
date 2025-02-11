#ifndef GNUTLS_TESTS_KTLS_UTILS_H
#define GNUTLS_TESTS_KTLS_UTILS_H

#include <fcntl.h>
#include <signal.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/wait.h>

/* Sets the NONBLOCK flag on the socket(fd) */
inline static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return 1;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		return 2;
	}

	return 0;
}

/* Creates a pair of TCP connected sockets */
static int create_socket_pair(int *client_fd, int *server_fd)
{
	int ret;
	struct sockaddr_in saddr;
	socklen_t addrlen;
	int listener;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener == -1) {
		fail("error in listener(): %s\n", strerror(errno));
		return 1;
	}

	int opt = 0;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	saddr.sin_port = 0;

	ret = bind(listener, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret == -1) {
		fail("error in bind(): %s\n", strerror(errno));
		return 1;
	}

	addrlen = sizeof(saddr);
	ret = getsockname(listener, (struct sockaddr *)&saddr, &addrlen);
	if (ret == -1) {
		fail("error in getsockname(): %s\n", strerror(errno));
		return 1;
	}

	ret = listen(listener, 1);
	if (ret == -1) {
		fail("error in listen(): %s\n", strerror(errno));
		close(listener);
		return 1;
	}

	*client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*client_fd < 0) {
		fail("error in socket(): %s\n", strerror(errno));
		return 1;
	}

	ret = connect(*client_fd, (struct sockaddr *)&saddr, addrlen);
	if (ret < 0) {
		fail("error in connect(): %s\n", strerror(errno));
		close(listener);
		close(*client_fd);
		return 1;
	}

	*server_fd = accept(listener, NULL, NULL);
	if (*server_fd < 0) {
		fail("error in accept(): %s\n", strerror(errno));
		close(listener);
		close(*client_fd);
		return 1;
	}

	return 0;
}

#endif //GNUTLS_TESTS_KTLS_UTILS_H
