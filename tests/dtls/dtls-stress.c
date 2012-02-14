/*
 * Copyright (C) 2012 Sean Buckheister
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

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <wait.h>

enum role {
	SERVER,
	CLIENT
} role;

int debug;
int nonblock;

int run_id;

static const char* role_to_name(enum role role)
{
	if (role == SERVER) {
		return "server";
	} else {
		return "client";
	}
}

static void logfn(int level, const char* s)
{
	if (debug) {
		fprintf(stdout, "%i %s|<%i> %s", run_id, role_to_name(role), level, s);
	}
}

static void auditfn(gnutls_session_t session, const char* s)
{
	if (debug) {
		fprintf(stdout, "%i %s| %s", run_id, role_to_name(role), s);
	}
}

static void drop(const char* packet)
{
	if (debug) {
		fprintf(stdout, "%i %s| dropping %s\n", run_id, role_to_name(role), packet);
	}
}


typedef struct {
	int count;
} filter_packet_state_t;

filter_packet_state_t state_packet_ServerHello = { 0 };
filter_packet_state_t state_packet_ServerKeyExchange = { 0 };
filter_packet_state_t state_packet_ServerHelloDone = { 0 };
filter_packet_state_t state_packet_ClientKeyExchange = { 0 };
filter_packet_state_t state_packet_ClientChangeCipherSpec = { 0 };
filter_packet_state_t state_packet_ClientFinished = { 0 };
filter_packet_state_t state_packet_ServerChangeCipherSpec = { 0 };
filter_packet_state_t state_packet_ServerFinished = { 0 };

typedef struct {
	gnutls_datum_t packets[3];
	int* order;
	int count;
} filter_permute_state_t;

filter_permute_state_t state_permute_ServerHello = { { { 0, 0 }, { 0, 0 }, { 0, 0 } }, 0, 0 };
filter_permute_state_t state_permute_ServerFinished = { { { 0, 0 }, { 0, 0 }, { 0, 0 } }, 0, 0 };
filter_permute_state_t state_permute_ClientFinished = { { { 0, 0 }, { 0, 0 }, { 0, 0 } }, 0, 0 };

typedef void (*filter_fn)(gnutls_transport_ptr_t, const unsigned char*, size_t);

filter_fn filter_chain[32];
int filter_current_idx;

static void filter_clear_state(void)
{
int i;

	memset(&state_packet_ServerHello, 0, sizeof(state_packet_ServerHello));
	memset(&state_packet_ServerKeyExchange, 0, sizeof(state_packet_ServerKeyExchange));
	memset(&state_packet_ServerHelloDone, 0, sizeof(state_packet_ServerHelloDone));
	memset(&state_packet_ClientKeyExchange, 0, sizeof(state_packet_ClientKeyExchange));
	memset(&state_packet_ClientChangeCipherSpec, 0, sizeof(state_packet_ClientChangeCipherSpec));
	memset(&state_packet_ServerChangeCipherSpec, 0, sizeof(state_packet_ServerChangeCipherSpec));
	memset(&state_packet_ServerFinished, 0, sizeof(state_packet_ServerFinished));

	for (i = 0; i < 3; i++) {
		if (state_permute_ServerHello.packets[i].data) {
			free(state_permute_ServerHello.packets[i].data);
		}
		if (state_permute_ServerFinished.packets[i].data) {
			free(state_permute_ServerFinished.packets[i].data);
		}
		if (state_permute_ClientFinished.packets[i].data) {
			free(state_permute_ClientFinished.packets[i].data);
		}
	}

	memset(&state_permute_ServerHello, 0, sizeof(state_permute_ServerHello));
	memset(&state_permute_ServerFinished, 0, sizeof(state_permute_ServerFinished));
	memset(&state_permute_ClientFinished, 0, sizeof(state_permute_ClientFinished));
}

static void filter_run_next(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	filter_fn fn = filter_chain[filter_current_idx];
	filter_current_idx++;
	if (fn) {
		fn(fd, buffer, len);
	} else {
		send((long int) fd, buffer, len, 0);
	}
}



static int match_ServerHello(const unsigned char* buffer, size_t len)
{
	return role == SERVER && len >= 13 + 1 && buffer[0] == 22 && buffer[13] == 2;
}

static void filter_packet_ServerHello(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ServerHello(buffer, len) && state_packet_ServerHello.count++ < 3) {
		drop("Server Hello");
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static int match_ServerKeyExchange(const unsigned char* buffer, size_t len)
{
	return role == SERVER && len >= 13 + 1 && buffer[0] == 22 && buffer[13] == 12;
}

static void filter_packet_ServerKeyExchange(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ServerKeyExchange(buffer, len) && state_packet_ServerKeyExchange.count++ < 3) {
		drop("Server Key Exchange");
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static int match_ServerHelloDone(const unsigned char* buffer, size_t len)
{
	return role == SERVER && len >= 13 + 1 && buffer[0] == 22 && buffer[13] == 14;
}

static 
void filter_packet_ServerHelloDone(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ServerHelloDone(buffer, len) && state_packet_ServerHelloDone.count++ < 3) {
		drop("Server Hello Done");
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static
int match_ClientKeyExchange(const unsigned char* buffer, size_t len)
{
	return role == CLIENT && len >= 13 + 1 && buffer[0] == 22 && buffer[13] == 16;
}

static
void filter_packet_ClientKeyExchange(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ClientKeyExchange(buffer, len) && state_packet_ClientKeyExchange.count++ < 3) {
		drop("Client Key Exchange");
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static
int match_ClientChangeCipherSpec(const unsigned char* buffer, size_t len)
{
	return role == CLIENT && len >= 13 && buffer[0] == 20;
}

static
void filter_packet_ClientChangeCipherSpec(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ClientChangeCipherSpec(buffer, len) && state_packet_ClientChangeCipherSpec.count++ < 3) {
		drop("Client Change Cipher Spec");
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static
int match_ClientFinished(const unsigned char* buffer, size_t len)
{
	return role == CLIENT && len >= 13 && buffer[0] == 22 && buffer[4] == 1;
}

static
void filter_packet_ClientFinished(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ClientFinished(buffer, len) && state_packet_ClientFinished.count++ < 3) {
		drop("Client Finished");
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static
int match_ServerChangeCipherSpec(const unsigned char* buffer, size_t len)
{
	return role == SERVER && len >= 13 && buffer[0] == 20;
}

static
void filter_packet_ServerChangeCipherSpec(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ServerChangeCipherSpec(buffer, len) && state_packet_ServerChangeCipherSpec.count++ < 3) {
		drop("Server Change Cipher Spec");
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static
int match_ServerFinished(const unsigned char* buffer, size_t len)
{
	return role == SERVER && len >= 13 && buffer[0] == 22 && buffer[4] == 1;
}

static
void filter_packet_ServerFinished(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ServerFinished(buffer, len) && state_packet_ServerFinished.count++ < 3) {
		drop("Server Finished");
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static
void filter_permutete_state_free_buffer(filter_permute_state_t* state)
{
	int i;

	for (i = 0; i < 3; i++) {
		if (state->packets[i].data) {
			free(state->packets[i].data);
		}
	}
}

static
void filter_permute_state_run(filter_permute_state_t* state, int packetCount,
		gnutls_transport_ptr_t fd, const unsigned char* buffer, size_t len)
{
	unsigned char* data = malloc(len);
	int packet = state->order[state->count];

	memcpy(data, buffer, len);
	state->packets[packet].data = data;
	state->packets[packet].size = len;
	state->count++;

	if (state->count == packetCount) {
		for (packet = 0; packet < packetCount; packet++) {
			filter_run_next(fd, state->packets[packet].data,
					state->packets[packet].size);
		}
		filter_permutete_state_free_buffer(state);
		state->count = 0;
	}
}

static
void filter_permute_ServerHello(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ServerHello(buffer, len)
			|| match_ServerKeyExchange(buffer, len)
			|| match_ServerHelloDone(buffer, len)) {
		filter_permute_state_run(&state_permute_ServerHello, 3, fd, buffer, len);
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static
void filter_permute_ServerFinished(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ServerChangeCipherSpec(buffer, len)
			|| match_ServerFinished(buffer, len)) {
		filter_permute_state_run(&state_permute_ServerFinished, 2, fd, buffer, len);
	} else {
		filter_run_next(fd, buffer, len);
	}
}

static
void filter_permute_ClientFinished(gnutls_transport_ptr_t fd,
		const unsigned char* buffer, size_t len)
{
	if (match_ClientKeyExchange(buffer, len)
			|| match_ClientChangeCipherSpec(buffer, len)
			|| match_ClientFinished(buffer, len)) {
		filter_permute_state_run(&state_permute_ClientFinished, 3, fd, buffer, len);
	} else {
		filter_run_next(fd, buffer, len);
	}
}


static
ssize_t writefn(gnutls_transport_ptr_t fd, const void* buffer, size_t len)
{
	filter_current_idx = 0;
	filter_run_next(fd, (const unsigned char*) buffer, len);
	return len;
}

static
void await(int fd)
{
	if (nonblock) {
		struct pollfd p = { fd, POLLIN, 0 };
		poll(&p, 1, 100);
	}
}




static
gnutls_session_t session(int sock, int server)
{
	gnutls_session_t r;

	gnutls_init(&r, GNUTLS_DATAGRAM | (server ? GNUTLS_SERVER : GNUTLS_CLIENT)
			| GNUTLS_NONBLOCK * nonblock);
	gnutls_priority_set_direct(r, "NORMAL:+ANON-ECDH", 0);
	gnutls_transport_set_ptr(r, (gnutls_transport_ptr_t) sock);

	if (server) {
		gnutls_anon_server_credentials_t cred;
		gnutls_anon_allocate_server_credentials(&cred);
		gnutls_credentials_set(r, GNUTLS_CRD_ANON, cred);
	} else {
		gnutls_anon_client_credentials_t cred;
		gnutls_anon_allocate_client_credentials(&cred);
		gnutls_credentials_set(r, GNUTLS_CRD_ANON, cred);
	}

	gnutls_transport_set_push_function(r, writefn);

	gnutls_dtls_set_mtu(r, 1400);
	gnutls_dtls_set_timeouts(r, 1000, 60000);

	return r;
}

static
int log_error(int code)
{
	if (code < 0 && code != GNUTLS_E_AGAIN) {
		fprintf(stdout, "%i <%s tls> %s", run_id, role_to_name(role), gnutls_strerror(code));
		if (gnutls_error_is_fatal(code)) {
			fprintf(stdout, " (fatal)\n");
			exit(1);
		} else {
			fprintf(stdout, "\n");
		}
	}
	return code;
}

timer_t killtimer_tid;

static
void reset_killtimer(void)
{
struct itimerspec tout = { { 0, 0 }, { 120, 0 } };

	if (nonblock) {
		return;
	}
	timer_settime(killtimer_tid, 0, &tout, 0);
}

static
void setup_killtimer(void)
{
	struct sigevent sig;
	struct itimerspec tout = { { 0, 0 }, { 240, 0 } };

	memset(&sig, 0, sizeof(sig));
	sig.sigev_notify = SIGEV_SIGNAL;
	sig.sigev_signo = 15;
	timer_create(CLOCK_MONOTONIC, &sig, &killtimer_tid);

	timer_settime(killtimer_tid, 0, &tout, 0);
}

static
void log_error_with_time(int err, time_t started)
{
	if (err < 0) {
		if (err != GNUTLS_E_TIMEDOUT || (time(0) - started) >= 60) {
			log_error(err);
		} else {
			fprintf(stdout, "{spurious}");
			log_error(err);
		}
		if (gnutls_error_is_fatal(err)) {
			exit(1);
		}
	}
}

static
void client(int sock)
{
	gnutls_session_t s = session(sock, 0);
	int err = 0;
	time_t started = time(0);
	const char* line = "foobar!";
	char buffer[8192];
	int len;

	setup_killtimer();

	do {
		await(sock);
		err = log_error(gnutls_handshake(s));
		reset_killtimer();
	} while (err != 0 && !gnutls_error_is_fatal(err));
	log_error_with_time(err, started);
	
	started = time(0);
	do {
		err = gnutls_record_send(s, line, strlen(line));
		reset_killtimer();
	} while (err < 0 && !gnutls_error_is_fatal(err));
	log_error_with_time(err, started);
	
	do {
		await(sock);
		len = gnutls_record_recv(s, buffer, sizeof(buffer));
	} while (len < 0 && !gnutls_error_is_fatal(len));
	if (len > 0 && strcmp(line, buffer) == 0) {
		exit(0);
	} else {
		log_error(len);
		exit(1);
	}
}

static
void server(int sock)
{ 
	gnutls_session_t s = session(sock, 1);
	int err;
	time_t started = time(0);

	write(sock, &sock, 1);

	setup_killtimer();

	do {
		await(sock);
		err = log_error(gnutls_handshake(s));
		reset_killtimer();
	} while (err != 0 && !gnutls_error_is_fatal(err));
	log_error_with_time(err, started);

	for (;;) {
		char buffer[8192];
		int len;
		do {
			await(sock);
			len = gnutls_record_recv(s, buffer, sizeof(buffer));
			reset_killtimer();
		} while (len < 0 && !gnutls_error_is_fatal(len));
		log_error_with_time(len, started);

		gnutls_record_send(s, buffer, len);
		exit(0);
	}
}

#if 0
static
void udp_sockpair(int* socks)
{
	struct sockaddr_in6 sa = { AF_INET6, htons(30000), 0, in6addr_loopback, 0 };
	struct sockaddr_in6 sb = { AF_INET6, htons(20000), 0, in6addr_loopback, 0 };

	socks[0] = socket(AF_INET6, SOCK_DGRAM, 0);
	socks[1] = socket(AF_INET6, SOCK_DGRAM, 0);

	bind(socks[0], (struct sockaddr*) &sa, sizeof(sa));
	bind(socks[1], (struct sockaddr*) &sb, sizeof(sb));

	connect(socks[1], (struct sockaddr*) &sa, sizeof(sa));
	connect(socks[0], (struct sockaddr*) &sb, sizeof(sb));
}
#endif

static
int run_test(void)
{
	int fds[2];
	int pid1, pid2;
	int status2;

	socketpair(AF_LOCAL, SOCK_DGRAM, 0, fds);

	if (nonblock) {
		fcntl(fds[0], F_SETFL, (long) O_NONBLOCK);
		fcntl(fds[1], F_SETFL, (long) O_NONBLOCK);
	}

	if (!(pid1 = fork())) {
		setpgrp();
		role = SERVER;
		server(fds[1]);
	}
	read(fds[0], &status2, sizeof(status2));
	if (!(pid2 = fork())) {
		setpgrp();
		role = CLIENT;
		client(fds[0]);
	}
	waitpid(pid2, &status2, 0);
	kill(pid1, 15);
	waitpid(pid1, 0, 0);

	close(fds[0]);
	close(fds[1]);

	if (WIFEXITED(status2)) {
		return !!WEXITSTATUS(status2);
	} else {
		return 2;
	}
}

static int permutations2[2][2]
	= { { 0, 1 }, { 1, 0 } };
static const char* permutations2names[2]
	= { "01", "10" };
static int permutations3[6][3]
	= { { 0, 1, 2 }, { 0, 2, 1 },
		{ 1, 0, 2 }, { 1, 2, 0 },
		{ 2, 0, 1 }, { 2, 1, 0 } };
static const char* permutations3names[6]
	= { "012", "021", "102", "120", "201", "210" };
static filter_fn filters[8]
	= { filter_packet_ServerHello,
		filter_packet_ServerKeyExchange,
		filter_packet_ServerHelloDone,
		filter_packet_ClientKeyExchange,
		filter_packet_ClientChangeCipherSpec,
		filter_packet_ClientFinished,
		filter_packet_ServerChangeCipherSpec,
		filter_packet_ServerFinished };
static const char* filter_names[8]
	= { "SHello",
		"SKeyExchange",
		"SHelloDone",
		"CKeyExchange",
		"CChangeCipherSpec",
		"CFinished",
		"SChangeCipherSpec",
		"SFinished" };

static
int run_one_test(int dropMode, int serverFinishedPermute, int serverHelloPermute, int clientFinishedPermute)
{
	int fnIdx = 0;
	int filterIdx, res;
	run_id = ((dropMode * 2 + serverFinishedPermute) * 6 + serverHelloPermute) * 6 + clientFinishedPermute;

	filter_clear_state();

	filter_chain[fnIdx++] = filter_permute_ServerHello;
	state_permute_ServerHello.order = permutations3[serverHelloPermute];

	filter_chain[fnIdx++] = filter_permute_ServerFinished;
	state_permute_ServerFinished.order = permutations2[serverFinishedPermute];
	
	filter_chain[fnIdx++] = filter_permute_ClientFinished;
	state_permute_ClientFinished.order = permutations3[clientFinishedPermute];

	if (dropMode) {
		for (filterIdx = 0; filterIdx < 8; filterIdx++) {
			if (dropMode & (1 << filterIdx)) {
				filter_chain[fnIdx++] = filters[filterIdx];
			}
		}
	}
	filter_chain[fnIdx++] = NULL;

	res = run_test();

	switch (res) {
		case 0:
			fprintf(stdout, "%i ++ ", run_id);
			break;
		case 1:
			fprintf(stdout, "%i -- ", run_id);
			break;
		case 2:
			fprintf(stdout, "%i !! ", run_id);
			break;
	}

	fprintf(stdout, "SHello(%s), ", permutations3names[serverHelloPermute]);
	fprintf(stdout, "SFinished(%s), ", permutations2names[serverFinishedPermute]);
	fprintf(stdout, "CFinished(%s) :- ", permutations3names[clientFinishedPermute]);
	if (dropMode) {
		for (filterIdx = 0; filterIdx < 8; filterIdx++) {
			if (dropMode & (1 << filterIdx)) {
				if (dropMode & ((1 << filterIdx) - 1)) {
					fprintf(stdout, ", ");
				}
				fprintf(stdout, "%s", filter_names[filterIdx]);
			}
		}
	}
	fprintf(stdout, "\n");

	if (res && debug) {
		return 1;
	} else {
		return 0;
	}
}

static
void run_tests(int childcount)
{
	int children = 0;
	int dropMode, serverFinishedPermute, serverHelloPermute, clientFinishedPermute;

	for (dropMode = 0; dropMode != 1 << 8; dropMode++)
	for (serverFinishedPermute = 0; serverFinishedPermute < 2; serverFinishedPermute++)
	for (serverHelloPermute = 0; serverHelloPermute < 6; serverHelloPermute++)
	for (clientFinishedPermute = 0; clientFinishedPermute < 6; clientFinishedPermute++) {
		if (!fork()) {
			exit(run_one_test(dropMode, serverFinishedPermute, serverHelloPermute, clientFinishedPermute));
		} else {
			children++;
			while (children >= childcount) {
				wait(0);
				children--;
			}
		}
	}

	while (children > 0) {
		wait(0);
		children--;
	}
}



int main(int argc, const char* argv[])
{
int arg;

	setlinebuf(stdout);
	gnutls_global_init();
	gnutls_global_set_log_function(logfn);
	gnutls_global_set_audit_log_function(auditfn);

	nonblock = 0;
	debug = 0;

	if (argc == 1) {
		run_tests(100);
	} else {
		int dropMode = 0;
		int serverFinishedPermute = 0;
		int serverHelloPermute = 0;
		int clientFinishedPermute = 0;

		for (arg = 1; arg < argc; arg++) {
			if (strcmp("-shello", argv[arg]) == 0) {
				arg++;
				if (arg >= argc) {
					fprintf(stderr, "No arg to -shello\n");
					exit(1);
				}
				while (serverHelloPermute < 6) {
					if (strcmp(permutations3names[serverHelloPermute], argv[arg]) == 0) {
						break;
					}
					serverHelloPermute++;
				}
				if (serverHelloPermute == 6) {
					fprintf(stderr, "Unknown permutation %s\n", argv[arg]);
					exit(1);
				}
			} else if (strcmp("-d", argv[arg]) == 0) {
				debug++;
			} else if (strcmp("-sfinished", argv[arg]) == 0) {
				arg++;
				if (arg >= argc) {
					fprintf(stderr, "No arg to -sfinished\n");
					exit(1);
				}
				while (serverFinishedPermute < 2) {
					if (strcmp(permutations2names[serverFinishedPermute], argv[arg]) == 0) {
						break;
					}
					serverFinishedPermute++;
				}
				if (serverFinishedPermute == 2) {
					fprintf(stderr, "Unknown permutation %s\n", argv[arg]);
					exit(1);
				}
			} else if (strcmp("-cfinished", argv[arg]) == 0) {
				arg++;
				if (arg >= argc) {
					fprintf(stderr, "No arg to -cfinished\n");
					exit(1);
				}
				while (clientFinishedPermute < 6) {
					if (strcmp(permutations3names[clientFinishedPermute], argv[arg]) == 0) {
						break;
					}
					clientFinishedPermute++;
				}
				if (clientFinishedPermute == 6) {
					fprintf(stderr, "Unknown permutation %s\n", argv[arg]);
					exit(1);
				}
			} else {
				int drop;
				for (drop = 0; drop < 8; drop++) {
					if (strcmp(filter_names[drop], argv[arg]) == 0) {
						dropMode |= (1 << drop);
						break;
					}
				}
				if (drop == 8) {
					fprintf(stderr, "Unknown packet %s\n", argv[arg]);
					exit(8);
				}
			}
		}
		
		if (debug)
			gnutls_global_set_log_level(99);
		run_one_test(dropMode, serverFinishedPermute, serverHelloPermute, clientFinishedPermute);
	}

	gnutls_global_deinit();
}

