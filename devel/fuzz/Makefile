# Copyright (C) 2016 Red Hat, Inc.
#
# This file is part of GnuTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

CC="gcc"
CFLAGS=-g -fsanitize=address -fsanitize=undefined
COMMON=-I../../lib/includes -L../../lib/.libs -Wl,-rpath=../../lib/.libs -lgnutls

all: gnutls_pkcs7_parser_fuzzer gnutls_client_fuzzer gnutls_dn_parser_fuzzer \
	gnutls_openpgp_cert_parser_fuzzer gnutls_pkcs7_parser_fuzzer gnutls_pkcs8_key_parser_fuzzer \
	gnutls_private_key_parser_fuzzer gnutls_server_fuzzer gnutls_x509_parser_fuzzer

gnutls_pkcs7_parser_fuzzer: gnutls_pkcs7_parser_fuzzer.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

gnutls_client_fuzzer: gnutls_client_fuzzer.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

gnutls_dn_parser_fuzzer: gnutls_dn_parser_fuzzer.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

gnutls_openpgp_cert_parser_fuzzer: gnutls_openpgp_cert_parser_fuzzer.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

gnutls_pkcs8_key_parser_fuzzer: gnutls_pkcs8_key_parser_fuzzer.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

gnutls_private_key_parser_fuzzer: gnutls_private_key_parser_fuzzer.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

gnutls_server_fuzzer: gnutls_server_fuzzer.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

gnutls_x509_parser_fuzzer: gnutls_x509_parser_fuzzer.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

clean:
	rm -f gnutls_pkcs7_parser_fuzzer gnutls_client_fuzzer gnutls_dn_parser_fuzzer \
	gnutls_openpgp_cert_parser_fuzzer gnutls_pkcs7_parser_fuzzer gnutls_pkcs8_key_parser_fuzzer \
	gnutls_private_key_parser_fuzzer gnutls_server_fuzzer gnutls_x509_parser_fuzzer
