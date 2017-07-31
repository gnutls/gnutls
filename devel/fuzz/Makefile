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

CC?="afl-gcc"
#CFLAGS?=-g -fsanitize=address -fsanitize=undefined
COMMON=-I../../lib/includes -L../../lib/.libs -Wl,-rpath=../../lib/.libs -lgnutls

all: gnutls_pkcs7_parser_fuzzer gnutls_client_fuzzer gnutls_dn_parser_fuzzer \
	gnutls_pkcs7_parser_fuzzer gnutls_pkcs8_key_parser_fuzzer \
	gnutls_private_key_parser_fuzzer gnutls_server_fuzzer gnutls_x509_parser_fuzzer \
	gnutls_reverse_idna_parser_fuzzer gnutls_idna_parser_fuzzer gnutls_ocsp_resp_parser_fuzzer \
	gnutls_ocsp_req_parser_fuzzer gnutls_pkcs12_key_parser_fuzzer gnutls_base64_decoder_fuzzer \
	gnutls_base64_encoder_fuzzer gnutls_psk_client_fuzzer gnutls_psk_server_fuzzer \
	gnutls_srp_client_fuzzer gnutls_srp_server_fuzzer

%: %.cc
	$(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@

clean:
	rm -f gnutls_pkcs7_parser_fuzzer gnutls_client_fuzzer gnutls_dn_parser_fuzzer \
	gnutls_pkcs7_parser_fuzzer gnutls_pkcs8_key_parser_fuzzer \
	gnutls_private_key_parser_fuzzer gnutls_server_fuzzer gnutls_x509_parser_fuzzer \
	gnutls_idna_parser_fuzzer gnutls_reverse_idna_parser_fuzzer gnutls_ocsp_resp_parser_fuzzer \
	gnutls_ocsp_req_parser_fuzzer gnutls_base64_decoder_fuzzer \
	gnutls_base64_encoder_fuzzer gnutls_psk_client_fuzzer gnutls_psk_server_fuzzer

update:
	@git clone --depth=1 https://github.com/openssl/openssl openssl.tmp
	@cp openssl.tmp/fuzz/corpora/x509/* gnutls_x509_parser.in
	@cp openssl.tmp/fuzz/corpora/server/* gnutls_server.in
	@cp openssl.tmp/fuzz/corpora/client/* gnutls_client.in
	@rm -rf openssl.tmp
	@echo "Updated corpus/trace files. Use git status to identify them and commit them."
