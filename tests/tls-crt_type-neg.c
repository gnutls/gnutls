/*
 * Copyright (C) 2017 - 2018 ARPA2 project
 *
 * Author: Tom Vrancken
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* This program tests the certificate type negotiation mechnism for
 * the handshake as specified in RFC7250 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include "utils.h"
#include "cert-common.h"
#include "eagain-common.h"
#include "crt_type-neg-common.c"

test_case_st tests[] = {
	/* Tests with only a single credential set for client/server.
	 * Tests for X.509 cases.
	 */
	{
		/* Default case A
		 *
		 * Priority cli: NORMAL
		 * Priority srv: NORMAL
		 * Certificate negotiation mechanism: disabled
		 * Cli creds: None
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: cert types should default to X.509
		 */
	 .name = "Default case A. Neg off (default). Creds set (CLI/SRV): None/X509.",
	 .client_prio = "NORMAL",
	 .server_prio = "NORMAL",
	 .set_cli_creds = CRED_EMPTY,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = false,
	 .enable_cert_type_neg_srv = false},
	{
		/* Default case B
		 *
		 * Priority: NORMAL
		 * Certificate negotiation mechanism: disabled
		 * Cli creds: X.509
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: cert types should default to X.509
		 */
	 .name = "Default case B. Neg off (default). Creds set (CLI/SRV): X509/X509.",
	 .client_prio = "NORMAL",
	 .server_prio = "NORMAL",
	 .set_cli_creds = CRED_X509,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = false,
	 .enable_cert_type_neg_srv = false},
	{
		/* No server credentials
		 *
		 * Priority: NORMAL
		 * Certificate negotiation mechanism: disabled
		 * Cli creds: None
		 * Srv creds: None
		 * Handshake: results in errors
		 * Negotiation: cert types are not evaluated
		 */
	 .name = "No server creds. Creds set (CLI/SRV): None/None.",
	 .client_prio = "NORMAL",
	 .server_prio = "NORMAL",
	 .set_cli_creds = CRED_EMPTY,
	 .set_srv_creds = CRED_EMPTY,
	 .client_err = GNUTLS_E_AGAIN,
	 .server_err = GNUTLS_E_NO_CIPHER_SUITES,
	 .enable_cert_type_neg_cli = false,
	 .enable_cert_type_neg_srv = false},
	{
		/* Client can negotiate, server not
		 *
		 * Priority: NORMAL
		 * Certificate negotiation mechanism (cli/srv): enabled/disabled
		 * Cli creds: None
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: cert types should default to X.509
		 */
	 .name = "Client can negotiate, server not",
	 .client_prio = "NORMAL",
	 .server_prio = "NORMAL",
	 .set_cli_creds = CRED_EMPTY,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = true,
	 .enable_cert_type_neg_srv = false},
	{
		/* Server can negotiate, client not
		 *
		 * Priority: NORMAL
		 * Certificate negotiation mechanism (cli/srv): disabled/enabled
		 * Cli creds: None
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: cert types should default to X.509
		 */
	 .name = "Server can negotiate, client not",
	 .client_prio = "NORMAL",
	 .server_prio = "NORMAL",
	 .set_cli_creds = CRED_EMPTY,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = false,
	 .enable_cert_type_neg_srv = true},
	{
		/* Client and server can negotiate
		 *
		 * Priority: NORMAL
		 * Certificate negotiation mechanism (cli/srv): enabled/enabled
		 * Cli creds: None
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: cert types should default to X.509
		 */
	 .name = "Client and server can negotiate",
	 .client_prio = "NORMAL",
	 .server_prio = "NORMAL",
	 .set_cli_creds = CRED_EMPTY,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = true,
	 .enable_cert_type_neg_srv = true},
	{
		/* Negotiate both, cli creds x509, srv creds x509
		 *
		 * Priority: NORMAL + request x509 for cli and srv
		 * Certificate negotiation mechanism (cli/srv): enabled/enabled
		 * Cli creds: X.509
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: Fallback to default cli X.509, srv X.509 because
		 *   we advertise with only the cert type defaults.
		 */
	 .name = "Negotiate CLI X.509 + SRV X.509, cli/srv X.509 creds set",
	 .client_prio = "NORMAL:+CTYPE-CLI-X509:+CTYPE-SRV-X509",
	 .server_prio = "NORMAL:+CTYPE-CLI-X509:+CTYPE-SRV-X509",
	 .set_cli_creds = CRED_X509,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = true,
	 .enable_cert_type_neg_srv = true},
	{
		/* Negotiate cli x509, cli creds x509, srv creds x509
		 *
		 * Priority: NORMAL + request x509 for cli
		 * Certificate negotiation mechanism (cli/srv): enabled/enabled
		 * Cli creds: X.509
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: Fallback to default cli X.509, srv X.509 because
		 *   we advertise with only the cert type defaults.
		 */
	 .name = "Negotiate CLI X.509, cli/srv X.509 creds set",
	 .client_prio = "NORMAL:+CTYPE-CLI-X509",
	 .server_prio = "NORMAL:+CTYPE-CLI-X509",
	 .set_cli_creds = CRED_X509,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = true,
	 .enable_cert_type_neg_srv = true},
	{
		/* Negotiate srv x509, cli creds x509, srv creds x509
		 *
		 * Priority: NORMAL + request x509 for srv
		 * Certificate negotiation mechanism (cli/srv): enabled/enabled
		 * Cli creds: X.509
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: Fallback to default cli X.509, srv X.509 because
		 *   we advertise with only the cert type defaults.
		 */
	 .name = "Negotiate SRV X.509, cli/srv X.509 creds set",
	 .client_prio = "NORMAL:+CTYPE-SRV-X509",
	 .server_prio = "NORMAL:+CTYPE-SRV-X509",
	 .set_cli_creds = CRED_X509,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = true,
	 .enable_cert_type_neg_srv = true},
	{
		/* All types allowed for CLI, cli creds x509, srv creds x509
		 *
		 * Priority: NORMAL + allow all client cert types
		 * Certificate negotiation mechanism (cli/srv): enabled/enabled
		 * Cli creds: X.509
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: Fallback to default cli X.509, srv X.509 because
		 *   we advertise with only the cert type defaults.
		 */
	 .name = "Negotiate CLI all, cli/srv X.509 creds set",
	 .client_prio = "NORMAL:+CTYPE-CLI-ALL",
	 .server_prio = "NORMAL:+CTYPE-CLI-ALL",
	 .set_cli_creds = CRED_X509,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = true,
	 .enable_cert_type_neg_srv = true},
	{
		/* All types allowed for SRV, cli creds x509, srv creds x509
		 *
		 * Priority: NORMAL + allow all server cert types
		 * Certificate negotiation mechanism (cli/srv): enabled/enabled
		 * Cli creds: X.509
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: Fallback to default cli X.509, srv X.509 because
		 *   we advertise with only the cert type defaults.
		 */
	 .name = "Negotiate SRV all, cli/srv X.509 creds set",
	 .client_prio = "NORMAL:+CTYPE-SRV-ALL",
	 .server_prio = "NORMAL:+CTYPE-SRV-ALL",
	 .set_cli_creds = CRED_X509,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = true,
	 .enable_cert_type_neg_srv = true},
	{
		/* All types allowed for CLI/SRV, cli creds x509, srv creds x509
		 *
		 * Priority: NORMAL + allow all client and server cert types
		 * Certificate negotiation mechanism (cli/srv): enabled/enabled
		 * Cli creds: X.509
		 * Srv creds: X.509
		 * Handshake: should complete without errors
		 * Negotiation: Fallback to default cli X.509, srv X.509 because
		 *   we advertise with only the cert type defaults.
		 */
	 .name = "Negotiate CLI/SRV all, cli/srv X.509 creds set",
	 .client_prio = "NORMAL:+CTYPE-CLI-ALL:+CTYPE-SRV-ALL",
	 .server_prio = "NORMAL:+CTYPE-CLI-ALL:+CTYPE-SRV-ALL",
	 .set_cli_creds = CRED_X509,
	 .set_srv_creds = CRED_X509,
	 .expected_cli_ctype = GNUTLS_CRT_X509,
	 .expected_srv_ctype = GNUTLS_CRT_X509,
	 .enable_cert_type_neg_cli = true,
	 .enable_cert_type_neg_srv = true}

	/* Tests with only a single credential set for client/server.
	 * Tests for Raw public-key cases.
	 */
	//TODO implement when Raw public key support is finished

	/* Tests with only a single credential set for client/server.
	 * Tests for KDH cases.
	 */
	//TODO implement when KDH support is finished

	/* Tests with multiple credentials set for client/server. */
	//TODO implement when support for more cert types is ready
};

void doit(void)
{
	unsigned i;
	global_init();

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		try(&tests[i]);
	}

	gnutls_global_deinit();
}
