/*
 * Copyright (C) 2004 Free Software Foundation
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

#include <cfg+.h>

char *organization = NULL, *unit = NULL, *locality = NULL, *state = NULL;
char *cn = NULL, *challenge_password = NULL, *pkcs9_email = NULL, *country = NULL;
char *dns_name = NULL, *email = NULL, *crl_dist_points = NULL, *password= NULL;
int serial = 0, expiration_days=0, ca=0, tls_www_client=0, tls_www_server=0, signing_key=0;
int encryption_key=0, cert_sign_key=0, crl_sign_key=0, code_sign_key=0, ocsp_sign_key=0;
int time_stamping_key=0;

int parse_template(const char *template)
{
	/* libcfg+ parsing context */
	CFG_CONTEXT con;

	/* Parsing return code */
	register int ret;

	/* Option variables */

	/* Option set */
	struct cfg_option options[] = {
		{NULL, '\0', "organization", CFG_STR, (void *) &organization, 0},
		{NULL, '\0', "unit", CFG_STR, (void *) &unit, 0},
		{NULL, '\0', "locality", CFG_STR, (void *) &locality, 0},
		{NULL, '\0', "state", CFG_STR, (void *) &state, 0},
		{NULL, '\0', "cn", CFG_STR, (void *) &cn, 0},
		{NULL, '\0', "challenge_password", CFG_STR, (void *) &challenge_password, 0},
		{NULL, '\0', "password", CFG_STR, (void *) &password, 0},
		{NULL, '\0', "pkcs9_email", CFG_STR, (void *) &pkcs9_email, 0},
		{NULL, '\0', "country", CFG_STR, (void *) &country, 0},
		{NULL,    '\0', "dns_name",      CFG_STR,          (void *) &dns_name,     0},
		{NULL,    '\0', "email",      CFG_STR,          (void *) &email,     0},
		{NULL, '\0', "crl_dist_points", CFG_STR, (void *) &crl_dist_points, 0},

		{NULL,    '\0', "serial",      CFG_INT,          (void *) &serial,     0},
		{NULL,    '\0', "expiration_days",      CFG_INT,          (void *) &expiration_days,     0},

		{NULL,    '\0', "ca",      CFG_BOOL,          (void *) &ca,     0},
		{NULL,    '\0', "tls_www_client",      CFG_BOOL,          (void *) &tls_www_client,     0},
		{NULL,    '\0', "tls_www_server",      CFG_BOOL,          (void *) &tls_www_server,     0},
		{NULL,    '\0', "signing_key",      CFG_BOOL,          (void *) &signing_key,     0},
		{NULL,    '\0', "encryption_key",      CFG_BOOL,          (void *) &encryption_key,     0},
		{NULL,    '\0', "cert_signing_key",      CFG_BOOL,          (void *) &cert_sign_key,     0},
		{NULL,    '\0', "crl_signing_key",      CFG_BOOL,          (void *) &crl_sign_key,     0},
		{NULL,    '\0', "code_signing_key",      CFG_BOOL,          (void *) &code_sign_key,     0},
		{NULL,    '\0', "ocsp_signing_key",      CFG_BOOL,          (void *) &ocsp_sign_key,     0},
		{NULL,    '\0', "time_stamping_key",      CFG_BOOL,          (void *) &time_stamping_key, 0},
		CFG_END_OF_LIST
	};

	/* Creating context */
	con = cfg_get_context(options);
	if (con == NULL) {
		puts("Not enough memory");
		exit(1);
	}

	cfg_set_cfgfile_context(con, 0, -1, template);

	/* Parsing command line */
	ret = cfg_parse(con);

	if (ret != CFG_OK) {
		printf("error parsing command line: %s: ", template);
		cfg_fprint_error(con, stdout);
		putchar('\n');
		exit( ret < 0 ? -ret : ret);
	}

	return 0;
}
