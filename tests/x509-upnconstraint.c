/*
 * Copyright (C) 2022 Brian Wickman
 *
 * Author: Brian Wickman
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "utils.h"
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/x509-ext.h>

#include <stdbool.h>

/* Test that UPN OTHERNAME constraints in a CA certificate are parsed correctly
 *
 * Test that a leaf certificate with a DNSName validates correctly
 * when issued by a CA with UPN OTHERNAME constraints (Issue 1132)
 * (UPN == User Principal Name - used in Active Directory
 * environments using smartcards for authentication)
 */

void verify_upn_constraints(gnutls_x509_name_constraints_t);
void verify_leaf(const gnutls_x509_crt_t *, unsigned,
		 gnutls_x509_name_constraints_t, const char *, const char *,
		 unsigned, bool);

static const char _domaincontroller[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEIjCCAwqgAwIBAgIUE/05VErpwLTz8EmFwbcH6j8xBaEwDQYJKoZIhvcNAQEL\n"
	"BQAwNDEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMRswGQYDVQQDDBJFeGFtcGxlIENv\n"
	"cnAgQUQgQ0EwHhcNMjYwODE0MTI0MzExWhcNMjcwODE0MTI0MzExWjAiMSAwHgYD\n"
	"VQQDDBdleGFtcGxlZGMwMS5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\n"
	"ggEPADCCAQoCggEBAIkk/DHp6jfdqkQIUkIy+42pqeRD0QYbvnvSlDqAfthBBmnf\n"
	"YMGZCjUOOybM+FYbP4x8smF5eMOzqpTgpvbYftqOraqWD3wk3UpiSIJFya5t0NWK\n"
	"TsuMDn6dCgNewwI2G4DdFV3XcAKlByO0oTvjLhW2C7n7jed+IWpNFNbAsah8alUe\n"
	"gQvDYN7AlRRHzJRrzO0IlzcWihpHMTy+cwD1+tpUHVUAMw1EfkpEQk64QMS7ULYU\n"
	"16m7Ed4zhTqaiopoPTP6kcGbdwXZU07yRR5dTE1wpCKrD1RUQQjxhJrUGKHfZ8y1\n"
	"SLC5SLvD2J1jkGL6zAf1UM4etCe9XN6y4OL6SQMCAwEAAaOCATwwggE4MAwGA1Ud\n"
	"EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\n"
	"BgEFBQcDAjA0BgNVHREELTArghdleGFtcGxlZGMwMS5leGFtcGxlLmNvbYIQbGRh\n"
	"cC5leGFtcGxlLmNvbTA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vcGtpLmV4YW1w\n"
	"bGUuY29tL2NkcC9FeGFtcGxlQURDQS5jcmwwRgYIKwYBBQUHAQEEOjA4MDYGCCsG\n"
	"AQUFBzAChipodHRwOi8vcGtpLmV4YW1wbGUuY29tL2FpYS9FeGFtcGxlQURDQS5j\n"
	"ZXIwHQYDVR0OBBYEFClqogDiApw9Pk/p38ylfnUpkuxcMB8GA1UdIwQYMBaAFFCX\n"
	"R+0zjvq4+SIYwOhimX7pqDu9MA0GCSqGSIb3DQEBCwUAA4IBAQBLljdFr7+jRwU2\n"
	"ssMIlo+EMU8kuby8FTd7TJOfJwtxOK4a2gsn7ql0py2U66dQj1xthISVrVJynMH9\n"
	"+m6W5QfLE4LXbzzYMEZ1B7wXw9S9ATqFLppeSlMLgZshkKreUH/Aq+hEsBRdgjmt\n"
	"WS2r9yp5JOv6Sjpwb/P3nVm33UyvrNUg/ls5/Uxj5DPFUwl6M0AXcAmNaiysuKio\n"
	"qj5R+3eSjHqPMGOl2hIhyoxp6gr+udm+OjifZDfZ4Ak6n5lYXD1qZhyPdz91D2kD\n"
	"uPdk+nIVa5yrqp6rgrc4Tb/CoU9vgLgkW7yG4CejVTJTDzVuUMrKLulvAfK4q1Ax\n"
	"ZbEbl7om\n"
	"-----END CERTIFICATE-----"
};

static const char _issuingca[] = {
	/* The intermediate CA with name constraints */
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEpDCCA4ygAwIBAgIUMztfVtTqmNvjWf03pkzYTzQXe3gwDQYJKoZIhvcNAQEL\n"
	"BQAwNjEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR0wGwYDVQQDDBRFeGFtcGxlIENv\n"
	"cnAgUm9vdCBDQTAeFw0yNjA4MTQxMjI5MDRaFw0zNjA4MTExMjI5MDRaMDQxFTAT\n"
	"BgNVBAoMDEV4YW1wbGUgSW5jLjEbMBkGA1UEAwwSRXhhbXBsZSBDb3JwIEFEIENB\n"
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Y5IEKNBSsuT4dZ9o6gG\n"
	"mGaPErvfr0PKAnRBHoClJJPwlrsk0q+VHqCTrnda5DGjZEe/NM/PDRQl3Nxyx40D\n"
	"XmmYLobeo15HYdyht5D4F6yJOZ0mbqzpsUq29WxK028XJz7Ds//4IQ2DPIgfHc1W\n"
	"QddE6JA04gFkRQ3Arrrx7nd5R2F50Bup+fYJTLEFFYbXf+/8ClqBCna3Cdi/AOsP\n"
	"umbWZpZvJA8QDnuo0bFtD5rztB87bYKb5jh30vig+rKm812zXmyaoXtMjsT14Azl\n"
	"/RYRhIWGwf+BGAlMJhhHV+R6cMZ/bXxmIFoeoNTVWl7xo8ZuAUJkN0y4rmxXMImF\n"
	"zQIDAQABo4IBqjCCAaYwEgYDVR0TAQH/BAgwBgEB/wIBADALBgNVHQ8EBAMCAYYw\n"
	"HQYDVR0OBBYEFFCXR+0zjvq4+SIYwOhimX7pqDu9MB8GA1UdIwQYMBaAFIlLkhdt\n"
	"gHDNkZBLiBUz0xYdZj4IMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9wa2kuZXhh\n"
	"bXBsZS5jb20vY2RwL0V4YW1wbGVSb290LmNybDCCAQQGA1UdHgEB/wSB+TCB9qBq\n"
	"MA2CC2V4YW1wbGUuY29tMA6CDC5leGFtcGxlLmNvbTAJggdFWEFNUExFMB6gHAYK\n"
	"KwYBBAGCNxQCA6AODAxAZXhhbXBsZS5jb20wHqAcBgorBgEEAYI3FAIDoA4MDC5l\n"
	"eGFtcGxlLmNvbaGBhzAXghVzdWJkb21haW4uZXhhbXBsZS5jb20wGIIWLnN1YmRv\n"
	"bWFpbi5leGFtcGxlLmNvbTAooCYGCisGAQQBgjcUAgOgGAwWQHN1YmRvbWFpbi5l\n"
	"eGFtcGxlLmNvbTAooCYGCisGAQQBgjcUAgOgGAwWLnN1YmRvbWFpbi5leGFtcGxl\n"
	"LmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAE2sdsEZMmfP1McdAc8Ww4sXbIu3GbPYw\n"
	"fYiukveJPUhAYsIDFfudpqnoaZyNYdeMi+3VjE4UnjH9tG3tGIQlBL2t3ITtXPnD\n"
	"JDsDwbLWRqO2QuSXKPk/Q8P/N7rX20Z6KnGk5KxaPTsaTM+rdckMGRxuTYknUEF9\n"
	"t0DIBsj/X7oFxpCW3uBBl3l3TXR4Uwn8tltHpW9KW2CDqPyAdmkcNLuFteSRRm63\n"
	"DNzG0CPLUcmT0eJQmgBxPw+sq8y13qdfkiGbOQG9nYeGxHIUKYdZbQWK21fzFUIo\n"
	"m0vG1t/gTxtyOQrIBWfpDI59pChZiGq3u0haaX9qrYsVlV9kzgNIZg==\n"
	"-----END CERTIFICATE-----\n"
};

static const char _rootca[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDXTCCAkWgAwIBAgIUYZX1t9BkTOKLka9yTXNTZmvw+NowDQYJKoZIhvcNAQEL\n"
	"BQAwNjEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR0wGwYDVQQDDBRFeGFtcGxlIENv\n"
	"cnAgUm9vdCBDQTAeFw0yNjA4MTQxMjI0MzVaFw00NjA4MDkxMjI0MzVaMDYxFTAT\n"
	"BgNVBAoMDEV4YW1wbGUgSW5jLjEdMBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3Qg\n"
	"Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCz7dh2aa4Ha1xv73UQ\n"
	"Iu3Dtmg8qBw/tBPou2lOwQu8lfvy/Stt0RsAtMlHdGv6XgkJk4LT9kBwaxqAcBw6\n"
	"UGvvg/R2mk218mn/qCEE3+LeWELmDV13wMmuj3OTM4MdqK37k1dg3ydhlvW0E8+K\n"
	"F/ayXJdXPUBzJBN0W/zAHo9r0q7Au/fDZQGKUn63BK4D6jPO8RRjo5ONnVT98uhB\n"
	"xQook2/Ip2+uY1JMHqMFHQdhB+xMRrwCJyJEin33j1/WFrDkdlxhpEtad6H5IW0z\n"
	"kF4rKWHIdBcHmrDEe5OGx2kzUXN+bwUymo1r/u8q25ZYv9FLWIfEl81dxiB3m1gG\n"
	"oEtnAgMBAAGjYzBhMB8GA1UdIwQYMBaAFIlLkhdtgHDNkZBLiBUz0xYdZj4IMA8G\n"
	"A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSJS5IXbYBw\n"
	"zZGQS4gVM9MWHWY+CDANBgkqhkiG9w0BAQsFAAOCAQEAbNgfrSARnymvBmwJfscf\n"
	"xgSKtyuwZY290qF817kf+FnEVXKDK9mVz7wa1HBsJKQKOKN0Wx2vsKrLYN7mslyy\n"
	"6ZLBO2xY1jkV3K9cCAQp08kZo0sVtSD7iL9TBtDU5Pv0T16dZSODcm4lfQ8foLKW\n"
	"u/7N6ESxOIwgx0Cp2SIUNuiIjKgeoiXAh1w7hOucDSEasxWRk+Cny2mwSz2WP5Eu\n"
	"+vEua3cJJaibFjZ/r6/CuPiDd81zpr7EVjYQeGxJCnNlQEiWJhf72V8bEVPAMVWr\n"
	"ZYiJaPjr/WCy5eQXOVpYROp+0xMrIOkb+/4HM5mmsBt+5ikQeMX3rW67LO55csvp\n"
	"5A==\n"
	"-----END CERTIFICATE-----\n"
};

const unsigned char example3[] = "@example.com";
const unsigned char example4[] = ".example.com";
const unsigned char subdomain2[] = "@subdomain.example.com";
const unsigned char subdomain3[] = ".subdomain.example.com";

void verify_upn_constraints(gnutls_x509_name_constraints_t name_constraints)
{
	int ret = 0;
	unsigned int type = 0;
	gnutls_datum_t constraint = { NULL, 0 };
	ret = gnutls_x509_name_constraints_get_permitted(name_constraints, 3,
							 &type, &constraint);
	if (ret < 0)
		fail("Error getting permitted constraint: %s\n",
		     gnutls_strerror(ret));

	if (type != GNUTLS_SAN_OTHERNAME_MSUSERPRINCIPAL)
		fail("Error permitted constraint 3 is not UPN, found: %u\n",
		     type);

	if ((constraint.size != sizeof(example3) - 1) ||
	    !memeq(constraint.data, example3, sizeof(example3) - 1))
		fail("Error permitted constraint 3 was %s expected %s\n",
		     constraint.data, example3);

	ret = gnutls_x509_name_constraints_get_permitted(name_constraints, 4,
							 &type, &constraint);
	if (ret < 0)
		fail("Error getting permitted constraint: %s\n",
		     gnutls_strerror(ret));

	if (type != GNUTLS_SAN_OTHERNAME_MSUSERPRINCIPAL)
		fail("Error permitted constraint 4 is not UPN, found: %u\n",
		     type);

	if ((constraint.size != sizeof(example4) - 1) ||
	    !memeq(constraint.data, example4, sizeof(example4) - 1))
		fail("Error permitted constraint 4 was %s expected %s\n",
		     constraint.data, example4);

	ret = gnutls_x509_name_constraints_get_excluded(name_constraints, 2,
							&type, &constraint);
	if (ret < 0)
		fail("Error getting excluded constraint: %s\n",
		     gnutls_strerror(ret));

	if (type != GNUTLS_SAN_OTHERNAME_MSUSERPRINCIPAL)
		fail("Error excluded constraint 2 is not UPN, found %u\n",
		     type);

	if ((constraint.size != sizeof(subdomain2) - 1) ||
	    !memeq(constraint.data, subdomain2, sizeof(subdomain2) - 1))
		fail("Error excluded constraint 2 was %s expected %s\n",
		     constraint.data, subdomain2);

	ret = gnutls_x509_name_constraints_get_excluded(name_constraints, 3,
							&type, &constraint);
	if (ret < 0)
		fail("Error getting excluded constraint: %s\n",
		     gnutls_strerror(ret));

	if (type != GNUTLS_SAN_OTHERNAME_MSUSERPRINCIPAL)
		fail("Error excluded constraint 3 is not UPN, found %u\n",
		     type);

	if ((constraint.size != sizeof(subdomain3) - 1) ||
	    !memeq(constraint.data, subdomain3, sizeof(subdomain3) - 1))
		fail("Error excluded constraint 3 was %s expected %s\n",
		     constraint.data, subdomain3);
}

void verify_leaf(const gnutls_x509_crt_t *chain, unsigned chain_len,
		 gnutls_x509_name_constraints_t name_constraints,
		 const char *label, const char *cert_pem, unsigned san_type,
		 bool expect_pass)
{
	int ret;
	gnutls_x509_crt_t crt;
	gnutls_datum_t datum = { (void *)cert_pem, strlen(cert_pem) };
	unsigned status;
	bool violated;

	gnutls_x509_crt_init(&crt);

	ret = gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("Error importing %s cert: %s\n", label,
		     gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_check_crt(name_constraints, san_type,
						     crt);

	if (expect_pass && ret <= 0)
		fail("Error %s leaf constraint rejected unexpectedly\n", label);
	else if (!expect_pass && ret > 0)
		fail("Error %s leaf constraint accepted unexpectedly\n", label);

	ret = gnutls_x509_crt_verify(crt, chain, chain_len,
				     GNUTLS_VERIFY_DISABLE_TIME_CHECKS,
				     &status);
	if (ret < 0)
		fail("Error %s certificate verify error: %s\n", label,
		     gnutls_strerror(ret));
	violated = status & GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE;

	if (expect_pass && violated)
		fail("Error %s certificate rejected unexpectedly\n", label);
	else if (!expect_pass && !violated)
		fail("Error %s certificate accepted unexpectedly\n", label);

	gnutls_x509_crt_deinit(crt);
}

void doit(void)
{
	int ret;
	unsigned int critical = 0;
	gnutls_x509_crt_t issuingca, rootca;
	gnutls_x509_crt_t chain[2];
	gnutls_datum_t issuingca_datum = { (void *)_issuingca,
					   sizeof(_issuingca) - 1 };
	gnutls_datum_t rootca_datum = { (void *)_rootca, sizeof(_rootca) - 1 };

	global_init();

	gnutls_x509_crt_init(&issuingca);
	ret = gnutls_x509_crt_import(issuingca, &issuingca_datum,
				     GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("Error importing issuing CA: %s\n", gnutls_strerror(ret));

	gnutls_x509_crt_init(&rootca);
	ret = gnutls_x509_crt_import(rootca, &rootca_datum,
				     GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("Error importing root CA: %s\n", gnutls_strerror(ret));

	chain[0] = issuingca;
	chain[1] = rootca;

	gnutls_x509_name_constraints_t name_constraints = NULL;

	ret = gnutls_x509_name_constraints_init(&name_constraints);
	if (ret < 0)
		fail("Error initializing constraints structure: %s\n",
		     gnutls_strerror(ret));

	ret = gnutls_x509_crt_get_name_constraints(issuingca, name_constraints,
						   0, &critical);
	if (ret < 0) /* #1132 */
		fail("Error loading constraints\n");

	verify_upn_constraints(name_constraints);

	verify_leaf(chain, 2, name_constraints, "domaincontroller",
		    _domaincontroller, GNUTLS_SAN_DNSNAME, 1);

	gnutls_x509_name_constraints_deinit(name_constraints);
	gnutls_x509_crt_deinit(issuingca);
	gnutls_x509_crt_deinit(rootca);

	success("UPN constraints tests completed successfully\n");

	gnutls_global_deinit();
}

/* How the certs/keys above were generated:
$ UPN=1.3.6.1.4.1.311.20.2.3
$ openssl genrsa 2048 | tee root-ca.key
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCz7dh2aa4Ha1xv
73UQIu3Dtmg8qBw/tBPou2lOwQu8lfvy/Stt0RsAtMlHdGv6XgkJk4LT9kBwaxqA
cBw6UGvvg/R2mk218mn/qCEE3+LeWELmDV13wMmuj3OTM4MdqK37k1dg3ydhlvW0
E8+KF/ayXJdXPUBzJBN0W/zAHo9r0q7Au/fDZQGKUn63BK4D6jPO8RRjo5ONnVT9
8uhBxQook2/Ip2+uY1JMHqMFHQdhB+xMRrwCJyJEin33j1/WFrDkdlxhpEtad6H5
IW0zkF4rKWHIdBcHmrDEe5OGx2kzUXN+bwUymo1r/u8q25ZYv9FLWIfEl81dxiB3
m1gGoEtnAgMBAAECggEAASLvgiIvFLc/1A1j3YIr2/QaKQBdRcH0z8qtBlNftm/y
hvJvMtg0jPUXXl8BRLQRdcRpzy/tRba6Itj9GRlqm1WgiGKT5aJAEJdE4TudAbn2
bxlxShS8mHzw6cYNIZH+PDh/2/Sc4K0zJKal06ja+lLfSEkreoslLd4jGGLjsgSy
Ntk2CL/M9hGmLn7BPgmTod0ATcsDgRRCkZ3SWaXxGxizY98nqFaN8cggZf0soqt9
A/MSiUpQMlEYM8nTK+rcn2F9+uyyKht6X3SS108gIKCcTTEui35FP4uWI5lHpXFP
Fwl5xzepe7sDz16D6N4qijrl5Psjtr162pRtIEZfRQKBgQDeCiLpZd8O61s6uGzz
AyvnGiK/pLjK2iaXgCBKE6hTBYRU6sH+DfU+jTNQi7iDG4xs9b2cIIZD1PqHI9oN
xfq6E8U+mIQouzgq/tlwI/zb+CcQOZJwL58b5Z/2PnJ3GI9mQ31IUSetsfWfaxBn
A4GAAAXSTC3bBGAvwYYY/WTQYwKBgQDPcuP1wV2419QZnF5gvGofA15TBIkpU5Re
QmH6sKDwWnXX0wLnnZ5zMKJNshtTi5lO92EA31nKbYbqkKACVyP6ppElf7s9cJIS
uno+EdSEuQdyj4Kb4Nuvgjp3Ikd2n1aPcELm8937ASh7uut7BtxaDQlP8vtDRH3u
wBRlvGjOLQKBgFMy/yPvvSZNAHE/W+uvO4ssGusuoOO53I4WP4MiXIdHYO+ky64T
stqOdDTxNeFCuFq3tiXDdiwCqSFsSK+yiKGi+Nzcr2DHzmMl/XnssjoGgTSuLfYF
khwU7dyKR7/inxEVpuMrLbADJ+Nlbc773FGHMKc9Tk1sFVKvtDy27ki7AoGACi4J
IbYrczakId2ahAS68Gqp5kkCshR342g+hp7ERwcpYT3plpQVgnGQhV+IF8Fx9H4P
NIvBTD2zsS8HqxW7nkEuPjjWZ11uzZx5AzK8ywaJZwXD0wJlxWcOl2oHN7r59G/9
2Hd/HSIhanDxvUfI6GJbYqD504M46s5iMdvdCMECgYBtQ8FLgmnItRAB9T3L7n5c
RHWLUlUAdkGFnAZOYrwmSI/0R/KZ660G3MRvOqwOeKkMkRNd+zRXz/7VwjKlMk8U
il+mbxqjnExw7YmuAdjJP1HaCLA6ev7MY/MhlW9nSCfkYk9UGarMz4MgwYdMQ4a0
rzOj+kKFtlhOE5TRiV3jTA==
-----END PRIVATE KEY-----
$ openssl req -new -x509 -key root-ca.key -days 7300 \
              -subj "/O=Example Inc./CN=Example Corp Root CA" \
              -addext "basicConstraints=critical,CA:TRUE" \
              -addext "keyUsage=critical,keyCertSign,cRLSign" \
              -addext "subjectKeyIdentifier=hash" | tee root-ca.pem
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIUYZX1t9BkTOKLka9yTXNTZmvw+NowDQYJKoZIhvcNAQEL
BQAwNjEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR0wGwYDVQQDDBRFeGFtcGxlIENv
cnAgUm9vdCBDQTAeFw0yNjA4MTQxMjI0MzVaFw00NjA4MDkxMjI0MzVaMDYxFTAT
BgNVBAoMDEV4YW1wbGUgSW5jLjEdMBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3Qg
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCz7dh2aa4Ha1xv73UQ
Iu3Dtmg8qBw/tBPou2lOwQu8lfvy/Stt0RsAtMlHdGv6XgkJk4LT9kBwaxqAcBw6
UGvvg/R2mk218mn/qCEE3+LeWELmDV13wMmuj3OTM4MdqK37k1dg3ydhlvW0E8+K
F/ayXJdXPUBzJBN0W/zAHo9r0q7Au/fDZQGKUn63BK4D6jPO8RRjo5ONnVT98uhB
xQook2/Ip2+uY1JMHqMFHQdhB+xMRrwCJyJEin33j1/WFrDkdlxhpEtad6H5IW0z
kF4rKWHIdBcHmrDEe5OGx2kzUXN+bwUymo1r/u8q25ZYv9FLWIfEl81dxiB3m1gG
oEtnAgMBAAGjYzBhMB8GA1UdIwQYMBaAFIlLkhdtgHDNkZBLiBUz0xYdZj4IMA8G
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSJS5IXbYBw
zZGQS4gVM9MWHWY+CDANBgkqhkiG9w0BAQsFAAOCAQEAbNgfrSARnymvBmwJfscf
xgSKtyuwZY290qF817kf+FnEVXKDK9mVz7wa1HBsJKQKOKN0Wx2vsKrLYN7mslyy
6ZLBO2xY1jkV3K9cCAQp08kZo0sVtSD7iL9TBtDU5Pv0T16dZSODcm4lfQ8foLKW
u/7N6ESxOIwgx0Cp2SIUNuiIjKgeoiXAh1w7hOucDSEasxWRk+Cny2mwSz2WP5Eu
+vEua3cJJaibFjZ/r6/CuPiDd81zpr7EVjYQeGxJCnNlQEiWJhf72V8bEVPAMVWr
ZYiJaPjr/WCy5eQXOVpYROp+0xMrIOkb+/4HM5mmsBt+5ikQeMX3rW67LO55csvp
5A==
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee issuing-ca.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDljkgQo0FKy5Ph
1n2jqAaYZo8Su9+vQ8oCdEEegKUkk/CWuyTSr5UeoJOud1rkMaNkR780z88NFCXc
3HLHjQNeaZguht6jXkdh3KG3kPgXrIk5nSZurOmxSrb1bErTbxcnPsOz//ghDYM8
iB8dzVZB10TokDTiAWRFDcCuuvHud3lHYXnQG6n59glMsQUVhtd/7/wKWoEKdrcJ
2L8A6w+6ZtZmlm8kDxAOe6jRsW0PmvO0HzttgpvmOHfS+KD6sqbzXbNebJqhe0yO
xPXgDOX9FhGEhYbB/4EYCUwmGEdX5Hpwxn9tfGYgWh6g1NVaXvGjxm4BQmQ3TLiu
bFcwiYXNAgMBAAECggEAAf9WMLDe91HkqEUnxDYI0qgnzAuu81U1a4aL74JCjZos
8H7R3/RvqXvPtSesNoqZB50ZNJIvVMeNWcngRMy9EAP+sz7wrn66Q8d578E262vQ
qNvtcu6VvPlvtJx73TGdA7Yn2Ufbppv5vZvYm3eHLdz76EMi9ql48CHhwJN3WfIT
d9Z/6DME06qrPZ+L+hnAj97wBhOEN3GiRL0KPKy4v7KIzC2eQ+BkHiEOEG4fnVuI
SLVxFpOrjI9SbfxXXu3e3++Qz+8ABN7CE7aMl70HnQ5D9Ub5IlE9leXbnTxeg+hJ
8imMfFbowGcz+mYOjSsKRsLUfBy1lZun/S0ThiLZOQKBgQDyjA4mYq6ciaIBrr33
Qu3+b2kPsRLPjyht23TphH5+qtQ9z2+SiGYlZVZkgfJFjMk52n1yoPbESIFVYe2V
Vo4cjiBpnTDNd0v2aTmoJnujuvz7YNNbxeUgjiJtA09WESyI9PGELBIxStoawG3s
Eg3fFwUDGZRfenxwWQeNjT9hVQKBgQDyScL/nQuftJEgEIVb3p19F3xO/nd8E8iF
1/IKz9SjukMGtNGXXROmwGmHbsAk8C3N8YxTu7Uy+0MXh3rkdpSiuXCUKiRdxvXJ
Famxe1YRLLdTn4SkSe+MW+mPTBfz9TbUqYM14/kl/c/At2v77JUcEQdW9Cmb/s9X
VezyZQ7ymQKBgQCXx0L3jFs+Q/ZoXSQtPenWhXtWQXXHAwvGq0Ue+DV8KISGZW+p
X8ej8SU94f9svGwT0wEboVSqgcDFYHGfOTnW7q2jyaUHfna/rRtSeTp3vAShffbl
gBIg7DDozOBxuG+JCNa14ipERFX11aMzzhx2FV6ikPhDQ0/pshzC3LfjvQKBgHb/
e2KIA3mA+fZBpv4kLD2QF2HE4XJzVP1Hvn1I7issBFd636Xz9P7lae82mfCKdjS7
+iv1+Vz8w0r/I4CqLP5vDbf3qrzUR0tn9FxTM0ZkK/ZKVp9KIPlS+zeCLBGJ0lBI
oUUKnwflzO/eJo8o92M9idlPOlB/qd4/OY0jzV+hAoGAAcI54bUtf9qw2F5I15Of
uU0TEfF3Q6yef1NCESX3xBrWJFZXxr+tDimazutN8LvY6Xz7zgFdxCakbyqwPqw+
Rw9HdPVMeJt3C7SzBABsYcYjaF5+8bpZIeges+9lETJdpl2/M/7wIihT1gUJAkFN
ASEHGlxBCn8jaVfCIeM0QN8=
-----END PRIVATE KEY-----
$ openssl req -new -key issuing-ca.key \
              -subj "/O=Example Inc./CN=Example Corp AD CA" > issuing-ca.csr
$ openssl x509 -req -in issuing-ca.csr -CA root-ca.pem -CAkey root-ca.key \
               -CAcreateserial -days 3650 -sha256 \
               -out issuing-ca.pem -extfile - <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
crlDistributionPoints=URI:http://pki.example.com/cdp/ExampleRoot.crl
nameConstraints = critical, \
  permitted;DNS:example.com, \
  permitted;DNS:.example.com, \
  permitted;DNS:EXAMPLE, \
  permitted;otherName:${UPN};UTF8:@example.com, \
  permitted;otherName:${UPN};UTF8:.example.com, \
  excluded;DNS:subdomain.example.com, \
  excluded;DNS:.subdomain.example.com, \
  excluded;otherName:${UPN};UTF8:@subdomain.example.com, \
  excluded;otherName:${UPN};UTF8:.subdomain.example.com
EOF
$ cat issuing-ca.pem
-----BEGIN CERTIFICATE-----
MIIEpDCCA4ygAwIBAgIUMztfVtTqmNvjWf03pkzYTzQXe3gwDQYJKoZIhvcNAQEL
BQAwNjEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR0wGwYDVQQDDBRFeGFtcGxlIENv
cnAgUm9vdCBDQTAeFw0yNjA4MTQxMjI5MDRaFw0zNjA4MTExMjI5MDRaMDQxFTAT
BgNVBAoMDEV4YW1wbGUgSW5jLjEbMBkGA1UEAwwSRXhhbXBsZSBDb3JwIEFEIENB
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Y5IEKNBSsuT4dZ9o6gG
mGaPErvfr0PKAnRBHoClJJPwlrsk0q+VHqCTrnda5DGjZEe/NM/PDRQl3Nxyx40D
XmmYLobeo15HYdyht5D4F6yJOZ0mbqzpsUq29WxK028XJz7Ds//4IQ2DPIgfHc1W
QddE6JA04gFkRQ3Arrrx7nd5R2F50Bup+fYJTLEFFYbXf+/8ClqBCna3Cdi/AOsP
umbWZpZvJA8QDnuo0bFtD5rztB87bYKb5jh30vig+rKm812zXmyaoXtMjsT14Azl
/RYRhIWGwf+BGAlMJhhHV+R6cMZ/bXxmIFoeoNTVWl7xo8ZuAUJkN0y4rmxXMImF
zQIDAQABo4IBqjCCAaYwEgYDVR0TAQH/BAgwBgEB/wIBADALBgNVHQ8EBAMCAYYw
HQYDVR0OBBYEFFCXR+0zjvq4+SIYwOhimX7pqDu9MB8GA1UdIwQYMBaAFIlLkhdt
gHDNkZBLiBUz0xYdZj4IMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9wa2kuZXhh
bXBsZS5jb20vY2RwL0V4YW1wbGVSb290LmNybDCCAQQGA1UdHgEB/wSB+TCB9qBq
MA2CC2V4YW1wbGUuY29tMA6CDC5leGFtcGxlLmNvbTAJggdFWEFNUExFMB6gHAYK
KwYBBAGCNxQCA6AODAxAZXhhbXBsZS5jb20wHqAcBgorBgEEAYI3FAIDoA4MDC5l
eGFtcGxlLmNvbaGBhzAXghVzdWJkb21haW4uZXhhbXBsZS5jb20wGIIWLnN1YmRv
bWFpbi5leGFtcGxlLmNvbTAooCYGCisGAQQBgjcUAgOgGAwWQHN1YmRvbWFpbi5l
eGFtcGxlLmNvbTAooCYGCisGAQQBgjcUAgOgGAwWLnN1YmRvbWFpbi5leGFtcGxl
LmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAE2sdsEZMmfP1McdAc8Ww4sXbIu3GbPYw
fYiukveJPUhAYsIDFfudpqnoaZyNYdeMi+3VjE4UnjH9tG3tGIQlBL2t3ITtXPnD
JDsDwbLWRqO2QuSXKPk/Q8P/N7rX20Z6KnGk5KxaPTsaTM+rdckMGRxuTYknUEF9
t0DIBsj/X7oFxpCW3uBBl3l3TXR4Uwn8tltHpW9KW2CDqPyAdmkcNLuFteSRRm63
DNzG0CPLUcmT0eJQmgBxPw+sq8y13qdfkiGbOQG9nYeGxHIUKYdZbQWK21fzFUIo
m0vG1t/gTxtyOQrIBWfpDI59pChZiGq3u0haaX9qrYsVlV9kzgNIZg==
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee domaincontroller.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCJJPwx6eo33apE
CFJCMvuNqankQ9EGG7570pQ6gH7YQQZp32DBmQo1DjsmzPhWGz+MfLJheXjDs6qU
4Kb22H7ajq2qlg98JN1KYkiCRcmubdDVik7LjA5+nQoDXsMCNhuA3RVd13ACpQcj
tKE74y4Vtgu5+43nfiFqTRTWwLGofGpVHoELw2DewJUUR8yUa8ztCJc3FooaRzE8
vnMA9fraVB1VADMNRH5KREJOuEDEu1C2FNepuxHeM4U6moqKaD0z+pHBm3cF2VNO
8kUeXUxNcKQiqw9UVEEI8YSa1Bih32fMtUiwuUi7w9idY5Bi+swH9VDOHrQnvVze
suDi+kkDAgMBAAECggEAJRhOaLfTBOpdmApCKaq9lNs720SmoIbXlolmU46XAKpR
8Egd1S+ubZxcTonpb+zt2vONkkT3b8PEk4FSV/lGEpq+CaKOLK+R9YExCJ+Uxivo
7SF8X50R/JhAcZnrmEkHVms2UMwpfWWi0TsV02uG9xNnB5atktxwcF7KEK5NP3uG
KSOJIMgrDakd/Eid04NIZ2vGgWEbdiBboMeT9lPmQBwNooj3US/ay5yo1SE2RhpU
D2tisq2+1aWemL6TYqYS/eOMGmhBSsuPqkOVJ30e01winFLWL/CXGgp8Pq5KM8Gh
DxPTyapTjqqn932t8RGg5FRX9rUEQ8+5hXWaP0txRQKBgQC/0t8+7JrUnvh3/+Xt
eB/pxY+RID3b4rASsdtodb4RnHDz+rTbVplB0ajah8t9ErFsKjfjdoW54K+fVsZN
MRRB28bzsLVd/Jnrtu3KP/LvJN7tlAtbUFSVlbZfwnVRE1ZI7SsI4UZtqM1MmSh0
ybX6mWjDYrtyd8muP1H61yhizQKBgQC3Bv/KY3pC2D1ii6AmSqU1zQPNS5I+YKo8
g6JagFw7EWrHkv99btVn9nAWo8BmrBZTHYPj+VHffZ0F4VQCo+8pn5Q15/6wZfyk
Nxa4kAH9URQfJsKdoIceDqTF9gwd/yPABHY2of3s+X/VqN0X9ooLc6hxNtW23o/+
aPmaCLR7DwKBgQCZmcOF4XRBmWIgxNpagvwa90V00jp2XljbP2wPg2jFNV4FH9W+
ZOOnnrj09BPvfQ5xLIVAMOH364D1uEhl+0zbR59R90fjkKe35e0XLIndEMsptog5
gGOavB0jJNVILJHFJ5R0Md9xY9+w3FtW2UZM+pa3DdJHYMAwNSfyEmOWaQKBgCy7
5zT+T1mbJJW7bq8tO2gE7dL1j47zbWhQ/BOGoARH44NX6F4uArbgQtElwNbXZLV3
106XF226c/CF/FSQ4NmZiU4Ln/JZWwB//muptvLFKFfcz2BbZerwxVElLB0AySob
bRE5Uqji6l28Yh2DQoY+BIN3VZDWoPcbjTYavpH9AoGAVbNvdMUacnMx2UA1YrBp
JvnTwz74m/qfwjgFmLAQb3nw5oY4VjfRi6OFQseWoAOnIaTLwqquABQCwE7pZNah
xDYqYGa4+0GU5e9XavMoDLc7az61PFXPThRiqil9Q1IYYgXw8o6duP/xD5jTXvyC
4j79mIPTtbv4r/wV7+ymY4Q=
-----END PRIVATE KEY-----
$ openssl req -new -key domaincontroller.key \
              -subj "/CN=exampledc01.example.com" -out domaincontroller.csr
$ openssl x509 -req -in domaincontroller.csr -CA issuing-ca.pem \
               -CAkey issuing-ca.key -CAcreateserial -days 365 \
               -out domaincontroller.pem -extfile - <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName=DNS:exampledc01.example.com,DNS:ldap.example.com
crlDistributionPoints=URI:http://pki.example.com/cdp/ExampleADCA.crl
authorityInfoAccess = caIssuers;URI:http://pki.example.com/aia/ExampleADCA.cer
EOF
$ cat domaincontroller.pem
-----BEGIN CERTIFICATE-----
MIIEIjCCAwqgAwIBAgIUE/05VErpwLTz8EmFwbcH6j8xBaEwDQYJKoZIhvcNAQEL
BQAwNDEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMRswGQYDVQQDDBJFeGFtcGxlIENv
cnAgQUQgQ0EwHhcNMjYwODE0MTI0MzExWhcNMjcwODE0MTI0MzExWjAiMSAwHgYD
VQQDDBdleGFtcGxlZGMwMS5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAIkk/DHp6jfdqkQIUkIy+42pqeRD0QYbvnvSlDqAfthBBmnf
YMGZCjUOOybM+FYbP4x8smF5eMOzqpTgpvbYftqOraqWD3wk3UpiSIJFya5t0NWK
TsuMDn6dCgNewwI2G4DdFV3XcAKlByO0oTvjLhW2C7n7jed+IWpNFNbAsah8alUe
gQvDYN7AlRRHzJRrzO0IlzcWihpHMTy+cwD1+tpUHVUAMw1EfkpEQk64QMS7ULYU
16m7Ed4zhTqaiopoPTP6kcGbdwXZU07yRR5dTE1wpCKrD1RUQQjxhJrUGKHfZ8y1
SLC5SLvD2J1jkGL6zAf1UM4etCe9XN6y4OL6SQMCAwEAAaOCATwwggE4MAwGA1Ud
EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjA0BgNVHREELTArghdleGFtcGxlZGMwMS5leGFtcGxlLmNvbYIQbGRh
cC5leGFtcGxlLmNvbTA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vcGtpLmV4YW1w
bGUuY29tL2NkcC9FeGFtcGxlQURDQS5jcmwwRgYIKwYBBQUHAQEEOjA4MDYGCCsG
AQUFBzAChipodHRwOi8vcGtpLmV4YW1wbGUuY29tL2FpYS9FeGFtcGxlQURDQS5j
ZXIwHQYDVR0OBBYEFClqogDiApw9Pk/p38ylfnUpkuxcMB8GA1UdIwQYMBaAFFCX
R+0zjvq4+SIYwOhimX7pqDu9MA0GCSqGSIb3DQEBCwUAA4IBAQBLljdFr7+jRwU2
ssMIlo+EMU8kuby8FTd7TJOfJwtxOK4a2gsn7ql0py2U66dQj1xthISVrVJynMH9
+m6W5QfLE4LXbzzYMEZ1B7wXw9S9ATqFLppeSlMLgZshkKreUH/Aq+hEsBRdgjmt
WS2r9yp5JOv6Sjpwb/P3nVm33UyvrNUg/ls5/Uxj5DPFUwl6M0AXcAmNaiysuKio
qj5R+3eSjHqPMGOl2hIhyoxp6gr+udm+OjifZDfZ4Ak6n5lYXD1qZhyPdz91D2kD
uPdk+nIVa5yrqp6rgrc4Tb/CoU9vgLgkW7yG4CejVTJTDzVuUMrKLulvAfK4q1Ax
ZbEbl7om
-----END CERTIFICATE-----
*/
