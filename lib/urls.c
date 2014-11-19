/*
 * Copyright © 2014 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * GnuTLS is free software; you can redistribute it and/or
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_str.h>
#include "urls.h"

static const char *_types[] =
{ "object-type=cert", "object-type=private", NULL };

static char *append_to_str(const char *str1, const char *str2)
{
	char *str = NULL;
	gnutls_buffer_st buf;
	int ret;

	_gnutls_buffer_init(&buf);

	ret = _gnutls_buffer_append_str(&buf, str1);
	if (ret < 0) {
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data(&buf, ";", 1);
	if (ret < 0) {
		goto cleanup;
	}

	ret = _gnutls_buffer_append_str(&buf, str2);
	if (ret < 0) {
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data(&buf, "\x00", 1);
	if (ret < 0) {
		goto cleanup;
	}

	str = (void*)buf.data;
	ret = 0;
fprintf(stderr, "str: %s\n", str);
 cleanup:
 	if (ret < 0) {
 		_gnutls_buffer_clear(&buf);
 	}
 	return str;	

}

/*
 * @type: 0 for cert, 1 for privkey
 *
 * This function will make sure that the URL is ok (e.g.,
 * that it contains type=cert, when it is a certificate,
 * or type=privkey for PKCS #11 URLs. That allows to use
 * the common URL part as input for keys and certificates.
 *
 *
 */
char *_gnutls_sanitize_url(const char *url, unsigned type)
{
#ifdef ENABLE_PKCS11
	if (strncmp(url, "pkcs11:", 7) == 0) {
		if (strstr(url, _types[type]) != NULL) {
			return gnutls_strdup(url);
		} else {
			return append_to_str(url, _types[type]);
		}
	} else
#endif
	{
		return gnutls_strdup(url);
	}
}
