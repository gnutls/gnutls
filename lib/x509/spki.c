/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Authors: Daiki Ueno
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include "gnutls_int.h"
#include "errors.h"
#include <common.h>
#include <x509.h>
#include <x509_int.h>

/**
 * gnutls_x509_spki_init:
 * @spki: A pointer to the type to be initialized
 *
 * This function will initialize a SubjectPublicKeyInfo structure used
 * in PKIX. The structure is used to set additional parameters
 * in the public key information field of a certificate.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.6.0
 *
 **/
int
gnutls_x509_spki_init(gnutls_x509_spki_t *spki)
{
	gnutls_x509_spki_t tmp;

	FAIL_IF_LIB_ERROR;

	tmp =
	    gnutls_calloc(1, sizeof(gnutls_x509_spki_st));

	if (!tmp)
		return GNUTLS_E_MEMORY_ERROR;

	*spki = tmp;

	return 0;		/* success */
}

/**
 * gnutls_x509_spki_deinit:
 * @spki: the SubjectPublicKeyInfo structure
 *
 * This function will deinitialize a SubjectPublicKeyInfo structure.
 *
 * Since: 3.6.0
 *
 **/
void
gnutls_x509_spki_deinit(gnutls_x509_spki_t spki)
{
	gnutls_free(spki);
}

/**
 * gnutls_x509_spki_set_pk_algorithm:
 * @spki: the SubjectPublicKeyInfo structure
 * @pk: the public key algorithm of type #gnutls_pk_algorithm_t
 *
 * This function will set the public key algorithm of a
 * SubjectPublicKeyInfo structure.
 *
 * Since: 3.6.0
 *
 **/
void
gnutls_x509_spki_set_pk_algorithm(gnutls_x509_spki_t spki,
				  gnutls_pk_algorithm_t pk)
{
	spki->pk = pk;
}

/**
 * gnutls_x509_spki_get_pk_algorithm:
 * @spki: the SubjectPublicKeyInfo structure
 *
 * This function will get the public key algorithm of a
 * SubjectPublicKeyInfo structure.
 *
 * Returns: a member of the #gnutls_pk_algorithm_t enumeration on
 * success, or %GNUTLS_PK_UNKNOWN on error.
 *
 * Since: 3.6.0
 *
 **/
int
gnutls_x509_spki_get_pk_algorithm(gnutls_x509_spki_t spki)
{
	return spki->pk;
}

/**
 * gnutls_x509_spki_set_digest_algorithm:
 * @spki: the SubjectPublicKeyInfo structure
 * @dig: a digest algorithm of type #gnutls_digest_algorithm_t
 *
 * This function will set the digest algorithm of a
 * SubjectPublicKeyInfo structure. This is relevant for
 * RSA-PSS signatures which store the digest algorithm
 * in the SubjectPublicKeyInfo.
 *
 * Since: 3.6.0
 *
 **/
void
gnutls_x509_spki_set_digest_algorithm(gnutls_x509_spki_t spki,
				      gnutls_digest_algorithm_t dig)
{
	spki->rsa_pss_dig = dig;
}

/**
 * gnutls_x509_spki_get_digest_algorithm:
 * @spki: the SubjectPublicKeyInfo structure
 *
 * This function will get the digest algorithm of a
 * SubjectPublicKeyInfo structure. This is relevant for
 * RSA-PSS signatures which store the digest algorithm
 * in the SubjectPublicKeyInfo.
 *
 * Returns: a member of the #gnutls_digest_algorithm_t enumeration on
 * success, or a %GNUTLS_DIG_UNKNOWN on error.
 *
 * Since: 3.6.0
 *
 **/
int
gnutls_x509_spki_get_digest_algorithm(gnutls_x509_spki_t spki)
{
	return spki->rsa_pss_dig;
}

/**
 * gnutls_x509_spki_set_salt_size:
 * @spki: the SubjectPublicKeyInfo structure
 * @salt_size: the size of salt string
 *
 * This function will set the salt size parameter of a
 * SubjectPublicKeyInfo structure.
 *
 * The salt is used in the RSA-PSS signature scheme.
 *
 * Since: 3.6.0
 *
 **/
void
gnutls_x509_spki_set_salt_size(gnutls_x509_spki_t spki,
			       unsigned int salt_size)
{
	spki->salt_size = salt_size;
}

/**
 * gnutls_x509_spki_get_salt_size:
 * @spki: the SubjectPublicKeyInfo structure
 *
 * This function will get the salt size parameter of a
 * SubjectPublicKeyInfo structure.
 *
 * The salt is used in the RSA-PSS signature scheme.
 *
 * Returns: salt size as a positive integer, or zero.
 *
 * Since: 3.6.0
 *
 **/
int
gnutls_x509_spki_get_salt_size(gnutls_x509_spki_t spki)
{
	return spki->salt_size;
}
