/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

#include <defines.h>
#include <gnutls_int.h>
#include <gnutls_gcry.h>
#include <gnutls_pk.h>
#include <gnutls_errors.h>

/* this is taken from gnupg 
 */
 
/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int _gnutls_pk_encrypt(enum gcry_pk_algos algo, MPI * resarr, MPI data, MPI * pkey)
{
	GCRY_SEXP s_ciph, s_data, s_pkey;
	int rc;

	/* make a sexp from pkey */
	if (algo == GCRY_PK_RSA) {
		rc = gcry_sexp_build(&s_pkey, NULL,
				     "(public-key(rsa(p%m)(e%m)))", 
				     pkey[0], pkey[1] );
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_KX_ALGORITHM;
	}

	if (rc!=0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	/* put the data into a simple list */
	if (gcry_sexp_build(&s_data, NULL, "%m", data)) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_encrypt(&s_ciph, s_data, s_pkey);
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_pkey);

	if (rc);
	else {			/* add better error handling or make gnupg use S-Exp directly */
		GCRY_SEXP list = gcry_sexp_find_token(s_ciph, "a", 0);
		/* assert(list); */
		resarr[0] = gcry_sexp_nth_mpi(list, 1, 0);
		/* assert(resarr[0]); */
		gcry_sexp_release(list);

	}

	gcry_sexp_release(s_ciph);
	return rc;
}
