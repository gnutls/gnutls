/*
 *  Copyright (C) 2002 Timo Schulz
 *  Portions Copyright (C) 2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS-EXTRA.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

/* Compatibility functions on OpenPGP key parsing.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_openpgp.h>
#include <openpgp.h>

#ifdef HAVE_LIBOPENCDK

/*-
 * gnutls_openpgp_verify_key - Verify all signatures on the key
 * @cert_list: the structure that holds the certificates.
 * @cert_list_lenght: the items in the cert_list.
 *
 * Verify all signatures in the certificate list. When the key
 * is not available, the signature is skipped.
 *
 * When the trustdb parameter is used, the function checks the
 * ownertrust of the key before the signatures are checked. It
 * is possible that the key was disabled or the owner is not trusted
 * at all. Then we don't check the signatures because it makes no sense.
 *
 * The return value is one of the CertificateStatus entries.
 *
 * NOTE: this function does not verify using any "web of trust". You
 * may use GnuPG for that purpose, or any other external PGP application.
 -*/
int gnutls_openpgp_verify_key(const char *trustdb,
			  const gnutls_datum * keyring,
			  const gnutls_datum * cert_list,
			  int cert_list_length)
{
	int ret = 0;
	gnutls_openpgp_key key = NULL;
	gnutls_openpgp_keyring ring = NULL;
	gnutls_openpgp_trustdb tdb = NULL;
	unsigned int verify;

	if (!cert_list || cert_list_length != 1 || !keyring) {
		gnutls_assert();
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	ret = gnutls_openpgp_key_init( &key);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_openpgp_key_import( key, &cert_list[0], 0);
	if (ret < 0) {
		gnutls_assert();
		goto leave;
	}


	if (trustdb) { /* Use the trustDB */
		ret = gnutls_openpgp_trustdb_init( &tdb);
		if (ret < 0) {
			gnutls_assert();
			goto leave;
		}

		ret = gnutls_openpgp_trustdb_import_file( tdb, trustdb);
		if (ret < 0) {
			gnutls_assert();
			goto leave;
		}
		
		ret = gnutls_openpgp_key_verify_trustdb( key, tdb, 0, &verify);
		if (ret < 0) {
			gnutls_assert();
			goto leave;
		}
		
		ret = verify;
		goto leave;
	}
	
	if (!keyring || !keyring->data || keyring->size == 0) {
		ret = GNUTLS_CERT_INVALID |
			GNUTLS_CERT_SIGNER_NOT_FOUND;
#warning CHECK SELF SIGNATURE HERE
		goto leave;
	}

	/* use the keyring
	 */
	ret = gnutls_openpgp_keyring_init( &ring);
	if (ret < 0) {
		gnutls_assert();
		goto leave;
	}

	ret = gnutls_openpgp_keyring_import( ring, keyring, 0);
	if (ret < 0) {
		gnutls_assert();
		goto leave;
	}
		
	ret = gnutls_openpgp_key_verify_ring( key, ring, 0, &verify);
	if (ret < 0) {
		gnutls_assert();
		goto leave;
	}
		
	ret = verify;
	goto leave;

leave:
	gnutls_openpgp_key_deinit( key);
	gnutls_openpgp_trustdb_deinit( tdb);
	gnutls_openpgp_keyring_deinit( ring);
	return ret;

}

/*-
 * gnutls_openpgp_fingerprint - Gets the fingerprint
 * @cert: the raw data that contains the OpenPGP public key.
 * @fpr: the buffer to save the fingerprint.
 * @fprlen: the integer to save the length of the fingerprint.
 *
 * Returns the fingerprint of the OpenPGP key. Depence on the algorithm,
 * the fingerprint can be 16 or 20 bytes.
 -*/
int gnutls_openpgp_fingerprint(const gnutls_datum * cert,
			   unsigned char *fpr, size_t * fprlen)
{
	gnutls_openpgp_key key;
	int ret;

	ret = gnutls_openpgp_key_init( &key);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_openpgp_key_import( key, cert, 0);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_openpgp_key_get_fingerprint( key, fpr, fprlen);
	
	gnutls_openpgp_key_deinit( key);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	return 0;
}

/*-
 * gnutls_openpgp_extract_key_creation_time - Extract the timestamp
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Returns the timestamp when the OpenPGP key was created.
 -*/
time_t gnutls_openpgp_extract_key_creation_time(const gnutls_datum * cert)
{
	gnutls_openpgp_key key;
	int ret;
	time_t tim;

	ret = gnutls_openpgp_key_init( &key);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_openpgp_key_import( key, cert, 0);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	tim = gnutls_openpgp_key_get_creation_time( key);
	
	gnutls_openpgp_key_deinit( key);
	
	return tim;
}


/*-
 * gnutls_openpgp_extract_key_expiration_time - Extract the expire date
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Returns the time when the OpenPGP key expires. A value of '0' means
 * that the key doesn't expire at all.
 -*/
time_t gnutls_openpgp_extract_key_expiration_time(const gnutls_datum * cert)
{
	gnutls_openpgp_key key;
	int ret;
	time_t tim;

	ret = gnutls_openpgp_key_init( &key);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_openpgp_key_import( key, cert, 0);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	tim = gnutls_openpgp_key_get_expiration_time( key);
	
	gnutls_openpgp_key_deinit( key);
	
	return tim;
}

#endif
