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

/* Functions on OpenPGP key parsing
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_openpgp.h>
#include <openpgp.h>

#ifdef HAVE_LIBOPENCDK

static int
openpgp_get_key_trust( gnutls_openpgp_trustdb trustdb, 
     gnutls_openpgp_key key, unsigned int *r_trustval )
{
    CDK_PACKET *pkt;
    cdk_pkt_pubkey_t pk = NULL;
    int flags = 0, ot = 0;
    int rc = 0;

    if( !trustdb || !key || !r_trustval ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    *r_trustval = 0;

    pkt = cdk_kbnode_find_packet( key->knode, CDK_PKT_PUBLIC_KEY );
    if( !pkt ) {
        rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
        goto leave;
    }
    pk = pkt->pkt.public_key;

    rc = cdk_trustdb_get_ownertrust( trustdb->st, pk, &ot, &flags );

    if ( rc ) { /* no ownertrust record was found */
        rc = 0;
        goto leave;
    }

    if( flags & CDK_TFLAG_DISABLED ) {
        *r_trustval |= GNUTLS_CERT_INVALID;
        goto leave;
    }
    
    if( flags & CDK_TFLAG_REVOKED ) {
        *r_trustval |= GNUTLS_CERT_REVOKED;
    }
    
    rc = 0;

leave:
    return rc;
}

/**
 * gnutls_openpgp_key_verify_ring - Verify all signatures on the key
 * @key: the structure that holds the key.
 * @keyring: holds the keyring to check against
 * @flags: unused (should be 0)
 * @verify: will hold the certificate verification output.
 *
 * Verify all signatures in the key, using the given set of keys (keyring). 
 * If a signer key is not available, the signature is skipped.
 *
 * The certificate verification output will be put in 'verify' and will be
 * one or more of the gnutls_certificate_status enumerated elements bitwise or'd.
 *
 * GNUTLS_CERT_INVALID\: A signature on the key is invalid.
 *
 * GNUTLS_CERT_REVOKED\: The key has been revoked.
 *
 * NOTE: this function does not verify using any "web of trust". You
 * may use GnuPG for that purpose, or any other external PGP application.
 *
 * Returns 0 on success.
 **/
int gnutls_openpgp_key_verify_ring( gnutls_openpgp_key key,
                           gnutls_openpgp_keyring keyring,
                           unsigned int flags, unsigned int *verify)
{
    int rc = 0;
    unsigned int status = 0;
  
    if( !key || !keyring ) {
        gnutls_assert();
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }
    
    *verify = 0;

    rc = cdk_pk_check_sigs( key->knode, keyring->hd, &status );
    if( rc == CDK_Error_No_Key ) {
        rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
        gnutls_assert();
        return rc;
    }

    if( rc) {
        rc = _gnutls_map_cdk_rc(rc);
        gnutls_assert();
        return rc;
    }
      
    if (status & CDK_KEY_INVALID) *verify |= GNUTLS_CERT_INVALID;
    if (status & CDK_KEY_REVOKED) *verify |= GNUTLS_CERT_REVOKED;
#warning CHECK HERE IF THE WAS ANY SIGNER

    return 0;
}

/**
 * gnutls_openpgp_key_verify_trustdb - Verify all signatures on the key
 * @key: the structure that holds the key.
 * @trustdb: holds the trustdb to check against
 * @flags: unused (should be 0)
 * @verify: will hold the certificate verification output.
 *
 * Checks if the key is revoked or disabled, in the trustdb.
 * The verification output will be put in 'verify' and will be
 * one or more of the gnutls_certificate_status enumerated elements bitwise or'd.
 *
 * GNUTLS_CERT_INVALID\: A signature on the key is invalid.
 *
 * GNUTLS_CERT_REVOKED\: The key has been revoked.
 *
 * NOTE: this function does not verify using any "web of trust". You
 * may use GnuPG for that purpose, or any other external PGP application.
 *
 * Returns 0 on success.
 **/
int gnutls_openpgp_key_verify_trustdb( gnutls_openpgp_key key, 
	gnutls_openpgp_trustdb trustdb,
        unsigned int flags, unsigned int *verify)
{
    cdk_keydb_hd_t hd = NULL;
    int rc = 0;
  
    if( !key) {
        gnutls_assert();
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

    if( !trustdb) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    rc = openpgp_get_key_trust( trustdb, key, verify);
    if( rc)
        goto leave;

    rc = 0;
    
leave:
    cdk_free( hd );
    if( rc ) {
        gnutls_assert();
    }
    return rc;
}

#endif
