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
        rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
        goto leave;
    }
    pk = pkt->pkt.public_key;

    rc = cdk_trustdb_get_ownertrust( trustdb->st, pk, &ot, &flags );

    if ( rc ) { /* no ownertrust record was found */
        rc = 0;
        *r_trustval = 0;
        goto leave;
    }

    if( flags & CDK_TFLAG_DISABLED ) {
        *r_trustval |= GNUTLS_CERT_NOT_TRUSTED;
        *r_trustval |= GNUTLS_CERT_INVALID;
        goto leave;
    }
    
    if( flags & CDK_TFLAG_REVOKED ) {
        *r_trustval |= GNUTLS_CERT_NOT_TRUSTED;
        *r_trustval |= GNUTLS_CERT_REVOKED;
    }
    
    switch( ot ) {
    case CDK_TRUST_NEVER:
        *r_trustval |= GNUTLS_CERT_NOT_TRUSTED;
        break;
    case CDK_TRUST_UNKNOWN:
    case CDK_TRUST_UNDEFINED:
    case CDK_TRUST_MARGINAL:
    case CDK_TRUST_FULLY:
    case CDK_TRUST_ULTIMATE:
        *r_trustval |= 1; /* means okay */
        rc = 0;
        break;
    }

leave:
    if( rc )
        *r_trustval |= GNUTLS_CERT_NOT_TRUSTED;
    return rc;
}

/**
 * gnutls_openpgp_key_verify_ring - Verify all signatures on the key
 * @key: the structure that holds the key.
 * @keyring: holds the keyring to check against
 * @flags: unused (should be 0)
 * @verify: will hold the certificate verification output.
 *
 * Verify all signatures in the certificate list. When the key
 * is not available, the signature is skipped.
 *
 * The certificate verification output will be put in 'verify' and will be
 * one or more of the gnutls_certificate_status enumerated elements bitwise or'd.
 *
 * GNUTLS_CERT_INVALID\: A signature on the key is invalid.
 *
 * GNUTLS_CERT_REVOKED\: The key has been revoked.
 *
 * GNUTLS_CERT_NOT_TRUSTED\: The key is either invalid or revoked.
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
    int status = 0;
  
    if( !key || !keyring ) {
        gnutls_assert();
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

    rc = cdk_pk_check_sigs( key->knode, keyring->hd, &status );
    if( rc == CDK_Error_No_Key )
        rc = GNUTLS_E_NO_CERTIFICATE_FOUND; /* fixme */
      
    switch( status ) {
    case CDK_KEY_INVALID:
        *verify = GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
        rc = 0;
        break;
      
    case CDK_KEY_REVOKED:
        *verify = GNUTLS_CERT_REVOKED | GNUTLS_CERT_NOT_TRUSTED;
        rc = 0;
        break;
    default:
        rc = 0;
    }

    if( rc ) {
        gnutls_assert();
    }
    return rc;
}

/**
 * gnutls_openpgp_key_verify_trustdb - Verify all signatures on the key
 * @key: the structure that holds the key.
 * @trustdb: holds the trustdb to check against
 * @flags: unused (should be 0)
 * @verify: will hold the certificate verification output.
 *
 * Verify all signatures in the certificate list. When the key
 * is not available, the signature is skipped.
 *
 * The function checks the ownertrust of the key before the signatures are checked. 
 * It is possible that the key was disabled or the owner is not trusted
 * at all. Then we don't check the signatures because it makes no sense.
 *
 * The certificate verification output will be put in 'verify' and will be
 * one or more of the gnutls_certificate_status enumerated elements bitwise or'd.
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
    int status = 0;
  
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
