/*
 * Copyright (C) 2002 Timo Schulz <twoaday@freakmail.de>
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_mpi.h"
#include "gnutls_cert.h"
#include "gnutls_datum.h"
#include "gnutls_global.h"
#include "auth_cert.h"
#include "gnutls_openpgp.h"

#ifdef HAVE_LIBOPENCDK
#include <gnutls/compat8.h>
#include <gnutls_str.h>
#include <stdio.h>
#include <gcrypt.h>
#include <opencdk.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>

#define OPENPGP_NAME_SIZE 256

#define datum_append(x, y, z) _gnutls_datum_append_m( x, y, z, gnutls_realloc )

typedef struct {
    int type;
    int armored;
    size_t size;
    uint8 *data;
} keybox_blob;

typedef enum {
    KBX_BLOB_FILE = 0x00,
    KBX_BLOB_DATA = 0x01
} keyring_blob_types;


static void
release_mpi_array( GNUTLS_MPI *arr, size_t n )
{
    GNUTLS_MPI x;
  
    while( arr && n-- ) {
        x = *arr;
        _gnutls_mpi_release( &x );
        *arr = NULL; arr++;
    }
}


int
_gnutls_map_cdk_rc( int rc )
{
    switch( rc ) {
    case CDK_Success: return 0;
    case CDK_General_Error: return GNUTLS_E_INTERNAL_ERROR;
    case CDK_File_Error: return GNUTLS_E_FILE_ERROR;
    case CDK_MPI_Error: return GNUTLS_E_MPI_SCAN_FAILED;
    case CDK_Error_No_Key: return GNUTLS_E_OPENPGP_GETKEY_FAILED;
    case CDK_Wrong_Format: return GNUTLS_E_OPENPGP_TRUSTDB_VERSION_UNSUPPORTED;
    case CDK_Armor_Error: return GNUTLS_E_BASE64_DECODING_ERROR;
    case CDK_Inv_Value: return GNUTLS_E_INVALID_REQUEST;
    default: return GNUTLS_E_INTERNAL_ERROR;
    }
    return rc;
}


static unsigned long
buftou32( const uint8 *buf )
{
    unsigned a;
    a  = buf[0] << 24;
    a |= buf[1] << 16;
    a |= buf[2] <<  8;
    a |= buf[3];
    return a;
}


static int
kbx_blob_new( keybox_blob **r_ctx )
{
    keybox_blob *c;
  
    if( !r_ctx ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }
  
    c = cdk_calloc( 1, sizeof * c );
    if( !c ) {
        gnutls_assert( );
        return GNUTLS_E_MEMORY_ERROR;
    }
    *r_ctx = c;
    
    return 0;
}


static void
kbx_blob_release( keybox_blob *ctx )
{
    if( ctx ) {
        cdk_free( ctx->data );
        cdk_free( ctx );
    }
}


static cdk_keydb_hd_t
kbx_to_keydb( keybox_blob *blob )
{
    cdk_keydb_hd_t hd;
    int rc;

    if( !blob ) {
        gnutls_assert( );
        return NULL;
    }
  
    switch( blob->type ) {
    case KBX_BLOB_FILE:
        rc = cdk_keydb_new( &hd, CDK_DBTYPE_PK_KEYRING, blob->data, blob->size );
        break;
      
    case KBX_BLOB_DATA:
        rc = cdk_keydb_new( &hd, CDK_DBTYPE_DATA, blob->data, blob->size );
        break;

    default:
        rc = GNUTLS_E_INTERNAL_ERROR;
        gnutls_assert( );
        break;
    }
    if( rc )
        hd = NULL;
    return hd;
}


/* Extract a keybox blob from the given position. */
static keybox_blob*
kbx_read_blob( const gnutls_datum* keyring, size_t pos )
{
    keybox_blob *blob = NULL;
    int rc;
  
    if( !keyring || !keyring->data || pos > keyring->size ) {
        gnutls_assert( );
        return NULL;
    }
    
    rc = kbx_blob_new( &blob );
    if( rc )
        return NULL;
    
    blob->type = keyring->data[pos];
    if( blob->type != KBX_BLOB_FILE && blob->type != KBX_BLOB_DATA ) {
        kbx_blob_release( blob );
        return NULL;
    }
    blob->armored = keyring->data[pos + 1];
    blob->size = buftou32( keyring->data + pos + 2 );
    if( !blob->size ) {
        kbx_blob_release( blob );
        return NULL;
    }
    blob->data = cdk_calloc( 1, blob->size + 1 );
    if( !blob->data )
        return NULL;
    memcpy( blob->data, keyring->data + (pos + 6), blob->size );
    blob->data[blob->size] = '\0';
  
    return blob;
}


/* Creates a keyring blob from raw data
 *
 * Format:
 * 1 octet  type
 * 1 octet  armored
 * 4 octet  size of blob
 * n octets data
 */
static uint8*
kbx_data_to_keyring( int type, int enc, const char *data,
                     size_t size, size_t *r_size )
{
    uint8 *p = NULL;

    if( !data )
        return NULL;
  
    p = gnutls_malloc( 1+4+size );
    if( !p )
        return NULL;
    p[0] = type; /* type: {keyring,name} */
    p[1] = enc;  /* encoded: {plain, armored} */
    p[2] = size >> 24;
    p[3] = size >> 16;
    p[4] = size >>  8;
    p[5] = size      ;
    memcpy( p + 6, data, size );
    if( r_size )
        *r_size = 6 + size;
    return p;
}


CDK_PACKET*
search_packet( const gnutls_datum *buf, int pkttype )
{
    static cdk_kbnode_t knode = NULL;
    CDK_PACKET *pkt;

    if( !buf && !pkttype ) {
        cdk_kbnode_release( knode );
        knode = NULL;
        return NULL;
    }
    if( cdk_kbnode_read_from_mem( &knode, buf->data, buf->size ) )
        return NULL;
    pkt = cdk_kbnode_find_packet( knode, pkttype );

    return pkt;
}


static int
stream_to_datum( cdk_stream_t inp, gnutls_datum *raw )
{
    uint8 buf[4096];
    int rc = 0, nread, nbytes = 0;
  
    if( !buf || !raw ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    cdk_stream_seek( inp, 0 );
    while( !cdk_stream_eof( inp ) ) {
        nread = cdk_stream_read( inp, buf, sizeof buf-1 );
        if( nread == EOF )
            break;
        datum_append( raw, buf, nread );
        nbytes += nread;
    }
    cdk_stream_seek( inp, 0 );
    if( !nbytes )
        rc = GNUTLS_E_INTERNAL_ERROR;

    return rc;
}


static int
openpgp_pk_to_gnutls_cert( gnutls_cert *cert, cdk_pkt_pubkey_t pk )
{
    uint8 buf[512];
    size_t nbytes = 0;
    int algo, i;
    int rc = 0;
  
    if( !cert || !pk ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* GnuTLS OpenPGP doesn't support ELG keys */
    if( is_ELG(pk->pubkey_algo) )
        return GNUTLS_E_UNWANTED_ALGORITHM;

    algo = is_DSA( pk->pubkey_algo )? GNUTLS_PK_DSA : GNUTLS_PK_RSA;
    cert->subject_pk_algorithm = algo;
    cert->version = pk->version;
    cert->cert_type = GNUTLS_CRT_OPENPGP;

    if( is_DSA(pk->pubkey_algo) || pk->pubkey_algo == GCRY_PK_RSA_S )
        cert->keyUsage = KEY_DIGITAL_SIGNATURE;
    else if( pk->pubkey_algo == GCRY_PK_RSA_E )
        cert->keyUsage = KEY_ENCIPHER_ONLY;
    else if( pk->pubkey_algo == GCRY_PK_RSA )
        cert->keyUsage = KEY_DIGITAL_SIGNATURE
            | KEY_ENCIPHER_ONLY;

    cert->params_size = cdk_pk_get_npkey( pk->pubkey_algo );
    for( i = 0; i < cert->params_size; i++ ) {
        nbytes = sizeof buf-1;
        cdk_pk_get_mpi( pk, i, buf, &nbytes, NULL );
        rc = _gnutls_mpi_scan_pgp( &cert->params[i], buf, &nbytes );
        if( rc ) {
            rc = GNUTLS_E_MPI_SCAN_FAILED;
            break;
        }
    }

    if( rc )
        release_mpi_array( cert->params, i-1 );
    return rc;
}

/*-
 * _gnutls_openpgp_key2gnutls_key - Converts an OpenPGP secret key to GnuTLS
 * @pkey: the GnuTLS private key context to store the key.
 * @raw_key: the raw data which contains the whole key packets.
 *
 * The RFC2440 (OpenPGP Message Format) data is converted into the
 * GnuTLS specific data which is need to perform secret key operations.
 -*/
int
_gnutls_openpgp_key2gnutls_key( gnutls_privkey *pkey,
                                gnutls_datum *raw_key )
{
    cdk_kbnode_t snode;
    CDK_PACKET *pkt;
    cdk_stream_t out;
    cdk_pkt_seckey_t sk = NULL;
    int pke_algo, i, j;
    size_t nbytes = 0;
    uint8 buf[512];
    int rc = 0;

    if( !pkey || raw_key->size <= 0 ) {
        gnutls_assert( );
        return GNUTLS_E_CERTIFICATE_ERROR;
    }

    out = cdk_stream_tmp( );
    if( !out )
        return GNUTLS_E_CERTIFICATE_ERROR;
    cdk_stream_write( out, raw_key->data, raw_key->size );
    cdk_stream_seek( out, 0 );

    cdk_keydb_get_keyblock( out, &snode );
    if( !snode ) {
        rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
        goto leave;
    }

    pkt = cdk_kbnode_find_packet( snode, CDK_PKT_SECRET_KEY );
    if( !pkt ) {
        rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
        goto leave;
    }
    sk = pkt->pkt.secret_key;
    pke_algo = sk->pk->pubkey_algo;
    pkey->params_size = cdk_pk_get_npkey( pke_algo );
    for( i = 0; i < pkey->params_size; i++ ) {
        nbytes = sizeof buf -1;
        cdk_pk_get_mpi( sk->pk, i, buf, &nbytes, NULL );
        rc = _gnutls_mpi_scan_pgp( &pkey->params[i], buf, &nbytes );
        if( rc ) {
            rc = GNUTLS_E_MPI_SCAN_FAILED;
            release_mpi_array( pkey->params, i-1 );
            goto leave;
        }
    }
    pkey->params_size += cdk_pk_get_nskey( pke_algo );
    for( j = 0; j < cdk_pk_get_nskey( pke_algo ); j++, i++ ) {
        nbytes = sizeof buf-1;
        cdk_sk_get_mpi( sk, j, buf, &nbytes, NULL );
        rc = _gnutls_mpi_scan_pgp( &pkey->params[i], buf, &nbytes );
        if ( rc ) {
            rc = GNUTLS_E_MPI_SCAN_FAILED;
            release_mpi_array( pkey->params, i-1 );
            goto leave;
        }
    }
    
    if( is_ELG(pke_algo) )
        return GNUTLS_E_UNWANTED_ALGORITHM;
    else if( is_DSA(pke_algo) )
        pkey->pk_algorithm = GNUTLS_PK_DSA;
    else if( is_RSA(pke_algo) )
        pkey->pk_algorithm = GNUTLS_PK_RSA;

leave:
    cdk_stream_close( out );
    cdk_kbnode_release( snode );
    return rc;
}


/*-
 * _gnutls_openpgp_cert2gnutls_cert - Converts raw OpenPGP data to GnuTLS certs
 * @cert: the certificate to store the data.
 * @raw: the buffer which contains the whole OpenPGP key packets.
 *
 * The RFC2440 (OpenPGP Message Format) data is converted to a GnuTLS
 * specific certificate.
 -*/
int
_gnutls_openpgp_cert2gnutls_cert( gnutls_cert *cert, const gnutls_datum *raw )
{
    cdk_kbnode_t knode = NULL;
    CDK_PACKET *pkt = NULL;
    int rc;
  
    if( !cert ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    memset( cert, 0, sizeof *cert );

    rc = cdk_kbnode_read_from_mem( &knode, raw->data, raw->size );
    if( !(rc = _gnutls_map_cdk_rc( rc )) )
        pkt = cdk_kbnode_find_packet( knode, CDK_PKT_PUBLIC_KEY );
    if( !pkt )
        rc = GNUTLS_E_INTERNAL_ERROR;
    if( !rc )
        rc = _gnutls_set_datum( &cert->raw, raw->data, raw->size );
    if( !rc )
        rc = openpgp_pk_to_gnutls_cert( cert, pkt->pkt.public_key );

    cdk_kbnode_release( knode );
    return rc;
}


/*-
 * gnutls_openpgp_get_key - Retrieve a key from the keyring.
 * @key: the destination context to save the key.
 * @keyring: the datum struct that contains all keyring information.
 * @attr: The attribute (keyid, fingerprint, ...).
 * @by: What attribute is used.
 *
 * This function can be used to retrieve keys by different pattern
 * from a binary or a file keyring.
 -*/
int
gnutls_openpgp_get_key( gnutls_datum *key, const gnutls_datum *keyring,
                        key_attr_t by, opaque *pattern )
{
    keybox_blob *blob = NULL;
    cdk_keydb_hd_t hd = NULL;
    cdk_kbnode_t knode = NULL;
    unsigned long keyid[2];
    unsigned char *buf;
    void * desc;
    size_t len;
    int rc = 0;
  
    if( !key || !keyring || by == KEY_ATTR_NONE ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    memset( key, 0, sizeof *key );
    blob = kbx_read_blob( keyring, 0 );
    if( !blob )
        return GNUTLS_E_MEMORY_ERROR;
    hd = kbx_to_keydb( blob );

    if( by == KEY_ATTR_SHORT_KEYID ) {
        keyid[0] = buftou32( pattern );
        desc = keyid;
    }
    else if( by == KEY_ATTR_KEYID ) {
        keyid[0] = buftou32( pattern );
        keyid[1] = buftou32( pattern + 4 );
        desc = keyid;
    }
    else
        desc = pattern;
    rc = cdk_keydb_search_start( hd, by, desc );
    if( rc ) {
        rc = _gnutls_map_cdk_rc( rc );
        goto leave;
    }
  
    rc = cdk_keydb_search( hd, &knode );
    if( rc ) {
        rc = _gnutls_map_cdk_rc( rc );
        goto leave;
    }    

    if( !cdk_kbnode_find( knode, CDK_PKT_PUBLIC_KEY ) ) {
        rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
        goto leave;
    }

    len = 20000;
    buf = cdk_calloc (1, len + 1);
    rc = cdk_kbnode_write_to_mem( knode, buf, &len );
    if( !rc )
        datum_append( key, buf, len );
    cdk_free( buf );
  
leave:
    cdk_free( hd );
    cdk_kbnode_release( knode );
    kbx_blob_release( blob );
    return rc;
}


int
gnutls_certificate_set_openpgp_key_mem( gnutls_certificate_credentials res,
                                        gnutls_datum *cert,
                                        gnutls_datum *key )
{
    gnutls_datum raw;
    cdk_kbnode_t knode = NULL, ctx = NULL, p;
    CDK_PACKET *pkt;
    int i = 0;
    int rc = 0;
    
    if ( !res || !key || !cert ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    rc = cdk_kbnode_read_from_mem( &knode, cert->data, cert->size );
    if( (rc = _gnutls_map_cdk_rc( rc )) )
      goto leave;

    /* fixme: too much duplicated code from (set_openpgp_key_file) */
    res->cert_list = gnutls_realloc_fast(res->cert_list,
                                    (1+res->ncerts)*sizeof(gnutls_cert*));
    if (res->cert_list == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    res->cert_list_length = gnutls_realloc_fast(res->cert_list_length,
                                           (1+res->ncerts)*sizeof(int));
    if (res->cert_list_length == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;    
    }

    res->cert_list[res->ncerts] = gnutls_calloc(1, sizeof(gnutls_cert));
    if (res->cert_list[res->ncerts] == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR; 
    }

    i = 1;
    while( (p = cdk_kbnode_walk( knode, &ctx, 0 )) ) {
        pkt = cdk_kbnode_get_packet( p );
        if( i > MAX_PUBLIC_PARAMS_SIZE )
            break;
        if( pkt->pkttype == CDK_PKT_PUBLIC_KEY ) {
            int n = res->ncerts;
            cdk_pkt_pubkey_t pk = pkt->pkt.public_key;
            res->cert_list_length[n] = 1;
            if (_gnutls_set_datum( &res->cert_list[n][0].raw,
                              cert->data, cert->size ) < 0) {
                 gnutls_assert();
                 return GNUTLS_E_MEMORY_ERROR;
            }
            openpgp_pk_to_gnutls_cert( &res->cert_list[n][0], pk );
            i++;
        }
    }
  
    res->ncerts++;
    res->pkey = gnutls_realloc_fast(res->pkey,
                               (res->ncerts)*sizeof(gnutls_privkey));
    if( !res->pkey ) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;   
    }
    /* ncerts has been incremented before */
    rc = _gnutls_set_datum( &raw, key->data, key->size );
    if (rc < 0) {
    	gnutls_assert();
    	return rc;
    }
    rc = _gnutls_openpgp_key2gnutls_key( &res->pkey[res->ncerts-1], &raw );
    _gnutls_free_datum(&raw);

leave:
    cdk_kbnode_release( knode );
  
    return rc;
}


/**
 * gnutls_certificate_set_openpgp_key_file - Used to set OpenPGP keys
 * @res: the destination context to save the data.
 * @CERTFILE: the file that contains the public key.
 * @KEYFILE: the file that contains the secret key.
 *
 * This funtion is used to load OpenPGP keys into the GnuTLS structure.
 * It doesn't matter whether the keys are armored or but, but the files
 * should only contain one key which should not be encrypted.
 **/
int
gnutls_certificate_set_openpgp_key_file( gnutls_certificate_credentials res,
                                         char* CERTFILE,
                                         char* KEYFILE )
{
    struct stat statbuf;
    cdk_stream_t inp = NULL;
    cdk_kbnode_t knode = NULL, ctx = NULL, p;
    CDK_PACKET *pkt = NULL;
    gnutls_datum raw;
    int i = 0, n;
    int rc = 0;
  
    if( !res || !KEYFILE || !CERTFILE ) {
    	gnutls_assert();
        return GNUTLS_E_INVALID_REQUEST;
    }

    if( stat( CERTFILE, &statbuf ) || stat( KEYFILE, &statbuf ) ) {
        gnutls_assert();
        return GNUTLS_E_FILE_ERROR;
    }

    rc = cdk_stream_open( CERTFILE, &inp );
    if( rc ) {
        gnutls_assert();
        return _gnutls_map_cdk_rc( rc );
    }

    if( cdk_armor_filter_use( inp ) )
        cdk_stream_set_armor_flag( inp, 0 );

    n = (1 + res->ncerts) * sizeof (gnutls_cert*);
    res->cert_list = gnutls_realloc_fast( res->cert_list, n );
    if( !res->cert_list ) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    n = (1 + res->ncerts) * sizeof (int);
    res->cert_list_length = gnutls_realloc_fast( res->cert_list_length, n );
    if( !res->cert_list_length ) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    res->cert_list[res->ncerts] = gnutls_calloc( 1,  sizeof(gnutls_cert) );
    if( !res->cert_list[res->ncerts] ) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }
    
    while( !rc ) {
        i = 1;
        rc = cdk_keydb_get_keyblock( inp, &knode );
        while( knode && (p = cdk_kbnode_walk( knode, &ctx, 0 )) ) {
            if( i > MAX_PUBLIC_PARAMS_SIZE )
                break;
            pkt = cdk_kbnode_get_packet( p );
            if( pkt->pkttype == CDK_PKT_PUBLIC_KEY ) {
                int n = res->ncerts;
                cdk_pkt_pubkey_t pk = pkt->pkt.public_key;
                res->cert_list_length[n] = 1;
                stream_to_datum( inp, &res->cert_list[n][0].raw );
                openpgp_pk_to_gnutls_cert( &res->cert_list[n][0], pk );
                i++;
            }
        }
    }
    if( rc == CDK_EOF && i > 1 )
        rc = 0;
    cdk_stream_close( inp );
    if( rc ) {
        cdk_kbnode_release( knode );

        gnutls_assert();
        rc = _gnutls_map_cdk_rc( rc );
        goto leave;
    }
    cdk_kbnode_release( knode );

    rc = cdk_stream_open( KEYFILE, &inp );
    if( rc ) {
        gnutls_assert();
        return _gnutls_map_cdk_rc( rc );
    }
    if( cdk_armor_filter_use( inp ) )
        cdk_stream_set_armor_flag( inp, 0 );

    memset( &raw, 0, sizeof raw );
    stream_to_datum( inp, &raw );
    cdk_stream_close( inp );

    n = (res->ncerts + 1) * sizeof (gnutls_privkey);
    res->pkey = gnutls_realloc_fast( res->pkey, n );
    if( !res->pkey ) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }
    
    res->ncerts++;
    /* ncerts has been incremented before */
    rc = _gnutls_openpgp_key2gnutls_key( &res->pkey[res->ncerts-1], &raw );
    
 leave:
    return rc;
}


int
gnutls_openpgp_count_key_names( const gnutls_datum *cert )
{
    cdk_kbnode_t knode, p, ctx = NULL;
    CDK_PACKET *pkt;
    int nuids = 0;

    if( cert == NULL ) {
        gnutls_assert();
        return 0;
    }
    if( cdk_kbnode_read_from_mem( &knode, cert->data, cert->size ) ) {
        gnutls_assert();
        return 0;
    }
    while( (p = cdk_kbnode_walk( knode, &ctx, 0 )) ) {
        pkt = cdk_kbnode_get_packet( p );
        if( pkt->pkttype == CDK_PKT_USER_ID )
            nuids++;
    }
    
    return nuids;
}



int
_gnutls_openpgp_get_key_trust( const char *trustdb,
                               const gnutls_datum *key,
                               int *r_trustval )
{
    cdk_kbnode_t knode = NULL;
    cdk_stream_t inp;
    CDK_PACKET *pkt;
    cdk_pkt_pubkey_t pk = NULL;
    int flags = 0, ot = 0;
    int rc = 0;

    if( !trustdb || !key || !r_trustval ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    *r_trustval = 0;

    rc = cdk_kbnode_read_from_mem( &knode, key->data, key->size );
    if( (rc = _gnutls_map_cdk_rc( rc )) )
        return rc;

    pkt = cdk_kbnode_find_packet( knode, CDK_PKT_PUBLIC_KEY );
    if( !pkt ) {
        rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
        goto leave;
    }
    pk = pkt->pkt.public_key;

    rc = cdk_stream_open( trustdb, &inp );
    if( rc ) {
        rc = _gnutls_map_cdk_rc( rc );
        goto leave;
    }
    
    rc = cdk_trustdb_get_ownertrust( inp, pk, &ot, &flags );
    cdk_stream_close( inp );
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
    cdk_kbnode_release( knode );
    return rc;
}


/**
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
 **/
int
gnutls_openpgp_verify_key( const char *trustdb,
                           const gnutls_datum* keyring,
                           const gnutls_datum* cert_list,
                           int cert_list_length )
{
    cdk_kbnode_t knode = NULL;
    cdk_keydb_hd_t hd = NULL;
    keybox_blob *blob = NULL;
    int rc = 0;
    int status = 0;
  
    if( !cert_list || cert_list_length != 1 || !keyring ) {
        gnutls_assert();
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

    if( !keyring->size && !trustdb ) {
        gnutls_assert( );
        return GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
    }

    blob = kbx_read_blob( keyring, 0 );
    if( !blob ) {
        gnutls_assert();
        return GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
    }
    hd = kbx_to_keydb( blob );
    if( !hd ) {
        rc = GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
        goto leave;
    }

    if( trustdb ) {
        int ktrust;
        rc = _gnutls_openpgp_get_key_trust( trustdb, cert_list, &ktrust );
        if( rc || !ktrust )
            goto leave;
    }

    rc = cdk_kbnode_read_from_mem( &knode, cert_list->data, cert_list->size );
    if( (rc = _gnutls_map_cdk_rc( rc )) ) {
        goto leave;
        return GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
    }

    rc = cdk_pk_check_sigs( knode, hd, &status );
    if( rc == CDK_Error_No_Key )
        rc = 0; /* fixme */
      
    switch( status ) {
    case CDK_KEY_INVALID:
        rc = GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
        break;
      
    case CDK_KEY_REVOKED:
        rc = GNUTLS_CERT_REVOKED | GNUTLS_CERT_NOT_TRUSTED;
        break;
    }

leave:
    kbx_blob_release( blob );
    cdk_free( hd );
    cdk_kbnode_release( knode );
    if( rc ) {
        gnutls_assert();
    }
    return rc;
}


/*-
 * gnutls_openpgp_add_keyring_file - Adds a keyring file for OpenPGP
 * @keyring: data buffer to store the file.
 * @name: filename of the keyring.
 *
 * The function is used to set keyrings that will be used internally
 * by various OpenCDK functions. For example to find a key when it
 * is needed for an operations.
 -*/
int
gnutls_openpgp_add_keyring_file(gnutls_datum *keyring, const char *name)
{
    cdk_stream_t inp = NULL;
    uint8 *blob;
    size_t nbytes;
    int enc = 0;
    int rc = 0;
  
    if( !keyring || !name ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    rc = cdk_stream_open( name, &inp );
    if( rc )
        return _gnutls_map_cdk_rc( rc );
    enc = cdk_armor_filter_use( inp );
    cdk_stream_close( inp );
  
    blob = kbx_data_to_keyring( KBX_BLOB_FILE, enc, name,
                                strlen( name ), &nbytes);
    if( blob && nbytes ) { 
        if ( datum_append( keyring, blob, nbytes ) < 0 ) {
            gnutls_assert();
            return GNUTLS_E_MEMORY_ERROR;
        }
        gnutls_free( blob );
    }
    return 0;
}


/*-
 * gnutls_openpgp_add_keyring_mem - Adds keyring data for OpenPGP
 * @keyring: data buffer to store the file.
 * @data: the binary data of the keyring.
 * @len: the size of the binary buffer.
 *
 * Same as gnutls_openpgp_add_keyring_mem but now we store the
 * data instead of the filename.
 -*/
int
gnutls_openpgp_add_keyring_mem(gnutls_datum *keyring,
                               const opaque *data, size_t len)
{
    uint8 *blob;
    size_t nbytes = 0;
  
    if( !keyring || !data || !len ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }
  
    blob = kbx_data_to_keyring( KBX_BLOB_DATA, 0, data, len, &nbytes );
    if( blob && nbytes ) {
        if ( datum_append( keyring, blob, nbytes ) < 0 ) {
            gnutls_assert();
            return GNUTLS_E_MEMORY_ERROR;
        }
        gnutls_free( blob );
    }
    
    return 0;
}


/**
 * gnutls_certificate_set_openpgp_keyring_file - Adds a keyring file for OpenPGP * @c: A certificate credentials structure
 * @file: filename of the keyring.
 *
 * The function is used to set keyrings that will be used internally
 * by various OpenPGP functions. For example to find a key when it
 * is needed for an operations. The keyring will also be used at the
 * verification functions.
 *
 **/
int
gnutls_certificate_set_openpgp_keyring_file( gnutls_certificate_credentials c,
                                             const char *file )
{
    struct stat statbuf;
    
    if( !c || !file ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    if( stat( file, &statbuf ) )
        return GNUTLS_E_FILE_ERROR;

    return gnutls_openpgp_add_keyring_file( &c->keyring, file );
}


int
gnutls_certificate_set_openpgp_keyring_mem( gnutls_certificate_credentials c,
                                            const opaque *data, size_t dlen )
{
    cdk_stream_t inp;
    size_t count;
    uint8 *buf;
    int rc = 0;
  
    if( !c || !data || !dlen ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    inp = cdk_stream_tmp_from_mem( data, dlen );
    if( !inp )
        return GNUTLS_E_FILE_ERROR;
    
    /* Maybe it's a little confusing that we check the output..
       but it's possible, that the data we want to add, is armored
       and we only want to store plaintext keyring data. */
    if( cdk_armor_filter_use( inp ) )
        cdk_stream_set_armor_flag( inp, 0 );

    /* fixme: this is possible the armored length. */
    count = cdk_stream_get_length( inp );
    buf = gnutls_malloc( count + 1 );
    if( !buf ) {
        gnutls_assert();
        cdk_stream_close( inp );
        return GNUTLS_E_MEMORY_ERROR;
    }

    count = cdk_stream_read( inp, buf, count );
    buf[count] = '\0';    
    rc = gnutls_openpgp_add_keyring_mem( &c->keyring, buf, count );
    cdk_stream_close( inp );

    return rc;
}

/*-
 * _gnutls_openpgp_request_key - Receives a key from a database, key server etc
 * @ret - a pointer to gnutls_datum structure.
 * @cred - a gnutls_certificate_credentials structure.
 * @key_fingerprint - The keyFingerprint
 * @key_fingerprint_size - the size of the fingerprint
 *
 * Retrieves a key from a local database, keyring, or a key server. The
 * return value is locally allocated.
 *
 -*/
int
_gnutls_openpgp_request_key( gnutls_session session, gnutls_datum* ret, 
                             const gnutls_certificate_credentials cred,
                             opaque* key_fpr,
                             int key_fpr_size)
{
    int rc = 0;

    if( !ret || !cred || !key_fpr ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }
    
    if( key_fpr_size != 16 && key_fpr_size != 20 )
        return GNUTLS_E_HASH_FAILED; /* only MD5 and SHA1 are supported */
  
    rc = gnutls_openpgp_get_key( ret, &cred->keyring, KEY_ATTR_FPR, key_fpr );
    if( rc >= 0 ) /* key was found */
        return rc;
    else rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;

    /* If the callback function was set, then try this one.
     */
    if( session->internals.openpgp_recv_key_func != NULL ) {
	rc = session->internals.openpgp_recv_key_func( session, 
                                                       key_fpr,
                                                       key_fpr_size,
                                                       ret);
	if( rc < 0 ) {
            gnutls_assert();
            return GNUTLS_E_OPENPGP_GETKEY_FAILED;
	}
    }

    return rc;
}


/**
 * gnutls_certificate_set_openpgp_keyserver - Used to set an OpenPGP key server
 * @res: the destination context to save the data.
 * @server: is the key server address
 * @port: is the key server port to connect to
 *
 * This funtion will set a key server for use with openpgp keys. This
 * key server will only be used if the peer sends a key fingerprint instead
 * of a key in the handshake. Using a key server may delay the handshake
 * process.
 *
 **/
int
gnutls_certificate_set_openpgp_keyserver(gnutls_certificate_credentials res,
                                         char* keyserver,
                                         int port)
{
    if( !res || !keyserver ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    if( !port )
        port = 11371;
  
    gnutls_free( res->pgp_key_server);
    res->pgp_key_server = gnutls_strdup( keyserver );
    if( !res->pgp_key_server )
    	return GNUTLS_E_MEMORY_ERROR;
    res->pgp_key_server_port = port;

   return 0;
}


/**
 * gnutls_certificate_set_openpgp_trustdb - Used to set an GnuPG trustdb
 * @res: the destination context to save the data.
 * @trustdb: is the trustdb filename
 *
 * This funtion will set a GnuPG trustdb which will be used in key
 * verification functions. Only version 3 trustdb files are supported.
 *
 **/
int
gnutls_certificate_set_openpgp_trustdb( gnutls_certificate_credentials res,
                                        char* trustdb )
{
    if( !res || !trustdb ) {
        gnutls_assert( );
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* the old v2 format was used with 1.0.6, do we still need to check
       it now because GPG 1.0.7, 1.2.0, 1.2.1 and even 1.3.0 is out? */
    
    gnutls_free( res->pgp_trustdb);
    res->pgp_trustdb = gnutls_strdup( trustdb );
    if( res->pgp_trustdb==NULL )
        return GNUTLS_E_MEMORY_ERROR;
        
    return 0;
} 

/**
 * gnutls_openpgp_set_recv_key_function - Used to set a key retrieval callback for PGP keys
 * @session: a TLS session
 * @func: the callback
 *
 * This funtion will set a key retrieval function for OpenPGP keys. This
 * callback is only useful in server side, and will be used if the peer
 * sent a key fingerprint instead of a full key.
 *
 **/
void gnutls_openpgp_set_recv_key_function( gnutls_session session,
                                           gnutls_openpgp_recv_key_func func )
{
    session->internals.openpgp_recv_key_func = func;
}

#endif /* HAVE_LIBOPENCDK */

