/*
 *      Copyright (C) 2002 Timo Schulz <twoaday@freakmail.de>
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

#define OPENPGP_NAME_SIZE GNUTLS_X509_CN_SIZE

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
  
    while ( arr && n-- ) {
        x = *arr;
        _gnutls_mpi_release( &x );
        *arr = NULL; arr++;
    }
}

static u32
buffer_to_u32( const uint8 *buffer )
{
    const uint8 *p = buffer;

    if ( !p )
        return 0;
    return  (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static int
file_exist(const char *file)
{
    FILE *fp;
  
    if (!file)
        return 0;
    
    fp = fopen(file, "r");
    if ( fp ) {
        fclose(fp);
        return 1;
    }
    
    return 0;
}

static int
kbx_blob_new( keybox_blob **r_ctx )
{
    keybox_blob *c;
  
    if ( !r_ctx )
        return GNUTLS_E_INVALID_PARAMETERS;
  
    c = cdk_alloc_clear( sizeof * c);
    if ( !c )
        return GNUTLS_E_MEMORY_ERROR;
    *r_ctx = c;
    
    return 0;
} /* kbx_blob_new */

static void
kbx_blob_release( keybox_blob *ctx )
{
    if ( ctx ) {
        cdk_free( ctx->data );
        cdk_free( ctx );
    }
} /* kbx_blob_release */

static KEYDB_HD
kbx_to_keydb( keybox_blob *blob )
{
    KEYDB_HD khd = NULL;

    if ( !blob )
        return NULL;
  
    khd = cdk_alloc_clear( sizeof *khd );
    if ( !khd )
        return NULL;
    khd->used = 1;
    if ( blob->type == KBX_BLOB_FILE ) { /* file */
        khd->name = cdk_strdup( blob->data );
        khd->type = blob->armored? KEYDB_TYPE_ARMORED: KEYDB_TYPE_KEYRING;
    }
    else if ( blob->type == KBX_BLOB_DATA ) { /* data */
        cdk_iobuf_new( &khd->buf, blob->size );
        cdk_iobuf_write( khd->buf, blob->data, blob->size );
        khd->type = KEYDB_TYPE_DATA;
    }
    else { /* error */
        cdk_free( khd );
        khd = NULL;
    }
  
    return khd;
} /* kbx_to_keydb */

/* Extract a keybox blob from the given position. */
static keybox_blob*
kbx_read_blob( const gnutls_datum* keyring, size_t pos )
{
    keybox_blob *blob = NULL;
  
    if ( !keyring || !keyring->data )
        return NULL;

    if ( pos > keyring->size )
        return NULL;
    
    kbx_blob_new( &blob );
    blob->type = keyring->data[pos];
    if ( blob->type != KBX_BLOB_FILE &&
         blob->type != KBX_BLOB_DATA ) {
        kbx_blob_release( blob );
        return NULL;
    }
    blob->armored = keyring->data[pos+1];
    blob->size = buffer_to_u32( keyring->data+pos+2 );
    if ( !blob->size ) {
        kbx_blob_release( blob );
        return NULL;
    }
    blob->data = cdk_alloc_clear( blob->size + 1 );
    if ( !blob->data )
        return NULL;
    memcpy( blob->data, keyring->data+(pos+6), blob->size );
    blob->data[blob->size] = '\0';
  
    return blob;
} /* kbx_read_blob */

/* Creates a keyring blob from raw data
 *
 * Format:
 * 1 octet  type
 * 1 octet  armored
 * 4 octet  size of blob
 * n octets data
 */
static byte*
kbx_data_to_keyring( int type, int enc, const char *data,
                     size_t size, size_t *r_size )
{
    uint8 *p = NULL;

    if ( !data )
        return NULL;
  
    p = gnutls_malloc( 1+4+size );
    if ( !p )
        return NULL;
    p[0] = type; /* type: {keyring,name} */
    p[1] = enc; /* encoded: {plain, armored} */
    p[2] = (size >> 24) & 0xff;
    p[3] = (size >> 16) & 0xff;
    p[4] = (size >>  8) & 0xff;
    p[5] = (size      ) & 0xff;
    memcpy( p+6, data, size );
    if ( r_size )
        *r_size = 6+size;
  
    return p;
} /* kbx_data_to_keyring */

static int
kbnode_to_datum( CDK_KBNODE kb_pk, gnutls_datum *raw )
{
    CDK_KBNODE p = NULL;
    CDK_BSTRING dat = NULL;
    CDK_IOBUF a = NULL;
    PACKET pkt = {0};
    int rc = 0;
  
    if ( !kb_pk || !raw )
        return GNUTLS_E_INVALID_PARAMETERS;

    /* fixme: conver the whole key */
    for (p=kb_pk; p && p->pkt->pkttype; p=p->next) {
        if (p->pkt->pkttype == PKT_PUBLIC_KEY) {
            a = cdk_iobuf_temp();
            pkt.pkttype = PKT_PUBLIC_KEY;
            pkt.pkt.public_key = p->pkt->pkt.public_key;
            rc = cdk_pkt_build( a, &pkt );
            if ( rc ) {
                rc = GNUTLS_E_UNKNOWN_ERROR;
                goto fail;
            }
            dat = cdk_iobuf_read_mem( a, 0 );
            if ( dat ) { 
                rc = gnutls_set_datum( raw, dat->d, dat->len );
                if ( rc < 0 ) {
                    gnutls_assert();
                    rc = GNUTLS_E_MEMORY_ERROR;
                    goto fail;
                }
            }
        }
    }

fail:
    cdk_free( dat );
    cdk_iobuf_close( a );
    return rc;
}

static int
datum_to_kbnode( const gnutls_datum *raw, CDK_KBNODE *r_pkt )
{
    CDK_IOBUF buf;
    CDK_KBNODE pkt = NULL;
    int dummy = 0;
    int rc = 0;

    if ( !raw || !r_pkt )
        return GNUTLS_E_INVALID_PARAMETERS;

    cdk_iobuf_new( &buf, raw->size );
    cdk_iobuf_write( buf, raw->data, raw->size );
    rc = cdk_keydb_get_keyblock( buf, &pkt, &dummy );
    if ( rc && rc != CDKERR_EOF ) {
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto fail;
    }
    else
        rc = 0;

fail:
    cdk_iobuf_close( buf );
    *r_pkt = (!rc)? pkt : NULL;

    return rc;
}

static int
iobuf_to_datum( CDK_IOBUF buf, gnutls_datum *raw )
{
    CDK_BSTRING a = NULL;
    int rc = 0;
  
    if ( !buf || !raw )
        return GNUTLS_E_INVALID_PARAMETERS;
  
    a = cdk_iobuf_read_mem( buf, 0 );
    if ( a ) {
        rc = gnutls_set_datum( raw, a->d, a->len );
        if ( rc < 0 ) {
            rc = GNUTLS_E_MEMORY_ERROR;
            goto fail;
        }
    }
    else
        rc = GNUTLS_E_UNKNOWN_ERROR;

fail:
    cdk_free( a );
    return rc;
}

static int
openpgp_pk_to_gnutls_cert(gnutls_cert *cert, PKT_public_key *pk)
{
    size_t nbytes = 0;
    int algo, i;
    int rc = 0;
  
    if (!cert || !pk)
        return GNUTLS_E_INVALID_PARAMETERS;

    /* GnuTLS OpenPGP doesn't support ELG keys */
    if ( is_ELG(pk->pubkey_algo) )
        return GNUTLS_E_UNWANTED_ALGORITHM;

    algo = is_DSA(pk->pubkey_algo)? GNUTLS_PK_DSA : GNUTLS_PK_RSA;
    cert->subject_pk_algorithm = algo;
    cert->version = pk->version;
    cert->valid = 0; /* fixme: should set after the verification */
    cert->cert_type = GNUTLS_CRT_OPENPGP;

    if (is_DSA(pk->pubkey_algo) || pk->pubkey_algo == GCRY_PK_RSA_S)
        cert->keyUsage = GNUTLS_X509KEY_DIGITAL_SIGNATURE;
    else if (pk->pubkey_algo == GCRY_PK_RSA_E)
        cert->keyUsage = GNUTLS_X509KEY_ENCIPHER_ONLY;
    else if (pk->pubkey_algo == GCRY_PK_RSA)
        cert->keyUsage = GNUTLS_X509KEY_DIGITAL_SIGNATURE
            | GNUTLS_X509KEY_ENCIPHER_ONLY;

    cert->params_size = cdk_pk_get_npkey( pk->pubkey_algo );
    for (i=0; i<cert->params_size; i++) {      
        nbytes = pk->mpi[i]->bytes + 2;
        rc = _gnutls_mpi_scan_pgp( &cert->params[i], 
                                   pk->mpi[i]->data, &nbytes );
        if ( rc ) {
            rc = GNUTLS_E_MPI_SCAN_FAILED;
            goto fail;
        }
    }
    cert->expiration_time = pk->expiredate;
    cert->activation_time = pk->timestamp;

fail:
    if ( rc )
        release_mpi_array(cert->params, i-1);

    return rc;
}

static int
openpgp_sig_to_gnutls_cert(gnutls_cert *cert, PKT_signature *sig)
{
    CDK_IOBUF buf = NULL;
    CDK_BSTRING a = NULL;
    PACKET pkt;
    size_t sigsize = 0;
    int rc = 0;
  
    if (!cert || !sig)
        return GNUTLS_E_INVALID_PARAMETERS;

    sigsize = 20 + sig->hashed_size + sig->unhashed_size + 2*MAX_MPI_BYTES;
    cdk_iobuf_new( &buf, sigsize );
    memset( &pkt, 0, sizeof pkt );
    pkt.pkttype = PKT_SIGNATURE;
    pkt.pkt.signature = sig;
    rc = cdk_pkt_build( buf, &pkt );
    if ( rc )
        goto fail;
    a = cdk_iobuf_read_mem( buf, 0 );
    if ( a ) {
        rc = gnutls_datum_append( &cert->signature, a->d, a->len );
        if (rc < 0) {
            gnutls_assert();
            rc = GNUTLS_E_MEMORY_ERROR;
            goto fail;
        }
    }
    else
        rc = GNUTLS_E_UNKNOWN_ERROR;

fail:
    cdk_free( a );
    cdk_iobuf_close( buf );

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
_gnutls_openpgp_key2gnutls_key( gnutls_private_key *pkey,
                                gnutls_datum raw_key )
{
    CDK_KBNODE p = NULL, kb_sk;
    CDK_IOBUF buf;
    PKT_secret_key *sk = NULL;
    int pke_algo, i, j, eof = 0;
    size_t nbytes = 0;
    int rc = 0;

    if ( !pkey || raw_key.size <= 0 )
        return GNUTLS_E_INVALID_PARAMETERS;

    cdk_secmem_init( 16384 );
    cdk_iobuf_new( &buf, raw_key.size );
    cdk_iobuf_write( buf, raw_key.data, raw_key.size );

    rc = cdk_keydb_get_keyblock( buf, &kb_sk, &eof );
    if ( !kb_sk || rc ) {
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto leave;
    }
    p = cdk_kbnode_find( kb_sk, PKT_SECRET_KEY );
    if ( !p ) {
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto leave;
    }
    sk = p->pkt->pkt.secret_key;
    pke_algo = sk->pk->pubkey_algo;
    pkey->params_size = cdk_pk_get_npkey( pke_algo );
    for ( i = 0; i < pkey->params_size; i++ ) {
        nbytes = sk->pk->mpi[i]->bytes + 2;
        rc = _gnutls_mpi_scan_pgp( &pkey->params[i],
                                   sk->pk->mpi[i]->data, &nbytes );
        if ( rc ) {
            rc = GNUTLS_E_MPI_SCAN_FAILED;
            release_mpi_array( pkey->params, i-1 );
            goto leave;
        }
    }
    pkey->params_size += cdk_pk_get_nskey( pke_algo );
    for (j=0; j<cdk_pk_get_nskey( pke_algo ); j++, i++) {
        nbytes = sk->mpi[j]->bytes + 2;
        rc = _gnutls_mpi_scan_pgp(&pkey->params[i],
                                  sk->mpi[j]->data, &nbytes);
        if ( rc ) {
            rc = GNUTLS_E_MPI_SCAN_FAILED;
            release_mpi_array(pkey->params, i-1);
            goto leave;
        }
    }
    if ( is_ELG(pke_algo) )
        return GNUTLS_E_UNWANTED_ALGORITHM;
    else if ( is_DSA(pke_algo) )
        pkey->pk_algorithm = GNUTLS_PK_DSA;
    else if ( is_RSA(pke_algo) )
        pkey->pk_algorithm = GNUTLS_PK_RSA;
    rc = gnutls_set_datum( &pkey->raw, raw_key.data, raw_key.size );
    if ( rc < 0 ) {
        release_mpi_array(pkey->params, i);
        rc = GNUTLS_E_MEMORY_ERROR;
    }

leave:
    cdk_iobuf_close( buf );
    cdk_kbnode_release( kb_sk );

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
_gnutls_openpgp_cert2gnutls_cert(gnutls_cert *cert, gnutls_datum raw)
{
    CDK_KBNODE p, kb_pk = NULL;
    PKT_public_key *pk = NULL;
    int rc = 0;
  
    if ( !cert )
        return GNUTLS_E_INVALID_PARAMETERS;

    memset( cert, 0, sizeof *cert );
    rc = datum_to_kbnode( &raw, &kb_pk );
    if ( rc )
        return rc;
    p = cdk_kbnode_find( kb_pk, PKT_PUBLIC_KEY );
    if ( !p ) {
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto fail;
    }
    pk = p->pkt->pkt.public_key;
    rc = gnutls_set_datum( &cert->raw, raw.data, raw.size );
    if ( rc < 0 ) {
        rc = GNUTLS_E_MEMORY_ERROR;
        goto fail;
    }
    rc = openpgp_pk_to_gnutls_cert( cert, pk );

fail:
    cdk_kbnode_release( kb_pk );
  
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
gnutls_openpgp_get_key(gnutls_datum *key, const gnutls_datum *keyring,
                       key_attr_t by, opaque *pattern)
{
    keybox_blob *blob = NULL;
    KEYDB_HD khd = NULL;
    CDK_KBNODE pk = NULL;
    KEYDB_SEARCH ks;
    int rc = 0;
  
    if ( !key || !keyring || by == KEY_ATTR_NONE )
        return GNUTLS_E_INVALID_PARAMETERS;

    blob = kbx_read_blob( keyring, 0 );
    if (!blob)
        return GNUTLS_E_MEMORY_ERROR;
    khd = kbx_to_keydb( blob );
    ks.type = by;
    switch (by) {
    case KEY_ATTR_SHORT_KEYID:
        ks.u.keyid[1] = buffer_to_u32(pattern);
        break;

    case KEY_ATTR_KEYID:
        ks.u.keyid[0] = buffer_to_u32(pattern);
        ks.u.keyid[1] = buffer_to_u32(pattern+4);
        break;

    case KEY_ATTR_FPR:
        memcpy(ks.u.fpr, pattern, 20);
        break;

    default:
        goto leave;
    }
  
    rc = cdk_keydb_search( khd, &ks, &pk );
    if ( rc ) {
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto leave;
    }    

    if ( !cdk_kbnode_find( pk, PKT_PUBLIC_KEY ) ) {
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto leave;
    }

    rc = kbnode_to_datum( pk, key );
  
leave:
    cdk_free( khd );
    cdk_kbnode_release( pk );
    kbx_blob_release( blob );
  
    return rc;
}

int
gnutls_certificate_set_openpgp_key_mem( GNUTLS_CERTIFICATE_CREDENTIALS res,
                                        gnutls_datum *cert,
                                        gnutls_datum *key )
{
    gnutls_datum raw;
    CDK_KBNODE kb_pk = NULL, pkt;
    int i = 0;
    int rc = 0;
    
    if ( !res || !key || !cert )
        return GNUTLS_E_INVALID_PARAMETERS;

    rc = datum_to_kbnode( cert, &kb_pk );
    if ( rc )
        goto leave;

    /* fixme: too much duplicated code from (set_openpgp_key_file) */
    res->cert_list = gnutls_realloc(res->cert_list,
                                    (1+res->ncerts)*sizeof(gnutls_cert*));
    if (res->cert_list == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    res->cert_list_length = gnutls_realloc(res->cert_list_length,
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

    for (i=1, pkt=kb_pk; pkt && pkt->pkt->pkttype; pkt=pkt->next) {
        if (i > MAX_PARAMS_SIZE)
            break;
        if (pkt->pkt->pkttype == PKT_PUBLIC_KEY) {
            int n = res->ncerts;
            PKT_public_key *pk = pkt->pkt->pkt.public_key;
            res->cert_list_length[n] = 1;
            gnutls_set_datum(&res->cert_list[n][0].raw,
                             cert->data, cert->size);
            openpgp_pk_to_gnutls_cert( &res->cert_list[n][0], pk );
            i++;
        }
        else if (pkt->pkt->pkttype == PKT_SIGNATURE) {
            int n = res->ncerts;
            PKT_signature *sig = pkt->pkt->pkt.signature;
            openpgp_sig_to_gnutls_cert( &res->cert_list[n][0], sig ); 
        }
    }
  
    res->ncerts++;
    res->pkey = gnutls_realloc(res->pkey,
                               (res->ncerts)*sizeof(gnutls_private_key));
    if (res->pkey == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;   
    }
    /* ncerts has been incremented before */
    gnutls_set_datum(&raw, key->data, key->size);
    rc =_gnutls_openpgp_key2gnutls_key( &res->pkey[res->ncerts-1], raw);
    gnutls_free_datum(&raw);
  
leave:
    cdk_kbnode_release( kb_pk );
  
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
gnutls_certificate_set_openpgp_key_file(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                        char* CERTFILE,
                                        char* KEYFILE)
{
    CDK_IOBUF inp = NULL;
    CDK_KBNODE kb_pk = NULL, pkt;
    armor_filter_s afx;
    gnutls_datum raw;
    int eof = 0, i = 0;
    int rc = 0;
  
    if ( !res || !KEYFILE || !CERTFILE )
        return GNUTLS_E_INVALID_PARAMETERS;

    if ( !file_exist(CERTFILE) || !file_exist(KEYFILE) )
        return GNUTLS_E_FILE_ERROR;
  
    rc = cdk_iobuf_open(&inp, CERTFILE, IOBUF_MODE_RD);
    if ( rc )
        return GNUTLS_E_FILE_ERROR;
    if ( cdk_armor_filter_use( inp ) ) {
        memset( &afx, 0, sizeof afx );
        rc = cdk_armor_filter( &afx, IOBUF_CTRL_UNDERFLOW, inp );
        if ( rc ) {
            cdk_iobuf_close( inp );
            rc = GNUTLS_E_ASCII_ARMOR_ERROR;
            goto leave;          
        }
        /*cdk_iobuf_close( inp );*/
    }

    res->cert_list = gnutls_realloc(res->cert_list,
                                    (1+res->ncerts)*sizeof(gnutls_cert*));
    if (res->cert_list == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    res->cert_list_length = gnutls_realloc(res->cert_list_length,
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

    do {
        rc = cdk_keydb_get_keyblock( inp, &kb_pk, &eof );
        if ( !kb_pk || rc )
            break;
        for (i=1, pkt=kb_pk; pkt && pkt->pkt->pkttype; pkt=pkt->next) {
            if (i > MAX_PARAMS_SIZE)
                break;
            if (pkt->pkt->pkttype == PKT_PUBLIC_KEY) {
                int n = res->ncerts;
                PKT_public_key *pk = pkt->pkt->pkt.public_key;
                res->cert_list_length[n] = 1;
                iobuf_to_datum(inp, &res->cert_list[n][0].raw);
                openpgp_pk_to_gnutls_cert( &res->cert_list[n][0], pk );
                i++;
            }
            else if (pkt->pkt->pkttype == PKT_SIGNATURE) {
                int n = res->ncerts;
                PKT_signature *sig = pkt->pkt->pkt.signature;
                openpgp_sig_to_gnutls_cert( &res->cert_list[n][0], sig );
            }
        }
    } while (!eof && !rc);

    cdk_iobuf_close(inp);
    if ( rc ) {
        cdk_kbnode_release( kb_pk );
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto leave;
    }
    cdk_kbnode_release( kb_pk );

    rc = cdk_iobuf_open( &inp, KEYFILE, IOBUF_MODE_RD );
    if ( rc )
        return GNUTLS_E_FILE_ERROR;
    if ( cdk_armor_filter_use( inp ) ) {      
        memset( &afx, 0, sizeof afx );
        rc = cdk_armor_filter( &afx, IOBUF_CTRL_UNDERFLOW, inp );
        if ( rc ) {
            cdk_iobuf_close( inp );
            rc = GNUTLS_E_ASCII_ARMOR_ERROR;
            goto leave;
        }
        /*cdk_iobuf_close( inp );*/
    }

    iobuf_to_datum( inp, &raw );
    cdk_iobuf_close( inp );
  
    res->pkey = gnutls_realloc(res->pkey,
                               (res->ncerts+1)*sizeof(gnutls_private_key));
    if (res->pkey == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
    }

    res->ncerts++;
  
    /* ncerts has been incremented before */
    rc =_gnutls_openpgp_key2gnutls_key( &res->pkey[res->ncerts-1], raw);

leave:
  
    return rc;
}

int
gnutls_openpgp_count_key_names( const gnutls_datum *cert )
{
    CDK_KBNODE kb_pk = NULL, pkt;
    int nuids = 0;
  
    if ( !cert )
        return 0;

    if ( datum_to_kbnode( cert, &kb_pk ) )
        return 0;
    for ( pkt=kb_pk; pkt; pkt=pkt->next ) {
        if ( pkt->pkt->pkttype == PKT_USER_ID )
            nuids++;
    }
    
    return nuids;
} /* gnutls_openpgp_count_key_names */

/**
 * gnutls_openpgp_extract_key_name - Extracts the userID
 * @cert: the raw data that contains the OpenPGP public key.
 * @dn: the structure to store the userID specific data in.
 *
 * Extracts the userID from the raw OpenPGP key.
 **/
int
gnutls_openpgp_extract_key_name( const gnutls_datum *cert,
                                 int idx,
                                 gnutls_openpgp_name *dn )
{
    CDK_KBNODE kb_pk = NULL, pkt;
    PKT_user_id *uid = NULL;
    char *email;
    int pos = 0, pos1 = 0, pos2 = 0;
    size_t size = 0;
    int rc = 0;

    if (!cert || !dn)
        return GNUTLS_E_INVALID_PARAMETERS;

    if ( idx < 0 || idx > gnutls_openpgp_count_key_names( cert ) )
        return GNUTLS_E_UNKNOWN_ERROR;

    memset(dn, 0, sizeof *dn);
    rc = datum_to_kbnode( cert, &kb_pk );
    if ( rc )
        return rc;
    if ( !idx )
        pkt = cdk_kbnode_find( kb_pk, PKT_USER_ID );
    else {
        for ( pos=0, pkt=kb_pk; pkt; pkt=pkt->next ) {
            if ( pkt->pkt->pkttype == PKT_USER_ID && ++pos == idx )
                break;
        }
    }
    if ( pkt )
        uid = pkt->pkt->pkt.user_id;
    if ( !uid ) {
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto leave;
    }
    size = uid->len < OPENPGP_NAME_SIZE? uid->len : OPENPGP_NAME_SIZE-1;
    memcpy(dn->name, uid->name, size);
    dn->name[size] = '\0'; /* make sure it's a string */

    /* Extract the email address from the userID string and save
       it to the email field. */
    email = strchr(uid->name, '<');
    if ( email )
        pos1 = email-uid->name+1;
    email = strchr(uid->name, '>');
    if ( email )
        pos2 = email-uid->name+1;
    if (pos1 && pos2) {
        pos2 -= pos1;
        size = pos2 < OPENPGP_NAME_SIZE? pos2 : OPENPGP_NAME_SIZE-1;
        memcpy(dn->email, uid->name+pos1, size);
        dn->email[size-1] = '\0'; /* make sure it's a string */
    }
    if ( uid->is_revoked ) {
        rc = GNUTLS_E_OPENPGP_UID_REVOKED;
        goto leave; 
    }
  
leave:
    cdk_kbnode_release( kb_pk );
  
    return rc;
}

/**
  * gnutls_openpgp_extract_key_pk_algorithm - This function returns the
  * key's PublicKey algorithm
  * @cert: is an OpenPGP key
  * @bits: if bits is non null it will hold the size of the parameters' in bits
  *
  * This function will return the public key algorithm of an OpenPGP
  * certificate.
  *
  * If bits is non null, it should have enough size to hold the parameters
  * size in bits. For RSA the bits returned is the modulus. 
  * For DSA the bits returned are of the public exponent.
  *
  * Returns a member of the GNUTLS_PKAlgorithm enumeration on success,
  * or a negative value on error.
  *
  **/
int
gnutls_openpgp_extract_key_pk_algorithm(const gnutls_datum *cert, int *r_bits)
{
    CDK_KBNODE kb_pk = NULL, pkt;
    int algo = 0;
  
    if ( !cert )
        return GNUTLS_E_INVALID_PARAMETERS;

    if ( datum_to_kbnode( cert, &kb_pk ) )
        return 0;
    pkt = cdk_kbnode_find( kb_pk, PKT_PUBLIC_KEY );
    if ( pkt && r_bits)
        *r_bits = cdk_pk_get_nbits( pkt->pkt->pkt.public_key );
    algo = pkt->pkt->pkt.public_key->pubkey_algo;
    if ( is_RSA( algo ) )
        algo = GNUTLS_PK_RSA;
    else if ( is_DSA( algo ) )
        algo = GNUTLS_PK_DSA;
    else
        algo = GNUTLS_E_UNKNOWN_PK_ALGORITHM;
    cdk_kbnode_release( kb_pk );
  
    return algo;
}
  

/**
 * gnutls_openpgp_extract_key_version - Extracts the version of the key.
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Extract the version of the OpenPGP key.
 **/
int
gnutls_openpgp_extract_key_version( const gnutls_datum *cert )
{
    CDK_KBNODE kb_pk = NULL, pkt;
    int version = 0;

    if (!cert)
        return GNUTLS_E_INVALID_PARAMETERS;

    if ( datum_to_kbnode( cert, &kb_pk ) )
        return 0;
    pkt = cdk_kbnode_find( kb_pk, PKT_PUBLIC_KEY );
    if ( pkt )
        version = pkt->pkt->pkt.public_key->version;
    cdk_kbnode_release( kb_pk );

    return version;
}

/**
 * gnutls_openpgp_extract_key_creation_time - Extract the timestamp
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Returns the timestamp when the OpenPGP key was created.
 **/
time_t
gnutls_openpgp_extract_key_creation_time( const gnutls_datum *cert )
{
    CDK_KBNODE kb_pk = NULL, pkt;
    time_t timestamp = 0;

    if (!cert)
        return GNUTLS_E_INVALID_PARAMETERS;
  
    if ( datum_to_kbnode( cert, &kb_pk ) )
        return 0;
    pkt = cdk_kbnode_find( kb_pk, PKT_PUBLIC_KEY );
    if ( pkt )
        timestamp = pkt->pkt->pkt.public_key->timestamp;
    cdk_kbnode_release( kb_pk );
  
    return timestamp;
}

/**
 * gnutls_openpgp_extract_key_expiration_time - Extract the expire date
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Returns the time when the OpenPGP key expires. A value of '0' means
 * that the key doesn't expire at all.
 **/
time_t
gnutls_openpgp_extract_key_expiration_time( const gnutls_datum *cert )
{
    CDK_KBNODE kb_pk = NULL, pkt;
    time_t expiredate = 0;

    if (!cert)
        return GNUTLS_E_INVALID_PARAMETERS;
  
    if ( datum_to_kbnode( cert, &kb_pk ) )
        return 0;
    pkt = cdk_kbnode_find( kb_pk, PKT_PUBLIC_KEY );
    if ( pkt )
        expiredate = pkt->pkt->pkt.public_key->expiredate;
    cdk_kbnode_release( kb_pk );
  
    return expiredate;
}

int
_gnutls_openpgp_get_key_trust(const char *trustdb,
                              const gnutls_datum *key,
                              int *r_success)
{
    CDK_KBNODE kb_pk = NULL, pkt;
    CDK_IOBUF buf;
    PKT_public_key *pk = NULL;
    int flags = 0, ot = 0, trustval = 0;
    int rc = 0;

    if ( !trustdb || !key || !r_success )
        return GNUTLS_E_INVALID_REQUEST;

    *r_success = 0;
    rc = datum_to_kbnode( key, &kb_pk );
    if ( rc )
        return GNUTLS_E_UNKNOWN_ERROR;

    pkt = cdk_kbnode_find( kb_pk, PKT_PUBLIC_KEY );
    if ( pkt )
        pk = pkt->pkt->pkt.public_key;
    if ( !pk )
        return GNUTLS_E_UNKNOWN_ERROR;

    rc = cdk_iobuf_open( &buf, trustdb, IOBUF_MODE_RD );
    if ( rc ) {
        trustval = GNUTLS_E_FILE_ERROR;
        goto leave;
    }
    rc = cdk_trustdb_get_ownertrust( buf, pk, &ot, &flags );
    cdk_iobuf_close( buf );
    if ( rc ) { /* no ownertrust record was found */
        trustval = 0;
        *r_success = 1;
        goto leave;
    }

    if (flags & TRUST_FLAG_DISABLED) {
        trustval |= GNUTLS_CERT_NOT_TRUSTED;
        trustval |= GNUTLS_CERT_INVALID;
        goto leave;
    }
    if (flags & TRUST_FLAG_REVOKED) {
        trustval |= GNUTLS_CERT_NOT_TRUSTED;
        trustval |= GNUTLS_CERT_REVOKED;
    }
    switch (ot) {
    case TRUST_NEVER:
        trustval |= GNUTLS_CERT_NOT_TRUSTED;
        break;

    case TRUST_UNKNOWN:
    case TRUST_UNDEFINED:
    case TRUST_MARGINAL:
      
    case TRUST_FULLY:
    case TRUST_ULTIMATE:
        trustval |= 1; /* means okay */
        *r_success = 1;
        break;
    }      

leave:
    cdk_kbnode_release( kb_pk );
    return trustval;
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
 **/
int
gnutls_openpgp_verify_key( const char *trustdb,
                           const gnutls_datum* keyring,
                           const gnutls_datum* cert_list,
                           int cert_list_length )
{
    CDK_KBNODE kb_pk = NULL;
    KEYDB_HD khd = NULL;
    keybox_blob *blob = NULL;
    int rc = 0;
    int status = 0;
  
    if (!cert_list || cert_list_length != 1 || !keyring)
        return GNUTLS_E_NO_CERTIFICATE_FOUND;

    if ( !keyring->size && !trustdb)
        return GNUTLS_E_INVALID_REQUEST;

    blob = kbx_read_blob(keyring, 0);
    if (!blob)
        return GNUTLS_CERT_INVALID|GNUTLS_CERT_NOT_TRUSTED;
    khd = kbx_to_keydb(blob);
    if (!khd) {
        rc = GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
        goto leave;
    }

    if ( trustdb ) {
        int success = 0;
        rc = _gnutls_openpgp_get_key_trust(trustdb, cert_list, &success);
        if (!success)
            goto leave;
    }

    rc = datum_to_kbnode( cert_list, &kb_pk );
    if ( rc ) {
        goto leave;
        return GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
    }

    rc = cdk_key_check_sigs( kb_pk, khd, &status );
    if (rc == CDKERR_NOKEY)
        rc = 0; /* fixme */
      
    switch (status) {
    case CDK_KEY_INVALID:
        rc = GNUTLS_CERT_INVALID | GNUTLS_CERT_NOT_TRUSTED;
        break;
      
    case CDK_KEY_REVOKED:
        rc = GNUTLS_CERT_REVOKED | GNUTLS_CERT_NOT_TRUSTED;
        break;
      
    }

leave:
    kbx_blob_release( blob );
    cdk_free( khd );
    cdk_kbnode_release( kb_pk );
  
    return rc;
}

/**
 * gnutls_openpgp_fingerprint - Gets the fingerprint
 * @cert: the raw data that contains the OpenPGP public key.
 * @fpr: the buffer to save the fingerprint.
 * @fprlen: the integer to save the length of the fingerprint.
 *
 * Returns the fingerprint of the OpenPGP key. Depence on the algorithm,
 * the fingerprint can be 16 or 20 bytes.
 **/
int
gnutls_openpgp_fingerprint(const gnutls_datum *cert, char *fpr, size_t *fprlen)
{
    CDK_KBNODE kb_pk = NULL, pkt;
    PKT_public_key *pk = NULL;
    int rc = 0;
  
    if (!cert || !fpr || !fprlen)
        return GNUTLS_E_UNKNOWN_ERROR;

    *fprlen = 0;
    rc = datum_to_kbnode( cert, &kb_pk );
    if (rc)
        return rc;
    pkt = cdk_kbnode_find( kb_pk, PKT_PUBLIC_KEY );
    if ( pkt )
        pk = pkt->pkt->pkt.public_key;
    if ( !pk )
        return GNUTLS_E_UNKNOWN_ERROR;

    *fprlen = 20;
    if ( is_RSA(pk->pubkey_algo) && pk->version < 4 )
        *fprlen = 16;
    cdk_pk_get_fingerprint( pk, fpr );
  
    return 0;
}

/**
 * gnutls_openpgp_keyid - Gets the keyID
 * @cert: the raw data that contains the OpenPGP public key.
 * @keyid: the buffer to save the keyid.
 *
 * Returns the 64-bit keyID of the OpenPGP key.
 **/
int
gnutls_openpgp_keyid( const gnutls_datum *cert, opaque keyid[8] )
{
    CDK_KBNODE kb_pk = NULL, pkt;
    PKT_public_key *pk = NULL;
    u32 kid[2];
    int rc = 0;
  
    if (!cert || !keyid)
        return GNUTLS_E_UNKNOWN_ERROR;

    rc = datum_to_kbnode( cert, &kb_pk );
    if ( rc )
        return rc;

    pkt = cdk_kbnode_find( kb_pk, PKT_PUBLIC_KEY );
    if ( pkt )
        pk = pkt->pkt->pkt.public_key;
    if ( !pk )
        return GNUTLS_E_UNKNOWN_ERROR;
    cdk_pk_get_keyid( pk, kid );
    keyid[0] = kid[0] >> 24; keyid[1] = kid[0] >> 16;
    keyid[2] = kid[0] >>  8; keyid[3] = kid[0];
    keyid[4] = kid[1] >> 24; keyid[5] = kid[1] >> 16;
    keyid[6] = kid[1] >>  8; keyid[7] = kid[1];
  
    return 0;
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
    CDK_IOBUF inp = NULL;
    uint8 *blob;
    size_t nbytes;
    int enc = 0;
    int rc = 0;
  
    if (!keyring || !name)
        return GNUTLS_E_INVALID_PARAMETERS;

    rc = cdk_iobuf_open( &inp, name, IOBUF_MODE_RD );
    if ( rc )
        return GNUTLS_E_FILE_ERROR;
    enc = cdk_armor_filter_use( inp );
    cdk_iobuf_close( inp );
  
    blob = kbx_data_to_keyring( KBX_BLOB_FILE, enc, name,
                                strlen(name), &nbytes);
    if ( blob && nbytes ) { 
        if ( gnutls_datum_append( keyring, blob, nbytes ) < 0 ) {
            gnutls_assert();
            return GNUTLS_E_MEMORY_ERROR;
        }
        gnutls_free(blob);
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
  
    if (!keyring || !data || !len)
        return GNUTLS_E_INVALID_PARAMETERS;
  
    blob = kbx_data_to_keyring( KBX_BLOB_DATA, 0, data, len, &nbytes );
    if ( blob && nbytes ) {
        if ( gnutls_datum_append( keyring, blob, nbytes ) < 0 ) {
            gnutls_assert();
            return GNUTLS_E_MEMORY_ERROR;
        }
        gnutls_free(blob);
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
gnutls_certificate_set_openpgp_keyring_file(GNUTLS_CERTIFICATE_CREDENTIALS c,
                                            const char *file)
{
    if (!c || !file)
        return GNUTLS_E_INVALID_PARAMETERS;

    if ( !file_exist(file) )
        return GNUTLS_E_FILE_ERROR;

    return gnutls_openpgp_add_keyring_file(&c->keyring, file);
}

int
gnutls_certificate_set_openpgp_keyring_mem( GNUTLS_CERTIFICATE_CREDENTIALS c,
                                            const opaque *data, size_t dlen )
{
    CDK_IOBUF out = NULL;
    CDK_BSTRING a = NULL;
    armor_filter_s afx;
    int rc = 0;
  
    if ( !c || !data || !dlen )
        return GNUTLS_E_INVALID_PARAMETERS;

    rc = cdk_iobuf_create( &out, NULL );
    if ( rc )
        return GNUTLS_E_FILE_ERROR;
    rc = cdk_iobuf_write( out, data, dlen );
    if ( rc ) {
        cdk_iobuf_close( out );
        return GNUTLS_E_FILE_ERROR;
    }
    /* Maybe it's a little confusing that we check the output..
       but it's possible, that the data we want to add, is armored
       and we only want to store plaintext keyring data. */
    if ( cdk_armor_filter_use( out ) ) {
        memset( &afx, 0, sizeof afx );
        rc = cdk_armor_filter( &afx, IOBUF_CTRL_UNDERFLOW, out );
        if ( rc ) {
            cdk_iobuf_close( out );
            return GNUTLS_E_ASCII_ARMOR_ERROR;
        }
    }

    a = cdk_iobuf_read_mem( out, 0 );
    if ( a ) {
        rc = gnutls_openpgp_add_keyring_mem( &c->keyring, a->d, a->len );
        cdk_free( a );
    }
    else
        rc = GNUTLS_E_UNKNOWN_ERROR;
    cdk_iobuf_close( out );
  
    return rc;
}

/**
 * gnutls_openpgp_recv_key - Receives a key from a HKP keyserver.
 * @host - the hostname of the keyserver.
 * @port - the service port (if not set use 11371).
 * @keyid - The 32-bit keyID (rightmost bits keyid[1])
 * @key - Context to store the raw (dearmored) key.
 *
 * Try to connect to a public keyserver to get the specified key.
 **/
int
gnutls_openpgp_recv_key(const char *host, short port, uint32 keyid,
                        gnutls_datum *key)
{
    CDK_IOBUF buf = NULL;
    CDK_BSTRING a = NULL;
    struct hostent *hp;
    struct sockaddr_in sock;
    armor_filter_s afx;
    char *request = NULL;
    char buffer[4096];
    int fd = -1;
    int rc = 0, state = 0;
    ssize_t nbytes = 0, n = 0;
  
    if ( !host || !key )
        return GNUTLS_E_INVALID_PARAMETERS;

    if ( !port )
        port = 11371; /* standard service port */
  
    hp = gethostbyname( host );
    if ( hp == NULL )
        return -1;
  
    memset( &sock, 0, sizeof sock );
    memcpy( &sock.sin_addr, hp->h_addr, hp->h_length );
    sock.sin_family = hp->h_addrtype;
    sock.sin_port = htons( port );

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if ( fd == -1 )
        return -1;
    setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (char *)1, 1 );
    if ( connect( fd, (struct sockaddr*)&sock, sizeof(sock) ) == -1 ) {
        close(fd);
        return -1;
    }

    n = strlen(host)+100;
    request = cdk_alloc_clear( n + 1 );
    if ( request == NULL ) {
        close( fd );
        return -1;
    }
    snprintf( request, n,
              "GET /pks/lookup?op=get&search=0x%08X HTTP/1.0\r\n"
              "Host: %s:%d\r\n", (u32)keyid, host, port );
    
    if ( write( fd, request, strlen(request) ) == -1 ) {
        cdk_free( request );
        close( fd );
        return -1;
    }
    cdk_free( request );

    buf = cdk_iobuf_temp();
    while ( (n = read(fd, buffer, sizeof(buffer)-1)) > 0 )
    {
        buffer[n] = '\0';
        nbytes += n;
        if ( nbytes > cdk_iobuf_get_length( buf ) )
            cdk_iobuf_expand(buf, n);
        cdk_iobuf_write(buf, buffer, n);
        if ( strstr(buffer, "<pre>") || strstr(buffer, "</pre>") )
            state++;
    }
  
    if ( state != 2 ) {
        rc = GNUTLS_E_UNKNOWN_ERROR;
        goto leave;
    }
    memset( &afx, 0, sizeof afx );
    rc = cdk_armor_filter( &afx, IOBUF_CTRL_UNDERFLOW, buf );
    if ( rc ) {
        rc = GNUTLS_E_ASCII_ARMOR_ERROR;
        goto leave;
    }
    a = cdk_iobuf_read_mem(buf, 0 );
    if ( a ) { 
        rc = gnutls_set_datum( key, a->d, a->len );
        if ( rc < 0 )
            rc = GNUTLS_E_MEMORY_ERROR;
        cdk_free( a );
    }
  
leave:
    cdk_iobuf_close(buf);
    close(fd);
  
    return 0;
}

/*-
 * _gnutls_openpgp_request_key - Receives a key from a database, key server etc
 * @ret - a pointer to gnutls_datum structure.
 * @cred - a GNUTLS_CERTIFICATE_CREDENTIALS structure.
 * @key_fingerprint - The keyFingerprint
 * @key_fingerprint_size - the size of the fingerprint
 *
 * Retrieves a key from a local database, keyring, or a key server. The
 * return value is locally allocated.
 *
 -*/
int
_gnutls_openpgp_request_key( gnutls_datum* ret, 
                             const GNUTLS_CERTIFICATE_CREDENTIALS cred,
                             opaque* key_fpr,
                             int key_fpr_size)
{
    uint32 keyid;
    int rc = 0;

    if (!ret || !cred || !key_fpr)
        return GNUTLS_E_INVALID_PARAMETERS;

    if ( key_fpr_size != 16 && key_fpr_size != 20 )
        return GNUTLS_E_HASH_FAILED; /* only MD5 and SHA1 are supported */
  
    rc = gnutls_openpgp_get_key( ret, &cred->keyring, KEY_ATTR_FPR, key_fpr );
    if ( rc >= 0 )
        goto leave;

    keyid = buffer_to_u32( key_fpr + (key_fpr_size-4) );
    rc = gnutls_openpgp_recv_key( cred->pgp_key_server,
                                  cred->pgp_key_server_port,
                                  keyid, ret );
    
leave:
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
gnutls_certificate_set_openpgp_keyserver(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                         char* keyserver,
                                         int port)
{
    if ( !res || !keyserver )
        return GNUTLS_E_ILLEGAL_PARAMETER;

    if (!port)
        port = 11371;
  
    gnutls_free( res->pgp_key_server);
    res->pgp_key_server = gnutls_strdup( keyserver );
    if ( res->pgp_key_server == NULL)
    	return GNUTLS_E_MEMORY_ERROR;

    res->pgp_key_server_port = port;

   return 0;
}

static void
xml_add_tag( gnutls_datum *xmlkey, const char *tag, const char *val )
{
    char *p = NULL;

    p = gnutls_calloc( 1, strlen( tag ) + 6 + 1 ); /* 6 chars + null */
    strcat( p, "    <" );
    strcat( p, tag );
    strcat( p, ">" );
    gnutls_datum_append( xmlkey, p, strlen( p ) );
    gnutls_free( p ); p = NULL;

    gnutls_datum_append( xmlkey, val, strlen( val ) );

    p = gnutls_calloc( 1, strlen( tag ) + 4 + 1 );
    strcat( p, "</" );
    strcat( p, tag );
    strcat( p, ">\n" );
    gnutls_datum_append( xmlkey, p, strlen( p ) );
    gnutls_free( p ); p = NULL;
}

static void
xml_add_mpi( gnutls_datum *xmlkey, CDK_MPI *m, const char *tag )
{
    char *p = NULL;
    int i = 0;

    p = gnutls_calloc( 1, 2 * ( m->bytes + 3 ) );
    for ( i = 0; i < (m->bytes + 2); i++ )
        sprintf( p + 2 * i, "%02X", m->data[i] );
    p[2 * ( m->bytes + 2 )] = '\0';
    xml_add_tag( xmlkey, tag, p );
    gnutls_free( p );
}

void
xml_add_key_mpi( gnutls_datum *xmlkey, PKT_public_key *pk )
{
    const char *s = "    <KEY ENCODING=\"HEX\"/>\n";

    gnutls_datum_append( xmlkey, s, strlen( s ) );
         
    if ( is_RSA( pk->pubkey_algo ) ) {
        xml_add_mpi( xmlkey, pk->mpi[0], "RSA-N" );
        xml_add_mpi( xmlkey, pk->mpi[1], "RSA-E" );
    }
    else if ( is_DSA( pk->pubkey_algo ) ) {
        xml_add_mpi( xmlkey, pk->mpi[0], "DSA-P" );
        xml_add_mpi( xmlkey, pk->mpi[1], "DSA-Q" );
        xml_add_mpi( xmlkey, pk->mpi[2], "DSA-G" );
        xml_add_mpi( xmlkey, pk->mpi[3], "DSA-Y" );
    }
    else if ( is_ELG( pk->pubkey_algo ) ) {
        xml_add_mpi( xmlkey, pk->mpi[0], "ELG-P" );
        xml_add_mpi( xmlkey, pk->mpi[1], "ELG-G" );
        xml_add_mpi( xmlkey, pk->mpi[2], "ELG-Y" );
    }
}

static void
xml_add_key( gnutls_datum *xmlkey, int ext, PKT_public_key *pk, int sub )
{
    const char *algo, *s;
    char keyid[16], fpr[41], tmp[32];
    byte fingerpr[20];
    u32 kid[2];
    int i = 0;

    s = sub? "  <SUBKEY>\n" : "  <MAINKEY>\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );

    cdk_pk_get_keyid( pk, kid );
    snprintf( keyid, 16, "%08X%08X", kid[0], kid[1] );
    xml_add_tag( xmlkey, "KEYID", keyid );

    cdk_pk_get_fingerprint( pk, fingerpr );
    for ( i = 0; i < 20; i++ )
        sprintf( fpr + 2 * i, "%02X", fingerpr[i] );
    fpr[40] = '\0';
    xml_add_tag( xmlkey, "FINGERPRINT", fpr );

    if ( is_DSA( pk->pubkey_algo ) ) algo = "DSA";
    else if ( is_RSA( pk->pubkey_algo ) ) algo = "RSA";
    else algo = "ELG";
    xml_add_tag( xmlkey, "PKALGO", algo );

    sprintf( tmp, "%d", cdk_pk_get_nbits( pk ) );
    xml_add_tag( xmlkey, "KEYLEN", tmp );

    sprintf( tmp, "%u", pk->timestamp );
    xml_add_tag( xmlkey, "CREATED", tmp );

    if ( pk->expiredate ) {
        sprintf( tmp, "%u", pk->expiredate );
        xml_add_tag( xmlkey, "EXPIREDATE", tmp );
    }

    sprintf( tmp, "%d", pk->is_revoked );
    xml_add_tag( xmlkey, "REVOKED", tmp );

    if ( ext )
        xml_add_key_mpi( xmlkey, pk );
    
    s = sub? "  </SUBKEY>\n" : "  </MAINKEY>\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );
}

static void
xml_add_userid( gnutls_datum *xmlkey, int ext,
                gnutls_openpgp_name *dn, PKT_user_id *id )
{
    const char *s;
    char *p, *name, tmp[32];

    s = "  <USERID>\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );

    p = strchr( dn->name, '<' );
    if ( p ) {
        int len = (p - dn->name - 1);
        name = gnutls_calloc( 1, len );
        memcpy( name, dn->name, len );
        xml_add_tag( xmlkey, "NAME", name );
        gnutls_free( name );
    }
    else
        xml_add_tag( xmlkey, "NAME", dn->name );
    xml_add_tag( xmlkey, "EMAIL", dn->email );

    if ( ext ) {
        sprintf( tmp, "%d", id->is_primary );
        xml_add_tag( xmlkey, "PRIMARY", tmp );

        sprintf( tmp, "%d", id->is_revoked );
        xml_add_tag( xmlkey, "REVOKED", tmp );
    }    

    s = "  </USERID>\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );
}

static void
xml_add_sig( gnutls_datum *xmlkey, int ext, PKT_signature *sig )
{
    const char *algo, *s;
    char tmp[32], keyid[16];
    u32 kid[2];

    s = "  <SIGNATURE>\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );

    sprintf( tmp, "%d", sig->version );
    xml_add_tag( xmlkey, "VERSION", tmp );

    if ( ext ) {
        sprintf( tmp, "%d", sig->sig_class );
        xml_add_tag( xmlkey, "SIGCLASS", tmp );
    }
    
    sprintf( tmp, "%d", sig->flags.expired );
    xml_add_tag( xmlkey, "EXPIRED", tmp );

    if ( ext ) {
        if ( is_DSA( sig->pubkey_algo ) ) algo = "DSA";
        else algo = "RSA";
        xml_add_tag( xmlkey, "PKALGO", algo );

        if ( sig->digest_algo == GCRY_MD_SHA1 ) algo = "SHA1";
        else algo = "MD5";
        xml_add_tag( xmlkey, "MDALGO", algo );
    }    

    sprintf( tmp, "%u", sig->timestamp );
    xml_add_tag( xmlkey, "CREATED", tmp );

    cdk_sig_get_keyid( sig, kid );
    snprintf( keyid, 16, "%08X%08X", kid[0], kid[1] );
    xml_add_tag( xmlkey, "KEYID", keyid );

    s = "  </SIGNATURE>\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );
}

/**
 * gnutls_certificate_openpgp_get_as_xml - Return a certificate as a XML fragment
 * @cert: the certificate which holds the whole OpenPGP key.
 * @ext: extension mode (1/0), 1 means include key signatures and key data.
 * @xmlkey: he datum struct to store the XML result.
 *
 * This function will return the all OpenPGP key information encapsulated as
 * a XML string.
 **/
int
gnutls_certificate_openpgp_get_as_xml( const gnutls_datum *cert, int ext,
                                       gnutls_datum *xmlkey )
{
    CDK_KBNODE kb_pk, p;
    PACKET *pkt;
    gnutls_openpgp_name dn;
    const char *s;
    int idx = 0, rc = 0;

    if ( !cert || !xmlkey )
        return GNUTLS_E_INVALID_PARAMETERS;
        
    rc = datum_to_kbnode( cert, &kb_pk );
    if ( rc )
        return rc;

    memset( xmlkey, 0, sizeof *xmlkey );

    s = "<?xml version=\"1.0\"?>\n\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );
    
    s = "<OPENPGPKEY>\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );

    for ( p = kb_pk; p; p = p->next ) {
        pkt = p->pkt;
        switch ( pkt->pkttype ) {
        case PKT_PUBLIC_KEY:
            xml_add_key( xmlkey, ext, pkt->pkt.public_key, 0 );
            break;

        case PKT_PUBLIC_SUBKEY:
            xml_add_key( xmlkey, ext, pkt->pkt.public_key, 1 );
            break;

        case PKT_USER_ID:
            gnutls_openpgp_extract_key_name( cert, idx, &dn );
            xml_add_userid( xmlkey, ext, &dn, pkt->pkt.user_id );
            idx++;
            break;

        case PKT_SIGNATURE:
            xml_add_sig( xmlkey, ext, pkt->pkt.signature );
            break;
        }
    }
    s = "</OPENPGPKEY>\n";
    gnutls_datum_append( xmlkey, s, strlen( s ) );

    return rc;
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
gnutls_certificate_set_openpgp_trustdb( GNUTLS_CERTIFICATE_CREDENTIALS res,
                                        char* trustdb )
{
    if ( !res || !trustdb )
        return GNUTLS_E_ILLEGAL_PARAMETER;

    if ( cdk_trustdb_check( trustdb, 3 ) ) {
        /* The trustdb version is less then 3 and this mean the old
           format is still used. We don't support this format. */
        return GNUTLS_E_OPENPGP_TRUSTDB_VERSION_UNSUPPORTED;
    }

    gnutls_free( res->pgp_trustdb);
    res->pgp_trustdb = gnutls_strdup( trustdb );
    if ( res->pgp_trustdb==NULL )
        return GNUTLS_E_MEMORY_ERROR;
        
    return 0;
} 

#else /*!HAVE_LIBOPENCDK*/

int
_gnutls_openpgp_key2gnutls_key(gnutls_private_key *pkey,
                               gnutls_datum raw_key)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int
_gnutls_openpgp_cert2gnutls_cert(gnutls_cert *cert, gnutls_datum raw)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE;  
}

int
gnutls_certificate_set_openpgp_key_mem(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                       gnutls_datum *cert,
                                       gnutls_datum *key)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE; 
}

int
gnutls_certificate_set_openpgp_key_file(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                        char* CERTFILE,
                                        char* KEYFILE)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int
gnutls_openpgp_extract_key_name( const gnutls_datum *cert, int idx, 
                                 gnutls_openpgp_name *dn )
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE; 
}

int
gnutls_openpgp_extract_key_pk_algorithm(const gnutls_datum *cert, int *r_bits)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int
gnutls_openpgp_extract_key_version( const gnutls_datum *cert )
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE; 
}

time_t
gnutls_openpgp_extract_key_creation_time( const gnutls_datum *cert )
{
    return (time_t)-1;  
}

time_t
gnutls_openpgp_extract_key_expiration_time( const gnutls_datum *cert )
{
    return (time_t)-1; 
}

int
gnutls_openpgp_verify_key(const char* ign, const gnutls_datum* keyring,
                          const gnutls_datum* cert_list,
                          int cert_list_length)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE; 
}

int
gnutls_openpgp_fingerprint(const gnutls_datum *cert, char *fpr, size_t *fprlen)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE;  
}

int
gnutls_openpgp_add_keyring_file(gnutls_datum *keyring, const char *name)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE; 
}

int
gnutls_openpgp_add_keyring_mem(gnutls_datum *keyring,
                               const char *data, size_t len)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE; 
}

int
gnutls_certificate_set_openpgp_keyring_file(GNUTLS_CERTIFICATE_CREDENTIALS c,
                                            const char *file)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int
gnutls_certificate_set_openpgp_keyring_mem(GNUTLS_CERTIFICATE_CREDENTIALS c,
                                           const char *file)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE; 
}

int
_gnutls_openpgp_request_key( gnutls_datum* ret,
                             const GNUTLS_CERTIFICATE_CREDENTIALS cred,
                             opaque* key_fpr,
                             int key_fpr_size)
{
    return GNUTLS_E_UNIMPLEMENTED_FEATURE; 
}

int
gnutls_certificate_set_openpgp_keyserver(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                         char* keyserver,
                                         int port)
{
    return;
}

int
gnutls_certificate_set_openpgp_trustdb(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                       char* trustdb)
{
    return;
}     

#endif /* HAVE_LIBOPENCDK */






