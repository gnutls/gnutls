/*
 *      Copyright (C) 2002 Timo Schulz <twoaday@freakmail.de>
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
#include <gcrypt.h>
#include <opencdk.h>
#include <time.h>
#include <sys/stat.h>

#include "gnutls_errors_int.h"
#include "gnutls_int.h"
#include "gnutls_gcry.h"
#include "gnutls_cert.h"
#include "gnutls_datum.h"
#include "gnutls_global.h"
#include "auth_cert.h"

#define DEBUG_OPENPGP 1

static int
release_mpi_array(MPI *arr, size_t n)
{
#ifdef DEBUG_OPENPGP
  fprintf(stderr, "release_mpi_array(%p, %d)\n", arr, n);
#endif
  while (arr && n--)
    {    
      gcry_mpi_release(*arr);
      *arr = NULL; arr++;
    }
}

static int
is_file_armored(char *file)
{
  int armored = 0;
  char *data = NULL;
  struct stat f_stat;

  FILE *fp = fopen(file, "r");
  if (fp)
    {
      fstat(fileno(fp), &f_stat);
      data = cdk_alloc_clear(f_stat.st_size+1);
      fread(data, 1, f_stat.st_size, fp);
      if ( strstr(data, "-----BEGIN PGP") )
        armored = 1;
      cdk_free(data); data = NULL;
      fclose(fp);
    }

#ifdef DEBUG_OPENPGP
  fprintf(stderr, "is_file_armored(%s) = %d\n", file, armored);
#endif
  
  return armored;
}    

static int
datum_to_openpgp_pkt( const gnutls_datum *raw, PKT *r_pkt )
{
  IOBUF buf;
  PKT a = NULL;
  int rc = 0;

  if (!raw || !r_pkt)
    return CDKERR_INV_VALUE;

  cdk_iobuf_new(&buf, raw->size);
  cdk_iobuf_write(buf, raw->data, raw->size);
  if ( (rc = cdk_pkt_parse(buf, &a)) != CDKERR_EOF )
    {
      *r_pkt = NULL;
      goto leave;
    }
  rc = 0;
  *r_pkt = a;

#ifdef DEBUG_OPENPGP
  fprintf(stderr, "datum_to_openpgp_pkt(%p, %p) = %d\n", raw, *r_pkt, rc);
#endif

leave:
  return rc;
}

static int
iobuf_to_datum(IOBUF a, gnutls_datum *raw)
{
  byte *data = NULL;
  size_t n = 0;
  
  if (!a)
    return CDKERR_INV_VALUE;
  data = cdk_iobuf_get_data_as_buffer(a, &n);
  if (data)
    {
      if ( gnutls_set_datum(raw, data, n) < 0 )
        return GNUTLS_E_MEMORY_ERROR;
      cdk_free(data); data = NULL;
    }
  return 0;
}

static PKT_signature *
openpgp_pkt_to_sig(PKT pkt, size_t idx)
{
  struct packet_s *p = NULL;
  size_t n = 0;

  for (p=pkt; p && pkt; p=p->next)
    {
      if (p->id == PKT_SIG && n == idx)
        return p->p.sig;
      else if (p->id == PKT_SIG)
        n++;
    }
  
  return NULL;
}

static PKT_public_key *
openpgp_pkt_to_pk(PKT pkt, size_t idx)
{
  struct packet_s *p = NULL;
  size_t n = 0;

  for (p=pkt; p && pkt; p=p->next)
    {
      if (p->id == PKT_PUBKEY && n == idx)
        return p->p.pk;
      else if (p->id == PKT_PUBKEY)
        n++;
    }
  
  return NULL;
}

static PKT_userid *
openpgp_pkt_to_uid(PKT pkt, size_t idx)
{
  struct packet_s *p = NULL;
  size_t n = 0;

  for (p=pkt; p && pkt; p=p->next)
    {
      if (p->id == PKT_USERID && n == idx)
        return p->p.uid;
      else if (p->id == PKT_USERID)
        n++;
    }
  
  return NULL;
}

static int
openpgp_pk_to_gnutls_cert(gnutls_cert *cert, PKT_public_key *pk)
{
  int algo, i, rc = 0;
  size_t n = 0;
  
  if (!cert || !pk)
    return CDKERR_INV_VALUE;

  algo = is_DSA(pk->pke_algo)? GNUTLS_PK_DSA : GNUTLS_PK_RSA;
  cert->subject_pk_algorithm = algo;
  cert->version = pk->version;
  cert->valid = 0; /* fixme: should set after the verification */
  cert->cert_type = GNUTLS_CRT_OPENPGP;
  cdk_key_create_fpr(pk, cert->fingerprint);

  for (i=0; i<cdk_key_pk_get_nmpis(pk->pke_algo, 0); i++)
    {      
      n = pk->mpi[i].bytes+2;
      if (gcry_mpi_scan(&cert->params[i], GCRYMPI_FMT_PGP,
                        pk->mpi[i].data, &n))
        {
          rc = GNUTLS_E_MPI_SCAN_FAILED;
          goto leave;
        }
    }
  cert->expiration_time = pk->expiredate;
  cert->activation_time = pk->timestamp;

leave:
  if (rc)
    release_mpi_array(cert->params, i-1);

#ifdef DEBUG_OPENPGP
  fprintf(stderr, "openpgp_pk_to_gnutls_cert(%p, %p) = %d\n", cert, pk, rc);
#endif
  
  return rc;
}

static int
openpgp_sig_to_gnutls_cert(gnutls_cert *cert, PKT_signature *sig)
{
  IOBUF a;
  int rc = 0;
  size_t n = 0;
  byte *data = NULL;
  
  if (!cert || !sig)
    return CDKERR_INV_VALUE;

  cdk_iobuf_new(&a, 9216); /* enough to hold the biggest signature */
  if ( (rc=cdk_pkt_write_signature(a, sig)) )
    goto leave;
  data = cdk_iobuf_get_data_as_buffer(a, &n);
  gnutls_datum_append(&cert->signature, data, n);
  cdk_free(data); data = NULL;

leave:
  cdk_iobuf_close(a);

#ifdef DEBUG_OPENPGP
  fprintf(stderr, "openpgp_sig_to_gnutls_cert(%p, %p) = %d\n", cert, sig, rc);
#endif
  
  return rc;
} 

/**
 * _gnutls_openpgp_key2gnutls_key - Converts an OpenPGP secret key to GnuTLS
 *
 * @pkey: the GnuTLS private key context to store the key.
 * @raw_key: the raw data which contains the whole key packets.
 *
 * The RFC2440 (OpenPGP Message Format) data is converted into the
 * GnuTLS specific data which is need to perform secret key operations.
 **/
int
_gnutls_openpgp_key2gnutls_key(gnutls_private_key *pkey,
                               gnutls_datum raw_key)
{
  struct packet_s *p = NULL;
  PKT_secret_key *sk = NULL;
  PKT pkt = NULL;
  IOBUF a;
  int pke_algo, i, j, rc = 0, eof = 0;
  size_t n = 0;

  if (!pkey)
    return GNUTLS_E_UNKNOWN_ERROR;

  cdk_secure_memory_init();
  
  cdk_iobuf_new(&a, raw_key.size);
  cdk_iobuf_write(a, raw_key.data, raw_key.size);

  cdk_pkt_new(&pkt);
  rc = cdk_keydb_enum_sk(a, &pkt, &eof);
  if (eof == 1 && !pkt || rc)
    {
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }
  
  for (p=pkt; p; p=p->next)
    {
      if (p->id == PKT_SECKEY)
        {
          sk = p->p.sk;
          break;
        }
    }
  if (sk == NULL)
    {
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }
  pke_algo = sk->pk->pke_algo;
  for (i=0; i<cdk_key_pk_get_nmpis(pke_algo, 0); i++)
    {
      n = sk->pk->mpi[i].bytes+2;
      if (gcry_mpi_scan(&pkey->params[i], GCRYMPI_FMT_PGP,
                        sk->pk->mpi[i].data, &n))
        {
          rc = GNUTLS_E_MPI_SCAN_FAILED;
          release_mpi_array(pkey->params, i-1);
          goto leave;
        }
    }
  for (j=0; j<cdk_key_sk_get_nmpis(pke_algo); j++, i++)
    {
      n = sk->mpi[j]->bytes+2;
      if (gcry_mpi_scan(&pkey->params[i], GCRYMPI_FMT_PGP,
                        sk->mpi[j]->data, &n))
        {
          rc = GNUTLS_E_MPI_SCAN_FAILED;
          release_mpi_array(pkey->params, i-1);
          goto leave;
        }
    }
  if (is_DSA(pke_algo))
    pkey->pk_algorithm = GNUTLS_PK_DSA;
  else if (is_RSA(pke_algo))
    pkey->pk_algorithm = GNUTLS_PK_RSA;
  else
    return GNUTLS_E_UNKNOWN_CIPHER;
  if (gnutls_set_datum(&pkey->raw, raw_key.data, raw_key.size) < 0)
    {
      release_mpi_array(pkey->params, i);
      rc = GNUTLS_E_MEMORY_ERROR;
    }

leave:
  cdk_iobuf_close(a);
  cdk_pkt_release(pkt);

#ifdef DEBUG_OPENPGP
  fprintf(stderr, "_gnutls_openpgp_key2gnutls_key(%p, %p) = %d\n",
          pkey, raw_key, rc);
#endif
  
  return rc;
}

/**
 * gnutls_openpgp_set_key_file - Used to set OpenPGP keys in the structure
 *
 * @res: the destination context to save the data.
 * @CERTFILE: the file that contains the public key.
 * @KEYFILE: the file that contains the secret key.
 *
 * This funtion is used to load OpenPGP keys into the GnuTLS structure.
 * It doesn't matter whether the keys are armored or but, but the files
 * should only contain one key.
 **/
int
gnutls_openpgp_set_key_file( GNUTLS_CERTIFICATE_CREDENTIALS res,
                             char* CERTFILE,
                             char* KEYFILE)
{
  IOBUF a, buf;
  PKT pkt = NULL;
  gnutls_datum raw;
  struct packet_s *p = NULL;
  int eof = 0, rc = 0, i, is_armored = 0;
  
  if (!res || !KEYFILE || !CERTFILE)
    return GNUTLS_E_UNKNOWN_ERROR;

  is_armored = is_file_armored(CERTFILE);
  if (cdk_iobuf_open(&a, CERTFILE, IOBUF_MODE_RD) == -1)
    return GNUTLS_E_UNKNOWN_ERROR;
  if (is_armored)
    {      
      if ( cdk_armor_decode_iobuf(a, &buf) )
        {
          cdk_iobuf_close(a);
          rc = GNUTLS_E_UNKNOWN_ERROR;
          goto leave;          
        }
    }
  else
    buf = a;
  cdk_pkt_new(&pkt);
  res->ncerts = 0;
  res->cert_list = gnutls_malloc(sizeof(gnutls_cert));
  res->cert_list_length = gnutls_malloc( sizeof(int) );
  do {
    rc = cdk_keydb_enum_pk(buf, &pkt, &eof);
    if (eof == 1 && !pkt || rc)
      break;
    for (i=1, p=pkt; p && p->id; p=p->next)
      {
        if (i > MAX_PARAMS_SIZE)
          break;
        if (!res->cert_list[res->ncerts])
          {
            int n = res->ncerts;
            res->cert_list_length = gnutls_realloc(res->cert_list_length,
                                                   i*sizeof(int));
            res->cert_list[n] = gnutls_realloc(res->cert_list[n],
                                               i*sizeof(gnutls_cert)); 
          }
        if (p->id == PKT_PUBKEY)
          {
            int n = res->ncerts;
            res->cert_list_length[n] = 1;
            iobuf_to_datum(buf, &res->cert_list[n]->raw);
            openpgp_pk_to_gnutls_cert( res->cert_list[n], p->p.pk );
            res->ncerts++; i++;
          }
        else if (p->id == PKT_SIG)
          {
            int n = res->ncerts;
            openpgp_sig_to_gnutls_cert( res->cert_list[n], p->p.sig );
          }
      }
  } while (!eof && !rc);
  res->x509_ca_list = NULL;
  res->x509_ncas = 0;
  cdk_iobuf_close(buf);
  cdk_iobuf_close(a);
  if (rc)
    {
      cdk_pkt_release(pkt);
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }
  cdk_pkt_release(pkt);

  is_armored = is_file_armored(KEYFILE);
  if (cdk_iobuf_open(&a, KEYFILE, IOBUF_MODE_RD) == -1)
    return GNUTLS_E_UNKNOWN_ERROR;
  if (is_armored)
    {      
      if ( cdk_armor_decode_iobuf(a, &buf) )
        {
          cdk_iobuf_close(a);
          rc = GNUTLS_E_UNKNOWN_ERROR;
          goto leave;
        }
    }
  else
    buf = a;
  iobuf_to_datum(buf, &raw);
  cdk_iobuf_close(a);
  cdk_iobuf_close(buf);
  res->pkey = gnutls_calloc(1, sizeof *res->pkey);
  rc =_gnutls_openpgp_key2gnutls_key(res->pkey, raw);

leave:
#ifdef DEBUG_OPENPGP
  fprintf(stderr, "gnutls_openpgp_set_key_file(%p, %s, %s) = %d\n",
          res, CERTFILE, KEYFILE, rc);
#endif
  
  return rc;
}

/**
 * gnutls_openpgp_extract_certificate_issuer_dn - Extracts the userID
 *
 * @cert: the raw data that contains the OpenPGP public key.
 * @dn: the structure to store the userID specific data in.
 *
 * Extracts the userID from the raw OpenPGP key.
 **/
int
gnutls_openpgp_extract_certificate_issuer_dn( const gnutls_datum *cert,
                                              gnutls_dn *dn)
{
  PKT pkt = NULL;
  PKT_userid *uid = NULL;
  char *p;
  int rc = 0, pos1 = 0, pos2 = 0;

  if (!cert || !dn)
    return GNUTLS_E_UNKNOWN_ERROR;

  datum_to_openpgp_pkt(cert, &pkt);
  uid = openpgp_pkt_to_uid(pkt, 0);
  if (!uid)
    {
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }    
  strcpy( dn->common_name, uid->name );

  /*
   * Extract the email address from the userID string and save it to
   * the email field.
   */
  p = strchr(uid->name, '<');
  if (p)
    pos1 = p-uid->name+1;
  p = strchr(uid->name, '>');
  if (p)
    pos2 = p-uid->name+1;
  if (pos1 && pos2)
    {
      memcpy( dn->email, uid->name+pos1, pos2-pos1 );
      dn->email[ pos2-pos1-1 ] = '\0';
    }
  
leave:
  cdk_pkt_release(pkt);
  
  return rc;
}

/**
 * gnutls_openpgp_extract_certificate_version- Extracts the version
 *
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Extract the version of the OpenPGP key.
 **/
int
gnutls_openpgp_extract_certificate_version( const gnutls_datum *cert )
{
  PKT pkt = NULL;
  PKT_public_key *pk = NULL;
  int version = 0;

  if (!cert)
    return GNUTLS_E_UNKNOWN_ERROR;

  datum_to_openpgp_pkt(cert, &pkt);
  pk = openpgp_pkt_to_pk(pkt, 0);
  if (pk)
    version = pk->version;
  cdk_pkt_release(pkt);

  return version;
}

/**
 * gnutls_openpgp_extract_certificate_activation_time - Extract the timestamp
 *
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Returns the timestamp when the OpenPGP key was created.
 **/
time_t
gnutls_openpgp_extract_certificate_activation_time( const gnutls_datum *cert )
{
  PKT pkt = NULL;
  PKT_public_key *pk = NULL;
  time_t timestamp = 0;

  if (!cert)
    return GNUTLS_E_UNKNOWN_ERROR;
  
  datum_to_openpgp_pkt(cert, &pkt);
  pk = openpgp_pkt_to_pk(pkt, 0);
  if (pk)
    timestamp = pk->timestamp;
  cdk_pkt_release(pkt);
  
  return timestamp;
}

/**
 * gnutls_openpgp_extract_certificate_expiration_time - Extract the expire date
 *
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Returns the time when the OpenPGP key expires. A value of '0' means
 * that the key doesn't expire at all.
 **/
time_t
gnutls_openpgp_extract_certificate_expiration_time( const gnutls_datum *cert )
{
  PKT pkt = NULL;
  PKT_public_key *pk = NULL;
  time_t expiredate = 0;

  if (!cert)
    return GNUTLS_E_UNKNOWN_ERROR;
  
  datum_to_openpgp_pkt(cert, &pkt);
  pk = openpgp_pkt_to_pk(pkt, 0);
  if (pk)
    expiredate = pk->expiredate;
  cdk_pkt_release(pkt); pkt = NULL;
  
  return expiredate;
}

/**
 * gnutls_openpgp_verify_certificate - Verify all signatures on the key
 *
 * @cert_list: the structure that holds the certificates.
 * @cert_list_lenght: the items in the cert_list.
 *
 * Verify all signatures in the certificate list. When the key
 * is not available, the signature is skipped.
 * A return value of '0' means that all checked signatures are good.
 **/
int
gnutls_openpgp_verify_certificate( const gnutls_datum* cert_list,
                                   int cert_list_length)

{
  if (!cert_list || !cert_list_length )
    return GNUTLS_E_UNKNOWN_ERROR;
  
  return 0;
}

/**
 * gnutls_openpgp_fingerprint - Gets the fingerprint
 *
 * @cert: the raw data that contains the OpenPGP public key.
 * @fpr: the buffer to save the fingerprint.
 * @fprlen: the integer to save the length of the fingerprint.
 *
 * Returns the fingerprint of the OpenPGP key. Depence on the algorithm,
 * the fingerprint can be 16 oder 20 bytes.
 **/
int
gnutls_openpgp_fingerprint( const gnutls_cert *cert, byte *fpr,size_t *fprlen )
{
  if (!cert)
    return GNUTLS_E_UNKNOWN_ERROR;

  if (cert->cert_type != GNUTLS_CRT_OPENPGP)
    {
      *fprlen = 0;
      return 0;
    }
  if (cert->subject_pk_algorithm == GNUTLS_PK_RSA)
    *fprlen = 16;
  else
    *fprlen = 20;
  memcpy(fpr, cert->fingerprint, *fprlen);

  return 0;  
}

/**
 * gnutls_openpgp_keyid - Gets the keyID
 *
 * @cert: the raw data that contains the OpenPGP public key.
 * @keyid: the buffer to save the keyid.
 *
 * Returns the 64-bit keyID of the OpenPGP key.
 **/
int
gnutls_openpgp_keyid( const gnutls_cert *cert, u32 *keyid )
{
  const byte *fpr;
  
  if (!cert || !keyid)
    return GNUTLS_E_UNKNOWN_ERROR;

  if (cert->cert_type != GNUTLS_CRT_OPENPGP)
    {
      keyid[0] = keyid[1] = 0;
      return 0;
    }
  /* fixme: this is only valid for V4 keys! */
  fpr = cert->fingerprint;
  keyid[0] = (fpr[12] << 24) | (fpr[13] << 16) | (fpr[14] << 8) | fpr[15];
  keyid[1] = (fpr[16] << 24) | (fpr[17] << 16) | (fpr[18] << 8) | fpr[19];

  return 0;
}

/**
 * gnutls_openpgp_add_keyring - Adds a global keyring for OpenPGP
 *
 * @fname: the filename of the keyring.
 * @is_secret: if the keyring contains secret keys or not.
 *
 * The function is used to set keyrings that will be used internally
 * by various OpenCDK functions. For example to find a key when it
 * is need for an operations.
 **/
int
gnutls_openpgp_add_keyring(const char *fname, int is_secret)
{
  
  if ( cdk_keydb_add_resource(fname, is_secret) )
    return GNUTLS_E_UNKNOWN_ERROR;

  return 0;
}





