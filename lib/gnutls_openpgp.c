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

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_gcry.h"
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

#define OPENPGP_NAME_SIZE GNUTLS_X509_CN_SIZE

static void
release_mpi_array(MPI *arr, size_t n)
{
  MPI x;
  
  while (arr && n--)
    {
      x = *arr;
      /*_gnutls_mpi_release(&x);*/
      gcry_mpi_release(x);
      *arr = NULL; arr++;
    }
}

static u32
buffer_to_u32(const byte *buffer)
{
  u32 u;

  if (!buffer)
    return 0;
  u = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
  return u;    
}

static int
file_exist(const char *file)
{
  FILE *fp;
  
  if (!file)
    return 0;

  fp = fopen(file, "r");
  if (fp)
    {
      fclose(fp);
      return 1;
    }

  return 0;
} 

typedef struct {
  int type;
  size_t size;
  byte *data;
} keyring_blob;

static int
keyring_blob_new(keyring_blob **r_ctx)
{
  keyring_blob *c;
  
  if (!r_ctx)
    return GNUTLS_E_INVALID_PARAMETERS;
  
  c = cdk_alloc_clear( sizeof * c);
  *r_ctx = c;

  return 0;
}

static void
keyring_blob_release(keyring_blob *ctx)
{
  if (!ctx)
    return;
  cdk_free(ctx->data);
  cdk_free(ctx);
}

static KEYDB_HD
keyring_to_keydb(keyring_blob *blob)
{
  KEYDB_HD khd = NULL;

  if (!blob)
    return NULL;
  
  khd = cdk_alloc_clear(sizeof *khd);
  khd->used = 1;
  if (blob->type == 0x00) /* file */
      khd->name = cdk_strdup(blob->data);   
  else if (blob->type == 0x01) /* data */
    {
      cdk_iobuf_new(&khd->buf, blob->size);
      cdk_iobuf_write(khd->buf, blob->data, blob->size);
    }
  else /* error */
    {
      cdk_free(khd);
      khd = NULL;
    }
  
  return khd;
}
                     
/* Extract a keyring blob from the given position. */
static keyring_blob*
read_keyring_blob(const gnutls_datum* keyring, size_t pos)
{
  keyring_blob *blob = NULL;
  
  if (!keyring || !keyring->data)
    return NULL;

  if (pos > keyring->size)
    return NULL;
    
  keyring_blob_new(&blob);
  blob->type = keyring->data[pos];
  if (blob->type < 0 || blob->type > 1)
    {
      keyring_blob_release(blob);
      return NULL;
    }
  blob->size = buffer_to_u32( keyring->data+pos+1 );
  if (!blob->size)
    {
      keyring_blob_release(blob);
      return NULL;
    }
  blob->data = cdk_alloc_clear(blob->size + 1);
  memcpy(blob->data, keyring->data+(pos+5), blob->size);
  blob->data[blob->size] = '\0';
  
  return blob;
}

/* Creates a keyring blob from raw data
 *
 * Format:
 * 1 octet  type
 * 4 octet  size of blob
 * n octets data
 */
static byte*
conv_data_to_keyring(int type, const char *data, size_t size, size_t *r_size)
{
  byte *p = NULL;

  if (!data)
    return NULL;
  
  p = gnutls_malloc( 1+4+size );
  p[0] = type; /* type: keyring name */
  p[1] = (size >> 24) & 0xff;
  p[2] = (size >> 16) & 0xff;
  p[3] = (size >>  8) & 0xff;
  p[4] = (size      ) & 0xff;
  memcpy(p+5, data, size);
  if (r_size)
    *r_size = 1+4+size;
  
  return p; 
}

static int
is_file_armored(char *file)
{
  int armored = 0;
  char *data = NULL;
  struct stat f_stat;
  FILE *fp;

  fp = fopen(file, "r");
  if (fp)
    {
      fstat(fileno(fp), &f_stat);
      if (f_stat.st_size == 0)
        {
          fclose(fp);
          armored = 0;
          goto leave;
        }
      data = cdk_alloc_clear(f_stat.st_size+1);
      fread(data, 1, f_stat.st_size, fp);
      if ( strstr(data, "-----BEGIN PGP")
           && strstr(data, "-----END PGP") )
        armored = 1;
      fclose(fp);
      cdk_free(data);
    }

leave:
  return armored;
}

static int
pkt_find_type(PACKET pkt, int type)
{
  struct packet_struct *p;
  
  if (!pkt)
    return 0;
  
  for (p=pkt; p && p->pkttype; p=p->next)
    {
      if (p->pkttype == type)
        return 1;
    }
  
  return 0;
}

static int
pkt_to_datum(PACKET pkt, gnutls_datum *raw)
{
  struct packet_struct *p;
  byte *data;
  size_t n = 0;
  int rc = 0;
  IOBUF a;
  
  if (!pkt || !raw)
    return GNUTLS_E_INVALID_PARAMETERS;

  /* fixme: conver the whole key */
  for (p=pkt; p && p->pkttype; p=p->next)
    {
      if (p->pkttype == PKT_PUBLIC_KEY)
        {
          a = cdk_iobuf_temp();
          rc = cdk_pkt_write_public_key(a, p->pkt.public_key);
          if (rc)
            return GNUTLS_E_UNKNOWN_ERROR;
          data = cdk_iobuf_get_data(a, &n);
          if (data && n)
            { 
              rc = gnutls_set_datum(raw, data, n);
              if (rc < 0)
                return GNUTLS_E_MEMORY_ERROR;
            }
          cdk_free(data);
          cdk_iobuf_close(a);
        }
    }

  return 0;
}

static int
datum_to_openpgp_pkt( const gnutls_datum *raw, PACKET *r_pkt )
{
  IOBUF buf;
  PACKET pkt = NULL;
  int rc = 0;

  if (!raw || !r_pkt)
    return GNUTLS_E_INVALID_PARAMETERS;

  cdk_iobuf_new(&buf, raw->size);
  cdk_iobuf_write(buf, raw->data, raw->size);
  rc = cdk_pkt_parse(buf, &pkt);
  if ( rc != CDKERR_EOF )
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }
  else
    rc = 0;

leave:
  cdk_iobuf_close(buf);
  *r_pkt = (!rc)? pkt : NULL;

  return rc;
}

static int
iobuf_to_datum(IOBUF buf, gnutls_datum *raw)
{
  byte *data = NULL;
  size_t nbytes = 0;
  int rc = 0;
  
  if (!buf || !raw)
    return GNUTLS_E_INVALID_PARAMETERS;
  
  data = cdk_iobuf_get_data(buf, &nbytes);
  if (data && nbytes)
    {
      rc = gnutls_set_datum(raw, data, nbytes);
      if (rc < 0)
        return GNUTLS_E_MEMORY_ERROR;
      cdk_free(data);
    }
  else
    rc = GNUTLS_E_UNKNOWN_ERROR;
  
  return rc;
}

static PKT_signature *
openpgp_pkt_to_sig(PACKET pkt, size_t idx)
{
  struct packet_struct *p = NULL;
  size_t n = 0;

  for (p=pkt; p && p->pkttype; p=p->next)
    {
      if (p->pkttype == PKT_SIGNATURE && n == idx)
        return p->pkt.signature;
      else if (p->pkttype == PKT_SIGNATURE)
        n++;
    }
  
  return NULL;
}

static PKT_public_key *
openpgp_pkt_to_pk(PACKET pkt, size_t idx)
{
  struct packet_struct *p = NULL;
  size_t n = 0;

  for (p=pkt; p && p->pkttype; p=p->next)
    {
      if (p->pkttype == PKT_PUBLIC_KEY && n == idx)
        return p->pkt.public_key;
      else if (p->pkttype == PKT_PUBLIC_KEY)
        n++;
    }
  
  return NULL;
}

static PKT_user_id *
openpgp_pkt_to_uid(PACKET pkt, size_t idx)
{
  struct packet_struct *p = NULL;
  size_t n = 0;

  for (p=pkt; p && p->pkttype; p=p->next)
    {
      if (p->pkttype == PKT_USER_ID && n == idx)
        return p->pkt.user_id;
      else if (p->pkttype == PKT_USER_ID)
        n++;
    }
  
  return NULL;
}

static int
openpgp_pk_to_gnutls_cert(gnutls_cert *cert, PKT_public_key *pk)
{
  int algo, i;
  int rc = 0;
  size_t nbytes = 0;
  
  if (!cert || !pk)
    return GNUTLS_E_INVALID_PARAMETERS;

  if ( is_ELG(pk->pubkey_algo) ) /* GnuTLS OpenPGP doesn't support ELG keys */
    return GNUTLS_E_UNWANTED_ALGORITHM;

  algo = is_DSA(pk->pubkey_algo)? GNUTLS_PK_DSA : GNUTLS_PK_RSA;
  cert->subject_pk_algorithm = algo;
  cert->version = pk->version;
  cert->valid = 0; /* fixme: should set after the verification */
  cert->cert_type = GNUTLS_CRT_OPENPGP;

  if (is_DSA(pk->pubkey_algo) || pk->pubkey_algo == PKE_RSA_S)
    cert->keyUsage = GNUTLS_X509KEY_DIGITAL_SIGNATURE;
  else if (pk->pubkey_algo == PKE_RSA_E)
    cert->keyUsage = GNUTLS_X509KEY_ENCIPHER_ONLY;
  else if (pk->pubkey_algo == PKE_RSA_ES)
    cert->keyUsage = GNUTLS_X509KEY_DIGITAL_SIGNATURE
                   | GNUTLS_X509KEY_ENCIPHER_ONLY;

  cert->params_size = cdk_key_pk_get_nmpis(pk->pubkey_algo, 0);
  for (i=0; i<cert->params_size; i++)
    {      
      nbytes = pk->mpi[i].bytes+2;
      rc = gcry_mpi_scan(&cert->params[i], GCRYMPI_FMT_PGP,
                         pk->mpi[i].data, &nbytes);
      if (rc)
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

  return rc;
}

static int
openpgp_sig_to_gnutls_cert(gnutls_cert *cert, PKT_signature *sig)
{
  IOBUF buf = NULL;
  int rc = 0;
  size_t nbytes = 0;
  size_t sigsize = 0;
  byte *data = NULL;
  
  if (!cert || !sig)
    return GNUTLS_E_INVALID_PARAMETERS;

  sigsize = 20 + sig->hashed_size + sig->unhashed_size + 2*MAX_MPI_BYTES;
  cdk_iobuf_new(&buf, sigsize);
  rc = cdk_pkt_write_signature(buf, sig);
  if (rc)
    goto leave;
  data = cdk_iobuf_get_data(buf, &nbytes);
  if (data && nbytes)
    {
      rc = gnutls_datum_append( &cert->signature, data, nbytes);
      if (rc < 0)
        {
          gnutls_assert();
          return GNUTLS_E_MEMORY_ERROR;
        }
      cdk_free(data);
    }
  else
    rc = GNUTLS_E_UNKNOWN_ERROR;

leave:
  cdk_iobuf_close(buf);

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
_gnutls_openpgp_key2gnutls_key(gnutls_private_key *pkey,
                               gnutls_datum raw_key)
{
  struct packet_struct *p = NULL;
  PKT_secret_key *sk = NULL;
  PACKET pkt = NULL;
  IOBUF buf;
  int pke_algo, i, j, eof = 0;
  int rc = 0;
  size_t nbytes = 0;

  if (!pkey || raw_key.size <= 0)
    return GNUTLS_E_INVALID_PARAMETERS;

  cdk_secure_memory_init(); 
  cdk_iobuf_new(&buf, raw_key.size);
  cdk_iobuf_write(buf, raw_key.data, raw_key.size);

  cdk_pkt_new(&pkt);
  rc = cdk_keydb_enum_sk(buf, &pkt, &eof);
  if ( (eof == 1 && !pkt) || rc)
    {
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }
  
  for (p=pkt; p; p=p->next)
    {
      if (p->pkttype == PKT_SECRET_KEY)
        {
          sk = p->pkt.secret_key;
          break;
        }
    }
  if (sk == NULL)
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }
  
  pke_algo = sk->pk->pubkey_algo;
  pkey->params_size = cdk_key_pk_get_nmpis(pke_algo, 0);
  for (i=0; i<pkey->params_size; i++)
    {
      nbytes = sk->pk->mpi[i].bytes+2;
      rc = gcry_mpi_scan(&pkey->params[i], GCRYMPI_FMT_PGP,
                         sk->pk->mpi[i].data, &nbytes);
      if (rc)
        {
          rc = GNUTLS_E_MPI_SCAN_FAILED;
          release_mpi_array(pkey->params, i-1);
          goto leave;
        }
    }
  pkey->params_size += cdk_key_sk_get_nmpis(pke_algo);
  for (j=0; j<cdk_key_sk_get_nmpis(pke_algo); j++, i++)
    {
      nbytes = sk->mpi[j]->bytes+2;
      rc = gcry_mpi_scan(&pkey->params[i], GCRYMPI_FMT_PGP,
                         sk->mpi[j]->data, &nbytes);
      if (rc)
        {
          rc = GNUTLS_E_MPI_SCAN_FAILED;
          release_mpi_array(pkey->params, i-1);
          goto leave;
        }
    }
  if (is_ELG(pke_algo))
    return GNUTLS_E_UNWANTED_ALGORITHM;
  else if (is_DSA(pke_algo))
    pkey->pk_algorithm = GNUTLS_PK_DSA;
  else if (is_RSA(pke_algo))
    pkey->pk_algorithm = GNUTLS_PK_RSA;
  rc = gnutls_set_datum(&pkey->raw, raw_key.data, raw_key.size);
  if (rc < 0)
    {
      release_mpi_array(pkey->params, i);
      rc = GNUTLS_E_MEMORY_ERROR;
    }

leave:
  cdk_iobuf_close(buf);
  cdk_pkt_release(pkt);

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
  struct packet_struct *p;
  PACKET pkt = NULL;
  PKT_public_key *pk = NULL;
  int rc = 0;
  
  if (!cert)
    return GNUTLS_E_INVALID_PARAMETERS;

  memset(cert, 0, sizeof *cert);
  rc = datum_to_openpgp_pkt(&raw, &pkt);
  if (rc)
    return rc;
  for (p=pkt; p && p->pkttype; p=p->next)
    {
      if (p->pkttype == PKT_PUBLIC_KEY)
        {
          pk = p->pkt.public_key;
          break;
        }
    }
  if (pk == NULL)
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }

  rc = gnutls_set_datum(&cert->raw, raw.data, raw.size);
  if (rc < 0)
    {
      rc = GNUTLS_E_MEMORY_ERROR;
      goto leave;
    }
  rc = openpgp_pk_to_gnutls_cert(cert, p->pkt.public_key);

leave:
  return rc;
}

/**
 * gnutls_openpgp_get_key - Retrieve a key from the keyring.
 * @key: the destination context to save the key.
 * @keyring: the datum struct that contains all keyring information.
 * @attr: The attribute (keyid, fingerprint, ...).
 * @by: What attribute is used.
 *
 * This function can be used to retrieve keys by different pattern
 * from a binary or a file keyring.
 **/
int
gnutls_openpgp_get_key(gnutls_datum *key, const gnutls_datum *keyring,
                       key_attr_t by, opaque *pattern)
{
  int rc = 0;
  keyring_blob *blob = NULL;
  KEYDB_HD khd = NULL;
  PACKET pk = NULL;
  KEYDB_SEARCH ks;
  
  if (!key || !keyring || by == KEY_ATTR_NONE)
    return GNUTLS_E_INVALID_PARAMETERS;

  blob = read_keyring_blob(keyring, 0);
  if (!blob)
    return GNUTLS_E_MEMORY_ERROR;
  khd = keyring_to_keydb(blob);
  ks.type = by;
  switch (by)
    {
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
  
  rc = cdk_keydb_search_key(khd, &pk, &ks);
  if (rc)
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND; 
      goto leave;
    }    

  if ( !pkt_find_type(pk, PKT_PUBLIC_KEY) )
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }

  rc = pkt_to_datum(pk, key);
  
leave:
  cdk_free(khd);
  cdk_pkt_release(pk);
  keyring_blob_release(blob);
  
  return rc;
}

int
gnutls_certificate_set_openpgp_key_mem(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                       gnutls_datum *cert,
                                       gnutls_datum *key)
{
  struct packet_struct *p;
  gnutls_datum raw;
  PACKET pk = NULL;
  int rc = 0;
  int i;
  
  if (!res || !key || !cert)
    return GNUTLS_E_INVALID_PARAMETERS;

  rc = datum_to_openpgp_pkt(cert, &pk);
  if (rc)
    goto leave;

  /* fixme: too much duplicated code from (set_openpgp_key_file) */
  res->cert_list = gnutls_realloc(res->cert_list,
                                  (1+res->ncerts)*sizeof(gnutls_cert*));
  if (res->cert_list == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list_length = gnutls_realloc(res->cert_list_length,
                                         (1+res->ncerts)*sizeof(int));
  if (res->cert_list_length == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;    
    }

  res->cert_list[res->ncerts] = gnutls_calloc(1, sizeof(gnutls_cert));
  if (res->cert_list[res->ncerts] == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR; 
    }

  for (i=1, p=pk; p && p->pkttype; p=p->next)
    {
      if (i > MAX_PARAMS_SIZE)
        break;
      if (p->pkttype == PKT_PUBLIC_KEY)
        {
          int n = res->ncerts;
          res->cert_list_length[n] = 1;
          gnutls_set_datum(&res->cert_list[n][0].raw, cert->data, cert->size);
          openpgp_pk_to_gnutls_cert(&res->cert_list[n][0], p->pkt.public_key);
          i++;
        }
      else if (p->pkttype == PKT_SIGNATURE)
        {
          int n = res->ncerts;
          openpgp_sig_to_gnutls_cert(&res->cert_list[n][0], p->pkt.signature); 
        }
    }
  
  res->ncerts++;
  res->pkey = gnutls_realloc(res->pkey,
                             (res->ncerts)*sizeof(gnutls_private_key));
  if (res->pkey == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;   
    }
  /* ncerts has been incremented before */
  gnutls_set_datum(&raw, key->data, key->size);
  rc =_gnutls_openpgp_key2gnutls_key( &res->pkey[res->ncerts-1], raw);
  gnutls_free_datum(&raw);
  
leave:
  cdk_pkt_release(pk);
  
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
 * should only contain one key.
 **/
int
gnutls_certificate_set_openpgp_key_file(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                        char* CERTFILE,
                                        char* KEYFILE)
{
  IOBUF buf = NULL;
  PACKET pkt = NULL;
  gnutls_datum raw;
  struct packet_struct *p = NULL;
  armor_filter_s afx;
  int eof = 0, i;
  int rc = 0;
  
  if (!res || !KEYFILE || !CERTFILE)
    return GNUTLS_E_INVALID_PARAMETERS;

  if ( !file_exist(CERTFILE) || !file_exist(KEYFILE) )
    return GNUTLS_E_FILE;
  
  if ( is_file_armored(CERTFILE) )
    {
      rc = cdk_iobuf_open(&buf, CERTFILE, IOBUF_MODE_RD);
      if (rc == -1)
        return GNUTLS_E_FILE;
      memset(&afx, 0, sizeof afx);
      rc = cdk_iobuf_push_filter(buf, &afx, cdk_armor_filter);
      if (rc)
        {
          cdk_iobuf_close(buf);
          rc = GNUTLS_E_ASCII_ARMOR;
          goto leave;          
        }
      /*cdk_iobuf_close(buf);*/
    }
  else
    {
      rc = cdk_iobuf_open(&buf, CERTFILE, IOBUF_MODE_RD);
      if (rc == -1)
        return GNUTLS_E_FILE;
    }
  cdk_pkt_new(&pkt);

  res->cert_list = gnutls_realloc(res->cert_list,
                                  (1+res->ncerts)*sizeof(gnutls_cert*));
  if (res->cert_list == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list_length = gnutls_realloc(res->cert_list_length,
                                         (1+res->ncerts)*sizeof(int));
  if (res->cert_list_length == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list[res->ncerts] = gnutls_calloc(1, sizeof(gnutls_cert)); 
  if (res->cert_list[res->ncerts] == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

  do {
    rc = cdk_keydb_enum_pk(buf, &pkt, &eof);
    if ( (eof == 1 && !pkt) || rc)
      break;
    for (i=1, p=pkt; p && p->pkttype; p=p->next)
      {
        if (i > MAX_PARAMS_SIZE)
          break;
        if (p->pkttype == PKT_PUBLIC_KEY)
          {
            int n = res->ncerts;
            res->cert_list_length[n] = 1;
            iobuf_to_datum(buf, &res->cert_list[n][0].raw);
            openpgp_pk_to_gnutls_cert(&res->cert_list[n][0], p->pkt.public_key);
            i++;
          }
        else if (p->pkttype == PKT_SIGNATURE)
          {
            int n = res->ncerts;
            openpgp_sig_to_gnutls_cert( &res->cert_list[n][0], p->pkt.signature);
          }
      }
  } while (!eof && !rc);

  cdk_iobuf_close(buf);
  if (rc)
    {
      cdk_pkt_release(pkt);
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }
  cdk_pkt_release(pkt);

  if ( is_file_armored(KEYFILE) )
    {
      rc = cdk_iobuf_open(&buf, KEYFILE, IOBUF_MODE_RD);
      if (rc == -1)
        return GNUTLS_E_FILE;
      memset(&afx, 0, sizeof afx);
      rc = cdk_iobuf_push_filter(buf, &afx, cdk_armor_filter);
      if (rc)
        {
          cdk_iobuf_close(buf);
          rc = GNUTLS_E_ASCII_ARMOR;
          goto leave;
        }
      /*cdk_iobuf_close(buf);*/
    }
  else
    {
      rc = cdk_iobuf_open(&buf, KEYFILE, IOBUF_MODE_RD);
      if (rc == -1)
        return GNUTLS_E_FILE;
    }
  iobuf_to_datum(buf, &raw);
  cdk_iobuf_close(buf);
  
  res->pkey = gnutls_realloc(res->pkey,
                             (res->ncerts+1)*sizeof(gnutls_private_key));
  if (res->pkey == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->ncerts++;
  
  /* ncerts has been incremented before */
  rc =_gnutls_openpgp_key2gnutls_key( &res->pkey[res->ncerts-1], raw);

leave:
  
  return rc;
}

/**
 * gnutls_openpgp_extract_key_name - Extracts the userID
 * @cert: the raw data that contains the OpenPGP public key.
 * @dn: the structure to store the userID specific data in.
 *
 * Extracts the userID from the raw OpenPGP key.
 **/
int
gnutls_openpgp_extract_key_name( const gnutls_datum *cert,
                                 gnutls_openpgp_name *dn )
{
  PACKET pkt = NULL;
  PKT_user_id *uid = NULL;
  char *p;
  int rc = 0;
  int pos1 = 0, pos2 = 0;
  size_t size = 0;

  if (!cert || !dn)
    return GNUTLS_E_INVALID_PARAMETERS;

  rc = datum_to_openpgp_pkt(cert, &pkt);
  if (rc)
    return rc;
  uid = openpgp_pkt_to_uid(pkt, 0);
  if (!uid)
    {
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }
  memset(dn, 0, sizeof *dn);
  size = uid->size < OPENPGP_NAME_SIZE? uid->size : OPENPGP_NAME_SIZE;
  memcpy(dn->name, uid->name, size);
  dn->name[size-1] = '\0'; /* make sure it's a string */

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
      pos2 -= pos1;
      size = pos2 < OPENPGP_NAME_SIZE? pos2 : OPENPGP_NAME_SIZE;
      memcpy(dn->email, uid->name+pos1, size);
      dn->email[size-1] = '\0'; /* make sure it's a string */
    }
  
leave:
  cdk_pkt_release(pkt);
  
  return rc;
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
  PACKET pkt = NULL;
  PKT_public_key *pk = NULL;
  int version = 0;

  if (!cert)
    return GNUTLS_E_INVALID_PARAMETERS;

  if ( datum_to_openpgp_pkt(cert, &pkt) )
    return 0;
  pk = openpgp_pkt_to_pk(pkt, 0);
  if (pk)
    version = pk->version;
  cdk_pkt_release(pkt);

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
  PACKET pkt = NULL;
  PKT_public_key *pk = NULL;
  time_t timestamp = 0;

  if (!cert)
    return GNUTLS_E_INVALID_PARAMETERS;
  
  if ( datum_to_openpgp_pkt(cert, &pkt) )
    return 0;
  pk = openpgp_pkt_to_pk(pkt, 0);
  if (pk)
    timestamp = pk->timestamp;
  cdk_pkt_release(pkt);
  
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
  PACKET pkt = NULL;
  PKT_public_key *pk = NULL;
  time_t expiredate = 0;

  if (!cert)
    return GNUTLS_E_INVALID_PARAMETERS;
  
  if ( datum_to_openpgp_pkt(cert, &pkt) )
    return 0;
  pk = openpgp_pkt_to_pk(pkt, 0);
  if (pk)
    expiredate = pk->expiredate;
  cdk_pkt_release(pkt);
  
  return expiredate;
}

int
_gnutls_openpgp_get_key_trust(const char *trustdb,
                              const gnutls_datum *key,
                              int *r_success)
{
  int flags = 0;
  int ot = 0, trustval = 0;
  int rc = 0;
  PACKET pkt;
  PKT_public_key *pk = NULL;
  IOBUF buf;

  if (!trustdb || !key || !r_success)
    return GNUTLS_E_NO_CERTIFICATE_FOUND;

  *r_success = 0;
  rc = datum_to_openpgp_pkt(key, &pkt);
  if (rc)
    return GNUTLS_E_NO_CERTIFICATE_FOUND;
  
  pk = openpgp_pkt_to_pk(pkt, 0);
  if (!pk)
    return GNUTLS_E_NO_CERTIFICATE_FOUND;

  rc = cdk_iobuf_open( &buf, trustdb, IOBUF_MODE_RD );
  if (rc == -1)
    {
      trustval = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }
  rc = cdk_trustdb_find_ownertrust(buf, pk, &ot, &flags);
  cdk_iobuf_close(buf);
  if (rc)
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }

  if (flags & TRUST_FLAG_DISABLED)
    {
      trustval = GNUTLS_CERT_INVALID;
      goto leave;
    }
  if (flags & TRUST_FLAG_REVOKED)
    trustval |= GNUTLS_CERT_REVOKED;
  if (ot == TRUST_EXPIRED)
      trustval |= GNUTLS_CERT_EXPIRED;
  switch (ot)
    {
    case TRUST_NEVER:
      trustval |= GNUTLS_CERT_NOT_TRUSTED;
      break;

    case TRUST_UNKNOWN:
    case TRUST_UNDEFINED:
    case TRUST_MARGINAL:
      
    case TRUST_FULLY:
    case TRUST_ULTIMATE:
      trustval |= GNUTLS_CERT_TRUSTED;
      *r_success = 1;
      break;
    }      

leave:
  return trustval;
}
               
/**
 * gnutls_openpgp_verify_key - Verify all signatures on the key
 * @cert_list: the structure that holds the certificates.
 * @cert_list_lenght: the items in the cert_list.
 *
 * Verify all signatures in the certificate list. When the key
 * is not available, the signature is skipped.
 * The return value is one of the CertificateStatus entries.
 **/
int
gnutls_openpgp_verify_key( const char *trustdb,
                           const gnutls_datum* keyring,
                           const gnutls_datum* cert_list,
                           int cert_list_length )
{
  PACKET pkt = NULL;
  KEYDB_HD khd = NULL;
  keyring_blob *blob = NULL;
  int rc = 0;
  int status = 0;
  
  if (!cert_list || !cert_list_length || !keyring)
    return GNUTLS_CERT_INVALID;

  if (cert_list_length != 1 || !keyring->size)
    return GNUTLS_CERT_INVALID;

  blob = read_keyring_blob(keyring, 0);
  if (!blob)
    return GNUTLS_CERT_INVALID;
  khd = keyring_to_keydb(blob);
  if (!khd)
    {
      rc = GNUTLS_CERT_INVALID;
      goto leave;
    }

  if ( trustdb )
    {
      int success = 0;
      rc = _gnutls_openpgp_get_key_trust(trustdb, cert_list, &success);
      if (!success)
        goto leave;
    }
  
  rc = datum_to_openpgp_pkt(cert_list, &pkt);
  if (rc)
    {
      goto leave;
      return GNUTLS_CERT_INVALID;
    }
  
  {
    struct packet_struct *p;
    PKT_user_id *id = NULL;
    PKT_signature *sig = NULL;
    for (p=pkt; p && p->pkttype; p=p->next)
      {
        if (p->pkttype == PKT_SIGNATURE)
          sig = p->pkt.signature;
        if (p->pkttype == PKT_USER_ID && sig && !sig->userid_hash)
          {
              id = p->pkt.user_id;
            if (sig->sig_class >= 0x10 && sig->sig_class <= 0x13)
              sig->userid_hash  = cdk_userid_create_hash(id);
            id = NULL;
          }
      }
  }
  
  rc = cdk_key_check_sigs(pkt, khd, &status);
  if (rc == CDKERR_NOKEY)
    rc = 0; /* fixme */
      
  switch (status)
    {
    case CDK_KEY_INVALID:
      rc = GNUTLS_CERT_INVALID;
      break;
      
    case CDK_KEY_REVOKED:
      rc = GNUTLS_CERT_REVOKED;
      break;
      
    case CDK_KEY_EXPIRED:
      rc = GNUTLS_CERT_EXPIRED;
      break;
    }

leave:
  keyring_blob_release(blob);
  cdk_free(khd);
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
gnutls_openpgp_fingerprint(const gnutls_datum *cert, byte *fpr, size_t *fprlen)
{
  PACKET pkt = NULL;
  PKT_public_key *pk = NULL;
  struct packet_struct *p;
  int rc = 0;
  
  if (!cert || !fpr || !fprlen)
    return GNUTLS_E_UNKNOWN_ERROR;

  *fprlen = 0;
  rc = datum_to_openpgp_pkt(cert, &pkt);
  if (rc)
    return rc;
  for (p=pkt; p && p->pkttype; p=p->next)
    {
      if (p->pkttype == PKT_PUBLIC_KEY)
        {
          pk = p->pkt.public_key;
          if ( is_RSA(pk->pubkey_algo) && pk->version < 4 )
            *fprlen = 16;
          else
            *fprlen = 20;
          cdk_key_create_fpr(pk, fpr);
        }
    }
  
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
gnutls_openpgp_keyid( const gnutls_datum *cert, uint32 *keyid )
{
  PACKET pkt;
  PKT_public_key *pk = NULL;
  struct packet_struct *p;
  int rc = 0;
  
  if (!cert || !keyid)
    return GNUTLS_E_UNKNOWN_ERROR;

  rc = datum_to_openpgp_pkt(cert, &pkt);
  if (rc)
    return rc;
  for (p=pkt; p && p->pkttype; p=p->next)
    {
      if (p->pkttype == PKT_PUBLIC_KEY)
        {
          pk = p->pkt.public_key;
          cdk_key_keyid_from_pk(pk, (u32*)keyid);
        }
    }

  return 0;
}

/**
 * gnutls_openpgp_add_keyring_file - Adds a keyring file for OpenPGP
 * @keyring: data buffer to store the file.
 * @name: filename of the keyring.
 *
 * The function is used to set keyrings that will be used internally
 * by various OpenCDK functions. For example to find a key when it
 * is needed for an operations.
 **/
int
gnutls_openpgp_add_keyring_file(gnutls_datum *keyring, const char *name)
{
  byte *blob;
  size_t nbytes;
  
  if (!keyring || !name)
    return GNUTLS_E_INVALID_PARAMETERS;

  blob = conv_data_to_keyring(0x00, name, strlen(name), &nbytes);
  if (blob && nbytes)
    { 
      if ( gnutls_datum_append( keyring, blob, nbytes ) < 0 )
        {
          gnutls_assert();
          return GNUTLS_E_MEMORY_ERROR;
        }
      gnutls_free(blob);
    }
  
  return 0;
}

/**
 * gnutls_openpgp_add_keyring_mem - Adds keyring data for OpenPGP
 * @keyring: data buffer to store the file.
 * @data: the binary data of the keyring.
 * @len: the size of the binary buffer.
 *
 * Same as gnutls_openpgp_add_keyring_mem but now we store the
 * data instead of the filename.
 **/
int
gnutls_openpgp_add_keyring_mem(gnutls_datum *keyring,
                               const char *data, size_t len)
{
  byte *blob;
  size_t nbytes = 0;
  
  if (!keyring || !data || !len)
    return GNUTLS_E_INVALID_PARAMETERS;
  
  blob = conv_data_to_keyring(0x01, data, len, &nbytes);
  if (blob && nbytes)
    {
      if ( gnutls_datum_append( keyring, blob, nbytes ) < 0 )
        {
          gnutls_assert();
          return GNUTLS_E_MEMORY_ERROR;
        }
      gnutls_free(blob);
    }
  
  return 0;
}

int
gnutls_certificate_set_openpgp_keyring_file(GNUTLS_CERTIFICATE_CREDENTIALS c,
                                            const char *file)
{
  if (!c || !file)
    return GNUTLS_E_INVALID_PARAMETERS;

  if ( !file_exist(file) )
    return GNUTLS_E_FILE;

  return gnutls_openpgp_add_keyring_file(&c->keyring, file);
}

int
gnutls_certificate_set_openpgp_keyring_mem(GNUTLS_CERTIFICATE_CREDENTIALS c,
                                           const char *file)
{
  IOBUF buf = NULL;
  byte *data = NULL;
  size_t nbytes = 0;
  armor_filter_s afx;
  int rc = 0;
  
  if (!c || !file)
    return GNUTLS_E_INVALID_PARAMETERS;

  if ( !file_exist(file) )
    return GNUTLS_E_FILE;

  if ( is_file_armored( (char*)file) )
    {
      rc = cdk_iobuf_open(&buf, file, IOBUF_MODE_RD);
      if (rc == -1)
        return GNUTLS_E_FILE;
      rc = cdk_iobuf_push_filter(buf, &afx, cdk_armor_filter);
      if (rc)
        {
          cdk_iobuf_close(buf);
          return GNUTLS_E_ASCII_ARMOR;
        }
    }
  else
    {
      rc = cdk_iobuf_open(&buf, file, IOBUF_MODE_RD);
      if (rc == -1)
        return GNUTLS_E_FILE;
    }
  data = cdk_iobuf_get_data(buf, &nbytes);
  if (data && nbytes)
    {
      rc = gnutls_openpgp_add_keyring_mem(&c->keyring, data, nbytes);
      cdk_free(data);
    }
  else
    rc = GNUTLS_E_UNKNOWN_ERROR;
  cdk_iobuf_close(buf);
  
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
  int rc = 0, state = 0;
  struct hostent *hp;
  struct sockaddr_in sock;
  armor_filter_s afx;
  char *request = NULL;
  char buffer[4096];
  IOBUF buf = NULL;
  int fd = -1;
  byte *data;
  ssize_t n = 0, nbytes = 0;
  
  if (!host || !key)
    return GNUTLS_E_INVALID_PARAMETERS;

  if (!port)
    port = 11371; /* standard service port */
  
  hp = gethostbyname(host);
  if (hp == NULL)
    return -1;
  
  memset(&sock, 0, sizeof sock);
  memcpy(&sock.sin_addr, hp->h_addr, hp->h_length);
  sock.sin_family = hp->h_addrtype;
  sock.sin_port = htons(port);

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    return -1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)1, 1);
  if ( connect(fd, (struct sockaddr*)&sock, sizeof(sock)) == -1 )
    {
      close(fd);
      return -1;
    }

  request = cdk_alloc_clear(strlen(host)+100);
  sprintf(request, "GET /pks/lookup?op=get&search=0x%08X HTTP/1.0\r\n"
          "Host: %s:%d\r\n", (u32)keyid, host, port);
  if ( write(fd, request, strlen(request)) == -1 )
    {
      cdk_free(request);
      close(fd);
      return -1;
    }
  cdk_free(request);

  buf = cdk_iobuf_temp();
  while ( (n = read(fd, buffer, sizeof(buffer)-1)) > 0 )
    {
      buffer[n] = '\0';
      nbytes += n;
      if (nbytes > cdk_iobuf_get_size(buf))
        cdk_iobuf_expand(buf, n);
      cdk_iobuf_write(buf, buffer, n);
      if ( strstr(buffer, "<pre>") || strstr(buffer, "</pre>") )
        state++;
    }
  
  if (state != 2)
    {
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }
  memset(&afx, 0, sizeof afx);
  rc = cdk_iobuf_push_filter(buf, &afx, cdk_armor_filter);
  if (rc)
    {
      rc = GNUTLS_E_ASCII_ARMOR;
      goto leave;
    }
  data = cdk_iobuf_get_data(buf, &n);
  if (data && n)
    { 
      gnutls_set_datum(key, data, n);
      cdk_free(data);
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
  int rc = 0;
  uint32 keyid;

  if (!ret || !cred || !key_fpr)
    return GNUTLS_E_INVALID_PARAMETERS;

  if (key_fpr_size != 16 && key_fpr_size != 20)
    return GNUTLS_E_HASH_FAILED; /* only MD5 and SHA1 are supported */
  
  rc = gnutls_openpgp_get_key(ret, &cred->keyring, KEY_ATTR_FPR, key_fpr);
  if (rc >= 0)
    goto leave;

  keyid = buffer_to_u32(key_fpr+16);
  rc = gnutls_openpgp_recv_key(cred->pgp_key_server,
                               cred->pgp_key_server_port,
                               keyid, ret);
    
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
void
gnutls_certificate_set_openpgp_keyserver(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                         char* keyserver,
                                         int port)
{
  if (!res || !keyserver)
    return;

  if (!port)
    port = 11371;
  
  res->pgp_key_server = keyserver;
  res->pgp_key_server_port = port;
}

void
gnutls_certificate_set_openpgp_trustdb(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                       char* trustdb)
{
  if (!res || !trustdb)
    return;

  res->pgp_trustdb = gnutls_strdup(trustdb);
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
gnutls_openpgp_extract_key_name( const gnutls_datum *cert,
                                 gnutls_openpgp_name *dn )
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
gnutls_openpgp_fingerprint(const gnutls_datum *cert, byte *fpr, size_t *fprlen)
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

void
gnutls_certificate_set_openpgp_keyserver(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                         char* keyserver,
                                         int port)
{
  return;
}

#endif /* HAVE_LIBOPENCDK */






