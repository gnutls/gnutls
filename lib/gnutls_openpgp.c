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

#ifdef HAVE_LIBOPENCDK

#include <stdio.h>
#include <gcrypt.h>
#include <opencdk.h>
#include <time.h>
#include <sys/stat.h>

#include "gnutls_errors.h"
#include "gnutls_gcry.h"
#include "gnutls_cert.h"
#include "gnutls_datum.h"
#include "gnutls_global.h"
#include "auth_cert.h"

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

static int
is_file_armored(char *file)
{
  int armored = 0;
  char *data = NULL;
  struct stat f_stat;
  FILE *fp;

  if ( (fp = fopen(file, "r")) )
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
      cdk_free(data); data = NULL;      
    }

leave:
  return armored;
}    

static int
datum_to_openpgp_pkt( const gnutls_datum *raw, PKT *r_pkt )
{
  IOBUF buf;
  PKT pkt = NULL;
  int rc = 0;

  if (!raw || !r_pkt)
    return GNUTLS_E_INVALID_PARAMETERS;

  cdk_iobuf_new(&buf, raw->size);
  cdk_iobuf_write(buf, raw->data, raw->size);
  if ( (rc = cdk_pkt_parse(buf, &pkt)) != CDKERR_EOF )
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }
  else
    rc = 0;

leave:
  cdk_iobuf_close(buf);
  if (!rc)
    *r_pkt = pkt;
  else
    *r_pkt = NULL;
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
  
  data = cdk_iobuf_get_data_as_buffer(buf, &nbytes);
  if (data && nbytes)
    {
      if ( gnutls_set_datum(raw, data, nbytes) < 0 )
        return GNUTLS_E_MEMORY_ERROR;
      cdk_free(data); data = NULL;
    }
  else
    rc = GNUTLS_E_UNKNOWN_ERROR;
  
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
  size_t nbytes = 0;
  
  if (!cert || !pk)
    return GNUTLS_E_INVALID_PARAMETERS;

  algo = is_DSA(pk->pke_algo)? GNUTLS_PK_DSA : GNUTLS_PK_RSA;
  cert->subject_pk_algorithm = algo;
  cert->version = pk->version;
  cert->valid = 0; /* fixme: should set after the verification */
  cert->cert_type = GNUTLS_CRT_OPENPGP;
  cdk_key_create_fpr(pk, cert->fingerprint);

  if (is_DSA(pk->pke_algo) || pk->pke_algo == PKE_RSA_S)
    cert->keyUsage = GNUTLS_X509KEY_DIGITAL_SIGNATURE;
  else if (pk->pke_algo == PKE_ELG_E || pk->pke_algo == PKE_RSA_E)
    cert->keyUsage = GNUTLS_X509KEY_ENCIPHER_ONLY;
  else if (pk->pke_algo == PKE_ELG_ES || pk->pke_algo == PKE_RSA_ES)
    cert->keyUsage = GNUTLS_X509KEY_DIGITAL_SIGNATURE
                   | GNUTLS_X509KEY_ENCIPHER_ONLY;

  cert->params_size = cdk_key_pk_get_nmpis(pk->pke_algo, 0);
  for (i=0; i<cert->params_size; i++)
    {      
      nbytes = pk->mpi[i].bytes+2;
      if (gcry_mpi_scan(&cert->params[i], GCRYMPI_FMT_PGP,
                        pk->mpi[i].data, &nbytes))
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
  byte *data = NULL;
  
  if (!cert || !sig)
    return GNUTLS_E_INVALID_PARAMETERS;

  cdk_iobuf_new(&buf, 9216); /* enough to hold the biggest signature */
  if ( (rc=cdk_pkt_write_signature(buf, sig)) )
    goto leave;
  data = cdk_iobuf_get_data_as_buffer(buf, &nbytes);
  if (data && nbytes)
    {
      if ( gnutls_datum_append( &cert->signature, data, nbytes) < 0 )
        {
          gnutls_assert();
          return GNUTLS_E_MEMORY_ERROR;
        }
      cdk_free(data); data = NULL;
    }
  else
    rc = GNUTLS_E_UNKNOWN_ERROR;

leave:
  cdk_iobuf_close(buf);

  return rc;
}

/*-
 * _gnutls_openpgp_key2gnutls_key - Converts an OpenPGP secret key to GnuTLS
 *
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
  struct packet_s *p = NULL;
  PKT_secret_key *sk = NULL;
  PKT pkt = NULL;
  IOBUF buf;
  int pke_algo, i, j, rc = 0, eof = 0;
  size_t nbytes = 0;

  if (!pkey)
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
      if (p->id == PKT_SECKEY)
        {
          sk = p->p.sk;
          break;
        }
    }
  if (sk == NULL)
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }
  
  pke_algo = sk->pk->pke_algo;
  pkey->params_size = cdk_key_pk_get_nmpis(pke_algo, 0);
  for (i=0; i<pkey->params_size; i++)
    {
      nbytes = sk->pk->mpi[i].bytes+2;
      if (gcry_mpi_scan(&pkey->params[i], GCRYMPI_FMT_PGP,
                        sk->pk->mpi[i].data, &nbytes))
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
      if (gcry_mpi_scan(&pkey->params[i], GCRYMPI_FMT_PGP,
                        sk->mpi[j]->data, &nbytes))
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
  if ( gnutls_set_datum(&pkey->raw, raw_key.data, raw_key.size) < 0 )
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
 *
 * @cert: the certificate to store the data.
 * @raw: the buffer which contains the whole OpenPGP key packets.
 *
 * The RFC2440 (OpenPGP Message Format) data is converted to a GnuTLS
 * specific certificate.
 -*/
int
_gnutls_openpgp_cert2gnutls_cert(gnutls_cert *cert, gnutls_datum raw)
{
  struct packet_s *p;
  PKT pkt = NULL;
  PKT_public_key *pk = NULL;
  int rc = 0;
  
  if (!cert)
    return GNUTLS_E_INVALID_PARAMETERS;

  memset(cert, 0, sizeof *cert);
  if ( (rc = datum_to_openpgp_pkt(&raw, &pkt)) )
    return rc;
  for (p=pkt; p && p->id; p=p->next)
    {
      if (p->id == PKT_PUBKEY)
        {
          pk = p->p.pk;
          break;
        }
    }
  if (pk == NULL)
    {
      rc = GNUTLS_E_NO_CERTIFICATE_FOUND;
      goto leave;
    }

  if ( gnutls_set_datum(&cert->raw, raw.data, raw.size) < 0 )
    {
      rc = GNUTLS_E_MEMORY_ERROR;
      goto leave;
    }
  rc = openpgp_pk_to_gnutls_cert(cert, p->p.pk);

leave:
  return rc;
}

/**
 * gnutls_certificate_set_openpgp_key_file - Used to set OpenPGP keys
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
gnutls_certificate_set_openpgp_key_file(GNUTLS_CERTIFICATE_CREDENTIALS res,
                                        char* CERTFILE,
                                        char* KEYFILE)
{
  IOBUF a, buf;
  PKT pkt = NULL;
  gnutls_datum raw;
  struct packet_s *p = NULL;
  int eof = 0, rc = 0, i;
  
  if (!res || !KEYFILE || !CERTFILE)
    return GNUTLS_E_INVALID_PARAMETERS;

  if ( is_file_armored(CERTFILE) )
    {      
      if (cdk_iobuf_open(&a, CERTFILE, IOBUF_MODE_RD) == -1)
        return GNUTLS_E_UNKNOWN_ERROR;
      if ( cdk_armor_decode_iobuf(a, &buf) )
        {
          cdk_iobuf_close(a);
          rc = GNUTLS_E_UNKNOWN_ERROR;
          goto leave;          
        }
      /*cdk_iobuf_close(a);*/
    }
  else
    {
      if (cdk_iobuf_open(&buf, CERTFILE, IOBUF_MODE_RD) == -1)
        return GNUTLS_E_UNKNOWN_ERROR;
    }
  cdk_pkt_new(&pkt);

  res->cert_list = gnutls_realloc( res->cert_list,
                                   (1+res->ncerts)*sizeof(gnutls_cert*));
  if (res->cert_list == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
  res->cert_list_length = gnutls_realloc( res->cert_list_length,
                                          (1+res->ncerts)*sizeof(int) );
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
    for (i=1, p=pkt; p && p->id; p=p->next)
      {
        if (i > MAX_PARAMS_SIZE)
          break;
        if (p->id == PKT_PUBKEY)
          {
            int n = res->ncerts;
            res->cert_list_length[n] = 1;
            iobuf_to_datum(buf, &res->cert_list[n][0].raw);
            openpgp_pk_to_gnutls_cert( &res->cert_list[n][0], p->p.pk );
	    i++;
          }
        else if (p->id == PKT_SIG)
          {
            int n = res->ncerts;
            openpgp_sig_to_gnutls_cert( &res->cert_list[n][0], p->p.sig );
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
      if (cdk_iobuf_open(&a, KEYFILE, IOBUF_MODE_RD) == -1)
        return GNUTLS_E_UNKNOWN_ERROR;
      if ( cdk_armor_decode_iobuf(a, &buf) )
        {
          cdk_iobuf_close(a);
          rc = GNUTLS_E_UNKNOWN_ERROR;
          goto leave;
        }
      /*cdk_iobuf_close(a);*/
    }
  else
    {
      if (cdk_iobuf_open(&buf, KEYFILE, IOBUF_MODE_RD) == -1)
        return GNUTLS_E_UNKNOWN_ERROR;
    }
  iobuf_to_datum(buf, &raw);
  cdk_iobuf_close(buf);
  
  res->ncerts++;
  
  res->pkey = gnutls_realloc( res->pkey, (res->ncerts)*
                              sizeof(gnutls_private_key));
  if (res->pkey == NULL)
    {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
  
  /* ncerts has been incremented before */
  rc =_gnutls_openpgp_key2gnutls_key( &res->pkey[res->ncerts-1], raw);

leave:
  
  return rc;
}

/**
 * gnutls_openpgp_extract_key_name - Extracts the userID
 *
 * @cert: the raw data that contains the OpenPGP public key.
 * @dn: the structure to store the userID specific data in.
 *
 * Extracts the userID from the raw OpenPGP key.
 **/
int
gnutls_openpgp_extract_key_name( const gnutls_datum *cert,
                                 gnutls_openpgp_name *dn )
{
  PKT pkt = NULL;
  PKT_userid *uid = NULL;
  char *p;
  int rc = 0;
  int pos1 = 0, pos2 = 0;

  if (!cert || !dn)
    return GNUTLS_E_INVALID_PARAMETERS;

  if ( (rc = datum_to_openpgp_pkt(cert, &pkt)) )
    return rc;
  uid = openpgp_pkt_to_uid(pkt, 0);
  if (!uid)
    {
      rc = GNUTLS_E_UNKNOWN_ERROR;
      goto leave;
    }
  memset(dn, 0, sizeof *dn);
  strcpy( dn->name, uid->name );

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
 * gnutls_openpgp_extract_key_version - Extracts the version of the key.
 *
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Extract the version of the OpenPGP key.
 **/
int
gnutls_openpgp_extract_key_version( const gnutls_datum *cert )
{
  PKT pkt = NULL;
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
 *
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Returns the timestamp when the OpenPGP key was created.
 **/
time_t
gnutls_openpgp_extract_key_creation_time( const gnutls_datum *cert )
{
  PKT pkt = NULL;
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
 *
 * @cert: the raw data that contains the OpenPGP public key.
 *
 * Returns the time when the OpenPGP key expires. A value of '0' means
 * that the key doesn't expire at all.
 **/
time_t
gnutls_openpgp_extract_key_expiration_time( const gnutls_datum *cert )
{
  PKT pkt = NULL;
  PKT_public_key *pk = NULL;
  time_t expiredate = 0;

  if (!cert)
    return GNUTLS_E_INVALID_PARAMETERS;
  
  if ( datum_to_openpgp_pkt(cert, &pkt) )
    return 0;
  pk = openpgp_pkt_to_pk(pkt, 0);
  if (pk)
    expiredate = pk->expiredate;
  cdk_pkt_release(pkt); pkt = NULL;
  
  return expiredate;
}

static char*
read_keyring_blob(const gnutls_datum* keyring, size_t pos,
                  int *r_type, size_t *r_size)
{
  byte *blob;
  
  if (!keyring)
    return NULL;

  *r_type = keyring->data[pos];
  if (*r_type < 0 || *r_type > 1)
    return NULL;
  *r_size = keyring->data[pos+1] << 24 | keyring->data[pos+2] << 16
          | keyring->data[pos+3] <<  8 | keyring->data[pos+4];
  if (!*r_size)
    return NULL;
  blob = gnutls_malloc(*r_size + 1);
  memcpy(blob, keyring->data+(pos+5), *r_size);
  blob[*r_size] = '\0';

  return blob;
}
                   
/**
 * gnutls_openpgp_verify_key - Verify all signatures on the key
 *
 * @cert_list: the structure that holds the certificates.
 * @cert_list_lenght: the items in the cert_list.
 *
 * Verify all signatures in the certificate list. When the key
 * is not available, the signature is skipped.
 * The return value is one of the CertificateStatus entries.
 **/
int
gnutls_openpgp_verify_key( const gnutls_datum* keyring,
                           const gnutls_datum* cert_list,
                           int cert_list_length)
{
  PKT pkt = NULL;
  KEYDB_HD khd = NULL;
  int rc = 0;
  size_t size = 0;
  int status = 0, type = -1;
  char *data;
  
  if (!cert_list || !cert_list_length || !keyring)
    return GNUTLS_CERT_CORRUPTED;

  if (cert_list_length != 1 || !keyring->size)
    return GNUTLS_CERT_CORRUPTED;

  data = read_keyring_blob(keyring, 0, &type, &size);
  if (!data)
    return GNUTLS_CERT_CORRUPTED;
  khd = cdk_alloc_clear(sizeof *khd);
  khd->used = 1;
  if (type == 0x00) /* file */
    {
      khd->name = cdk_strdup(data);
    }
  else if (type == 0x01) /* data */
    {
      cdk_iobuf_new(&khd->buf, size);
      cdk_iobuf_write(khd->buf, data, size);
    }
  else /* error */
    {
      rc = GNUTLS_CERT_CORRUPTED;
      goto leave;
    }
  
  if ( (rc = datum_to_openpgp_pkt(cert_list, &pkt)) )
    {
      goto leave;
      return GNUTLS_CERT_CORRUPTED;
    }
  rc = cdk_key_check_sigs(pkt, khd, &status);
  if (rc == CDKERR_NOKEY)
    rc = 0; /* fixme */
      
  switch (status)
    {
    case CDK_KEY_INVALID:
      rc = GNUTLS_CERT_CORRUPTED;
      break;
    case CDK_KEY_REVOKED:
      rc = GNUTLS_CERT_REVOKED;
      break;
    case CDK_KEY_EXPIRED:
      rc = GNUTLS_CERT_EXPIRED;
      break;
    case CDK_KEY_VALID:
      rc = GNUTLS_CERT_TRUSTED;
      break;
    }

leave:
  cdk_free(khd); khd = NULL;
  return rc;
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
gnutls_openpgp_fingerprint(const gnutls_datum *cert, byte *fpr,size_t *fprlen )
{
  PKT pkt = NULL;
  PKT_public_key *pk = NULL;
  struct packet_s *p;
  int rc = 0;
  
  if (!cert || !fpr || !fprlen)
    return GNUTLS_E_UNKNOWN_ERROR;

  *fprlen = 0;
  if ( (rc = datum_to_openpgp_pkt(cert, &pkt)) )
    return rc;
  for (p=pkt; p && p->id; p=p->next)
    {
      if (p->id == PKT_PUBKEY)
        {
          pk = p->p.pk;
          if ( is_RSA(pk->pke_algo) )
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
 *
 * @cert: the raw data that contains the OpenPGP public key.
 * @keyid: the buffer to save the keyid.
 *
 * Returns the 64-bit keyID of the OpenPGP key.
 **/
int
gnutls_openpgp_keyid( const gnutls_datum *cert, u32 *keyid )
{
  PKT pkt;
  PKT_public_key *pk = NULL;
  struct packet_s *p;
  int rc = 0;
  
  if (!cert || !keyid)
    return GNUTLS_E_UNKNOWN_ERROR;

  if ( (rc = datum_to_openpgp_pkt(cert, &pkt)) )
    return rc;
  for (p=pkt; p && p->id; p=p->next)
    {
      if (p->id == PKT_PUBKEY)
        {
          pk = p->p.pk;
          cdk_key_keyid_from_pk(pk, keyid);
        }
    }

  return 0;
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
  byte *p;
  
  p = gnutls_malloc( 1+4+size );
  p[0] = type; /* type: keyring name */
  p[1] = (size >> 24) & 0xff;
  p[2] = (size >> 16) & 0xff;
  p[3] = (size >>  8) & 0xff;
  p[4] = (size      ) & 0xff;
  memcpy(p+5, data, size);
  *r_size = 1+4+size;

  return p;
}

/**
 * gnutls_openpgp_add_keyring_file - Adds a keyring file for OpenPGP
 *
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
 *
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

  return gnutls_openpgp_add_keyring_file(&c->keyring, file);
}

int
gnutls_certificate_set_openpgp_keyring_mem(GNUTLS_CERTIFICATE_CREDENTIALS c,
                                           const char *file)
{
  IOBUF a;
  byte *data;
  size_t nbytes = 0;
  int rc = 0;
  
  if (!c || !file)
    return GNUTLS_E_INVALID_PARAMETERS;

  if (cdk_iobuf_open(&a, file, IOBUF_MODE_RD) == -1)
    return GNUTLS_E_UNKNOWN_ERROR;
  data = cdk_iobuf_get_data_as_buffer(a, &nbytes);
  if (data && nbytes)
    {
      rc = gnutls_openpgp_add_keyring_mem(&c->keyring, data, nbytes);
      cdk_free(data);
    }
  else
    rc = GNUTLS_E_UNKNOWN_ERROR;
  cdk_iobuf_close(a);
  
  return rc;
}

#endif /* HAVE_LIBOPENCDK */







