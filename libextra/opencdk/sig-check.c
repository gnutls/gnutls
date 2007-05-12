/* sig-check.c - Check signatures
 *        Copyright (C) 2001, 2002, 2003, 2007 Timo Schulz
 *        Copyright (C) 1998-2002 Free Software Foundation, Inc.
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or 
 * (at your option) any later version. 
 *  
 * OpenCDK is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details. 
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <time.h>
#include <gcrypt.h>
#include <assert.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"


/* Hash all multi precision integers of the key PK with the given
   message digest context MD. */
static int
hash_mpibuf (cdk_pubkey_t pk, gcry_md_hd_t md, int usefpr)
{
  byte buf[MAX_MPI_BYTES];
  size_t nbytes;
  int i, npkey;
  gcry_error_t err;
  
  /* We have to differ between two modes for v3 keys. To form the
     fingerprint, we hash the MPI values without the length prefix.
     But if we calculate the hash for verifying/signing we use all data. */
  npkey = cdk_pk_get_npkey (pk->pubkey_algo);
  for (i = 0; i < npkey; i++) 
    {
      err = gcry_mpi_print (GCRYMPI_FMT_PGP, buf, MAX_MPI_BYTES, 
			    &nbytes, pk->mpi[i]);
      if (err)
	return map_gcry_error (err);
      if (!usefpr || pk->version == 4)
	gcry_md_write (md, buf, nbytes);
      else /* without the prefix. */
	gcry_md_write (md, buf + 2, nbytes - 2);
    }
  return 0;
}


/* Hash an entire public key PK with the given message digest context
   MD. The USEFPR param is only valid for version 3 keys because of
   the different way to calculate the fingerprint. */
int
_cdk_hash_pubkey (cdk_pubkey_t pk, gcry_md_hd_t md, int usefpr)
{
  byte buf[12];
  u16 n;
  int i, npkey;
  
  if (!pk || !md)
    return CDK_Inv_Value;
  
  if (usefpr && pk->version < 4 && is_RSA (pk->pubkey_algo)) 
    return hash_mpibuf (pk, md, 1);
  
  n = pk->version < 4? 8 : 6;  /* v4: without the expire 'date' */
  npkey = cdk_pk_get_npkey (pk->pubkey_algo);
  for (i = 0; i < npkey; i++) 
    n = n + (gcry_mpi_get_nbits (pk->mpi[i])+7)/8 + 2;
  
  i = 0;
  buf[i++] = 0x99;
  buf[i++] = n >> 8;
  buf[i++] = n >> 0;
  buf[i++] = pk->version;
  buf[i++] = pk->timestamp >> 24;
  buf[i++] = pk->timestamp >> 16;
  buf[i++] = pk->timestamp >>  8;
  buf[i++] = pk->timestamp >>  0;
  
  if (pk->version < 4) 
    {    
      u16 a = 0;
      
      if (pk->expiredate)
	a = (u16)((pk->expiredate - pk->timestamp) / 86400L);
      buf[i++] = a >> 8;
      buf[i++] = a;
    }
  buf[i++] = pk->pubkey_algo;
  gcry_md_write (md, buf, i);
  return hash_mpibuf (pk, md, 0);
}


void
_cdk_hash_userid (cdk_pkt_userid_t uid, int is_v4, gcry_md_hd_t md)
{
  const byte *data;
  byte buf[5];
  u32 dlen;
  
  if (!uid || !md)
    return;

  if (!is_v4)
    {
      gcry_md_write (md, (byte*)uid->name, uid->len);
      return;
    }
  
  dlen = uid->attrib_img? uid->attrib_len : uid->len;
  data = uid->attrib_img? uid->attrib_img : (byte*)uid->name;
  buf[0] = uid->attrib_img? 0xD1 : 0xB4;
  buf[1] = dlen >> 24;
  buf[2] = dlen >> 16;
  buf[3] = dlen >>  8;
  buf[4] = dlen >>  0;
  gcry_md_write (md, buf, 5);
  gcry_md_write (md, data, dlen);
}


cdk_error_t
_cdk_hash_sig_data (cdk_pkt_signature_t sig, gcry_md_hd_t md)
{
  byte buf[4];
  
  if (!sig || !md)
    return CDK_Inv_Value;
  
  if (sig->version == 4)
    gcry_md_putc (md, sig->version);
  gcry_md_putc (md, sig->sig_class);
  if (sig->version < 4) 
    {
      buf[0] = sig->timestamp >> 24;
      buf[1] = sig->timestamp >> 16;
      buf[2] = sig->timestamp >>  8;
      buf[3] = sig->timestamp >>  0;
      gcry_md_write (md, buf, 4);
    }
  else
    {
      size_t n;
      
      gcry_md_putc (md, sig->pubkey_algo);
      gcry_md_putc (md, sig->digest_algo);
      if (sig->hashed != NULL)
	{
	  byte *p = _cdk_subpkt_get_array (sig->hashed, 0, &n);
	  assert (p != NULL);
	  buf[0] = n >> 8;
	  buf[1] = n >> 0;
	  gcry_md_write (md, buf, 2);
	  gcry_md_write (md, p, n);
	  cdk_free (p);
	  sig->hashed_size = n;
	  n = sig->hashed_size + 6;
	}
      else 
	{
	  gcry_md_putc (md, 0x00);
	  gcry_md_putc (md, 0x00);
	  n = 6;
	}
      gcry_md_putc (md, sig->version);
      gcry_md_putc (md, 0xFF);      
      buf[0] = n >> 24;
      buf[1] = n >> 16;
      buf[2] = n >>  8;      
      buf[3] = n >>  0;
      gcry_md_write (md, buf, 4);
    }
  return 0;
}


static void
cache_sig_result (cdk_pkt_signature_t sig, int res)
{
  sig->flags.checked = 0;
  sig->flags.valid = 0;
  if (!res) 
    {
      sig->flags.checked = 1;
      sig->flags.valid = 1;
    }
  else if (res == CDK_Bad_Sig) 
    {
      sig->flags.checked = 1;
      sig->flags.valid = 0;
    }
}


cdk_error_t
_cdk_sig_check (cdk_pubkey_t pk, cdk_pkt_signature_t sig,
                gcry_md_hd_t digest, int *r_expired)
{
  byte md[MAX_DIGEST_LEN];
  time_t cur_time = (u32)time (NULL);
  cdk_error_t rc;

  if (!pk || !sig || !digest)
    return CDK_Inv_Value;
  
  if (sig->flags.checked)
    return sig->flags.valid ?0 : CDK_Bad_Sig;  
  if (!KEY_CAN_SIGN (pk->pubkey_algo))
    return CDK_Inv_Algo;
  if (pk->timestamp > sig->timestamp || pk->timestamp > cur_time)
    return CDK_Time_Conflict;
  
  if (r_expired && pk->expiredate
      && (pk->expiredate + pk->timestamp) > cur_time)
    *r_expired = 1;

  _cdk_hash_sig_data (sig, digest);
  gcry_md_final (digest);
  memcpy (md, gcry_md_read (digest, sig->digest_algo),
	  gcry_md_get_algo_dlen (sig->digest_algo));
  
  if (md[0] != sig->digest_start[0] || 
      md[1] != sig->digest_start[1])
    return CDK_Chksum_Error;

  rc = cdk_pk_verify (pk, sig, md);
  cache_sig_result (sig, rc);
  return rc;
}


cdk_error_t
_cdk_pk_check_sig (cdk_keydb_hd_t keydb, 
		   cdk_kbnode_t knode, cdk_kbnode_t snode, int *is_selfsig)
{
  gcry_md_hd_t md;
  cdk_pubkey_t pk;
  cdk_pkt_signature_t sig;
  cdk_kbnode_t node;
  int is_expired;
  gcry_error_t err;
  cdk_error_t rc = 0;

  if (!knode || !snode)
    return CDK_Inv_Value;
  
  if (is_selfsig)
    *is_selfsig = 0;
  if (knode->pkt->pkttype != CDK_PKT_PUBLIC_KEY ||
      snode->pkt->pkttype != CDK_PKT_SIGNATURE)
    return CDK_Inv_Value;
  pk = knode->pkt->pkt.public_key;
  sig = snode->pkt->pkt.signature;
  
  err = gcry_md_open (&md, sig->digest_algo, 0);  
  if (err)
    return map_gcry_error (err);

  is_expired = 0;
  if (sig->sig_class == 0x20)
    { /* key revocation */
      cdk_kbnode_hash (knode, md, 0, 0, 0);
      rc = _cdk_sig_check (pk, sig, md, &is_expired);
    }
  else if (sig->sig_class == 0x28)
    { /* subkey revocation */
      node = cdk_kbnode_find_prev (knode, snode, CDK_PKT_PUBLIC_SUBKEY);
      if (!node) 
	{ /* no subkey for subkey revocation packet */
	  rc = CDK_Error_No_Key;
	  goto fail;
	}
      cdk_kbnode_hash (knode, md, 0, 0, 0);
      cdk_kbnode_hash (node, md, 0, 0, 0);
      rc = _cdk_sig_check (pk, sig, md, &is_expired);
    }
  else if (sig->sig_class == 0x18 || sig->sig_class == 0x19)
    { /* primary/secondary key binding */
      node = cdk_kbnode_find_prev (knode, snode, CDK_PKT_PUBLIC_SUBKEY);
      if (!node) 
	{ /* no subkey for subkey binding packet */
	  rc = CDK_Error_No_Key;
	  goto fail;
	}
      cdk_kbnode_hash (knode, md, 0, 0, 0);
      cdk_kbnode_hash (node, md, 0, 0, 0);
      rc = _cdk_sig_check (pk, sig, md, &is_expired);
    }
  else if (sig->sig_class == 0x1F)
    { /* direct key signature */
      cdk_kbnode_hash (knode, md, 0, 0, 0);
      rc = _cdk_sig_check (pk, sig, md, &is_expired);
    }
  else 
    { /* all other classes */
      node = cdk_kbnode_find_prev (knode, snode, CDK_PKT_USER_ID);
      if (!node)
	{ /* no user ID for key signature packet */
	  rc = CDK_Error_No_Key;
	  goto fail;
	}
      cdk_kbnode_hash (knode, md, 0, 0, 0);
      cdk_kbnode_hash (node, md, sig->version==4, 0, 0);
      if (pk->keyid[0] == sig->keyid[0] && pk->keyid[1] == sig->keyid[1])
	{
	  rc = _cdk_sig_check (pk, sig, md, &is_expired);
	  if (is_selfsig)
	    *is_selfsig = 1;
	}
      else if (keydb != NULL)
	{
	  cdk_pubkey_t sig_pk;
	  
	  rc = cdk_keydb_get_pk (keydb, sig->keyid, &sig_pk);
	  if (!rc)
	    rc = _cdk_sig_check (sig_pk, sig, md, &is_expired);
	  cdk_pk_release (sig_pk);
	}
    }
  fail:
  gcry_md_close (md);
  return rc;
}


/**
 * cdk_pk_check_sigs:
 * @knode: the key node
 * @hd: an optinal key database handle
 * @r_status: variable to store the status of the key
 *
 * Check all signatures. When no key is available for checking, the
 * sigstat is marked as 'NOKEY'. The @r_status contains the key flags
 * which are or-ed or zero when there are no flags.
 **/
cdk_error_t
cdk_pk_check_sigs (cdk_kbnode_t knode, cdk_keydb_hd_t keydb, int *r_status)
{
  cdk_pkt_signature_t sig;
  cdk_kbnode_t node;
  u32 keyid;
  int key_status, is_selfsig = 0;
  int no_signer = 0, n_sigs = 0;
  cdk_error_t rc;
  
  if (!knode || !r_status)
    return CDK_Inv_Value;
  
  *r_status = 0;
  node = cdk_kbnode_find (knode, CDK_PKT_PUBLIC_KEY);
  if (!node)
    return CDK_Error_No_Key;
  
  key_status = 0;
  if (node->pkt->pkt.public_key->is_revoked)
    key_status |= CDK_KEY_REVOKED;
  if (node->pkt->pkt.public_key->has_expired)
    key_status |= CDK_KEY_EXPIRED;
  if (key_status) 
    {
      *r_status = key_status;
      return CDK_General_Error;
    }
  rc = 0;
  keyid = cdk_pk_get_keyid (node->pkt->pkt.public_key, NULL);
  for (node = knode; node; node = node->next) 
    {
      if (node->pkt->pkttype != CDK_PKT_SIGNATURE)
	continue;
      sig = node->pkt->pkt.signature;
      rc = _cdk_pk_check_sig (keydb, knode, node, &is_selfsig);
      if (IS_UID_SIG (sig)) 
	{
	  if (is_selfsig == 0)
	    n_sigs++;
	}
      if (rc && IS_UID_SIG (sig) && rc == CDK_Error_No_Key)
	{
	  sig->flags.missing_key = 1;
	  no_signer++;
	  continue;
        }
      else if (rc && rc != CDK_Error_No_Key)
	{
	  /* If there was an error during the verify process and
	     we checked the self signature, we immediately bail out. */
	  *r_status = CDK_KEY_INVALID;
	  if (is_selfsig)
	    return rc;
	  break;
        }
      _cdk_log_debug ("signature %s: signer %08lX keyid %08lX\n",
		      rc==CDK_Bad_Sig? "BAD" : "good", sig->keyid[1],
		      keyid);
    }
  if (n_sigs == no_signer)
    *r_status |= CDK_KEY_NOSIGNER;
  if (!rc || rc == CDK_Error_No_Key)
    *r_status = CDK_KEY_VALID;
  return rc;
}


/**
 * cdk_pk_check_self_sig:
 * @knode: the key node
 * @keydb: an optional handle to the key database
 * @r_status: output the status of the key.
 * 
 * A convenient function to make sure the key is valid.
 * Valid means the self signature is ok.
 **/
cdk_error_t
cdk_pk_check_self_sig (cdk_kbnode_t knode, int *r_status)
{
  cdk_pkt_signature_t sig;
  cdk_kbnode_t node;
  u32 keyid[2], sigid[2];
  cdk_error_t rc;
  int is_selfsig, sig_ok;
  
  if (!knode || !r_status)
    return CDK_Inv_Value;
  
  node = cdk_kbnode_find (knode, CDK_PKT_PUBLIC_KEY);
  if (!node)
    return CDK_Error_No_Key;
  cdk_pk_get_keyid (knode->pkt->pkt.public_key, keyid);
  sig_ok = 0;
  for (node = knode; node; node = node->next)
    {
      if (node->pkt->pkttype != CDK_PKT_SIGNATURE)
	continue;
      sig = node->pkt->pkt.signature;
      if (!IS_UID_SIG (sig))
	continue;
      cdk_sig_get_keyid (sig, sigid);
      if (sigid[0] != keyid[0] || sigid[1] != keyid[1])
	continue;
      /* FIXME: Now we check all self signatures. */
      rc = _cdk_pk_check_sig (NULL, knode, node, &is_selfsig);
      if (rc)
	{
	  *r_status = CDK_KEY_INVALID;
	  return rc;
	}      
      else /* For each valid self sig we increase this counter. */
	sig_ok++;
    }
  
  /* A key without a self signature is not valid. */
  if (!sig_ok)
    {
      *r_status = CDK_KEY_INVALID;
      return CDK_General_Error;
    }  
  *r_status = CDK_KEY_VALID;
  return 0;
}
