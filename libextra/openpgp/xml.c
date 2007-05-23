/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Timo Schulz, Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS-EXTRA.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS-EXTRA; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include <gnutls_int.h>
#include <gnutls_str.h>
#include <gnutls_errors.h>
#include <openpgp.h>
#include <x509/rfc2818.h>	/* for MAX_CN */


static int
xml_add_tag (gnutls_string * xmlkey, const char *tag, const char *val)
{
  if (!xmlkey || !tag || !val)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _gnutls_string_append_str (xmlkey, "    <");
  _gnutls_string_append_str (xmlkey, tag);
  _gnutls_string_append_str (xmlkey, ">");
  _gnutls_string_append_str (xmlkey, val);
  _gnutls_string_append_str (xmlkey, "</");
  _gnutls_string_append_str (xmlkey, tag);
  _gnutls_string_append_str (xmlkey, ">\n");

  return 0;
}


/* Add a tag to the xml key with an unsigned integer based value.
   We use the unsigned format, because no key attribute has a
   negative values. */
static int
xml_add_tag_uint_val (gnutls_string *xmlkey, const char *tag, unsigned int val)
{
  char tmp[32];
  
  sprintf (tmp, "%lu", (unsigned long)val);
  return xml_add_tag (xmlkey, tag, tmp);
}


static int
xml_add_mpi2 (gnutls_string * xmlkey, const uint8_t * data, size_t count,
	      const char *tag)
{
  char *p;
  size_t i;
  int rc;

  if (!xmlkey || !data || !tag)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  p = gnutls_calloc (1, 2 * (count + 3));
  if (!p)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  for (i = 0; i < count; i++)
    sprintf (p + 2 * i, "%02X", data[i]);
  p[2 * count] = '\0';

  rc = xml_add_tag (xmlkey, tag, p);
  gnutls_free (p);

  return rc;
}


static int
xml_add_mpi (gnutls_string * xmlkey, cdk_pkt_pubkey_t pk, int idx,
	     const char *tag)
{
  uint8_t buf[4096]; /* Maximal supported MPI of size 32786 bits */
  size_t nbytes;
  
  /* FIXME: we should not hardcode the buffer size. */
  nbytes = 4096;
  if (cdk_pk_get_mpi (pk, idx, buf, nbytes, &nbytes, NULL))
    return GNUTLS_E_INTERNAL_ERROR;
  return xml_add_mpi2 (xmlkey, buf, nbytes, tag);
}



static int
xml_add_key_mpi (gnutls_string * xmlkey, cdk_pkt_pubkey_t pk)
{
  const char *s = "    <KEY ENCODING=\"HEX\"/>\n";
  int rc = 0;

  if (!xmlkey || !pk)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _gnutls_string_append_str (xmlkey, s);

  if (is_RSA (pk->pubkey_algo))
    {
      rc = xml_add_mpi (xmlkey, pk, 0, "RSA-N");
      if (!rc)
	rc = xml_add_mpi (xmlkey, pk, 1, "RSA-E");
    }
  else if (is_DSA (pk->pubkey_algo))
    {
      rc = xml_add_mpi (xmlkey, pk, 0, "DSA-P");
      if (!rc)
	rc = xml_add_mpi (xmlkey, pk, 1, "DSA-Q");
      if (!rc)
	rc = xml_add_mpi (xmlkey, pk, 2, "DSA-G");
      if (!rc)
	rc = xml_add_mpi (xmlkey, pk, 3, "DSA-Y");
    }
  else
    return GNUTLS_E_UNWANTED_ALGORITHM;

  return rc;
}


static int
xml_add_key (gnutls_string * xmlkey, int ext, cdk_pkt_pubkey_t pk, int sub)
{
  const char *algo, *s;
  char keyid[32+1], strfpr[40+1];
  uint8_t keyfpr[20];
  unsigned int kid[2];
  int i = 0, rc = 0;

  if (!xmlkey || !pk)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  s = sub ? "  <SUBKEY>\n" : "  <MAINKEY>\n";
  _gnutls_string_append_str (xmlkey, s);

  cdk_pk_get_keyid (pk, kid);
  snprintf (keyid, 32, "%08lX%08lX", 
	    (unsigned long)kid[0], (unsigned long)kid[1]);
  rc = xml_add_tag (xmlkey, "KEYID", keyid);
  if (rc)
    return rc;

  cdk_pk_get_fingerprint (pk, keyfpr);
  for (i = 0; i < 20; i++)
    sprintf (strfpr + 2 * i, "%02X", keyfpr[i]);
  strfpr[40] = '\0';
  rc = xml_add_tag (xmlkey, "FINGERPRINT", strfpr);
  if (rc)
    return rc;

  if (is_DSA (pk->pubkey_algo))
    algo = "DSA";
  else if (is_RSA (pk->pubkey_algo))
    algo = "RSA";
  else
    return GNUTLS_E_UNWANTED_ALGORITHM;
  rc = xml_add_tag (xmlkey, "PKALGO", algo);
  if (rc)
    return rc;
  
  rc = xml_add_tag_uint_val (xmlkey, "KEYLEN", cdk_pk_get_nbits (pk));
  if (rc)
    return rc;

  rc = xml_add_tag_uint_val (xmlkey, "CREATED", pk->timestamp);
  if (rc)
    return rc;

  if (pk->expiredate > 0)
    {
      rc = xml_add_tag_uint_val (xmlkey, "EXPIREDATE", pk->expiredate);
      if (rc)
	return rc;
    }

  rc = xml_add_tag_uint_val (xmlkey, "REVOKED", pk->is_revoked);
  if (rc)
    return rc;

  if (ext)
    {
      rc = xml_add_key_mpi (xmlkey, pk);
      if (rc)
	return rc;
    }

  s = sub ? "  </SUBKEY>\n" : "  </MAINKEY>\n";
  _gnutls_string_append_str (xmlkey, s);

  return 0;
}


static int
xml_add_userid (gnutls_string * xmlkey, int ext,
		const char *dn, cdk_pkt_userid_t id)
{
  const char *s;
  int rc;

  if (!xmlkey || !dn || !id)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  s = "  <USERID>\n";
  _gnutls_string_append_str (xmlkey, s);

  rc = xml_add_tag (xmlkey, "NAME", dn);
  if (rc)
    return rc;

  if (ext)
    {
      rc = xml_add_tag_uint_val (xmlkey, "PRIMARY", id->is_primary);
      if (!rc)
	rc = xml_add_tag_uint_val (xmlkey, "REVOKED", id->is_revoked);
      if (rc)
	return rc;
    }

  s = "  </USERID>\n";
  _gnutls_string_append_str (xmlkey, s);

  return 0;
}


static int
xml_add_sig (gnutls_string * xmlkey, int ext, cdk_pkt_signature_t sig)
{
  const char *algo, *s;
  char keyid[16+1];
  unsigned int kid[2];
  int rc;

  if (!xmlkey || !sig)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  s = "  <SIGNATURE>\n";
  _gnutls_string_append_str (xmlkey, s);

  rc = xml_add_tag_uint_val (xmlkey, "VERSION", sig->version);
  if (rc)
    return rc;

  if (ext)
    {
      rc = xml_add_tag_uint_val (xmlkey, "SIGCLASS", sig->sig_class);
      if (rc)
	return rc;
    }

  rc = xml_add_tag_uint_val (xmlkey, "EXPIRED", sig->flags.expired);
  if (rc)
    return rc;

  if (ext)
    {
      switch (sig->pubkey_algo)
	{
	case GCRY_PK_DSA:
	  algo = "DSA";
	  break;
	case GCRY_PK_RSA:
	case GCRY_PK_RSA_E:
	case GCRY_PK_RSA_S:
	  algo = "RSA";
	  break;
	default:
	  algo = "???";		/* unknown algorithm */
	}
      rc = xml_add_tag (xmlkey, "PKALGO", algo);
      if (rc)
	return rc;

      switch (sig->digest_algo)
	{
	case GCRY_MD_SHA1:
	  algo = "SHA1";
	  break;
	case GCRY_MD_RMD160:
	  algo = "RMD160";
	  break;
	case GCRY_MD_MD5:
	  algo = "MD5";
	  break;
	case GCRY_MD_SHA256:
	  algo = "SHA256";
	  break;
	case GCRY_MD_SHA384:
	  algo = "SHA384";
	  break;
	case GCRY_MD_SHA512:
	  algo = "SHA512";
	  break;
	default:
	  algo = "???";
	}
      rc = xml_add_tag (xmlkey, "MDALGO", algo);
      if (rc)
	return rc;
    }

  rc = xml_add_tag_uint_val (xmlkey, "CREATED", sig->timestamp);
  if (rc)
    return rc;

  cdk_sig_get_keyid (sig, kid);
  snprintf (keyid, 16, "%08lX%08lX", 
	    (unsigned long)kid[0], (unsigned long)kid[1]);
  rc = xml_add_tag (xmlkey, "KEYID", keyid);
  if (rc)
    return rc;

  s = "  </SIGNATURE>\n";
  _gnutls_string_append_str (xmlkey, s);

  return 0;
}


/**
 * gnutls_openpgp_key_to_xml - Return a certificate as a XML fragment
 * @cert: the certificate which holds the whole OpenPGP key.
 * @xmlkey: he datum struct to store the XML result.
 * @ext: extension mode (1/0), 1 means include key signatures and key data.
 *
 * This function will return the all OpenPGP key information encapsulated as
 * a XML string.
 **/
int
gnutls_openpgp_key_to_xml (gnutls_openpgp_key_t key,
			   gnutls_datum_t * xmlkey, int ext)
{
  cdk_kbnode_t node, ctx;
  cdk_packet_t pkt;
  char name[MAX_CN];
  size_t name_len;
  const char *s;
  int idx;
  int rc = 0;
  gnutls_string string_xml_key;

  if (!key || !xmlkey)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _gnutls_string_init (&string_xml_key, malloc, realloc, free);
  memset (xmlkey, 0, sizeof *xmlkey);

  s = "<?xml version=\"1.0\"?>\n\n";
  _gnutls_string_append_str (&string_xml_key, s);

  s = "<gnutls:openpgp:key version=\"1.0\">\n";
  _gnutls_string_append_str (&string_xml_key, s);

  s = " <OPENPGPKEY>\n";
  _gnutls_string_append_str (&string_xml_key, s);

  ctx = NULL;
  idx = 1;
  while ((node = cdk_kbnode_walk (key->knode, &ctx, 0)))
    {
      pkt = cdk_kbnode_get_packet (node);
      switch (pkt->pkttype)
	{
	case CDK_PKT_PUBLIC_KEY:
	  rc = xml_add_key (&string_xml_key, ext, pkt->pkt.public_key, 0);
	  break;
	  
	case CDK_PKT_PUBLIC_SUBKEY:
	  rc = xml_add_key (&string_xml_key, ext, pkt->pkt.public_key, 1);
	  break;

	case CDK_PKT_USER_ID:
	  name_len = sizeof (name) / sizeof (name[0]);
	  gnutls_openpgp_key_get_name (key, idx, name, &name_len);
	  rc = xml_add_userid (&string_xml_key, ext, name, pkt->pkt.user_id);
	  idx++;
	  break;

	case CDK_PKT_SIGNATURE:
	  rc = xml_add_sig (&string_xml_key, ext, pkt->pkt.signature);
	  break;

	default:
	  break;
	}
    }
  if (!rc)
    {
      s = " </OPENPGPKEY>\n";
      _gnutls_string_append_str (&string_xml_key, s);
    }
  s = "</gnutls:openpgp:key>\n";
  _gnutls_string_append_str (&string_xml_key, s);
  _gnutls_string_append_data (&string_xml_key, "\n\0", 2);

  *xmlkey = _gnutls_string2datum (&string_xml_key);
  xmlkey->size--;

  return rc;
}
