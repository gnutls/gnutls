/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2008, 2009, 2010
 * Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* Some high level functions to be used in the record encryption are
 * included here.
 */

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_compress.h"
#include "gnutls_cipher.h"
#include "algorithms.h"
#include "gnutls_hash_int.h"
#include "gnutls_cipher_int.h"
#include "debug.h"
#include "gnutls_num.h"
#include "gnutls_datum.h"
#include "gnutls_kx.h"
#include "gnutls_record.h"
#include "gnutls_constate.h"
#include <gnutls_state.h>
#include <random.h>

static int compressed_to_ciphertext (gnutls_session_t session,
                                   opaque * cipher_data, int cipher_size,
                                   gnutls_datum_t *compressed,
                                   content_type_t _type, 
                                   record_parameters_st * params);
static int ciphertext_to_compressed (gnutls_session_t session,
                                   gnutls_datum_t *ciphertext, 
                                   opaque * compress_data,
                                   int compress_size,
                                   uint8_t type,
                                   record_parameters_st * params, uint64* sequence);

inline static int
is_write_comp_null (record_parameters_st * record_params)
{
  if (record_params->compression_algorithm == GNUTLS_COMP_NULL)
    return 0;

  return 1;
}

inline static int
is_read_comp_null (record_parameters_st * record_params)
{
  if (record_params->compression_algorithm == GNUTLS_COMP_NULL)
    return 0;

  return 1;
}


/* returns ciphertext which contains the headers too. This also
 * calculates the size in the header field.
 * 
 * If random pad != 0 then the random pad data will be appended.
 */
int
_gnutls_encrypt (gnutls_session_t session, const opaque * headers,
                 size_t headers_size, const opaque * data,
                 size_t data_size, opaque * ciphertext,
                 size_t ciphertext_size, content_type_t type, 
                 record_parameters_st * params)
{
  gnutls_datum_t comp;
  int free_comp = 0;
  int ret;

  if (data_size == 0 || is_write_comp_null (params) == 0)
    {
      comp.data = (opaque*)data;
      comp.size = data_size;
    }
  else
    {
      /* Here comp is allocated and must be 
       * freed.
       */
      free_comp = 1;
      
      comp.size = ciphertext_size - headers_size;
      comp.data = gnutls_malloc(comp.size);
      if (comp.data == NULL)
        return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
      
      ret = _gnutls_compress( &params->write.compression_state, data, data_size, comp.data, comp.size);
      if (ret < 0)
        {
          gnutls_free(comp.data);
          return gnutls_assert_val(ret);
        }
      
      comp.size = ret;
    }

  ret = compressed_to_ciphertext (session, &ciphertext[headers_size],
                                       ciphertext_size - headers_size,
                                       &comp, type, params);

  if (free_comp)
    gnutls_free(comp.data);

  if (ret < 0)
    return gnutls_assert_val(ret);

  /* copy the headers */
  memcpy (ciphertext, headers, headers_size);
  
  if(IS_DTLS(session))
    _gnutls_write_uint16 (ret, &ciphertext[11]);
  else
    _gnutls_write_uint16 (ret, &ciphertext[3]);

  return ret + headers_size;
}

/* Decrypts the given data.
 * Returns the decrypted data length.
 */
int
_gnutls_decrypt (gnutls_session_t session, opaque * ciphertext,
                 size_t ciphertext_size, uint8_t * data,
                 size_t max_data_size, content_type_t type,
                 record_parameters_st * params, uint64 *sequence)
{
  gnutls_datum_t gcipher;
  int ret, data_size;

  if (ciphertext_size == 0)
    return 0;

  gcipher.size = ciphertext_size;
  gcipher.data = ciphertext;

  if (is_read_comp_null (params) == 0)
    {
      ret =
        ciphertext_to_compressed (session, &gcipher, data, max_data_size,
                                   type, params, sequence);
      if (ret < 0)
        return gnutls_assert_val(ret);
      
      return ret;
    }
  else
    {
      opaque* tmp_data;
      
      tmp_data = gnutls_malloc(max_data_size);
      if (tmp_data == NULL)
        return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
      
      ret =
        ciphertext_to_compressed (session, &gcipher, tmp_data, max_data_size,
                                   type, params, sequence);
      if (ret < 0)
        goto leave;
      
      data_size = ret;
        
      if (ret != 0)
        {
          ret = _gnutls_decompress( &params->read.compression_state, tmp_data, data_size, data, max_data_size);
          if (ret < 0)
            goto leave;
        }
        
leave:
      gnutls_free(tmp_data);
      return ret;
    }
}


inline static int
calc_enc_length (gnutls_session_t session, int data_size,
                 int hash_size, uint8_t * pad, int random_pad,
                 unsigned block_algo, unsigned auth_cipher, uint16_t blocksize)
{
  uint8_t rnd;
  int length, ret;

  *pad = 0;

  switch (block_algo)
    {
    case CIPHER_STREAM:
      length = data_size + hash_size;
      if (auth_cipher)
        length += AEAD_EXPLICIT_DATA_SIZE;

      break;
    case CIPHER_BLOCK:
      ret = gnutls_rnd (GNUTLS_RND_NONCE, &rnd, 1);
      if (ret < 0)
        return gnutls_assert_val(ret);

      /* make rnd a multiple of blocksize */
      if (session->security_parameters.version == GNUTLS_SSL3 ||
          random_pad == 0)
        {
          rnd = 0;
        }
      else
        {
          rnd = (rnd / blocksize) * blocksize;
          /* added to avoid the case of pad calculated 0
           * seen below for pad calculation.
           */
          if (rnd > blocksize)
            rnd -= blocksize;
        }

      length = data_size + hash_size;

      *pad = (uint8_t) (blocksize - (length % blocksize)) + rnd;

      length += *pad;
      if (_gnutls_version_has_explicit_iv
          (session->security_parameters.version))
        length += blocksize;    /* for the IV */

      break;
    default:
      return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
    }

  return length;
}

#define MAX_PREAMBLE_SIZE 16

/* generates the authentication data (data to be hashed only
 * and are not to be send). Returns their size.
 */
static inline int
make_preamble (opaque * uint64_data, opaque type, int length,
               opaque ver, opaque * preamble)
{
  opaque minor = _gnutls_version_get_minor (ver);
  opaque major = _gnutls_version_get_major (ver);
  opaque *p = preamble;
  uint16_t c_length;

  c_length = _gnutls_conv_uint16 (length);

  memcpy (p, uint64_data, 8);
  p += 8;
  *p = type;
  p++;
  if (ver != GNUTLS_SSL3)
    { /* TLS protocols */
      *p = major;
      p++;
      *p = minor;
      p++;
    }
  memcpy (p, &c_length, 2);
  p += 2;
  return p - preamble;
}

/* This is the actual encryption 
 * Encrypts the given compressed datum, and puts the result to cipher_data,
 * which has cipher_size size.
 * return the actual encrypted data length.
 */
static int
compressed_to_ciphertext (gnutls_session_t session,
                               opaque * cipher_data, int cipher_size,
                               gnutls_datum_t *compressed,
                               content_type_t type, 
                               record_parameters_st * params)
{
  uint8_t * tag_ptr = NULL;
  uint8_t pad;
  int length, length_to_encrypt, ret;
  opaque preamble[MAX_PREAMBLE_SIZE];
  int preamble_size;
  int tag_size = _gnutls_auth_cipher_tag_len (&params->write.cipher_state);
  int blocksize = gnutls_cipher_get_block_size (params->cipher_algorithm);
  unsigned block_algo =
    _gnutls_cipher_is_block (params->cipher_algorithm);
  opaque *data_ptr;
  int ver = gnutls_protocol_get_version (session);
  int explicit_iv = _gnutls_version_has_explicit_iv (session->security_parameters.version);
  int auth_cipher = _gnutls_auth_cipher_is_aead(&params->write.cipher_state);
  int random_pad;
  
  /* We don't use long padding if requested or if we are in DTLS.
   */
  if (session->internals.priorities.no_padding == 0 && (!IS_DTLS(session)))
    random_pad = 1;
  else
    random_pad = 0;
  
  _gnutls_hard_log("ENC[%p]: cipher: %s, MAC: %s, Epoch: %u\n",
    session, gnutls_cipher_get_name(params->cipher_algorithm), gnutls_mac_get_name(params->mac_algorithm),
    (unsigned int)params->epoch);

  preamble_size =
    make_preamble (UINT64DATA
                   (params->write.sequence_number),
                   type, compressed->size, ver, preamble);

  /* Calculate the encrypted length (padding etc.)
   */
  length_to_encrypt = length =
    calc_enc_length (session, compressed->size, tag_size, &pad,
                     random_pad, block_algo, auth_cipher, blocksize);
  if (length < 0)
    {
      return gnutls_assert_val(length);
    }

  /* copy the encrypted data to cipher_data.
   */
  if (cipher_size < length)
    {
      return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
    }

  data_ptr = cipher_data;

  if (explicit_iv)
    {

      if (block_algo == CIPHER_BLOCK)
        {
          /* copy the random IV.
           */
          ret = gnutls_rnd (GNUTLS_RND_NONCE, data_ptr, blocksize);
          if (ret < 0)
            return gnutls_assert_val(ret);

          _gnutls_auth_cipher_setiv(&params->write.cipher_state, data_ptr, blocksize);

          data_ptr += blocksize;
          cipher_data += blocksize;
          length_to_encrypt -= blocksize;
        }
      else if (auth_cipher)
        {
          uint8_t nonce[blocksize];

          /* Values in AEAD are pretty fixed in TLS 1.2 for 128-bit block
           */
          if (params->write.IV.data == NULL || params->write.IV.size != AEAD_IMPLICIT_DATA_SIZE)
            return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

          /* Instead of generating a new nonce on every packet, we use the
           * write.sequence_number (It is a MAY on RFC 5288).
           */
          memcpy(nonce, params->write.IV.data, params->write.IV.size);
          memcpy(&nonce[AEAD_IMPLICIT_DATA_SIZE], UINT64DATA(params->write.sequence_number), 8);

          _gnutls_auth_cipher_setiv(&params->write.cipher_state, nonce, AEAD_IMPLICIT_DATA_SIZE+AEAD_EXPLICIT_DATA_SIZE);

          /* copy the explicit part */
          memcpy(data_ptr, &nonce[AEAD_IMPLICIT_DATA_SIZE], AEAD_EXPLICIT_DATA_SIZE);

          data_ptr += AEAD_EXPLICIT_DATA_SIZE;
          cipher_data += AEAD_EXPLICIT_DATA_SIZE;
          /* In AEAD ciphers we don't encrypt the tag 
           */
          length_to_encrypt -= AEAD_EXPLICIT_DATA_SIZE + tag_size;
        }
    }
  else
    {
      /* AEAD ciphers have an explicit IV. Shouldn't be used otherwise.
       */
      if (auth_cipher) return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
    }

  memcpy (data_ptr, compressed->data, compressed->size);
  data_ptr += compressed->size;

  if (tag_size > 0)
    {
      tag_ptr = data_ptr;
      data_ptr += tag_size;
    }
  if (block_algo == CIPHER_BLOCK && pad > 0)
    {
      memset (data_ptr, pad - 1, pad);
    }

  /* add the authenticate data */
  _gnutls_auth_cipher_add_auth(&params->write.cipher_state, preamble, preamble_size);

  /* Actual encryption (inplace).
   */
  ret =
    _gnutls_auth_cipher_encrypt_tag (&params->write.cipher_state,
      cipher_data, length_to_encrypt, tag_ptr, tag_size, compressed->size);
  if (ret < 0)
    return gnutls_assert_val(ret);

  return length;
}


/* Deciphers the ciphertext packet, and puts the result to compress_data, of compress_size.
 * Returns the actual compressed packet size.
 */
static int
ciphertext_to_compressed (gnutls_session_t session,
                          gnutls_datum_t *ciphertext, 
                          opaque * compress_data,
                          int compress_size,
                          uint8_t type, record_parameters_st * params, 
                          uint64* sequence)
{
  uint8_t tag[MAX_HASH_SIZE];
  uint8_t pad;
  int length, length_to_decrypt;
  uint16_t blocksize;
  int ret, i, pad_failed = 0;
  opaque preamble[MAX_PREAMBLE_SIZE];
  int preamble_size;
  int ver = gnutls_protocol_get_version (session);
  int tag_size = _gnutls_auth_cipher_tag_len (&params->read.cipher_state);
  int explicit_iv = _gnutls_version_has_explicit_iv (session->security_parameters.version);

  blocksize = gnutls_cipher_get_block_size (params->cipher_algorithm);

  /* actual decryption (inplace)
   */
  switch (_gnutls_cipher_is_block (params->cipher_algorithm))
    {
    case CIPHER_STREAM:
      /* The way AEAD ciphers are defined in RFC5246, it allows
       * only stream ciphers.
       */
      if (explicit_iv && _gnutls_auth_cipher_is_aead(&params->read.cipher_state))
        {
          uint8_t nonce[blocksize];
          /* Values in AEAD are pretty fixed in TLS 1.2 for 128-bit block
           */
          if (params->read.IV.data == NULL || params->read.IV.size != 4)
            return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
          
          if (ciphertext->size < tag_size+AEAD_EXPLICIT_DATA_SIZE)
            return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

          memcpy(nonce, params->read.IV.data, AEAD_IMPLICIT_DATA_SIZE);
          memcpy(&nonce[AEAD_IMPLICIT_DATA_SIZE], ciphertext->data, AEAD_EXPLICIT_DATA_SIZE);
          
          _gnutls_auth_cipher_setiv(&params->read.cipher_state, nonce, AEAD_EXPLICIT_DATA_SIZE+AEAD_IMPLICIT_DATA_SIZE);

          ciphertext->data += AEAD_EXPLICIT_DATA_SIZE;
          ciphertext->size -= AEAD_EXPLICIT_DATA_SIZE;
          
          length_to_decrypt = ciphertext->size - tag_size;
        }
      else
        {
          if (ciphertext->size < tag_size)
            return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
  
          length_to_decrypt = ciphertext->size;
        }

      length = ciphertext->size - tag_size;

      /* Pass the type, version, length and compressed through
       * MAC.
       */
      preamble_size =
        make_preamble (UINT64DATA(*sequence), type,
                       length, ver, preamble);

      _gnutls_auth_cipher_add_auth (&params->read.cipher_state, preamble, preamble_size);

      if ((ret =
           _gnutls_auth_cipher_decrypt (&params->read.cipher_state,
             ciphertext->data, length_to_decrypt)) < 0)
        return gnutls_assert_val(ret);

      break;
    case CIPHER_BLOCK:
      if (ciphertext->size < MAX(blocksize, tag_size) || (ciphertext->size % blocksize != 0))
        return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

      /* ignore the IV in TLS 1.1+
       */
      if (explicit_iv)
        {
          _gnutls_auth_cipher_setiv(&params->read.cipher_state,
            ciphertext->data, blocksize);

          ciphertext->size -= blocksize;
          ciphertext->data += blocksize;

          if (ciphertext->size == 0)
            {
              gnutls_assert ();
              return GNUTLS_E_DECRYPTION_FAILED;
            }
        }

      /* we don't use the auth_cipher interface here, since
       * TLS with block ciphers is impossible to be used under such
       * an API. (the length of plaintext is required to calculate
       * auth_data, but it is not available before decryption).
       */
      if ((ret =
           _gnutls_cipher_decrypt (&params->read.cipher_state.cipher,
             ciphertext->data, ciphertext->size)) < 0)
        return gnutls_assert_val(ret);

      pad = ciphertext->data[ciphertext->size - 1] + 1;   /* pad */

      if ((int) pad > (int) ciphertext->size - tag_size)
        {
          gnutls_assert ();
          _gnutls_record_log
            ("REC[%p]: Short record length %d > %d - %d (under attack?)\n",
             session, pad, ciphertext->size, tag_size);
          /* We do not fail here. We check below for the
           * the pad_failed. If zero means success.
           */
          pad_failed = GNUTLS_E_DECRYPTION_FAILED;
          pad %= blocksize;
        }

      length = ciphertext->size - tag_size - pad;

      /* Check the pading bytes (TLS 1.x)
       */
      if (ver != GNUTLS_SSL3)
        for (i = 2; i < pad; i++)
          {
            if (ciphertext->data[ciphertext->size - i] !=
                ciphertext->data[ciphertext->size - 1])
              pad_failed = GNUTLS_E_DECRYPTION_FAILED;
          }

      if (length < 0)
        length = 0;

      /* Pass the type, version, length and compressed through
       * MAC.
       */
      preamble_size =
        make_preamble (UINT64DATA(*sequence), type,
                       length, ver, preamble);
      _gnutls_auth_cipher_add_auth (&params->read.cipher_state, preamble, preamble_size);
      _gnutls_auth_cipher_add_auth (&params->read.cipher_state, ciphertext->data, length);

      break;
    default:
      return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
    }

  ret = _gnutls_auth_cipher_tag(&params->read.cipher_state, tag, tag_size);
  if (ret < 0)
    return gnutls_assert_val(ret);

  /* This one was introduced to avoid a timing attack against the TLS
   * 1.0 protocol.
   */
  /* HMAC was not the same. 
   */
  if (memcmp (tag, &ciphertext->data[length], tag_size) != 0 || pad_failed != 0)
    return gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);

  /* copy the decrypted stuff to compress_data.
   */
  if (compress_size < length)
    return gnutls_assert_val(GNUTLS_E_DECOMPRESSION_FAILED);

  if (compress_data != ciphertext->data)
    memcpy (compress_data, ciphertext->data, length);

  return length;
}
