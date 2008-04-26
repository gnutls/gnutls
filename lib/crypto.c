/*
 * Copyright (C) 2008 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#include <gnutls_errors.h>
#include <gnutls_int.h>
#include <gnutls/crypto.h>
#include <crypto.h>

typedef struct algo_list {
  int algorithm;
  int priority;
  void* alg_data;
  struct algo_list* next;
} algo_list;

#define cipher_list algo_list
#define mac_list algo_list
#define digest_list algo_list
#define rnd_list algo_list

static int _algo_register( algo_list* al, int algorithm, int priority, void* s)
{
algo_list* cl;
algo_list* last_cl = al;

  /* look if there is any cipher with lowest priority. In that case do not add.
   */
  cl = al;
  while( cl && cl->alg_data) {
    if (cl->algorithm == algorithm) {
      if (cl->priority < priority) {
        gnutls_assert();
        return GNUTLS_E_CRYPTO_ALREADY_REGISTERED;
      } else {
        /* the current has higher priority -> overwrite */
        cl->algorithm = algorithm;
        cl->priority = priority;
        cl->alg_data = s;
        return 0;
      }
    }
    cl = cl->next;
    if (cl) last_cl = cl;
  }

  cl = gnutls_malloc(sizeof(cipher_list));

  if (cl == NULL) {
    gnutls_assert();
    return GNUTLS_E_MEMORY_ERROR;
  }
  
  cl->algorithm = algorithm;
  cl->priority = priority;
  cl->alg_data = s;
  cl->next = NULL;

  last_cl->next = cl;
  return 0;

}

static void *_get_algo( algo_list* al, int algo)
{
cipher_list* cl;

  /* look if there is any cipher with lowest priority. In that case do not add.
   */
  cl = al->next;
  while( cl && cl->alg_data) {
    if (cl->algorithm == algo) {
      return cl->alg_data;
    }
    cl = cl->next;
  }
  
  return NULL;
}

static cipher_list glob_cl = { GNUTLS_CIPHER_NULL, 0, NULL, NULL };
static mac_list glob_ml = { GNUTLS_MAC_NULL, 0, NULL, NULL };
static digest_list glob_dl = { GNUTLS_MAC_NULL, 0, NULL, NULL };
static rnd_list glob_rnd = { 0, 0, NULL, NULL };

static void _deregister(algo_list* cl)
{
algo_list* next;

  next = cl->next;
  cl->next = NULL;
  cl = next;

  while( cl) 
    {
      next = cl->next;
      gnutls_free(cl);
      cl = next;
    }
}

void _gnutls_crypto_deregister(void)
{
  _deregister( &glob_cl);
  _deregister( &glob_ml);
  _deregister( &glob_dl);
  _deregister( &glob_rnd);
}

/**
  * gnutls_crypto_cipher_register - register a cipher algorithm
  * @algorithm: is the gnutls algorithm identifier
  * @priority: is the priority of the algorithm
  * @s: is a structure holding new cipher's data
  *
  * This function will register a cipher algorithm to be used
  * by gnutls. Any algorithm registered will override
  * the included algorithms and by convention kernel implemented
  * algorithms have priority of 90. The algorithm with the lowest
  * priority will be used by gnutls.
  *
  * This function should be called before gnutls_global_init().
  *
  * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
  *
  **/
int gnutls_crypto_cipher_register( gnutls_cipher_algorithm_t algorithm, int priority, gnutls_crypto_cipher_st* s)
{
  return _algo_register( &glob_cl, algorithm, priority, s);
}

gnutls_crypto_cipher_st *_gnutls_get_crypto_cipher( gnutls_cipher_algorithm_t algo)
{
  return _get_algo( &glob_cl, algo);
}

/**
  * gnutls_crypto_rnd_register - register a random generator
  * @priority: is the priority of the generator
  * @s: is a structure holding new generator's data
  *
  * This function will register a random generator to be used
  * by gnutls. Any generator registered will override
  * the included generator and by convention kernel implemented
  * generators have priority of 90. The generator with the lowest
  * priority will be used by gnutls.
  *
  * This function should be called before gnutls_global_init().
  *
  * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
  *
  **/
int gnutls_crypto_rnd_register( int priority, gnutls_crypto_rnd_st* s)
{
  return _algo_register( &glob_rnd, 1, priority, s);
}

gnutls_crypto_rnd_st *_gnutls_get_crypto_rnd()
{
  return _get_algo( &glob_rnd, 1);
}

/**
  * gnutls_crypto_mac_register - register a MAC algorithm
  * @algorithm: is the gnutls algorithm identifier
  * @priority: is the priority of the algorithm
  * @s: is a structure holding new algorithms's data
  *
  * This function will register a MAC algorithm to be used
  * by gnutls. Any algorithm registered will override
  * the included algorithms and by convention kernel implemented
  * algorithms have priority of 90. The algorithm with the lowest
  * priority will be used by gnutls.
  *
  * This function should be called before gnutls_global_init().
  *
  * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
  *
  **/
int gnutls_crypto_mac_register( gnutls_mac_algorithm_t algorithm, int priority, gnutls_crypto_mac_st* s)
{
  return _algo_register( &glob_ml, algorithm, priority, s);
}

gnutls_crypto_mac_st *_gnutls_get_crypto_mac( gnutls_mac_algorithm_t algo)
{
  return _get_algo( &glob_ml, algo);
}

/**
  * gnutls_crypto_digest_register - register a digest algorithm
  * @algorithm: is the gnutls algorithm identifier
  * @priority: is the priority of the algorithm
  * @s: is a structure holding new algorithms's data
  *
  * This function will register a digest (hash) algorithm to be used
  * by gnutls. Any algorithm registered will override
  * the included algorithms and by convention kernel implemented
  * algorithms have priority of 90. The algorithm with the lowest
  * priority will be used by gnutls.
  *
  * This function should be called before gnutls_global_init().
  *
  * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
  *
  **/
int gnutls_crypto_digest_register( gnutls_digest_algorithm_t algorithm, int priority, gnutls_crypto_digest_st* s)
{
  return _algo_register( &glob_dl, algorithm, priority, s);
}

gnutls_crypto_digest_st *_gnutls_get_crypto_digest( gnutls_digest_algorithm_t algo)
{
  return _get_algo( &glob_dl, algo);
}
