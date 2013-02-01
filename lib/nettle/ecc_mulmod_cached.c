/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
 *
 * Author: Ilya Tumaykin
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* needed for gnutls_* types */
#include <gnutls_int.h>
#include <algorithms.h>

#include "ecc.h"


/* per-curve cache structure */
typedef struct
{
  /* curve's id */
  gnutls_ecc_curve_t id;

    /** The array of positive multipliers of G */
  ecc_point *pos[WMNAF_PRECOMPUTED_LENGTH];

    /** The array of negative multipliers of G */
  ecc_point *neg[WMNAF_PRECOMPUTED_LENGTH];
} gnutls_ecc_curve_cache_entry_t;

/* global cache */
static gnutls_ecc_curve_cache_entry_t *ecc_wmnaf_cache = NULL;

/* free single cache entry */
static void
_ecc_wmnaf_cache_entry_free (gnutls_ecc_curve_cache_entry_t * p)
{
  int i;

  for (i = 0; i < WMNAF_PRECOMPUTED_LENGTH; ++i)
    {
      ecc_del_point (p->pos[i]);
      ecc_del_point (p->neg[i]);
    }
}

/* free curves caches */
void
ecc_wmnaf_cache_free (void)
{
  gnutls_ecc_curve_cache_entry_t *p = ecc_wmnaf_cache;
  if (p)
    {
      for (; p->id != GNUTLS_ECC_CURVE_INVALID; ++p)
        {
          _ecc_wmnaf_cache_entry_free (p);
        }

      free (ecc_wmnaf_cache);
      ecc_wmnaf_cache = NULL;
    }
}

/* initialize single cache entry
 * for a curve with the given id */
static int
_ecc_wmnaf_cache_entry_init (gnutls_ecc_curve_cache_entry_t * p,
                             gnutls_ecc_curve_t id)
{
  int i, j, err;
  ecc_point *G;
  mpz_t a, modulus;

  const gnutls_ecc_curve_entry_st *st = NULL;

  if (p == NULL || id == 0)
    return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;

  G = ecc_new_point ();
  if (G == NULL)
    {
      return GNUTLS_E_MEMORY_ERROR;
    }

  st = _gnutls_ecc_curve_get_params (id);
  if (st == NULL)
    {
      err = GNUTLS_E_INTERNAL_ERROR;
      goto done;
    }

  if ((err = mp_init_multi (&a, &modulus, NULL) != 0))
    return err;

  /* set id */
  p->id = id;

  /* set modulus */
  mpz_set_str (modulus, st->prime, 16);

  /* get generator point */
  mpz_set_str (G->x, st->Gx, 16);
  mpz_set_str (G->y, st->Gy, 16);
  mpz_set_ui (G->z, 1);

  /* set A */
  mpz_set_str (a, st->A, 16);

  /* alloc ram for precomputed values */
  for (i = 0; i < WMNAF_PRECOMPUTED_LENGTH; ++i)
    {
      p->pos[i] = ecc_new_point ();
      p->neg[i] = ecc_new_point ();
      if (p->pos[i] == NULL || p->neg[i] == NULL)
        {
          for (j = 0; j < i; ++j)
            {
              ecc_del_point (p->pos[j]);
              ecc_del_point (p->neg[j]);
            }

          err = GNUTLS_E_MEMORY_ERROR;
          goto done;
        }
    }

  /* fill in pos and neg arrays with precomputed values
   * pos holds kG for k ==  1, 3, 5, ..., (2^w - 1)
   * neg holds kG for k == -1,-3,-5, ...,-(2^w - 1)
   */

  /* pos[0] == 2G for a while, later it will be set to the expected 1G */
  if ((err = ecc_projective_dbl_point (G, p->pos[0], a, modulus)) != 0)
    goto done;

  /* pos[1] == 3G */
  if ((err =
       ecc_projective_add_point (p->pos[0], G, p->pos[1], a,
                                    modulus)) != 0)
    goto done;

  /* fill in kG for k = 5, 7, ..., (2^w - 1) */
  for (j = 2; j < WMNAF_PRECOMPUTED_LENGTH; ++j)
    {
      if ((err =
           ecc_projective_add_point (p->pos[j - 1], p->pos[0], p->pos[j],
                                        a, modulus)) != 0)
        goto done;
    }

  /* set pos[0] == 1G as expected
   * after this step we don't need G at all */
  mpz_set (p->pos[0]->x, G->x);
  mpz_set (p->pos[0]->y, G->y);
  mpz_set (p->pos[0]->z, G->z);

  /* map to affine all elements in pos
   * this will allow to use ecc_projective_madd later
   * set neg[i] == -pos[i] */
  for (j = 0; j < WMNAF_PRECOMPUTED_LENGTH; ++j)
    {
      if ((err = ecc_map (p->pos[j], modulus)) != 0)
        goto done;

      if ((err =
           ecc_projective_negate_point (p->pos[j], p->neg[j], modulus)) != 0)
        goto done;
    }

  err = 0;
done:
  ecc_del_point (G);
  mp_clear_multi (&a, &modulus, NULL);

  return err;
}

/* initialize curves caches */
int
ecc_wmnaf_cache_init (void)
{
  int j, err;

  gnutls_ecc_curve_cache_entry_t *ret;

  const gnutls_ecc_curve_t *p;

  ret = (gnutls_ecc_curve_cache_entry_t *)
    malloc (MAX_ALGOS * sizeof (gnutls_ecc_curve_cache_entry_t));
  if (ret == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  /* get supported curves' ids */
  p = gnutls_ecc_curve_list ();

  for (j = 0; *p; ++p, ++j)
    {
      if ((err = _ecc_wmnaf_cache_entry_init (ret + *p - 1, *p)) != 0)
        goto done;
    }

  /* nullify last cache entry id */
  ret[j].id = GNUTLS_ECC_CURVE_INVALID;

  err = GNUTLS_E_SUCCESS;

  ecc_wmnaf_cache = ret;
done:
  if (err)
    {
      int i;
      for (i = 0; i < j; ++i)
        {
          _ecc_wmnaf_cache_entry_free (ret + i);
        }

      free (ret);
      ecc_wmnaf_cache = NULL;
    }
  return err;
}


/*
   Perform a point wMNAF-multiplication utilizing cache
   @param k    The scalar to multiply by
   @param id   The curve's id
   @param R    [out] Destination for kG
   @param a        The curve's A value
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1 == map, 0 == leave in projective)
   @return     GNUTLS_E_SUCCESS on success
*/
int
ecc_mulmod_cached (mpz_t k, gnutls_ecc_curve_t id, ecc_point * R,
                         mpz_t a, mpz_t modulus, int map)
{
  int j, err;

  gnutls_ecc_curve_cache_entry_t *cache = NULL;
  signed char *wmnaf = NULL;
  size_t wmnaf_len;
  signed char digit;

  if (k == NULL || R == NULL || modulus == NULL || id == 0)
    return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;

  /* calculate wMNAF */
  wmnaf = ecc_wMNAF (k, &wmnaf_len);
  if (!wmnaf)
    {
      err = GNUTLS_E_INTERNAL_ERROR;
      goto done;
    }

  /* set R to neutral */
  mpz_set_ui (R->x, 1);
  mpz_set_ui (R->y, 1);
  mpz_set_ui (R->z, 0);

  /* do cache lookup */
  cache = ecc_wmnaf_cache + id - 1;

  /* perform ops */
  for (j = wmnaf_len - 1; j >= 0; --j)
    {
      if ((err = ecc_projective_dbl_point (R, R, a, modulus)) != 0)
        goto done;

      digit = wmnaf[j];

      if (digit)
        {
          if (digit > 0)
            {
              if ((err =
                   ecc_projective_madd (R, cache->pos[(digit / 2)], R, a,
                                        modulus)) != 0)
                goto done;
            }
          else
            {
              if ((err =
                   ecc_projective_madd (R, cache->neg[(-digit / 2)], R, a,
                                        modulus)) != 0)
                goto done;
            }
        }
    }


  /* map R back from projective space */
  if (map)
    {
      err = ecc_map (R, modulus);
    }
  else
    {
      err = GNUTLS_E_SUCCESS;
    }
done:
  if (wmnaf)
    free (wmnaf);
  return err;
}

/*
   Perform a point wMNAF-multiplication utilizing cache
   This version tries to be timing resistant
   @param k    The scalar to multiply by
   @param id   The curve's id
   @param R    [out] Destination for kG
   @param a        The curve's A value
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1 == map, 0 == leave in projective)
   @return     GNUTLS_E_SUCCESS on success
*/
int
ecc_mulmod_cached_timing (mpz_t k, gnutls_ecc_curve_t id, ecc_point * R,
                                mpz_t a, mpz_t modulus, int map)
{
  int j, err;

  gnutls_ecc_curve_cache_entry_t *cache = NULL;
  signed char *wmnaf = NULL;
  size_t wmnaf_len;
  signed char digit;
  /* point for throttle */
  ecc_point *T;

  if (k == NULL || R == NULL || modulus == NULL || id == 0)
    return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;

  /* prepare T point */
  T = ecc_new_point ();
  if (T == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  /* calculate wMNAF */
  wmnaf = ecc_wMNAF (k, &wmnaf_len);
  if (!wmnaf)
    {
      err = GNUTLS_E_INTERNAL_ERROR;
      goto done;
    }

  /* set R to neutral */
  mpz_set_ui (R->x, 1);
  mpz_set_ui (R->y, 1);
  mpz_set_ui (R->z, 0);

  /* set T to neutral */
  mpz_set_ui (T->x, 1);
  mpz_set_ui (T->y, 1);
  mpz_set_ui (T->z, 0);

  /* do cache lookup */
  cache = ecc_wmnaf_cache + id - 1;

  /* perform ops */
  for (j = wmnaf_len - 1; j >= 0; --j)
    {
      if ((err = ecc_projective_dbl_point (R, R, a, modulus)) != 0)
        goto done;

      digit = wmnaf[j];

      if (digit)
        {
          if (digit > 0)
            {
              if ((err =
                   ecc_projective_madd (R, cache->pos[(digit / 2)], R, a,
                                        modulus)) != 0)
                goto done;
            }
          else
            {
              if ((err =
                   ecc_projective_madd (R, cache->neg[(-digit / 2)], R, a,
                                        modulus)) != 0)
                goto done;
            }
        }
      else
        {
          /* we add middle element of pos array as a general case
           * there is no real difference between using pos and neg */
          if ((err =
               ecc_projective_madd (R,
                                    cache->
                                    pos[(WMNAF_PRECOMPUTED_LENGTH / 2)], T, a,
                                    modulus)) != 0)
            goto done;
        }
    }


  /* map R back from projective space */
  if (map)
    {
      err = ecc_map (R, modulus);
    }
  else
    {
      err = GNUTLS_E_SUCCESS;
    }
done:
  ecc_del_point (T);
  if (wmnaf)
    free (wmnaf);
  return err;
}

/*
   Perform a point wMNAF-multiplication utilizing cache
   This function will lookup for an apropriate curve first
   This function's definition allows in-place substitution instead of ecc_mulmod
   @param k    The scalar to multiply by
   @param id   The curve's id
   @param R    [out] Destination for kG
   @param a        The curve's A value
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1 == map, 0 == leave in projective)
   @return     GNUTLS_E_SUCCESS on success
*/
int
ecc_mulmod_cached_lookup (mpz_t k, ecc_point * G, ecc_point * R,
                                mpz_t a, mpz_t modulus, int map)
{
  int i, id;

  if (k == NULL || G == NULL || R == NULL || modulus == NULL)
    return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;

  for (i = 0; (id = ecc_wmnaf_cache[i].id); ++i)
    {
      if (!(mpz_cmp (G->x, ecc_wmnaf_cache[i].pos[0]->x)) &&
          !(mpz_cmp (G->y, ecc_wmnaf_cache[i].pos[0]->y)))
        {
          break;
        }
    }

  return ecc_mulmod_cached (k, id, R, a, modulus, map);
}
