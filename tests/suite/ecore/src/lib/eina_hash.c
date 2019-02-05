/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Carsten Haitzler, Gustavo Sverzut Barbieri,
 *                         Vincent Torri, Jorge Luis Zapata Muga, Cedric Bail
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
#include <Evil.h>
#else
#include <stdint.h>
#endif

#include "eina_config.h"
#include "eina_private.h"
#include "eina_rbtree.h"
#include "eina_error.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_hash.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

#define EINA_MAGIC_CHECK_HASH(d)                                        \
   do {                                                                  \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_HASH)) {                         \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_HASH); }                             \
     } while(0)

#define EINA_MAGIC_CHECK_HASH_ITERATOR(d, ...)                          \
   do {                                                                  \
        if (!EINA_MAGIC_CHECK(d, EINA_MAGIC_HASH_ITERATOR))                \
          {                                                                  \
             EINA_MAGIC_FAIL(d, EINA_MAGIC_HASH_ITERATOR);                 \
             return __VA_ARGS__;                                                   \
          }                                                                  \
     } while(0)

#define EINA_HASH_BUCKET_SIZE 8
#define EINA_HASH_SMALL_BUCKET_SIZE 5

#define EINA_HASH_RBTREE_MASK 0xFFF

typedef struct _Eina_Hash_Head Eina_Hash_Head;
typedef struct _Eina_Hash_Element Eina_Hash_Element;
typedef struct _Eina_Hash_Foreach_Data Eina_Hash_Foreach_Data;
typedef struct _Eina_Iterator_Hash Eina_Iterator_Hash;
typedef struct _Eina_Hash_Each Eina_Hash_Each;

struct _Eina_Hash {
	Eina_Key_Length key_length_cb;
	Eina_Key_Cmp key_cmp_cb;
	Eina_Key_Hash key_hash_cb;
	Eina_Free_Cb data_free_cb;

	Eina_Rbtree **buckets;
	int size;
	int mask;

	int population;

 EINA_MAGIC};

struct _Eina_Hash_Head {
	EINA_RBTREE;
	int hash;

	Eina_Rbtree *head;
};

struct _Eina_Hash_Element {
	EINA_RBTREE;
	Eina_Hash_Tuple tuple;
	Eina_Bool begin:1;
};

struct _Eina_Hash_Foreach_Data {
	Eina_Hash_Foreach cb;
	const void *fdata;
};

typedef void *(*Eina_Iterator_Get_Content_Callback) (Eina_Iterator_Hash *
						     it);
#define FUNC_ITERATOR_GET_CONTENT(Function) ((Eina_Iterator_Get_Content_Callback)Function)

struct _Eina_Iterator_Hash {
	Eina_Iterator iterator;

	Eina_Iterator_Get_Content_Callback get_content;
	const Eina_Hash *hash;

	Eina_Iterator *current;
	Eina_Iterator *list;
	Eina_Hash_Head *hash_head;
	Eina_Hash_Element *hash_element;
	int bucket;

	int index;

 EINA_MAGIC};

struct _Eina_Hash_Each {
	Eina_Hash_Head *hash_head;
	const Eina_Hash_Element *hash_element;
	const void *data;
};

#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8) \
                       + (uint32_t)(((const uint8_t *)(d))[0]))

static inline int
_eina_hash_hash_rbtree_cmp_hash(const Eina_Hash_Head * hash_head,
				const int *hash,
				__UNUSED__ int key_length,
				__UNUSED__ void *data)
{
	return hash_head->hash - *hash;
}

static Eina_Rbtree_Direction
_eina_hash_hash_rbtree_cmp_node(const Eina_Hash_Head * left,
				const Eina_Hash_Head * right,
				__UNUSED__ void *data)
{
	if (left->hash - right->hash < 0)
		return EINA_RBTREE_LEFT;

	return EINA_RBTREE_RIGHT;
}

static inline int
_eina_hash_key_rbtree_cmp_key_data(const Eina_Hash_Element * hash_element,
				   const Eina_Hash_Tuple * tuple,
				   __UNUSED__ unsigned int key_length,
				   Eina_Key_Cmp cmp)
{
	int result;

	result = cmp(hash_element->tuple.key,
		     hash_element->tuple.key_length,
		     tuple->key, tuple->key_length);

	if (result == 0 && tuple->data
	    && tuple->data != hash_element->tuple.data)
		return 1;

	return result;
}

static Eina_Rbtree_Direction
_eina_hash_key_rbtree_cmp_node(const Eina_Hash_Element * left,
			       const Eina_Hash_Element * right,
			       Eina_Key_Cmp cmp)
{
	int result;

	result = cmp(left->tuple.key, left->tuple.key_length,
		     right->tuple.key, right->tuple.key_length);

	if (result < 0)
		return EINA_RBTREE_LEFT;

	return EINA_RBTREE_RIGHT;
}

static inline Eina_Bool
eina_hash_add_alloc_by_hash(Eina_Hash * hash,
			    const void *key, int key_length,
			    int alloc_length, int key_hash,
			    const void *data)
{
	Eina_Hash_Element *new_hash_element = NULL;
	Eina_Hash_Head *hash_head;
	Eina_Error error = 0;
	int hash_num;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(data, EINA_FALSE);
	EINA_MAGIC_CHECK_HASH(hash);

	error = EINA_ERROR_OUT_OF_MEMORY;

	/* Apply eina mask to hash. */
	hash_num = key_hash & hash->mask;
	key_hash &= EINA_HASH_RBTREE_MASK;

	if (!hash->buckets) {
		hash->buckets = calloc(sizeof(Eina_Rbtree *), hash->size);
		if (!hash->buckets)
			goto on_error;

		hash_head = NULL;
	} else
		/* Look up for head node. */
		hash_head =
		    (Eina_Hash_Head *) eina_rbtree_inline_lookup(hash->
								 buckets
								 [hash_num],
								 &key_hash,
								 0,
								 EINA_RBTREE_CMP_KEY_CB
								 (_eina_hash_hash_rbtree_cmp_hash),
								 NULL);

	if (!hash_head) {
		/* If not found allocate it and an element. */
		hash_head =
		    malloc(sizeof(Eina_Hash_Head) +
			   sizeof(Eina_Hash_Element) + alloc_length);
		if (!hash_head)
			goto on_error;

		hash_head->hash = key_hash;
		hash_head->head = NULL;

		hash->buckets[hash_num] =
		    eina_rbtree_inline_insert(hash->buckets[hash_num],
					      EINA_RBTREE_GET(hash_head),
					      EINA_RBTREE_CMP_NODE_CB
					      (_eina_hash_hash_rbtree_cmp_node),
					      NULL);

		new_hash_element = (Eina_Hash_Element *) (hash_head + 1);
		new_hash_element->begin = EINA_TRUE;
	}

	if (!new_hash_element) {
		/*
		   Alloc a new element
		   (No more lookup as we expect to support more than one item for one key).
		 */
		new_hash_element =
		    malloc(sizeof(Eina_Hash_Element) + alloc_length);
		if (!new_hash_element)
			goto on_error;

		new_hash_element->begin = EINA_FALSE;
	}

	/* Setup the element */
	new_hash_element->tuple.key_length = key_length;
	new_hash_element->tuple.data = (void *) data;
	if (alloc_length > 0) {
		new_hash_element->tuple.key =
		    (char *) (new_hash_element + 1);
		memcpy((char *) new_hash_element->tuple.key, key,
		       alloc_length);
	} else
		new_hash_element->tuple.key = key;

	/* add the new element to the hash. */
	hash_head->head =
	    eina_rbtree_inline_insert(hash_head->head,
				      EINA_RBTREE_GET(new_hash_element),
				      EINA_RBTREE_CMP_NODE_CB
				      (_eina_hash_key_rbtree_cmp_node),
				      (const void *) hash->key_cmp_cb);
	hash->population++;
	return EINA_TRUE;

      on_error:
	eina_error_set(error);
	return EINA_FALSE;
}

static Eina_Bool
_eina_hash_rbtree_each(__UNUSED__ const Eina_Rbtree * container,
		       const Eina_Hash_Head * hash_head,
		       Eina_Hash_Each * data)
{
	Eina_Iterator *it;
	Eina_Hash_Element *hash_element;
	Eina_Bool found = EINA_TRUE;

	it = eina_rbtree_iterator_prefix(hash_head->head);
	EINA_ITERATOR_FOREACH(it, hash_element) {
		if (hash_element->tuple.data == data->data) {
			data->hash_element = hash_element;
			data->hash_head = (Eina_Hash_Head *) hash_head;
			found = EINA_FALSE;
			break;
		}
	}

	eina_iterator_free(it);
	return found;
}

static inline Eina_Hash_Element *_eina_hash_find_by_hash(const Eina_Hash *
							 hash,
							 Eina_Hash_Tuple *
							 tuple,
							 int key_hash,
							 Eina_Hash_Head **
							 hash_head)
{
	Eina_Hash_Element *hash_element;
	int rb_hash = key_hash & EINA_HASH_RBTREE_MASK;

	key_hash &= hash->mask;

	if (!hash->buckets)
		return NULL;

	*hash_head =
	    (Eina_Hash_Head *) eina_rbtree_inline_lookup(hash->
							 buckets[key_hash],
							 &rb_hash, 0,
							 EINA_RBTREE_CMP_KEY_CB
							 (_eina_hash_hash_rbtree_cmp_hash),
							 NULL);
	if (!*hash_head)
		return NULL;

	hash_element =
	    (Eina_Hash_Element *) eina_rbtree_inline_lookup((*hash_head)->
							    head, tuple, 0,
							    EINA_RBTREE_CMP_KEY_CB
							    (_eina_hash_key_rbtree_cmp_key_data),
							    (const void *)
							    hash->key_cmp_cb);

	return hash_element;
}

static inline Eina_Hash_Element *_eina_hash_find_by_data(const Eina_Hash *
							 hash,
							 const void *data,
							 int *key_hash,
							 Eina_Hash_Head **
							 hash_head)
{
	Eina_Hash_Each each;
	Eina_Iterator *it;
	int hash_num;

	if (!hash->buckets)
		return NULL;

	each.hash_element = NULL;
	each.data = data;

	for (hash_num = 0; hash_num < hash->size; hash_num++) {
		if (!hash->buckets[hash_num])
			continue;

		it = eina_rbtree_iterator_prefix(hash->buckets[hash_num]);
		eina_iterator_foreach(it,
				      EINA_EACH_CB(_eina_hash_rbtree_each),
				      &each);
		eina_iterator_free(it);

		if (each.hash_element) {
			*key_hash = hash_num;
			*hash_head = each.hash_head;
			return (Eina_Hash_Element *) each.hash_element;
		}
	}

	return NULL;
}

static void
_eina_hash_el_free(Eina_Hash_Element * hash_element, Eina_Hash * hash)
{
	if (hash->data_free_cb)
		hash->data_free_cb(hash_element->tuple.data);

	if (hash_element->begin == EINA_FALSE)
		free(hash_element);
}

static void
_eina_hash_head_free(Eina_Hash_Head * hash_head, Eina_Hash * hash)
{
	eina_rbtree_delete(hash_head->head,
			   EINA_RBTREE_FREE_CB(_eina_hash_el_free), hash);
	free(hash_head);
}

static Eina_Bool
_eina_hash_del_by_hash_el(Eina_Hash * hash,
			  Eina_Hash_Element * hash_element,
			  Eina_Hash_Head * hash_head, int key_hash)
{
	hash_head->head =
	    eina_rbtree_inline_remove(hash_head->head,
				      EINA_RBTREE_GET(hash_element),
				      EINA_RBTREE_CMP_NODE_CB
				      (_eina_hash_key_rbtree_cmp_node),
				      (const void *) hash->key_cmp_cb);
	_eina_hash_el_free(hash_element, hash);

	if (!hash_head->head) {
		key_hash &= hash->mask;

		hash->buckets[key_hash] =
		    eina_rbtree_inline_remove(hash->buckets[key_hash],
					      EINA_RBTREE_GET(hash_head),
					      EINA_RBTREE_CMP_NODE_CB
					      (_eina_hash_hash_rbtree_cmp_node),
					      NULL);
		free(hash_head);
	}

	hash->population--;
	if (hash->population == 0) {
		free(hash->buckets);
		hash->buckets = NULL;
	}

	return EINA_TRUE;
}

static Eina_Bool
_eina_hash_del_by_key_hash(Eina_Hash * hash,
			   const void *key,
			   int key_length, int key_hash, const void *data)
{
	Eina_Hash_Element *hash_element;
	Eina_Hash_Head *hash_head;
	Eina_Hash_Tuple tuple;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, EINA_FALSE);
	EINA_MAGIC_CHECK_HASH(hash);

	if (!hash->buckets)
		return EINA_FALSE;

	tuple.key = (void *) key;
	tuple.key_length = key_length;
	tuple.data = (void *) data;

	hash_element =
	    _eina_hash_find_by_hash(hash, &tuple, key_hash, &hash_head);
	if (!hash_element)
		return EINA_FALSE;

	return _eina_hash_del_by_hash_el(hash, hash_element, hash_head,
					 key_hash);
}

static Eina_Bool
_eina_hash_del_by_key(Eina_Hash * hash, const void *key, const void *data)
{
	int key_length, key_hash;

	EINA_MAGIC_CHECK_HASH(hash);
	if (!hash)
		return EINA_FALSE;

	if (!key)
		return EINA_FALSE;

	if (!hash->buckets)
		return EINA_FALSE;

	key_length = hash->key_length_cb ? hash->key_length_cb(key) : 0;
	key_hash = hash->key_hash_cb(key, key_length);
	return _eina_hash_del_by_key_hash(hash, key, key_length, key_hash,
					  data);
}

static unsigned int _eina_string_key_length(const char *key)
{
	if (!key)
		return 0;

	return (int) strlen(key) + 1;
}

static int
_eina_string_key_cmp(const char *key1, __UNUSED__ int key1_length,
		     const char *key2, __UNUSED__ int key2_length)
{
	return strcmp(key1, key2);
}

static int
_eina_stringshared_key_cmp(const char *key1, __UNUSED__ int key1_length,
			   const char *key2, __UNUSED__ int key2_length)
{
	return key1 - key2;
}

static unsigned int _eina_int32_key_length(__UNUSED__ const uint32_t * key)
{
	return 4;
}

static int
_eina_int32_key_cmp(const uint32_t * key1, __UNUSED__ int key1_length,
		    const uint32_t * key2, __UNUSED__ int key2_length)
{
	return *key1 - *key2;
}

static unsigned int _eina_int64_key_length(__UNUSED__ const uint32_t * key)
{
	return 8;
}

static int
_eina_int64_key_cmp(const uint64_t * key1, __UNUSED__ int key1_length,
		    const uint64_t * key2, __UNUSED__ int key2_length)
{
	return *key1 - *key2;
}

static Eina_Bool
_eina_foreach_cb(const Eina_Hash * hash,
		 Eina_Hash_Tuple * data, Eina_Hash_Foreach_Data * fdata)
{
	return fdata->cb((Eina_Hash *) hash,
			 data->key, data->data, (void *) fdata->fdata);
}

static void *_eina_hash_iterator_data_get_content(Eina_Iterator_Hash * it)
{
	Eina_Hash_Element *stuff;

	EINA_MAGIC_CHECK_HASH_ITERATOR(it, NULL);

	stuff = it->hash_element;

	if (!stuff)
		return NULL;

	return stuff->tuple.data;
}

static void *_eina_hash_iterator_key_get_content(Eina_Iterator_Hash * it)
{
	Eina_Hash_Element *stuff;

	EINA_MAGIC_CHECK_HASH_ITERATOR(it, NULL);

	stuff = it->hash_element;

	if (!stuff)
		return NULL;

	return (void *) stuff->tuple.key;
}

static Eina_Hash_Tuple
    *_eina_hash_iterator_tuple_get_content(Eina_Iterator_Hash * it)
{
	Eina_Hash_Element *stuff;

	EINA_MAGIC_CHECK_HASH_ITERATOR(it, NULL);

	stuff = it->hash_element;

	if (!stuff)
		return NULL;

	return &stuff->tuple;
}

static Eina_Bool
_eina_hash_iterator_next(Eina_Iterator_Hash * it, void **data)
{
	Eina_Bool ok;
	int bucket;

	if (!(it->index < it->hash->population))
		return EINA_FALSE;

	if (!it->current) {
		ok = EINA_FALSE;
		bucket = 0;
		it->index = -1;
	} else {
		ok = eina_iterator_next(it->list,
					(void **) &it->hash_element);
		if (!ok) {
			eina_iterator_free(it->list);
			it->list = NULL;

			ok = eina_iterator_next(it->current,
						(void **) &it->hash_head);
			if (!ok) {
				eina_iterator_free(it->current);
				it->current = NULL;
				it->bucket++;
			} else {
				it->list =
				    eina_rbtree_iterator_prefix(it->
								hash_head->
								head);
				ok = eina_iterator_next(it->list,
							(void **) &it->
							hash_element);
			}
		}

		bucket = it->bucket;
	}

	if (ok == EINA_FALSE) {
		while (bucket < it->hash->size) {
			if (it->hash->buckets[bucket]) {
				it->current =
				    eina_rbtree_iterator_prefix(it->hash->
								buckets
								[bucket]);
				ok = eina_iterator_next(it->current,
							(void **) &it->
							hash_head);
				if (ok)
					break;

				eina_iterator_free(it->current);
				it->current = NULL;
			}

			++bucket;
		}
		if (it->list)
			eina_iterator_free(it->list);

		it->list =
		    eina_rbtree_iterator_prefix(it->hash_head->head);
		ok = eina_iterator_next(it->list,
					(void **) &it->hash_element);
		if (bucket == it->hash->size)
			ok = EINA_FALSE;
	}

	it->index++;
	it->bucket = bucket;

	if (ok)
		*data = it->get_content(it);

	return ok;
}

static void *_eina_hash_iterator_get_container(Eina_Iterator_Hash * it)
{
	EINA_MAGIC_CHECK_HASH_ITERATOR(it, NULL);
	return (void *) it->hash;
}

static void _eina_hash_iterator_free(Eina_Iterator_Hash * it)
{
	EINA_MAGIC_CHECK_HASH_ITERATOR(it);
	if (it->current)
		eina_iterator_free(it->current);

	if (it->list)
		eina_iterator_free(it->list);

	free(it);
}

/**
 * @endcond
 */

/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @addtogroup Eina_Hash_Group Hash Table
 *
 * @brief give a small description here : what it is for, what it does
 * , etc...
 *
 * Hash API. Give some hints about the use (functions that must be
 * used like init / shutdown), general use, etc... Give also a link to
 * tutorial below.
 *
 * @section hashtable_algo Algorithm
 *
 * Give here the algorithm used in the implementation
 *
 * @section hashtable_perf Performance
 *
 * Give some hints about performance if it is possible, and an image !
 *
 * @section hashtable_tutorial Tutorial
 *
 * Here is a fantastic tutorial about our hash table
 *
 * @{
 */

/**
 * @brief Create a new hash table.
 *
 * @param key_length_cb The function called when getting the size of the key.
 * @param key_cmp_cb The function called when comparing the keys.
 * @param key_hash_cb The function called when getting the values.
 * @param data_free_cb The function called when the hash table is freed.
 * @param buckets_power_size The size of the buckets.
 * @return The new hash table.
 *
 * This function create a new hash table using user-defined callbacks
 * to manage the hash table. On failure, @c NULL is returned and
 * #EINA_ERROR_OUT_OF_MEMORY is set. If @p key_cmp_cb or @pkey_hash_cb
 * are @c NULL, @c NULL is returned. If @p buckets_power_size is
 * smaller or equal than 2, or if it is greater or equal than 17,
 * @c NULL is returned.
 *
 * Pre-defined functions are available to create a hash table. See
 * eina_hash_string_djb2_new(), eina_hash_string_superfast_new(),
 * eina_hash_string_small_new(), eina_hash_int32_new(),
 * eina_hash_int64_new(), eina_hash_pointer_new() and
 * eina_hash_stringshared_new().
 */
EAPI Eina_Hash *eina_hash_new(Eina_Key_Length key_length_cb,
			      Eina_Key_Cmp key_cmp_cb,
			      Eina_Key_Hash key_hash_cb,
			      Eina_Free_Cb data_free_cb,
			      int buckets_power_size)
{
	/* FIXME: Use mempool. */
	Eina_Hash *new;

	eina_error_set(0);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key_cmp_cb, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key_hash_cb, NULL);
	EINA_SAFETY_ON_TRUE_RETURN_VAL(buckets_power_size < 3, NULL);
	EINA_SAFETY_ON_TRUE_RETURN_VAL(buckets_power_size > 16, NULL);

	new = malloc(sizeof(Eina_Hash));
	if (!new)
		goto on_error;

	EINA_MAGIC_SET(new, EINA_MAGIC_HASH);

	new->key_length_cb = key_length_cb;
	new->key_cmp_cb = key_cmp_cb;
	new->key_hash_cb = key_hash_cb;
	new->data_free_cb = data_free_cb;
	new->buckets = NULL;
	new->population = 0;

	new->size = 1 << buckets_power_size;
	new->mask = new->size - 1;

	return new;

      on_error:
	eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
	return NULL;
}

/**
 * @brief Create a new hash table using the djb2 algorithm.
 *
 * @param data_free_cb The function called when the hash table is freed.
 * @return The new hash table.
 *
 * This function create a new hash table using the djb2 algorithm for
 * table management and strcmp() to compare the keys. Values can then
 * be looked up with pointers other than the original key pointer that
 * was used to add values. On failure, this function returns @c NULL.
 * @p data_free_cb is a callback called when the hash table is
 * freed. @c NULL can be passed as callback.
 */
EAPI Eina_Hash *eina_hash_string_djb2_new(Eina_Free_Cb data_free_cb)
{
	return eina_hash_new(EINA_KEY_LENGTH(_eina_string_key_length),
			     EINA_KEY_CMP(_eina_string_key_cmp),
			     EINA_KEY_HASH(eina_hash_djb2),
			     data_free_cb, EINA_HASH_BUCKET_SIZE);
}

/**
 * @brief Create a new hash table for use with strings.
 *
 * @param data_free_cb The function called when the hash table is freed.
 * @return The new hash table.
 *
 * This function create a new hash table using the superfast algorithm
 * for table management and strcmp() to compare the keys. Values can
 * then be looked up with pointers other than the original key pointer
 * that was used to add values. On failure, this function returns
 * @c NULL. @p data_free_cb is a callback called when the hash table is
 * freed. @c NULL can be passed as callback. 
 */
EAPI Eina_Hash *eina_hash_string_superfast_new(Eina_Free_Cb data_free_cb)
{
	return eina_hash_new(EINA_KEY_LENGTH(_eina_string_key_length),
			     EINA_KEY_CMP(_eina_string_key_cmp),
			     EINA_KEY_HASH(eina_hash_superfast),
			     data_free_cb, EINA_HASH_BUCKET_SIZE);
}

/**
 * @brief Create a new hash table for use with strings with small bucket size.
 *
 * @param data_free_cb  The function called when the hash table is freed.
 * @return  The new hash table.
 *
 * This function create a new hash table using the superfast algorithm
 * for table management and strcmp() to compare the keys, but with a
 * smaller bucket size (compared to eina_hash_string_superfast_new())
 * which will minimize the memory used by the returned hash
 * table. Values can then be looked up with pointers other than the
 * original key pointer that was used to add values. On failure, this
 * function returns @c NULL. @p data_free_cb is a callback called when
 * the hash table is freed. @c NULL can be passed as callback.
 */
EAPI Eina_Hash *eina_hash_string_small_new(Eina_Free_Cb data_free_cb)
{
	return eina_hash_new(EINA_KEY_LENGTH(_eina_string_key_length),
			     EINA_KEY_CMP(_eina_string_key_cmp),
			     EINA_KEY_HASH(eina_hash_superfast),
			     data_free_cb, EINA_HASH_SMALL_BUCKET_SIZE);
}

/**
 * @brief Create a new hash table for use with 32bit integers.
 *
 * @param data_free_cb  The function called when the hash table is freed.
 * @return  The new hash table.
 *
 * This function create a new hash table using the int32 algorithm for
 * table management and dereferenced pointers to compare the
 * keys. Values can then be looked up with pointers other than the
 * original key pointer that was used to add values. This method may
 * appear to be able to match string keys, actually it only matches
 * the first character. On failure, this function returns @c NULL.
 * @p data_free_cb is a callback called when the hash table is freed.
 * @c NULL can be passed as callback.
 */
EAPI Eina_Hash *eina_hash_int32_new(Eina_Free_Cb data_free_cb)
{
	return eina_hash_new(EINA_KEY_LENGTH(_eina_int32_key_length),
			     EINA_KEY_CMP(_eina_int32_key_cmp),
			     EINA_KEY_HASH(eina_hash_int32),
			     data_free_cb, EINA_HASH_BUCKET_SIZE);
}

/**
 * @brief Create a new hash table for use with 64bit integers.
 *
 * @param data_free_cb  The function called when the hash table is freed.
 * @return  The new hash table.
 *
 * This function create a new hash table using the int64 algorithm for
 * table management and dereferenced pointers to compare the
 * keys. Values can then be looked up with pointers other than the
 * original key pointer that was used to add values. This method may
 * appear to be able to match string keys, actually it only matches
 * the first character. On failure, this function returns @c NULL.
 * @p data_free_cb is a callback called when the hash table is freed.
 * @c NULL can be passed as callback.
 */
EAPI Eina_Hash *eina_hash_int64_new(Eina_Free_Cb data_free_cb)
{
	return eina_hash_new(EINA_KEY_LENGTH(_eina_int64_key_length),
			     EINA_KEY_CMP(_eina_int64_key_cmp),
			     EINA_KEY_HASH(eina_hash_int64),
			     data_free_cb, EINA_HASH_BUCKET_SIZE);
}

/**
 * @brief Create a new hash table for use with pointers.
 *
 * @param data_free_cb  The function called when the hash table is freed.
 * @return  The new hash table.
 *
 * This function create a new hash table using the int64 algorithm for
 * table management and dereferenced pointers to compare the
 * keys. Values can then be looked up with pointers other than the
 * original key pointer that was used to add values. This method may
 * appear to be able to match string keys, actually it only matches
 * the first character. On failure, this function returns @c NULL.
 * @p data_free_cb is a callback called when the hash table is freed.
 * @c NULL can be passed as callback.
 */
EAPI Eina_Hash *eina_hash_pointer_new(Eina_Free_Cb data_free_cb)
{
#ifdef __LP64__
	return eina_hash_new(EINA_KEY_LENGTH(_eina_int64_key_length),
			     EINA_KEY_CMP(_eina_int64_key_cmp),
			     EINA_KEY_HASH(eina_hash_int64),
			     data_free_cb, EINA_HASH_BUCKET_SIZE);
#else
	return eina_hash_new(EINA_KEY_LENGTH(_eina_int32_key_length),
			     EINA_KEY_CMP(_eina_int32_key_cmp),
			     EINA_KEY_HASH(eina_hash_int32),
			     data_free_cb, EINA_HASH_BUCKET_SIZE);
#endif
}

/**
 * @brief Create a new hash table optimized for stringshared values.
 *
 * @param data_free_cb  The function called when the hash table is freed.
 * @return  The new hash table.
 *
 * This function create a new hash table optimized for stringshared
 * values. Values CAN NOT be looked up with pointers not
 * equal to the original key pointer that was used to add a value. On failure, this function returns @c NULL.
 * @p data_free_cb is a callback called when the hash table is freed.
 * @c NULL can be passed as callback.
 *
 * Excerpt of code that will NOT work with this type of hash:
 *
 * @code
 * extern Eina_Hash *hash;
 * extern const char *value;
 * const char *a = eina_stringshare_add("key");
 *
 * eina_hash_add(hash, a, value);
 * eina_hash_find(hash, "key")
 * @endcode
 */
EAPI Eina_Hash *eina_hash_stringshared_new(Eina_Free_Cb data_free_cb)
{
	return eina_hash_new(NULL,
			     EINA_KEY_CMP(_eina_stringshared_key_cmp),
			     EINA_KEY_HASH(eina_hash_superfast),
			     data_free_cb, EINA_HASH_BUCKET_SIZE);
}

/**
 * @brief Returns the number of entries in the given hash table.
 *
 * @param hash The given hash table.
 * @return The number of entries in the hash table.
 *
 * This function returns the number of entries in @p hash, or 0 on
 * error. If @p hash is @c NULL, 0 is returned.
 */
EAPI int eina_hash_population(const Eina_Hash * hash)
{
	if (!hash)
		return 0;

	EINA_MAGIC_CHECK_HASH(hash);
	return hash->population;
}

/**
 * Free the given hash table resources.
 *
 * @param hash The hash table to be freed.
 *
 * This function frees up all the memory allocated to storing @p hash,
 * and call the free callback if it has been passed to the hash table
 * at creation time. If no free callback has been passed, any entries
 * in the table that the program has no more pointers for elsewhere
 * may now be lost, so this should only be called if the program has
 * already freed any allocated data in the hash table or has the
 * pointers for data in the table stored elsewhere as well. If @p hash
 * is @c NULL, the function returns immediately.
 *
 * Example:
 * @code
 * extern Eina_Hash *hash;
 *
 * eina_hash_free(hash);
 * hash = NULL;
 * @endcode
 */
EAPI void eina_hash_free(Eina_Hash * hash)
{
	int i;

	EINA_MAGIC_CHECK_HASH(hash);
	EINA_SAFETY_ON_NULL_RETURN(hash);

	if (hash->buckets) {
		for (i = 0; i < hash->size; i++)
			eina_rbtree_delete(hash->buckets[i],
					   EINA_RBTREE_FREE_CB
					   (_eina_hash_head_free), hash);
		free(hash->buckets);
	}
	free(hash);
}

/**
 * Free the given hash table buckets resources.
 *
 * @param hash The hash table whose buckets have to be freed.
 *
 * This function frees up all the memory allocated to storing the
 * buckets of @p hash, and call the free callback on all hash table
 * buckets if it has been passed to the hash table at creation time,
 * then frees the buckets. If no free callback has been passed, no
 * buckets value will be freed. If @p hash is @c NULL, the function
 * returns immediately.
 */
EAPI void eina_hash_free_buckets(Eina_Hash * hash)
{
	int i;

	EINA_MAGIC_CHECK_HASH(hash);
	EINA_SAFETY_ON_NULL_RETURN(hash);

	if (hash->buckets) {
		for (i = 0; i < hash->size; i++)
			eina_rbtree_delete(hash->buckets[i],
					   EINA_RBTREE_FREE_CB
					   (_eina_hash_head_free), hash);
		free(hash->buckets);
		hash->buckets = NULL;
		hash->population = 0;
	}
}

/**
 * @brief Add an entry to the given hash table.
 *
 * @param hash The given hash table.
 * @param key A unique key.
 * @param key_length The length of the key.
 * @param key_hash The hash that will always match key.
 * @param data The data to associate with the string given by the key.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * This function adds @p key to @p hash. @p hash, @p key and @p data
 * can be @c NULL, in that case #EINA_FALSE is returned. @p key is
 * expected to be a unique string within the hash table. Otherwise,
 * one cannot be sure which inserted data pointer will be accessed
 * with @ref eina_hash_find, and removed with @ref eina_hash_del. Do
 * not forget to count '\\0' for string when setting the value of
 * @p key_length. @p key_hash is expected to always match
 * @p key. Otherwise, one cannot be sure to find it again with @ref
 * eina_hash_find_by_hash. Key strings are case sensitive. If an error
 * occurs, eina_error_get() should be used to determine if an
 * allocation error occurred during this function. This function
 * returns #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 */
EAPI Eina_Bool
eina_hash_add_by_hash(Eina_Hash * hash,
		      const void *key,
		      int key_length, int key_hash, const void *data)
{
	return eina_hash_add_alloc_by_hash(hash,
					   key,
					   key_length,
					   key_length, key_hash, data);
}

/**
 * @brief Add an entry to the given hash table and do not duplicate the string key.
 *
 * @param hash The given hash table.  Can be @c NULL.
 * @param key A unique key.  Can be @c NULL.
 * @param key_length Should be the length of @p key (don't forget to count '\\0' for string).
 * @param key_hash The hash that will always match key.
 * @param data Data to associate with the string given by @p key.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * This function adds @p key to @p hash. @p hash, @p key and @p data
 * can be @c NULL, in that case #EINA_FALSE is returned. @p key is
 * expected to be a unique string within the hash table. Otherwise,
 * one cannot be sure which inserted data pointer will be accessed
 * with @ref eina_hash_find, and removed with @ref eina_hash_del. This
 * function does not make a copy of @p key so it must be a string
 * constant or stored elsewhere (in the object being added). Do
 * not forget to count '\\0' for string when setting the value of
 * @p key_length. @p key_hash is expected to always match
 * @p key. Otherwise, one cannot be sure to find it again with @ref
 * eina_hash_find_by_hash. Key strings are case sensitive. If an error
 * occurs, eina_error_get() should be used to determine if an
 * allocation error occurred during this function. This function
 * returns #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 */
EAPI Eina_Bool
eina_hash_direct_add_by_hash(Eina_Hash * hash,
			     const void *key,
			     int key_length,
			     int key_hash, const void *data)
{
	return eina_hash_add_alloc_by_hash(hash, key, key_length, 0,
					   key_hash, data);
}

/**
 * @brief Add an entry to the given hash table.
 *
 * @param hash The given hash table.
 * @param key A unique key.
 * @param data Data to associate with the string given by @p key.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * This function adds @p key to @p hash. @p hash, @p key and @p data
 * can be @c NULL, in that case #EINA_FALSE is returned. @p key is
 * expected to be unique within the hash table. Key uniqueness varies
 * depending on the type of @p hash: a stringshared @ref Eina_Hash
 * need only have unique pointers for keys, but the strings in the
 * pointers may be identical. All other hash types require the strings
 * themselves to be unique. Failure to use sufficient uniqueness will
 * result in unexpected results when inserting data pointers accessed
 * with eina_hash_find(), and removed with eina_hash_del(). Key
 * strings are case sensitive. If an error occurs, eina_error_get()
 * should be used to determine if an allocation error occurred during
 * this function. This function returns #EINA_FALSE if an error
 * occurred, #EINA_TRUE otherwise.
 */
EAPI Eina_Bool
eina_hash_add(Eina_Hash * hash, const void *key, const void *data)
{
	unsigned int key_length;
	int key_hash;

	EINA_MAGIC_CHECK_HASH(hash);
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash->key_hash_cb, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(data, EINA_FALSE);

	key_length = hash->key_length_cb ? hash->key_length_cb(key) : 0;
	key_hash = hash->key_hash_cb(key, key_length);

	return eina_hash_add_alloc_by_hash(hash, key, key_length,
					   key_length, key_hash, data);
}

/**
 * @brief Add an entry to the given hash table without duplicating the string key.
 *
 * @param hash The given hash table.  Can be @c NULL.
 * @param key A unique key.  Can be @c NULL.
 * @param data Data to associate with the string given by @p key.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * This function adds @p key to @p hash. @p hash, @p key and @p data
 * can be @c NULL, in that case #EINA_FALSE is returned. @p key is
 * expected to be unique within the hash table. Key uniqueness varies
 * depending on the type of @p hash: a stringshared @ref Eina_Hash
 * need only have unique pointers for keys, but the strings in the
 * pointers may be identical. All other hash types require the strings
 * themselves to be unique. Failure to use sufficient uniqueness will
 * result in unexpected results when inserting data pointers accessed
 * with eina_hash_find(), and removed with eina_hash_del(). This
 * function does not make a copy of @p key, so it must be a string
 * constant or stored elsewhere ( in the object being added). Key
 * strings are case sensitive. If an error occurs, eina_error_get()
 * should be used to determine if an allocation error occurred during
 * this function. This function returns #EINA_FALSE if an error
 * occurred, #EINA_TRUE otherwise.
 */
EAPI Eina_Bool
eina_hash_direct_add(Eina_Hash * hash, const void *key, const void *data)
{
	int key_length;
	int key_hash;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash->key_hash_cb, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(data, EINA_FALSE);
	EINA_MAGIC_CHECK_HASH(hash);

	key_length = hash->key_length_cb ? hash->key_length_cb(key) : 0;
	key_hash = hash->key_hash_cb(key, key_length);

	return eina_hash_add_alloc_by_hash(hash, key, key_length, 0,
					   key_hash, data);
}

/**
 * @brief Remove the entry identified by a key and a key hash from the given hash table.
 *
 * @param hash The given hash table.
 * @param key The key.
 * @param key_length The length of the key.
 * @param key_hash The hash that always match the key.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * This function removes the entry identified by @p key and
 * @p key_hash from @p hash. If a free function was given to the
 * callback on creation, it will be called for the data being
 * deleted. Do not forget to count '\\0' for string when setting the
 * value of @p key_length. If @p hash or @p key are @c NULL, the
 * functions returns immediately #EINA_FALSE. This function returns
 * #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * @note if you don't have the key_hash, use eina_hash_del_by_key() instead.
 * @note if you don't have the key, use eina_hash_del_by_data() instead.
 */
EAPI Eina_Bool
eina_hash_del_by_key_hash(Eina_Hash * hash,
			  const void *key, int key_length, int key_hash)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, EINA_FALSE);

	return _eina_hash_del_by_key_hash(hash, key, key_length, key_hash,
					  NULL);
}

/**
 * @brief Remove the entry identified by a key from the given hash table.
 *
 * This version will calculate key length and hash by using functions
 * provided to hash creation function.
 *
 * @param hash The given hash table.
 * @param key  The key.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * This function removes the entry identified by @p key from @p
 * hash. The key length and hash will be calculated automatically by
 * using functiond provided to has creation function. If a free
 * function was given to the callback on creation, it will be called
 * for the data being deleted. If @p hash or @p key are @c NULL, the
 * functions returns immediately #EINA_FALSE. This function returns
 * #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * @note if you already have the key_hash, use eina_hash_del_by_key_hash() instead.
 * @note if you don't have the key, use eina_hash_del_by_data() instead.
 */
EAPI Eina_Bool eina_hash_del_by_key(Eina_Hash * hash, const void *key)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, EINA_FALSE);

	return _eina_hash_del_by_key(hash, key, NULL);
}

/**
 * @brief Remove the entry identified by a data from the given hash table.
 *
 * This version is slow since there is no quick access to nodes based on data.
 *
 * @param hash The given hash table.
 * @param data The data value to search and remove.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *          thing goes fine.
 *
 * This function removes the entry identified by @p data from @p
 * hash. If a free function was given to the callback on creation, it
 * will be called for the data being deleted. If @p hash or @p data
 * are @c NULL, the functions returns immediately #EINA_FALSE. This
 * function returns #EINA_FALSE if an error occurred, #EINA_TRUE
 * otherwise.
 *
 * @note if you already have the key, use eina_hash_del_by_key() or eina_hash_del_by_key_hash() instead.
 */
EAPI Eina_Bool eina_hash_del_by_data(Eina_Hash * hash, const void *data)
{
	Eina_Hash_Element *hash_element;
	Eina_Hash_Head *hash_head;
	int key_hash;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(data, EINA_FALSE);
	EINA_MAGIC_CHECK_HASH(hash);

	hash_element =
	    _eina_hash_find_by_data(hash, data, &key_hash, &hash_head);
	if (!hash_element)
		goto error;

	if (hash_element->tuple.data != data)
		goto error;

	return _eina_hash_del_by_hash_el(hash, hash_element, hash_head,
					 key_hash);

      error:
	return EINA_FALSE;
}

/**
 * @brief Remove the entry identified by a key and a key hash or a
 * data from the given hash table.
 *
 * If @p key is @c NULL, then @p data is used to find a match to
 * remove.
 *
 * @param hash The given hash table.
 * @param key The key.
 * @param key_length The length of the key.
 * @param key_hash The hash that always match the key.
 * @param data The data pointer to remove if the key is @c NULL.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * This function removes the entry identified by @p key and
 * @p key_hash, or @p data, from @p hash. If a free function was given to
 * the  callback on creation, it will be called for the data being
 * deleted. If @p hash is @c NULL, the functions returns immediately
 * #EINA_FALSE. If @p key is @c NULL, then @p key_hash and @p key_hash
 * are ignored and @p data is used to find a match to remove,
 * otherwise @p key and @p key_hash are used and @p data is not
 * required and can be @c NULL. Do not forget to count '\\0' for
 * string when setting the value of @p key_length. This function
 * returns #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * @note if you know you already have the key, use eina_hash_del_by_key_hash(),
 *       if you know you don't have the key, use eina_hash_del_by_data()
 *       directly.
 */
EAPI Eina_Bool
eina_hash_del_by_hash(Eina_Hash * hash,
		      const void *key,
		      int key_length, int key_hash, const void *data)
{
	Eina_Bool ret;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_MAGIC_CHECK_HASH(hash);

	if (key)
		ret =
		    _eina_hash_del_by_key_hash(hash, key, key_length,
					       key_hash, data);
	else
		ret = eina_hash_del_by_data(hash, data);

	return ret;
}

/**
 * @brief Remove the entry identified by a key or a data from the given
 * hash table.
 *
 * @param hash The given hash table.
 * @param key  The key.
 * @param data The data pointer to remove if the key is @c NULL.
 * @return #EINA_FALSE if an error occurred, #EINA_TRUE otherwise.
 *
 * This function removes the entry identified by @p key or @p data
 * from @p hash. If a free function was given to the
 * callback on creation, it will be called for the data being
 * deleted. If @p hash is @c NULL, the functions returns immediately
 * #EINA_FALSE. If @p key is @c NULL, then @p data is used to find the a
 * match to remove, otherwise @p key is used and @p data is not
 * required and can be @c NULL. This function returns #EINA_FALSE if
 * an error occurred, #EINA_TRUE otherwise.
 *
 * @note if you know you already have the key, use
 *       eina_hash_del_by_key() or eina_hash_del_by_key_hash(). If you
 *       know you don't have the key, use eina_hash_del_by_data()
 *       directly.
 */
EAPI Eina_Bool
eina_hash_del(Eina_Hash * hash, const void *key, const void *data)
{
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_MAGIC_CHECK_HASH(hash);

	if (!key)
		return eina_hash_del_by_data(hash, data);

	return _eina_hash_del_by_key(hash, key, data);
}

/**
 * @brief Retrieve a specific entry in the given hash table.
 *
 * @param hash The given hash table.
 * @param key The key of the entry to find.
 * @param key_length The length of the key.
 * @param key_hash The hash that always match the key
 * @return The data pointer for the stored entry on success, @c NULL
 * otherwise.
 *
 * This function retrieves the entry associated to @p key of length
 * @p key_length in @p hash. @p key_hash is the hash that always match
 * @p key. It is ignored if @p key is @c NULL. Do not forget to count
 * '\\0' for string when setting the value of @p key_length. If
 * @p hash is @c NULL, this function returns immediately @c NULL. This
 * function returns the data pointer on success, @c NULL otherwise.
 */
EAPI void *eina_hash_find_by_hash(const Eina_Hash * hash,
				  const void *key,
				  int key_length, int key_hash)
{
	Eina_Hash_Head *hash_head;
	Eina_Hash_Element *hash_element;
	Eina_Hash_Tuple tuple;

	if (!hash)
		return NULL;

	EINA_SAFETY_ON_NULL_RETURN_VAL(key, NULL);
	EINA_MAGIC_CHECK_HASH(hash);

	tuple.key = key;
	tuple.key_length = key_length;
	tuple.data = NULL;

	hash_element =
	    _eina_hash_find_by_hash(hash, &tuple, key_hash, &hash_head);
	if (hash_element)
		return hash_element->tuple.data;

	return NULL;
}

/**
 * @brief Retrieve a specific entry in the given hash table.
 *
 * @param hash The given hash table.
 * @param key The key of the entry to find.
 * @return The data pointer for the stored entry on success, @c NULL
 * otherwise.
 *
 * This function retrieves the entry associated to @p key in
 * @p hash. If @p hash is @c NULL, this function returns immediately
 * @c NULL. This function returns the data pointer on success, @c NULL
 * otherwise.
 */
EAPI void *eina_hash_find(const Eina_Hash * hash, const void *key)
{
	int key_length;
	int hash_num;

	if (!hash)
		return NULL;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash->key_hash_cb, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, NULL);
	EINA_MAGIC_CHECK_HASH(hash);

	key_length = hash->key_length_cb ? hash->key_length_cb(key) : 0;
	hash_num = hash->key_hash_cb(key, key_length);

	return eina_hash_find_by_hash(hash, key, key_length, hash_num);
}

/**
 * @brief Modify the entry pointer at the specified key and returns
 * the old entry.
 *
 * @param hash The given hash table.
 * @param key The key of the entry to modify.
 * @param key_length Should be the length of @p key (don't forget to count '\\0' for string).
 * @param key_hash The hash that always match the key. Ignored if @p key is @c NULL.
 * @param data The data to replace the old entry, if it exists.
 * @return The data pointer for the old stored entry, or @c NULL if not
 *          found. If an existing entry is not found, nothing is added to the
 *          hash.
 */
EAPI void *eina_hash_modify_by_hash(Eina_Hash * hash,
				    const void *key,
				    int key_length,
				    int key_hash, const void *data)
{
	Eina_Hash_Head *hash_head;
	Eina_Hash_Element *hash_element;
	void *old_data = NULL;
	Eina_Hash_Tuple tuple;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(data, NULL);
	EINA_MAGIC_CHECK_HASH(hash);

	tuple.key = key;
	tuple.key_length = key_length;
	tuple.data = NULL;

	hash_element =
	    _eina_hash_find_by_hash(hash, &tuple, key_hash, &hash_head);
	if (hash_element) {
		old_data = hash_element->tuple.data;
		hash_element->tuple.data = (void *) data;
	}

	return old_data;
}

/**
 * @brief Modify the entry pointer at the specified key and return the
 * old entry or add the entry if not found.
 *
 * @param hash The given hash table.
 * @param key The key of the entry to modify.
 * @param data The data to replace the old entry
 * @return The data pointer for the old stored entry, or @c NULL
 * otherwise.
 *
 * This function modifies the data of @p key with @p data in @p
 * hash. If no entry is found, @p data is added to @p hash with the
 * key @p key. On success this function returns the old entry,
 * otherwise it returns @c NULL. To check for errors, use
 * eina_error_get().
 */
EAPI void *eina_hash_set(Eina_Hash * hash, const void *key,
			 const void *data)
{
	Eina_Hash_Tuple tuple;
	Eina_Hash_Head *hash_head;
	Eina_Hash_Element *hash_element;
	int key_length;
	int key_hash;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash->key_hash_cb, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(data, NULL);
	EINA_MAGIC_CHECK_HASH(hash);

	key_length = hash->key_length_cb ? hash->key_length_cb(key) : 0;
	key_hash = hash->key_hash_cb(key, key_length);

	tuple.key = key;
	tuple.key_length = key_length;
	tuple.data = NULL;

	hash_element =
	    _eina_hash_find_by_hash(hash, &tuple, key_hash, &hash_head);
	if (hash_element) {
		void *old_data = NULL;

		old_data = hash_element->tuple.data;
		hash_element->tuple.data = (void *) data;
		return old_data;
	}

	eina_hash_add_alloc_by_hash(hash,
				    key,
				    key_length,
				    key_length, key_hash, data);
	return NULL;
}

/**
 * @brief Modify the entry pointer at the specified key and return the old entry.
 * @param hash The given hash table.
 * @param key The key of the entry to modify.
 * @param data The data to replace the old entry.
 * @return The data pointer for the old stored entry on success, or
 * @c NULL otherwise.
 *
 * This function modifies the data of @p key with @p data in @p
 * hash. If no entry is found, nothing is added to @p hash. On success
 * this function returns the old entry, otherwise it returns @c NULL.
 */
EAPI void *eina_hash_modify(Eina_Hash * hash, const void *key,
			    const void *data)
{
	int key_length;
	int hash_num;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash->key_hash_cb, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(key, NULL);
	EINA_SAFETY_ON_NULL_RETURN_VAL(data, NULL);
	EINA_MAGIC_CHECK_HASH(hash);

	key_length = hash->key_length_cb ? hash->key_length_cb(key) : 0;
	hash_num = hash->key_hash_cb(key, key_length);

	return eina_hash_modify_by_hash(hash, key, key_length, hash_num,
					data);
}

/**
 * @brief Change the key associated with a data without triggering the
 * free callback.
 *
 * @param hash    The given hash table.
 * @param old_key The current key associated with the data
 * @param new_key The new key to associate data with
 * @return EINA_FALSE in any case but success, EINA_TRUE on success.
 *
 * This function allows for the move of data from one key to another,
 * but does not call the Eina_Free_Cb associated with the hash table
 * when destroying the old key.
 */
EAPI Eina_Bool
eina_hash_move(Eina_Hash * hash, const void *old_key, const void *new_key)
{
	Eina_Free_Cb hash_free_cb;
	const void *data;
	Eina_Bool result = EINA_FALSE;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(hash->key_hash_cb, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(old_key, EINA_FALSE);
	EINA_SAFETY_ON_NULL_RETURN_VAL(new_key, EINA_FALSE);
	EINA_MAGIC_CHECK_HASH(hash);

	data = eina_hash_find(hash, old_key);
	if (!data)
		goto error;

	hash_free_cb = hash->data_free_cb;
	hash->data_free_cb = NULL;

	eina_hash_del(hash, old_key, data);
	result = eina_hash_add(hash, new_key, data);

	hash->data_free_cb = hash_free_cb;

      error:
	return result;
}

/*============================================================================*
*                                Iterator                                    *
*============================================================================*/

/**
 * @brief Call a function on every member stored in the hash table
 *
 * @param hash The hash table whose members will be walked
 * @param func The function to call on each parameter
 * @param fdata The data pointer to pass to the function being called
 *
 * This function goes through every entry in the hash table @p hash and calls
 * the function @p func on each member. The function should @b not modify the
 * hash table contents if it returns 1. @b If the hash table contents are
 * modified by this function or the function wishes to stop processing it must
 * return 0, otherwise return 1 to keep processing.
 *
 * Example:
 * @code
 * extern Eina_Hash *hash;
 *
 * Eina_Bool hash_fn(const Eina_Hash *hash, const void *key, void *data, void *fdata)
 * {
 *   printf("Func data: %s, Hash entry: %s / %p\n", fdata, (const char *)key, data);
 *   return 1;
 * }
 *
 * int main(int argc, char **argv)
 * {
 *   char *hash_fn_data;
 *
 *   hash_fn_data = strdup("Hello World");
 *   eina_hash_foreach(hash, hash_fn, hash_fn_data);
 *   free(hash_fn_data);
 * }
 * @endcode
 */
EAPI void
eina_hash_foreach(const Eina_Hash * hash,
		  Eina_Hash_Foreach func, const void *fdata)
{
	Eina_Iterator *it;
	Eina_Hash_Foreach_Data foreach;

	EINA_MAGIC_CHECK_HASH(hash);
	EINA_SAFETY_ON_NULL_RETURN(hash);
	EINA_SAFETY_ON_NULL_RETURN(func);

	foreach.cb = func;
	foreach.fdata = fdata;

	it = eina_hash_iterator_tuple_new(hash);
	if (!it)
		return;
	eina_iterator_foreach(it, EINA_EACH_CB(_eina_foreach_cb),
			      &foreach);

	eina_iterator_free(it);
}

/**
 * @brief Returned a new iterator associated to hash data.
 *
 * @param hash The hash.
 * @return A new iterator.
 *
 * This function returns a newly allocated iterator associated to
 * @p hash. If @p hash is not populated, this function still returns a
 * valid iterator that will always return false on
 * eina_iterator_next(), thus keeping API sane.
 *
 * If the memory can not be allocated, @c NULL is returned and
 * #EINA_ERROR_OUT_OF_MEMORY is set. Otherwise, a valid iterator is
 * returned.
 *
 * @warning if the hash structure changes then the iterator becomes
 * invalid. That is, if you add or remove items this iterator behavior
 * is undefined and your program may crash.
 */
EAPI Eina_Iterator *eina_hash_iterator_data_new(const Eina_Hash * hash)
{
	Eina_Iterator_Hash *it;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, NULL);
	EINA_MAGIC_CHECK_HASH(hash);

	eina_error_set(0);
	it = calloc(1, sizeof(Eina_Iterator_Hash));
	if (!it) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	it->hash = hash;
	it->get_content =
	    FUNC_ITERATOR_GET_CONTENT
	    (_eina_hash_iterator_data_get_content);

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next = FUNC_ITERATOR_NEXT(_eina_hash_iterator_next);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER(_eina_hash_iterator_get_container);
	it->iterator.free = FUNC_ITERATOR_FREE(_eina_hash_iterator_free);

	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);
	EINA_MAGIC_SET(it, EINA_MAGIC_HASH_ITERATOR);

	return &it->iterator;
}

/**
 * @brief Returned a new iterator associated to hash keys.
 *
 * @param hash The hash.
 * @return A new iterator.
 *
 * This function returns a newly allocated iterator associated to @p
 * hash. If @p hash is not populated, this function still returns a
 * valid iterator that will always return false on
 * eina_iterator_next(), thus keeping API sane.
 *
 * If the memory can not be allocated, NULL is returned and
 * #EINA_ERROR_OUT_OF_MEMORY is set. Otherwise, a valid iterator is
 * returned.
 *
 * @warning if the hash structure changes then the iterator becomes
 *    invalid! That is, if you add or remove items this iterator
 *    behavior is undefined and your program may crash!
 */
EAPI Eina_Iterator *eina_hash_iterator_key_new(const Eina_Hash * hash)
{
	Eina_Iterator_Hash *it;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, NULL);
	EINA_MAGIC_CHECK_HASH(hash);

	eina_error_set(0);
	it = calloc(1, sizeof(Eina_Iterator_Hash));
	if (!it) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	it->hash = hash;
	it->get_content =
	    FUNC_ITERATOR_GET_CONTENT(_eina_hash_iterator_key_get_content);

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next = FUNC_ITERATOR_NEXT(_eina_hash_iterator_next);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER(_eina_hash_iterator_get_container);
	it->iterator.free = FUNC_ITERATOR_FREE(_eina_hash_iterator_free);

	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);
	EINA_MAGIC_SET(it, EINA_MAGIC_HASH_ITERATOR);

	return &it->iterator;
}

/**
 * @brief Returned a new iterator associated to hash keys and data.
 *
 * @param hash The hash.
 * @return A new iterator.
 *
 * This function returns a newly allocated iterator associated to @p
 * hash. If @p hash is not populated, this function still returns a
 * valid iterator that will always return false on
 * eina_iterator_next(), thus keeping API sane.
 *
 * If the memory can not be allocated, NULL is returned and
 * #EINA_ERROR_OUT_OF_MEMORY is set. Otherwise, a valid iterator is
 * returned.
 *
 * @note iterator data will provide values as Eina_Hash_Tuple that should not
 *   be modified!
 *
 * @warning if the hash structure changes then the iterator becomes
 *    invalid! That is, if you add or remove items this iterator
 *    behavior is undefined and your program may crash!
 */
EAPI Eina_Iterator *eina_hash_iterator_tuple_new(const Eina_Hash * hash)
{
	Eina_Iterator_Hash *it;

	EINA_SAFETY_ON_NULL_RETURN_VAL(hash, NULL);
	EINA_MAGIC_CHECK_HASH(hash);

	eina_error_set(0);
	it = calloc(1, sizeof(Eina_Iterator_Hash));
	if (!it) {
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	it->hash = hash;
	it->get_content =
	    FUNC_ITERATOR_GET_CONTENT
	    (_eina_hash_iterator_tuple_get_content);

	it->iterator.version = EINA_ITERATOR_VERSION;
	it->iterator.next = FUNC_ITERATOR_NEXT(_eina_hash_iterator_next);
	it->iterator.get_container =
	    FUNC_ITERATOR_GET_CONTAINER(_eina_hash_iterator_get_container);
	it->iterator.free = FUNC_ITERATOR_FREE(_eina_hash_iterator_free);

	EINA_MAGIC_SET(&it->iterator, EINA_MAGIC_ITERATOR);
	EINA_MAGIC_SET(it, EINA_MAGIC_HASH_ITERATOR);

	return &it->iterator;
}

/* Common hash functions */

/* Paul Hsieh (http://www.azillionmonkeys.com/qed/hash.html)
   used by WebCore (http://webkit.org/blog/8/hashtables-part-2/) */
EAPI int eina_hash_superfast(const char *key, int len)
{
	unsigned hash = len;
	int tmp;
	int rem;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
	for (; len > 0; len--) {
		hash += get16bits(key);
		tmp = (get16bits(key + 2) << 11) ^ hash;
		hash = (hash << 16) ^ tmp;
		key += 2 * sizeof(uint16_t);
		hash += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
	case 3:
		hash += get16bits(key);
		hash ^= hash << 16;
		hash ^= key[sizeof(uint16_t)] << 18;
		hash += hash >> 11;
		break;

	case 2:
		hash += get16bits(key);
		hash ^= hash << 11;
		hash += hash >> 17;
		break;

	case 1:
		hash += *key;
		hash ^= hash << 10;
		hash += hash >> 1;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

/**
 * @}
 * @}
 */
