/* EINA - EFL data type library
 * Copyright (C) 2002,2003,2004,2005,2006,2007,2008,2010
 *                         Carsten Haitzler,
 *                         Jorge Luis Zapata Muga,
 *                         Cedric Bail,
 *                         Gustavo Sverzut Barbieri
 *                         Tom Hacohen
 *                         Brett Nash
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
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * Copyright (C) 2008 Peter Wehrfritz
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies of the Software and its Copyright notices. In addition publicly
 *  documented acknowledgment must be given that this software has been used if no
 *  source code of this software is made available publicly. This includes
 *  acknowledgments in either Copyright notices, Manuals, Publicity and Marketing
 *  documents or any documentation provided with any product containing this
 *  software. This License does not apply to any software that links to the
 *  libraries provided by this software (statically or dynamically), but only to
 *  the software provided.
 *
 *  Please see the OLD-COPYING.PLAIN for a plain-english explanation of this notice
 *  and it's intent.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 *  THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 *  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#ifdef EFL_HAVE_POSIX_THREADS
#include <pthread.h>
#endif

#ifdef HAVE_EVIL
#include <Evil.h>
#endif

#include "eina_config.h"
#include "eina_private.h"
#include "eina_hash.h"
#include "eina_rbtree.h"
#include "eina_error.h"
#include "eina_log.h"

/* undefs EINA_ARG_NONULL() so NULL checks are not compiled out! */
#include "eina_safety_checks.h"
#include "eina_share_common.h"

/*============================================================================*
*                                  Local                                     *
*============================================================================*/

/**
 * @cond LOCAL
 */

#define EINA_SHARE_COMMON_BUCKETS 256
#define EINA_SHARE_COMMON_MASK 0xFF

static const char EINA_MAGIC_SHARE_STR[] = "Eina Share";
static const char EINA_MAGIC_SHARE_HEAD_STR[] = "Eina Share Head";


#define EINA_MAGIC_CHECK_SHARE_COMMON_HEAD(d, unlock, ...)      \
   do {                                                          \
        if (!EINA_MAGIC_CHECK((d), EINA_MAGIC_SHARE_HEAD))  \
          {                                                           \
             EINA_MAGIC_FAIL((d), EINA_MAGIC_SHARE_HEAD);    \
             unlock;                                                 \
             return __VA_ARGS__;                                     \
          }                                                           \
     } while (0)

#define EINA_MAGIC_CHECK_SHARE_COMMON_NODE(d, _node_magic, unlock)              \
   do {                                                          \
        if (!EINA_MAGIC_CHECK((d), _node_magic))    \
          {                                                           \
             unlock;                                                   \
             EINA_MAGIC_FAIL((d), _node_magic);        \
          }                                                           \
     } while (0)

#ifdef EINA_SHARE_USAGE
typedef struct _Eina_Share_Common_Population Eina_Share_Common_Population;
#endif

typedef struct _Eina_Share_Common Eina_Share_Common;
typedef struct _Eina_Share_Common_Node Eina_Share_Common_Node;
typedef struct _Eina_Share_Common_Head Eina_Share_Common_Head;

int _eina_share_common_log_dom = -1;

struct _Eina_Share {
	Eina_Share_Common *share;
	Eina_Magic node_magic;
#ifdef EINA_SHARE_COMMON_USAGE
	Eina_Share_Common_Population population;
	int max_node_population;
#endif
};

struct _Eina_Share_Common {
	Eina_Share_Common_Head *buckets[EINA_SHARE_COMMON_BUCKETS];

 EINA_MAGIC};

struct _Eina_Share_Common_Node {
	Eina_Share_Common_Node *next;

	 EINA_MAGIC unsigned int length;
	unsigned int references;
	char str[];
};

struct _Eina_Share_Common_Head {
	EINA_RBTREE;
	EINA_MAGIC int hash;

#ifdef EINA_SHARE_COMMON_USAGE
	int population;
#endif

	Eina_Share_Common_Node *head;
	Eina_Share_Common_Node builtin_node;
};

#ifdef EFL_HAVE_THREADS
Eina_Bool _share_common_threads_activated = EINA_FALSE;

#ifdef EFL_HAVE_POSIX_THREADS
static pthread_mutex_t _mutex_big = PTHREAD_MUTEX_INITIALIZER;
#define SHARE_COMMON_LOCK_BIG() if(_share_common_threads_activated) \
      pthread_mutex_lock(&_mutex_big)
#define SHARE_COMMON_UNLOCK_BIG() if(_share_common_threads_activated) \
      pthread_mutex_unlock(&_mutex_big)
#else				/* EFL_HAVE_WIN32_THREADS */
static HANDLE _mutex_big = NULL;
#define SHARE_COMMON_LOCK_BIG() if(_share_common_threads_activated) \
      WaitForSingleObject(_mutex_big, INFINITE)
#define SHARE_COMMON_UNLOCK_BIG() if(_share_common_threads_activated) \
      ReleaseMutex(_mutex_big)

#endif				/* EFL_HAVE_WIN32_THREADS */
#else				/* EFL_HAVE_THREADS */
#define SHARE_COMMON_LOCK_BIG() do {} while (0)
#define SHARE_COMMON_UNLOCK_BIG() do {} while (0)
#endif

#ifdef EINA_SHARE_COMMON_USAGE
struct _Eina_Share_Common_Population {
	int count;
	int max;
};

static Eina_Share_Common_Population population = { 0, 0 };

static Eina_Share_Common_Population population_group[4] = {
	{0, 0},
	{0, 0},
	{0, 0},
	{0, 0}
};

static void _eina_share_common_population_init(Eina_Share * share)
{
	unsigned int i;

	for (i = 0;
	     i < sizeof(share->population_group) /
	     sizeof(share->population_group[0]); ++i) {
		share->population_group[i].count = 0;
		share->population_group[i].max = 0;
	}
}

static void _eina_share_common_population_shutdown(Eina_Share * share)
{
	unsigned int i;

	share->max_node_population = 0;
	share->population.count = 0;
	share->population.max = 0;

	for (i = 0;
	     i < sizeof(share->population_group) /
	     sizeof(share->population_group[0]); ++i) {
		share->population_group[i].count = 0;
		share->population_group[i].max = 0;
	}
}

static void _eina_share_common_population_stats(Eina_Share * share)
{
	unsigned int i;

	fprintf(stderr, "eina share_common statistic:\n");
	fprintf(stderr,
		" * maximum shared strings : %i\n", share->population.max);
	fprintf(stderr,
		" * maximum shared strings per node : %i\n",
		share->max_node_population);

	for (i = 0;
	     i < sizeof(share->population_group) /
	     sizeof(share->population_group[0]); ++i)
		fprintf(stderr,
			"DDD: %i strings of length %i, max strings: %i\n",
			share->population_group[i].count,
			i, share->population_group[i].max);
}

void eina_share_common_population_add(Eina_Share * share, int slen)
{
	SHARE_COMMON_LOCK_BIG();

	share->population.count++;
	if (share->population.count > share->population.max)
		share->population.max = share->population.count;

	if (slen < 4) {
		share->population_group[slen].count++;
		if (share->population_group[slen].count >
		    share->population_group[slen].max)
			share->population_group[slen].max =
			    share->population_group[slen].count;
	}

	SHARE_COMMON_UNLOCK_BIG();
}

void eina_share_common_population_del(Eina_Share * share, int slen)
{
	SHARE_COMMON_LOCK_BIG();

	share->population.count--;
	if (slen < 4)
		share->population_group[slen].count--;

	SHARE_COMMON_UNLOCK_BIG();
}

static void
_eina_share_common_population_head_init(Eina_Share * share,
					Eina_Share_Common_Head * head)
{
	head->population = 1;
}

static void
_eina_share_common_population_head_add(Eina_Share * share,
				       Eina_Share_Common_Head * head)
{
	head->population++;
	if (head->population > share->max_node_population)
		share->max_node_population = head->population;
}

static void
_eina_share_common_population_head_del(Eina_Share * share,
				       Eina_Share_Common_Head * head)
{
	head->population--;
}

#else				/* EINA_SHARE_COMMON_USAGE undefined */

static void _eina_share_common_population_init(__UNUSED__ Eina_Share *
					       share)
{
}

static void _eina_share_common_population_shutdown(__UNUSED__ Eina_Share *
						   share)
{
}

static void _eina_share_common_population_stats(__UNUSED__ Eina_Share *
						share)
{
}

void eina_share_common_population_add(__UNUSED__ Eina_Share * share,
				      __UNUSED__ int slen)
{
}

void eina_share_common_population_del(__UNUSED__ Eina_Share * share,
				      __UNUSED__ int slen)
{
}

static void _eina_share_common_population_head_init(__UNUSED__ Eina_Share *
						    share,
						    __UNUSED__
						    Eina_Share_Common_Head
						    * head)
{
}

static void _eina_share_common_population_head_add(__UNUSED__ Eina_Share *
						   share,
						   __UNUSED__
						   Eina_Share_Common_Head *
						   head)
{
}

static void _eina_share_common_population_head_del(__UNUSED__ Eina_Share *
						   share,
						   __UNUSED__
						   Eina_Share_Common_Head *
						   head)
{
}
#endif

static int
_eina_share_common_cmp(const Eina_Share_Common_Head * ed,
		       const int *hash,
		       __UNUSED__ int length, __UNUSED__ void *data)
{
	EINA_MAGIC_CHECK_SHARE_COMMON_HEAD(ed,, 0);

	return ed->hash - *hash;
}

static Eina_Rbtree_Direction
_eina_share_common_node(const Eina_Share_Common_Head * left,
			const Eina_Share_Common_Head * right,
			__UNUSED__ void *data)
{
	EINA_MAGIC_CHECK_SHARE_COMMON_HEAD(left,, 0);
	EINA_MAGIC_CHECK_SHARE_COMMON_HEAD(right,, 0);

	if (left->hash - right->hash < 0)
		return EINA_RBTREE_LEFT;

	return EINA_RBTREE_RIGHT;
}

static void
_eina_share_common_head_free(Eina_Share_Common_Head * ed,
			     __UNUSED__ void *data)
{
	EINA_MAGIC_CHECK_SHARE_COMMON_HEAD(ed,);

	while (ed->head) {
		Eina_Share_Common_Node *el = ed->head;

		ed->head = ed->head->next;
		if (el != &ed->builtin_node)
			MAGIC_FREE(el);
	}
	MAGIC_FREE(ed);
}

static void
_eina_share_common_node_init(Eina_Share_Common_Node * node,
			     const char *str,
			     int slen,
			     unsigned int null_size, Eina_Magic node_magic)
{
	EINA_MAGIC_SET(node, node_magic);
	node->references = 1;
	node->length = slen;
	memcpy(node->str, str, slen);
	memset(node->str + slen, 0, null_size);	/* Nullify the null */

	(void) node_magic;	/* When magic are disable, node_magic is unused, this remove a warning. */
}

static Eina_Share_Common_Head *_eina_share_common_head_alloc(int slen)
{
	Eina_Share_Common_Head *head;
	const size_t head_size =
	    offsetof(Eina_Share_Common_Head, builtin_node.str);

	head = malloc(head_size + slen);
	if (!head)
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);

	return head;
}

static const char *_eina_share_common_add_head(Eina_Share * share,
					       Eina_Share_Common_Head **
					       p_bucket, int hash,
					       const char *str,
					       unsigned int slen,
					       unsigned int null_size)
{
	Eina_Rbtree **p_tree = (Eina_Rbtree **) p_bucket;
	Eina_Share_Common_Head *head;

	head = _eina_share_common_head_alloc(slen + null_size);
	if (!head)
		return NULL;

	EINA_MAGIC_SET(head, EINA_MAGIC_SHARE_HEAD);
	head->hash = hash;
	head->head = &head->builtin_node;
	_eina_share_common_node_init(head->head,
				     str,
				     slen, null_size, share->node_magic);
	head->head->next = NULL;

	_eina_share_common_population_head_init(share, head);

	*p_tree = eina_rbtree_inline_insert
	    (*p_tree, EINA_RBTREE_GET(head),
	     EINA_RBTREE_CMP_NODE_CB(_eina_share_common_node), NULL);

	return head->head->str;
}

static void
_eina_share_common_del_head(Eina_Share_Common_Head ** p_bucket,
			    Eina_Share_Common_Head * head)
{
	Eina_Rbtree **p_tree = (Eina_Rbtree **) p_bucket;

	*p_tree = eina_rbtree_inline_remove
	    (*p_tree, EINA_RBTREE_GET(head),
	     EINA_RBTREE_CMP_NODE_CB(_eina_share_common_node), NULL);

	MAGIC_FREE(head);
}


static inline Eina_Bool
_eina_share_common_node_eq(const Eina_Share_Common_Node * node,
			   const char *str, unsigned int slen)
{
	return ((node->length == slen) &&
		(memcmp(node->str, str, slen) == 0));
}

static Eina_Share_Common_Node
    *_eina_share_common_head_find(Eina_Share_Common_Head * head,
				  const char *str, unsigned int slen)
{
	Eina_Share_Common_Node *node, *prev;

	node = head->head;
	if (_eina_share_common_node_eq(node, str, slen))
		return node;

	prev = node;
	node = node->next;
	for (; node; prev = node, node = node->next)
		if (_eina_share_common_node_eq(node, str, slen)) {
			/* promote node, make hot items be at the beginning */
			prev->next = node->next;
			node->next = head->head;
			head->head = node;
			return node;
		}

	return NULL;
}

static Eina_Bool
_eina_share_common_head_remove_node(Eina_Share_Common_Head * head,
				    const Eina_Share_Common_Node * node)
{
	Eina_Share_Common_Node *cur, *prev;

	if (head->head == node) {
		head->head = node->next;
		return 1;
	}

	prev = head->head;
	cur = head->head->next;
	for (; cur; prev = cur, cur = cur->next)
		if (cur == node) {
			prev->next = cur->next;
			return 1;
		}

	return 0;
}

static Eina_Share_Common_Head
    *_eina_share_common_find_hash(Eina_Share_Common_Head * bucket,
				  int hash)
{
	return (Eina_Share_Common_Head *) eina_rbtree_inline_lookup
	    (EINA_RBTREE_GET(bucket), &hash, 0,
	     EINA_RBTREE_CMP_KEY_CB(_eina_share_common_cmp), NULL);
}

static Eina_Share_Common_Node *_eina_share_common_node_alloc(unsigned int
							     slen,
							     unsigned int
							     null_size)
{
	Eina_Share_Common_Node *node;
	const size_t node_size = offsetof(Eina_Share_Common_Node, str);

	node = malloc(node_size + slen + null_size);
	if (!node)
		eina_error_set(EINA_ERROR_OUT_OF_MEMORY);

	return node;
}

static Eina_Share_Common_Node *_eina_share_common_node_from_str(const char
								*str,
								Eina_Magic
								node_magic)
{
	Eina_Share_Common_Node *node;
	const size_t offset = offsetof(Eina_Share_Common_Node, str);

	node = (Eina_Share_Common_Node *) (str - offset);
	EINA_MAGIC_CHECK_SHARE_COMMON_NODE(node, node_magic,);
	return node;

	(void) node_magic;	/* When magic are disable, node_magic is unused, this remove a warning. */
}

static Eina_Bool
eina_iterator_array_check(const Eina_Rbtree * rbtree __UNUSED__,
			  Eina_Share_Common_Head * head,
			  struct dumpinfo *fdata)
{
	Eina_Share_Common_Node *node;

	SHARE_COMMON_LOCK_BIG();

	fdata->used += sizeof(Eina_Share_Common_Head);
	for (node = head->head; node; node = node->next) {
		printf("DDD: %5i %5i ", node->length, node->references);
		printf("'%.*s'\n", node->length,
		       ((char *) node) + sizeof(Eina_Share_Common_Node));
		fdata->used += sizeof(Eina_Share_Common_Node);
		fdata->used += node->length;
		fdata->saved += (node->references - 1) * node->length;
		fdata->dups += node->references - 1;
		fdata->unique++;
	}

	SHARE_COMMON_UNLOCK_BIG();

	return EINA_TRUE;
}

/**
 * @endcond
 */


/*============================================================================*
*                                 Global                                     *
*============================================================================*/

/**
 * @internal
 * @brief Initialize the share_common module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function sets up the share_common module of Eina. It is called by
 * eina_init().
 *
 * @see eina_init()
 */
Eina_Bool
eina_share_common_init(Eina_Share ** _share,
		       Eina_Magic node_magic, const char *node_magic_STR)
{
	Eina_Share *share;
	share = *_share = calloc(sizeof(Eina_Share), 1);
	if (!share)
		return EINA_FALSE;

	if (_eina_share_common_log_dom < 0)	/*Only register if not already */
		_eina_share_common_log_dom =
		    eina_log_domain_register("eina_share",
					     EINA_LOG_COLOR_DEFAULT);

	if (_eina_share_common_log_dom < 0) {
		EINA_LOG_ERR
		    ("Could not register log domain: eina_share_common");
		return EINA_FALSE;
	}

	share->share = calloc(1, sizeof(Eina_Share_Common));
	if (!share->share) {
		if (_eina_share_common_log_dom > 0) {
			eina_log_domain_unregister
			    (_eina_share_common_log_dom);
			_eina_share_common_log_dom = -1;
		}

		return EINA_FALSE;
	}

	share->node_magic = node_magic;
#define EMS(n) eina_magic_string_static_set(n, n ## _STR)
	EMS(EINA_MAGIC_SHARE);
	EMS(EINA_MAGIC_SHARE_HEAD);
	EMS(node_magic);
#undef EMS
	EINA_MAGIC_SET(share->share, EINA_MAGIC_SHARE);

	_eina_share_common_population_init(share);
	return EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the share_common module.
 *
 * @return #EINA_TRUE on success, #EINA_FALSE on failure.
 *
 * This function shuts down the share_common module set up by
 * eina_share_common_init(). It is called by eina_shutdown().
 *
 * @see eina_shutdown()
 */
Eina_Bool eina_share_common_shutdown(Eina_Share ** _share)
{
	unsigned int i;
	Eina_Share *share = *_share;

	SHARE_COMMON_LOCK_BIG();

	_eina_share_common_population_stats(share);

	/* remove any string still in the table */
	for (i = 0; i < EINA_SHARE_COMMON_BUCKETS; i++) {
		eina_rbtree_delete(EINA_RBTREE_GET
				   (share->share->buckets[i]),
				   EINA_RBTREE_FREE_CB
				   (_eina_share_common_head_free), NULL);
		share->share->buckets[i] = NULL;
	}
	MAGIC_FREE(share->share);

	_eina_share_common_population_shutdown(share);
	if (_eina_share_common_log_dom > 0) {	/* Only free if necessary */
		eina_log_domain_unregister(_eina_share_common_log_dom);
		_eina_share_common_log_dom = -1;
	}

	SHARE_COMMON_UNLOCK_BIG();

	free(*_share);
	*_share = NULL;
	return EINA_TRUE;
}

#ifdef EFL_HAVE_THREADS

/**
 * @internal
 * @brief Activate the share_common mutexes.
 *
 * This function activate the mutexes in the eina share_common module. It is called by
 * eina_threads_init().
 *
 * @see eina_threads_init()
 */
void eina_share_common_threads_init(void)
{
	_share_common_threads_activated = EINA_TRUE;
}

/**
 * @internal
 * @brief Shut down the share_common mutexes.
 *
 * This function shuts down the mutexes in the share_common module.
 * It is called by eina_threads_shutdown().
 *
 * @see eina_threads_shutdown()
 */
void eina_share_common_threads_shutdown(void)
{
	_share_common_threads_activated = EINA_FALSE;
}

#endif

/*============================================================================*
*                                   API                                      *
*============================================================================*/

/**
 * @cond LOCAL
 */

const char *eina_share_common_add_length(Eina_Share * share,
					 const char *str,
					 unsigned int slen,
					 unsigned int null_size)
{
	Eina_Share_Common_Head **p_bucket, *ed;
	Eina_Share_Common_Node *el;
	int hash_num, hash;

	if (!str)
		return NULL;

	eina_share_common_population_add(share, slen);

	if (slen <= 0)
		return NULL;

	hash = eina_hash_superfast(str, slen);
	hash_num = hash & 0xFF;
	hash = (hash >> 8) & EINA_SHARE_COMMON_MASK;

	SHARE_COMMON_LOCK_BIG();
	p_bucket = share->share->buckets + hash_num;

	ed = _eina_share_common_find_hash(*p_bucket, hash);
	if (!ed) {
		const char *s = _eina_share_common_add_head(share,
							    p_bucket,
							    hash,
							    str,
							    slen,
							    null_size);
		SHARE_COMMON_UNLOCK_BIG();
		return s;
	}

	EINA_MAGIC_CHECK_SHARE_COMMON_HEAD(ed, SHARE_COMMON_UNLOCK_BIG(),
					   NULL);

	el = _eina_share_common_head_find(ed, str, slen);
	if (el) {
		EINA_MAGIC_CHECK_SHARE_COMMON_NODE(el,
						   share->node_magic,
						   SHARE_COMMON_UNLOCK_BIG
						   ());
		el->references++;
		SHARE_COMMON_UNLOCK_BIG();
		return el->str;
	}

	el = _eina_share_common_node_alloc(slen, null_size);
	if (!el) {
		SHARE_COMMON_UNLOCK_BIG();
		return NULL;
	}

	_eina_share_common_node_init(el, str, slen, null_size,
				     share->node_magic);
	el->next = ed->head;
	ed->head = el;
	_eina_share_common_population_head_add(share, ed);

	SHARE_COMMON_UNLOCK_BIG();

	return el->str;
}

const char *eina_share_common_ref(Eina_Share * share, const char *str)
{
	Eina_Share_Common_Node *node;

	if (!str)
		return NULL;

	SHARE_COMMON_LOCK_BIG();
	node = _eina_share_common_node_from_str(str, share->node_magic);
	node->references++;
	DBG("str=%p refs=%u", str, node->references);

	SHARE_COMMON_UNLOCK_BIG();

	eina_share_common_population_add(share, node->length);

	return str;
}


void eina_share_common_del(Eina_Share * share, const char *str)
{
	unsigned int slen;
	Eina_Share_Common_Head *ed;
	Eina_Share_Common_Head **p_bucket;
	Eina_Share_Common_Node *node;
	int hash_num, hash;

	if (!str)
		return;

	SHARE_COMMON_LOCK_BIG();

	node = _eina_share_common_node_from_str(str, share->node_magic);
	slen = node->length;
	eina_share_common_population_del(share, slen);
	if (node->references > 1) {
		node->references--;
		DBG("str=%p refs=%u", str, node->references);
		SHARE_COMMON_UNLOCK_BIG();
		return;
	}

	DBG("str=%p refs=0, delete.", str);
	node->references = 0;

	hash = eina_hash_superfast(str, slen);
	hash_num = hash & 0xFF;
	hash = (hash >> 8) & EINA_SHARE_COMMON_MASK;

	p_bucket = share->share->buckets + hash_num;
	ed = _eina_share_common_find_hash(*p_bucket, hash);
	if (!ed)
		goto on_error;

	EINA_MAGIC_CHECK_SHARE_COMMON_HEAD(ed, SHARE_COMMON_UNLOCK_BIG());

	if (!_eina_share_common_head_remove_node(ed, node))
		goto on_error;

	if (node != &ed->builtin_node)
		MAGIC_FREE(node);

	if (!ed->head)
		_eina_share_common_del_head(p_bucket, ed);
	else
		_eina_share_common_population_head_del(share, ed);

	SHARE_COMMON_UNLOCK_BIG();

	return;

      on_error:
	SHARE_COMMON_UNLOCK_BIG();
	/* possible segfault happened before here, but... */
	CRITICAL("EEEK trying to del non-shared share_common \"%s\"", str);
}

int
eina_share_common_length(__UNUSED__ Eina_Share * share, const char *str)
{
	const Eina_Share_Common_Node *node;

	if (!str)
		return -1;

	node = _eina_share_common_node_from_str(str, share->node_magic);
	return node->length;
}

void
eina_share_common_dump(Eina_Share * share,
		       void (*additional_dump) (struct dumpinfo *),
		       int used)
{
	Eina_Iterator *it;
	unsigned int i;
	struct dumpinfo di;

	if (!share)
		return;

	di.used = used;
	di.saved = 0;
	di.dups = 0;
	di.unique = 0;
	printf("DDD:   len   ref string\n");
	printf("DDD:-------------------\n");

	SHARE_COMMON_LOCK_BIG();
	for (i = 0; i < EINA_SHARE_COMMON_BUCKETS; i++) {
		if (!share->share->buckets[i]) {
			continue;	//       printf("DDD: BUCKET # %i (HEAD=%i, NODE=%i)\n", i,

		}
//             sizeof(Eina_Share_Common_Head), sizeof(Eina_Share_Common_Node));
		it = eina_rbtree_iterator_prefix((Eina_Rbtree *) share->
						 share->buckets[i]);
		eina_iterator_foreach(it,
				      EINA_EACH_CB
				      (eina_iterator_array_check), &di);
		eina_iterator_free(it);
	}
	if (additional_dump)
		additional_dump(&di);

#ifdef EINA_SHARE_COMMON_USAGE
	/* One character strings are not counted in the hash. */
	di.saved += share->population_group[0].count * sizeof(char);
	di.saved += share->population_group[1].count * sizeof(char) * 2;
#endif
	printf("DDD:-------------------\n");
	printf("DDD: usage (bytes) = %i, saved = %i (%3.0f%%)\n",
	       di.used, di.saved,
	       di.used ? (di.saved * 100.0 / di.used) : 0.0);
	printf("DDD: unique: %d, duplicates: %d (%3.0f%%)\n", di.unique,
	       di.dups, di.unique ? (di.dups * 100.0 / di.unique) : 0.0);

#ifdef EINA_SHARE_COMMON_USAGE
	printf("DDD: Allocated strings: %i\n", share->population.count);
	printf("DDD: Max allocated strings: %i\n", share->population.max);

	for (i = 0;
	     i < sizeof(share->population_group) /
	     sizeof(share->population_group[0]); ++i)
		fprintf(stderr,
			"DDD: %i strings of length %i, max strings: %i\n",
			share->population_group[i].count,
			i, share->population_group[i].max);
#endif

	SHARE_COMMON_UNLOCK_BIG();
}

/**
 * @endcond
 */
