/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "gnutls_int.h"
#include "algorithms.h"
#include "errors.h"
#include "x509/common.h"
#include "pk.h"
#include "c-strcase.h"

/* Supported ECC curves
 */

static const gnutls_group_entry_st supported_groups[] = {
	{
		.name = "SECP192R1",
		.id = GNUTLS_GROUP_SECP192R1,
		.curve = GNUTLS_ECC_CURVE_SECP192R1,
		.tls_id = 19,
		.pk = GNUTLS_PK_ECDSA,
	},
	{
		.name = "SECP224R1",
		.id = GNUTLS_GROUP_SECP224R1,
		.curve = GNUTLS_ECC_CURVE_SECP224R1,
		.tls_id = 21,
		.pk = GNUTLS_PK_ECDSA,
	},
	{
		.name = "SECP256R1",
		.id = GNUTLS_GROUP_SECP256R1,
		.curve = GNUTLS_ECC_CURVE_SECP256R1,
		.tls_id = 23,
		.pk = GNUTLS_PK_ECDSA,
	},
	{
		.name = "SECP384R1",
		.id = GNUTLS_GROUP_SECP384R1,
		.curve = GNUTLS_ECC_CURVE_SECP384R1,
		.tls_id = 24,
		.pk = GNUTLS_PK_ECDSA,
	},
	{
		.name = "SECP521R1",
		.id = GNUTLS_GROUP_SECP521R1,
		.curve = GNUTLS_ECC_CURVE_SECP521R1,
		.tls_id = 25,
		.pk = GNUTLS_PK_ECDSA,
	},
	{
		.name = "X25519",
		.id = GNUTLS_GROUP_X25519,
		.curve = GNUTLS_ECC_CURVE_X25519,
		.tls_id = 29,
		.pk = GNUTLS_PK_ECDH_X25519,
	},
#ifdef ENABLE_GOST
	/* draft-smyshlyaev-tls12-gost-suites-06, Section 6 */
	{
		.name = "GC256A",
		.id = GNUTLS_GROUP_GC256A,
		.curve = GNUTLS_ECC_CURVE_GOST256A,
		.pk = GNUTLS_PK_GOST_12_256,
		.tls_id = 34,
	},
	{
		.name = "GC256B",
		.id = GNUTLS_GROUP_GC256B,
		.curve = GNUTLS_ECC_CURVE_GOST256B,
		.pk = GNUTLS_PK_GOST_12_256,
		.tls_id = 35,
	},
	{
		.name = "GC256C",
		.id = GNUTLS_GROUP_GC256C,
		.curve = GNUTLS_ECC_CURVE_GOST256C,
		.pk = GNUTLS_PK_GOST_12_256,
		.tls_id = 36,
	},
	{
		.name = "GC256D",
		.id = GNUTLS_GROUP_GC256D,
		.curve = GNUTLS_ECC_CURVE_GOST256D,
		.pk = GNUTLS_PK_GOST_12_256,
		.tls_id = 37,
	},
	{
		.name = "GC512A",
		.id = GNUTLS_GROUP_GC512A,
		.curve = GNUTLS_ECC_CURVE_GOST512A,
		.pk = GNUTLS_PK_GOST_12_512,
		.tls_id = 38,
	},
	{
		.name = "GC512B",
		.id = GNUTLS_GROUP_GC512B,
		.curve = GNUTLS_ECC_CURVE_GOST512B,
		.pk = GNUTLS_PK_GOST_12_512,
		.tls_id = 39,
	},
	{
		.name = "GC512C",
		.id = GNUTLS_GROUP_GC512C,
		.curve = GNUTLS_ECC_CURVE_GOST512C,
		.pk = GNUTLS_PK_GOST_12_512,
		.tls_id = 40,
	},
#endif
	{ .name = "X448",
	  .id = GNUTLS_GROUP_X448,
	  .curve = GNUTLS_ECC_CURVE_X448,
	  .tls_id = 30,
	  .pk = GNUTLS_PK_ECDH_X448 },
#ifdef ENABLE_DHE
	{ .name = "FFDHE2048",
	  .id = GNUTLS_GROUP_FFDHE2048,
	  .generator = &gnutls_ffdhe_2048_group_generator,
	  .prime = &gnutls_ffdhe_2048_group_prime,
	  .q = &gnutls_ffdhe_2048_group_q,
	  .q_bits = &gnutls_ffdhe_2048_key_bits,
	  .pk = GNUTLS_PK_DH,
	  .tls_id = 0x100 },
	{ .name = "FFDHE3072",
	  .id = GNUTLS_GROUP_FFDHE3072,
	  .generator = &gnutls_ffdhe_3072_group_generator,
	  .prime = &gnutls_ffdhe_3072_group_prime,
	  .q = &gnutls_ffdhe_3072_group_q,
	  .q_bits = &gnutls_ffdhe_3072_key_bits,
	  .pk = GNUTLS_PK_DH,
	  .tls_id = 0x101 },
	{ .name = "FFDHE4096",
	  .id = GNUTLS_GROUP_FFDHE4096,
	  .generator = &gnutls_ffdhe_4096_group_generator,
	  .prime = &gnutls_ffdhe_4096_group_prime,
	  .q = &gnutls_ffdhe_4096_group_q,
	  .q_bits = &gnutls_ffdhe_4096_key_bits,
	  .pk = GNUTLS_PK_DH,
	  .tls_id = 0x102 },
	{ .name = "FFDHE6144",
	  .id = GNUTLS_GROUP_FFDHE6144,
	  .generator = &gnutls_ffdhe_6144_group_generator,
	  .prime = &gnutls_ffdhe_6144_group_prime,
	  .q = &gnutls_ffdhe_6144_group_q,
	  .q_bits = &gnutls_ffdhe_6144_key_bits,
	  .pk = GNUTLS_PK_DH,
	  .tls_id = 0x103 },
	{ .name = "FFDHE8192",
	  .id = GNUTLS_GROUP_FFDHE8192,
	  .generator = &gnutls_ffdhe_8192_group_generator,
	  .prime = &gnutls_ffdhe_8192_group_prime,
	  .q = &gnutls_ffdhe_8192_group_q,
	  .q_bits = &gnutls_ffdhe_8192_key_bits,
	  .pk = GNUTLS_PK_DH,
	  .tls_id = 0x104 },
#endif
#ifdef HAVE_LEANCRYPTO
	{
		.name = "MLKEM768",
		.id = GNUTLS_GROUP_EXP_MLKEM768,
		.pk = GNUTLS_PK_MLKEM768,
		.pubkey_size = MLKEM768_PUBKEY_SIZE,
		.ciphertext_size = MLKEM768_CIPHERTEXT_SIZE,
		/* absense of .tls_id means that this group alone cannot be used in TLS */
	},
	{
		.name = "MLKEM1024",
		.id = GNUTLS_GROUP_EXP_MLKEM1024,
		.pk = GNUTLS_PK_MLKEM1024,
		.pubkey_size = MLKEM1024_PUBKEY_SIZE,
		.ciphertext_size = MLKEM1024_CIPHERTEXT_SIZE,
		/* absense of .tls_id means that this group alone cannot be used in TLS */
	},
#endif
#ifdef HAVE_LEANCRYPTO
	{ .name = "SECP256R1-MLKEM768",
	  .id = GNUTLS_GROUP_EXP_SECP256R1_MLKEM768,
	  .ids = { GNUTLS_GROUP_SECP256R1, GNUTLS_GROUP_EXP_MLKEM768,
		   GNUTLS_GROUP_INVALID },
	  .tls_id = 0x11EB },
	{ .name = "SECP384R1-MLKEM1024",
	  .id = GNUTLS_GROUP_EXP_SECP384R1_MLKEM1024,
	  .ids = { GNUTLS_GROUP_SECP384R1, GNUTLS_GROUP_EXP_MLKEM1024,
		   GNUTLS_GROUP_INVALID },
	  .tls_id = 0x11ED },
	{ .name = "X25519-MLKEM768",
	  .id = GNUTLS_GROUP_EXP_X25519_MLKEM768,
	  .ids = { GNUTLS_GROUP_EXP_MLKEM768, GNUTLS_GROUP_X25519,
		   GNUTLS_GROUP_INVALID },
	  .tls_id = 0x11EC },
#endif
	{ 0, 0, 0 }
};

#define GNUTLS_GROUP_LOOP(b)                                       \
	{                                                          \
		const gnutls_group_entry_st *p;                    \
		for (p = supported_groups; p->name != NULL; p++) { \
			b;                                         \
		}                                                  \
	}

static inline const gnutls_group_entry_st *group_to_entry(gnutls_group_t group)
{
	if (group == 0)
		return NULL;

	GNUTLS_GROUP_LOOP(if (p->id == group) { return p; });

	return NULL;
}

static inline bool
group_is_supported_standalone(const gnutls_group_entry_st *group)
{
	return group->pk != 0 && _gnutls_pk_exists(group->pk) &&
	       (group->curve == 0 ||
		_gnutls_ecc_curve_is_supported(group->curve));
}

static inline bool group_is_supported(const gnutls_group_entry_st *group)
{
	if (!IS_GROUP_HYBRID(group))
		return group_is_supported_standalone(group);

	for (size_t i = 0;
	     i < MAX_HYBRID_GROUPS && group->ids[i] != GNUTLS_GROUP_INVALID;
	     i++) {
		const gnutls_group_entry_st *p = group_to_entry(group->ids[i]);
		if (!p || !group_is_supported_standalone(p))
			return false;
	}

	return true;
}

/* Returns the TLS id of the given curve
 */
const gnutls_group_entry_st *_gnutls_tls_id_to_group(unsigned num)
{
	GNUTLS_GROUP_LOOP(
		if (p->tls_id == num && group_is_supported(p)) { return p; });

	return NULL;
}

const gnutls_group_entry_st *_gnutls_id_to_group(unsigned id)
{
	if (id == 0)
		return NULL;

	GNUTLS_GROUP_LOOP(
		if (p->id == id && group_is_supported(p)) { return p; });

	return NULL;
}

/**
 * gnutls_group_list:
 *
 * Get the list of supported elliptic curves.
 *
 * This function is not thread safe.
 *
 * Returns: Return a (0)-terminated list of #gnutls_group_t
 *   integers indicating the available groups.
 *
 * Since: 3.6.0
 **/
const gnutls_group_t *gnutls_group_list(void)
{
	static gnutls_group_t groups[MAX_ALGOS + 1] = { 0 };

	if (groups[0] == 0) {
		size_t i = 0;

		for (const gnutls_group_entry_st *p = supported_groups;
		     p->name != NULL; p++) {
			if (group_is_supported(p))
				groups[i++] = p->id;
		}
		groups[i++] = GNUTLS_GROUP_INVALID;
	}

	return groups;
}

/**
 * gnutls_group_get_id:
 * @name: is a group name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: return a #gnutls_group_t value corresponding to
 *   the specified group, or %GNUTLS_GROUP_INVALID on error.
 *
 * Since: 3.6.0
 **/
gnutls_group_t gnutls_group_get_id(const char *name)
{
	gnutls_group_t ret = GNUTLS_GROUP_INVALID;

	GNUTLS_GROUP_LOOP(if (c_strcasecmp(p->name, name) == 0 &&
			      (p->curve == 0 ||
			       _gnutls_ecc_curve_is_supported(p->curve))) {
		ret = p->id;
		break;
	});

	return ret;
}

/* Similar to gnutls_group_get_id, except that it does not check if
 * the curve is supported.
 */
gnutls_group_t _gnutls_group_get_id(const char *name)
{
	gnutls_group_t ret = GNUTLS_GROUP_INVALID;

	GNUTLS_GROUP_LOOP(if (c_strcasecmp(p->name, name) == 0) {
		ret = p->id;
		break;
	});

	return ret;
}

/**
 * gnutls_group_get_name:
 * @group: is an element from %gnutls_group_t
 *
 * Convert a #gnutls_group_t value to a string.
 *
 * Returns: a string that contains the name of the specified
 *   group or %NULL.
 *
 * Since: 3.6.0
 **/
const char *gnutls_group_get_name(gnutls_group_t group)
{
	GNUTLS_GROUP_LOOP(if (p->id == group) { return p->name; });

	return NULL;
}

/* Expand GROUP into hybrid SUBGROUPS if any, otherwise an array
 * containing the GROUP itself. The result will be written to
 * SUBGROUPS, which will be NUL-terminated.
 */
int _gnutls_group_expand(
	const gnutls_group_entry_st *group,
	const gnutls_group_entry_st *subgroups[MAX_HYBRID_GROUPS + 1])
{
	size_t pos = 0;

	if (IS_GROUP_HYBRID(group)) {
		for (size_t i = 0; i < MAX_HYBRID_GROUPS &&
				   group->ids[i] != GNUTLS_GROUP_INVALID;
		     i++) {
			const gnutls_group_entry_st *p =
				group_to_entry(group->ids[i]);
			/* This shouldn't happen, as GROUP is assumed
			 * to be supported before calling this
			 * function. */
			if (unlikely(!p))
				return gnutls_assert_val(
					GNUTLS_E_INTERNAL_ERROR);
			subgroups[pos++] = p;
		}
	} else {
		subgroups[pos++] = group;
	}
	subgroups[pos] = NULL;
	return 0;
}
