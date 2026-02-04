/*
 * Copyright (C) 2014-2016 Free Software Foundation, Inc.
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Authors: Nikos Mavrogiannopoulos, Daiki Ueno, Martin Ukrop
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

/* Functions on X.509 Certificate parsing
 */

#include "gnutls_int.h"
#include "datum.h"
#include "global.h"
#include "errors.h"
#include "common.h"
#include "x509.h"
#include <gnutls/x509-ext.h>
#include "x509_b64.h"
#include "x509_int.h"
#include "x509_ext_int.h"
#include <libtasn1.h>

#include "ip.h"
#include "ip-in-cidr.h"
#include "intprops.h"
#include "minmax.h"

#include <string.h>

#define MAX_NC_CHECKS (1 << 20)

struct name_constraints_node_st {
	unsigned type;
	gnutls_datum_t name;
};

struct name_constraints_node_list_st {
	struct name_constraints_node_st **data;
	size_t size;
	size_t capacity;
	/* sorted-on-demand view, valid only when dirty == false */
	bool dirty;
	struct name_constraints_node_st **sorted_view;
};

struct gnutls_name_constraints_st {
	struct name_constraints_node_list_st nodes; /* owns elements */
	struct name_constraints_node_list_st permitted; /* borrows elements */
	struct name_constraints_node_list_st excluded; /* borrows elements */
};

static struct name_constraints_node_st *
name_constraints_node_new(gnutls_x509_name_constraints_t nc, unsigned type,
			  const unsigned char *data, unsigned int size);

/* An enum for "rich" comparisons that not only let us sort name constraints,
 * children-before-parent, but also subsume them during intersection. */
enum name_constraint_relation {
	NC_SORTS_BEFORE = -2, /* unrelated constraints */
	NC_INCLUDED_BY = -1, /* nc1 is included by nc2 / children sort first */
	NC_EQUAL = 0, /* exact match */
	NC_INCLUDES = 1, /* nc1 includes nc2 / parents sort last */
	NC_SORTS_AFTER = 2 /* unrelated constraints */
};

/* A helper to compare just a pair of strings with this rich comparison */
static enum name_constraint_relation
compare_strings(const void *n1, size_t n1_len, const void *n2, size_t n2_len)
{
	int r = memcmp(n1, n2, MIN(n1_len, n2_len));
	if (r < 0)
		return NC_SORTS_BEFORE;
	if (r > 0)
		return NC_SORTS_AFTER;
	if (n1_len < n2_len)
		return NC_SORTS_BEFORE;
	if (n1_len > n2_len)
		return NC_SORTS_AFTER;
	return NC_EQUAL;
}

/* Rich-compare DNS names. Example order/relationships:
 * z.x.a INCLUDED_BY x.a BEFORE y.a INCLUDED_BY a BEFORE x.b BEFORE y.b */
static enum name_constraint_relation compare_dns_names(const gnutls_datum_t *n1,
						       const gnutls_datum_t *n2)
{
	enum name_constraint_relation rel;
	unsigned int i, j, i_end, j_end;

	/* start from the end of each name */
	i = i_end = n1->size;
	j = j_end = n2->size;

	/* skip the trailing dots for the comparison */
	while (i && n1->data[i - 1] == '.')
		i_end = i = i - 1;
	while (j && n2->data[j - 1] == '.')
		j_end = j = j - 1;

	while (1) {
		// rewind back to beginning or an after-dot position
		while (i && n1->data[i - 1] != '.')
			i--;
		while (j && n2->data[j - 1] != '.')
			j--;

		rel = compare_strings(&n1->data[i], i_end - i, &n2->data[j],
				      j_end - j);
		if (rel == NC_SORTS_BEFORE) /* x.a BEFORE y.a */
			return NC_SORTS_BEFORE;
		if (rel == NC_SORTS_AFTER) /* y.a AFTER x.a */
			return NC_SORTS_AFTER;
		if (!i && j) /* x.a INCLUDES z.x.a */
			return NC_INCLUDES;
		if (i && !j) /* z.x.a INCLUDED_BY x.a */
			return NC_INCLUDED_BY;

		if (!i && !j) /* r == 0, we ran out of components to compare */
			return NC_EQUAL;
		/* r == 0, i && j: step back past a dot and keep comparing */
		i_end = i = i - 1;
		j_end = j = j - 1;

		/* support for non-standard ".gr INCLUDES example.gr" [1] */
		if (!i && j) /* .a INCLUDES x.a */
			return NC_INCLUDES;
		if (i && !j) /* x.a INCLUDED_BY .a */
			return NC_INCLUDED_BY;
	}
}
/* [1] https://mailarchive.ietf.org/arch/msg/saag/Bw6PtreW0G7aEG7SikfzKHES4VA */

/* Rich-compare email name constraints. Example order/relationships:
 * z@x.a INCLUDED_BY x.a BEFORE y.a INCLUDED_BY a BEFORE x@b BEFORE y@b */
static enum name_constraint_relation compare_emails(const gnutls_datum_t *n1,
						    const gnutls_datum_t *n2)
{
	enum name_constraint_relation domains_rel;
	unsigned int i, j, i_end, j_end;
	gnutls_datum_t d1, d2; /* borrow from n1 and n2 */

	/* start from the end of each name */
	i = i_end = n1->size;
	j = j_end = n2->size;

	/* rewind to @s to look for domains */
	while (i && n1->data[i - 1] != '@')
		i--;
	d1.size = i_end - i;
	d1.data = &n1->data[i];
	while (j && n2->data[j - 1] != '@')
		j--;
	d2.size = j_end - j;
	d2.data = &n2->data[j];

	domains_rel = compare_dns_names(&d1, &d2);

	/* email constraint semantics differ from DNS
	 * DNS: x.a INCLUDED_BY a
	 * Email: x.a INCLUDED_BY .a BEFORE a */
	if (domains_rel == NC_INCLUDED_BY || domains_rel == NC_INCLUDES) {
		bool d1_has_dot = (d1.size > 0 && d1.data[0] == '.');
		bool d2_has_dot = (d2.size > 0 && d2.data[0] == '.');
		/* a constraint without a dot is exact, excluding subdomains */
		if (!d2_has_dot && domains_rel == NC_INCLUDED_BY)
			domains_rel = NC_SORTS_BEFORE; /* x.a BEFORE a */
		if (!d1_has_dot && domains_rel == NC_INCLUDES)
			domains_rel = NC_SORTS_AFTER; /* a AFTER x.a */
	}

	if (!i && !j) { /* both are domains-only */
		return domains_rel;
	} else if (i && !j) { /* n1 is email, n2 is domain */
		switch (domains_rel) {
		case NC_SORTS_AFTER:
			return NC_SORTS_AFTER;
		case NC_SORTS_BEFORE:
			return NC_SORTS_BEFORE;
		case NC_INCLUDES: /* n2 is more specific, a@x.a AFTER z.x.a */
			return NC_SORTS_AFTER;
		case NC_EQUAL: /* subdomains match, z@x.a INCLUDED_BY x.a */
		case NC_INCLUDED_BY: /* n1 is more specific */
			return NC_INCLUDED_BY;
		}
	} else if (!i && j) { /* n1 is domain, n2 is email */
		switch (domains_rel) {
		case NC_SORTS_AFTER:
			return NC_SORTS_AFTER;
		case NC_SORTS_BEFORE:
			return NC_SORTS_BEFORE;
		case NC_INCLUDES: /* n2 is more specific, a AFTER z@x.a */
			return NC_SORTS_AFTER;
		case NC_EQUAL: /* subdomains match, x.a INCLUDES z@x.a */
			return NC_INCLUDES;
		case NC_INCLUDED_BY: /* n1 is more specific, x.a BEFORE z@a */
			return NC_SORTS_BEFORE;
		}
	} else if (i && j) { /* both are emails */
		switch (domains_rel) {
		case NC_SORTS_AFTER:
			return NC_SORTS_AFTER;
		case NC_SORTS_BEFORE:
			return NC_SORTS_BEFORE;
		case NC_INCLUDES: // n2 is more specific
			return NC_SORTS_AFTER;
		case NC_INCLUDED_BY: // n1 is more specific
			return NC_SORTS_BEFORE;
		case NC_EQUAL: // only case when we need to look before the @
			break; // see below for readability
		}
	}

	/* i && j, both are emails, domain names match, compare up to @ */
	return compare_strings(n1->data, i - 1, n2->data, j - 1);
}

/* Rich-compare IP address constraints. Example order/relationships:
 * 10.0.0.0/24 INCLUDED_BY 10.0.0.0/16 BEFORE 1::1/128 INCLUDED_BY 1::1/127 */
static enum name_constraint_relation compare_ip_ncs(const gnutls_datum_t *n1,
						    const gnutls_datum_t *n2)
{
	unsigned int len, i;
	int r;
	const unsigned char *ip1, *ip2, *mask1, *mask2;
	unsigned char masked11[16], masked22[16], masked12[16], masked21[16];

	if (n1->size < n2->size)
		return NC_SORTS_BEFORE;
	if (n1->size > n2->size)
		return NC_SORTS_AFTER;
	len = n1->size / 2; /* 4 for IPv4, 16 for IPv6 */

	/* data is a concatenation of prefix and mask */
	ip1 = n1->data;
	ip2 = n2->data;
	mask1 = n1->data + len;
	mask2 = n2->data + len;
	for (i = 0; i < len; i++) {
		masked11[i] = ip1[i] & mask1[i];
		masked22[i] = ip2[i] & mask2[i];
		masked12[i] = ip1[i] & mask2[i];
		masked21[i] = ip2[i] & mask1[i];
	}

	r = memcmp(mask1, mask2, len);
	if (r < 0 && !memcmp(masked11, masked21, len)) /* prefix1 < prefix2 */
		return NC_INCLUDES; /* ip1 & mask1 == ip2 & mask1 */
	if (r > 0 && !memcmp(masked12, masked22, len)) /* prefix1 > prefix2 */
		return NC_INCLUDED_BY; /* ip1 & mask2 == ip2 & mask2 */

	r = memcmp(masked11, masked22, len);
	if (r < 0)
		return NC_SORTS_BEFORE;
	else if (r > 0)
		return NC_SORTS_AFTER;
	return NC_EQUAL;
}

static inline bool is_supported_type(unsigned type)
{
	return type == GNUTLS_SAN_DNSNAME || type == GNUTLS_SAN_RFC822NAME ||
	       type == GNUTLS_SAN_IPADDRESS;
}

/* Universal comparison for name constraint nodes.
 * Unsupported types sort before supported types to allow early handling.
 * NULL represents end-of-list and sorts after everything else. */
static enum name_constraint_relation
compare_name_constraint_nodes(const struct name_constraints_node_st *n1,
			      const struct name_constraints_node_st *n2)
{
	bool n1_supported, n2_supported;

	if (!n1 && !n2)
		return NC_EQUAL;
	if (!n1)
		return NC_SORTS_AFTER;
	if (!n2)
		return NC_SORTS_BEFORE;

	n1_supported = is_supported_type(n1->type);
	n2_supported = is_supported_type(n2->type);

	/* unsupported types bubble up (sort first). intersect relies on this */
	if (!n1_supported && n2_supported)
		return NC_SORTS_BEFORE;
	if (n1_supported && !n2_supported)
		return NC_SORTS_AFTER;

	/* next, sort by type */
	if (n1->type < n2->type)
		return NC_SORTS_BEFORE;
	if (n1->type > n2->type)
		return NC_SORTS_AFTER;

	/* now look deeper */
	switch (n1->type) {
	case GNUTLS_SAN_DNSNAME:
		return compare_dns_names(&n1->name, &n2->name);
	case GNUTLS_SAN_RFC822NAME:
		return compare_emails(&n1->name, &n2->name);
	case GNUTLS_SAN_IPADDRESS:
		return compare_ip_ncs(&n1->name, &n2->name);
	default:
		/* unsupported types: stable lexicographic order */
		return compare_strings(n1->name.data, n1->name.size,
				       n2->name.data, n2->name.size);
	}
}

/* qsort-compatible wrapper */
static int compare_name_constraint_nodes_qsort(const void *a, const void *b)
{
	const struct name_constraints_node_st *const *n1 = a;
	const struct name_constraints_node_st *const *n2 = b;
	enum name_constraint_relation rel;

	rel = compare_name_constraint_nodes(*n1, *n2);
	switch (rel) {
	case NC_SORTS_BEFORE:
	case NC_INCLUDED_BY:
		return -1;
	case NC_SORTS_AFTER:
	case NC_INCLUDES:
		return 1;
	case NC_EQUAL:
	default:
		return 0;
	}
}

/* Bring the sorted view up to date with the list data; clear the dirty flag. */
static int ensure_sorted(struct name_constraints_node_list_st *list)
{
	struct name_constraints_node_st **new_data;

	if (!list->dirty)
		return GNUTLS_E_SUCCESS;
	if (!list->size) {
		list->dirty = false;
		return GNUTLS_E_SUCCESS;
	}

	/* reallocate sorted view to match current size */
	new_data =
		_gnutls_reallocarray(list->sorted_view, list->size,
				     sizeof(struct name_constraints_node_st *));
	if (!new_data)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	list->sorted_view = new_data;

	/* copy pointers and sort in-place */
	memcpy(list->sorted_view, list->data,
	       list->size * sizeof(struct name_constraints_node_st *));
	qsort(list->sorted_view, list->size,
	      sizeof(struct name_constraints_node_st *),
	      compare_name_constraint_nodes_qsort);

	list->dirty = false;
	return GNUTLS_E_SUCCESS;
}

static int
name_constraints_node_list_add(struct name_constraints_node_list_st *list,
			       struct name_constraints_node_st *node)
{
	if (!list->capacity || list->size == list->capacity) {
		size_t new_capacity = list->capacity;
		struct name_constraints_node_st **new_data;

		if (!INT_MULTIPLY_OK(new_capacity, 2, &new_capacity) ||
		    !INT_ADD_OK(new_capacity, 1, &new_capacity))
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
		new_data = _gnutls_reallocarray(
			list->data, new_capacity,
			sizeof(struct name_constraints_node_st *));
		if (!new_data)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		list->capacity = new_capacity;
		list->data = new_data;
	}
	list->dirty = true;
	list->data[list->size++] = node;
	return 0;
}

static void
name_constraints_node_list_clear(struct name_constraints_node_list_st *list)
{
	gnutls_free(list->data);
	gnutls_free(list->sorted_view);
	list->data = NULL;
	list->sorted_view = NULL;
	list->capacity = 0;
	list->size = 0;
	list->dirty = false;
}

static int
name_constraints_node_add_new(gnutls_x509_name_constraints_t nc,
			      struct name_constraints_node_list_st *list,
			      unsigned type, const unsigned char *data,
			      unsigned int size)
{
	struct name_constraints_node_st *node;
	int ret;
	node = name_constraints_node_new(nc, type, data, size);
	if (node == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	ret = name_constraints_node_list_add(list, node);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	return GNUTLS_E_SUCCESS;
}

static int
name_constraints_node_add_copy(gnutls_x509_name_constraints_t nc,
			       struct name_constraints_node_list_st *dest,
			       const struct name_constraints_node_st *src)
{
	if (!src)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	return name_constraints_node_add_new(nc, dest, src->type,
					     src->name.data, src->name.size);
}

// for documentation see the implementation
static int name_constraints_intersect_nodes(
	gnutls_x509_name_constraints_t nc,
	const struct name_constraints_node_st *node1,
	const struct name_constraints_node_st *node2,
	struct name_constraints_node_st **intersection);

/*-
 * _gnutls_x509_name_constraints_is_empty:
 * @nc: name constraints structure
 * @type: type (gnutls_x509_subject_alt_name_t or 0)
 *
 * Test whether given name constraints structure has any constraints (permitted
 * or excluded) of a given type. @nc must be allocated (not NULL) before the call.
 * If @type is 0, type checking will be skipped.
 *
 * Returns: false if @nc contains constraints of type @type, true otherwise
 -*/
bool _gnutls_x509_name_constraints_is_empty(gnutls_x509_name_constraints_t nc,
					    unsigned type)
{
	if (nc->permitted.size == 0 && nc->excluded.size == 0)
		return true;

	if (type == 0)
		return false;

	for (size_t i = 0; i < nc->permitted.size; i++) {
		if (nc->permitted.data[i]->type == type)
			return false;
	}

	for (size_t i = 0; i < nc->excluded.size; i++) {
		if (nc->excluded.data[i]->type == type)
			return false;
	}

	/* no constraint for that type exists */
	return true;
}

/*-
 * validate_name_constraints_node:
 * @type: type of name constraints
 * @name: datum of name constraint
 *
 * Check the validity of given name constraints node (@type and @name).
 * The supported types are GNUTLS_SAN_DNSNAME, GNUTLS_SAN_RFC822NAME,
 * GNUTLS_SAN_DN, GNUTLS_SAN_URI and GNUTLS_SAN_IPADDRESS.
 *
 * CIDR ranges are checked for correct length (IPv4/IPv6) and correct mask format.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 -*/
static int validate_name_constraints_node(gnutls_x509_subject_alt_name_t type,
					  const gnutls_datum_t *name)
{
	if (type != GNUTLS_SAN_DNSNAME && type != GNUTLS_SAN_RFC822NAME &&
	    type != GNUTLS_SAN_DN && type != GNUTLS_SAN_URI &&
	    type != GNUTLS_SAN_IPADDRESS &&
	    type != GNUTLS_SAN_OTHERNAME_MSUSERPRINCIPAL) {
		return gnutls_assert_val(GNUTLS_E_X509_UNKNOWN_SAN);
	}

	if (type == GNUTLS_SAN_IPADDRESS) {
		if (name->size != 8 && name->size != 32)
			return gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
		int prefix = _gnutls_mask_to_prefix(name->data + name->size / 2,
						    name->size / 2);
		if (prefix < 0)
			return gnutls_assert_val(GNUTLS_E_MALFORMED_CIDR);
	}

	/* Validate DNS names and email addresses for malformed input */
	if (type == GNUTLS_SAN_DNSNAME || type == GNUTLS_SAN_RFC822NAME) {
		unsigned int i;
		if (name->size == 0)
			return GNUTLS_E_SUCCESS;

		/* reject names with consecutive dots... */
		for (i = 0; i + 1 < name->size; i++) {
			if (name->data[i] == '.' && name->data[i + 1] == '.')
				return gnutls_assert_val(
					GNUTLS_E_ILLEGAL_PARAMETER);
		}
		/* ... or names consisting exclusively of dots */
		if (name->size == 1 && name->data[0] == '.')
			return gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
	}

	return GNUTLS_E_SUCCESS;
}

static int extract_name_constraints(gnutls_x509_name_constraints_t nc,
				    asn1_node c2, const char *vstr,
				    struct name_constraints_node_list_st *nodes)
{
	int ret;
	char tmpstr[128];
	unsigned indx;
	gnutls_datum_t tmp = { NULL, 0 };
	unsigned int type;

	for (indx = 1;; indx++) {
		snprintf(tmpstr, sizeof(tmpstr), "%s.?%u.base", vstr, indx);

		ret = _gnutls_parse_general_name2(c2, tmpstr, -1, &tmp, &type,
						  0);

		if (ret < 0) {
			gnutls_assert();
			break;
		}

		if (type == GNUTLS_SAN_OTHERNAME) {
			gnutls_datum_t oid = { NULL, 0 };
			gnutls_datum_t parsed_othername = { NULL, 0 };
			ret = _gnutls_parse_general_name2(c2, tmpstr, -1, &oid,
							  &type, 1);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}

			ret = gnutls_x509_othername_to_virtual(
				(char *)oid.data, &tmp, &type,
				&parsed_othername);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}

			gnutls_free(oid.data);
			gnutls_free(tmp.data);

			memcpy(&tmp, &parsed_othername, sizeof(gnutls_datum_t));
		}

		ret = validate_name_constraints_node(type, &tmp);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = name_constraints_node_add_new(nc, nodes, type, tmp.data,
						    tmp.size);
		_gnutls_free_datum(&tmp);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}

	assert(ret < 0);
	if (ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
cleanup:
	gnutls_free(tmp.data);
	return ret;
}

int _gnutls_x509_name_constraints_extract(asn1_node c2,
					  const char *permitted_name,
					  const char *excluded_name,
					  gnutls_x509_name_constraints_t nc)
{
	int ret;

	ret = extract_name_constraints(nc, c2, permitted_name, &nc->permitted);
	if (ret < 0)
		return gnutls_assert_val(ret);
	ret = extract_name_constraints(nc, c2, excluded_name, &nc->excluded);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return ret;
}

/*-
 * name_constraints_node_free:
 * @node: name constraints node
 *
 * Deallocate a name constraints node.
 -*/
static void name_constraints_node_free(struct name_constraints_node_st *node)
{
	if (node) {
		gnutls_free(node->name.data);
		gnutls_free(node);
	}
}

/*-
 * name_constraints_node_new:
 * @type: name constraints type to set (gnutls_x509_subject_alt_name_t)
 * @nc: a %gnutls_x509_name_constraints_t
 * @data: name.data to set or NULL
 * @size: name.size to set
 *
 * Allocate a new name constraints node and set its type, name size and name data.
 *
 * Returns: Pointer to newly allocated node or NULL in case of memory error.
 -*/
static struct name_constraints_node_st *
name_constraints_node_new(gnutls_x509_name_constraints_t nc, unsigned type,
			  const unsigned char *data, unsigned int size)
{
	struct name_constraints_node_st *tmp;
	int ret;

	tmp = gnutls_calloc(1, sizeof(struct name_constraints_node_st));
	if (tmp == NULL)
		return NULL;
	tmp->type = type;

	if (data) {
		ret = _gnutls_set_strdatum(&tmp->name, data, size);
		if (ret < 0) {
			gnutls_assert();
			gnutls_free(tmp);
			return NULL;
		}
	}

	ret = name_constraints_node_list_add(&nc->nodes, tmp);
	if (ret < 0) {
		gnutls_assert();
		name_constraints_node_free(tmp);
		return NULL;
	}

	return tmp;
}

/*-
 * @brief name_constraints_node_list_intersect:
 * @nc: %gnutls_x509_name_constraints_t
 * @permitted: first name constraints list (permitted)
 * @permitted2: name constraints list to merge with (permitted)
 * @excluded: Corresponding excluded name constraints list
 *
 * This function finds the intersection of @permitted and @permitted2. The result is placed in @permitted,
 * the original @permitted is modified. @permitted2 is not changed. If necessary, a universal
 * excluded name constraint node of the right type is added to the list provided
 * in @excluded.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 -*/
static int name_constraints_node_list_intersect(
	gnutls_x509_name_constraints_t nc,
	struct name_constraints_node_list_st *permitted,
	const struct name_constraints_node_list_st *permitted2,
	struct name_constraints_node_list_st *excluded)
{
	struct name_constraints_node_st *tmp;
	int ret, type, used;
	struct name_constraints_node_list_st removed = { .data = NULL,
							 .size = 0,
							 .capacity = 0 };
	static const unsigned char universal_ip[32] = { 0 };

	/* temporary array to see, if we need to add universal excluded constraints
	 * (see phase 3 for details)
	 * indexed directly by (gnutls_x509_subject_alt_name_t enum - 1) */
	unsigned char types_with_empty_intersection[GNUTLS_SAN_MAX];
	memset(types_with_empty_intersection, 0,
	       sizeof(types_with_empty_intersection));

	if (permitted->size == 0 || permitted2->size == 0)
		return 0;

	/* Phase 1
	 * For each name in PERMITTED, if a PERMITTED2 does not contain a name
	 * with the same type, move the original name to REMOVED.
	 * Do this also for node of unknown type (not DNS, email, IP) */
	for (size_t i = 0; i < permitted->size;) {
		struct name_constraints_node_st *t = permitted->data[i];
		const struct name_constraints_node_st *found = NULL;

		for (size_t j = 0; j < permitted2->size; j++) {
			const struct name_constraints_node_st *t2 =
				permitted2->data[j];
			if (t->type == t2->type) {
				// check bounds (we will use 't->type' as index)
				if (t->type > GNUTLS_SAN_MAX || t->type == 0) {
					gnutls_assert();
					ret = GNUTLS_E_INTERNAL_ERROR;
					goto cleanup;
				}
				// note the possibility of empty intersection for this type
				// if we add something to the intersection in phase 2,
				// we will reset this flag back to 0 then
				types_with_empty_intersection[t->type - 1] = 1;
				found = t2;
				break;
			}
		}

		if (found != NULL && is_supported_type(t->type)) {
			/* move node from PERMITTED to REMOVED */
			ret = name_constraints_node_list_add(&removed, t);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}
			/* remove node by swapping */
			if (i < permitted->size - 1)
				permitted->data[i] =
					permitted->data[permitted->size - 1];
			permitted->size--;
			permitted->dirty = true;
			continue;
		}
		i++;
	}

	/* Phase 2
	 * iterate through all combinations from PERMITTED2 and PERMITTED
	 * and create intersections of nodes with same type */
	for (size_t i = 0; i < permitted2->size; i++) {
		const struct name_constraints_node_st *t2 = permitted2->data[i];

		// current PERMITTED2 node has not yet been used for any intersection
		// (and is not in REMOVED either)
		used = 0;
		for (size_t j = 0; j < removed.size; j++) {
			const struct name_constraints_node_st *t =
				removed.data[j];
			// save intersection of name constraints into tmp
			ret = name_constraints_intersect_nodes(nc, t, t2, &tmp);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}

			if (t->type == t2->type)
				used = 1;

			// if intersection is not empty
			if (tmp !=
			    NULL) { // intersection for this type is not empty
				// check bounds
				if (tmp->type > GNUTLS_SAN_MAX ||
				    tmp->type == 0) {
					gnutls_free(tmp);
					return gnutls_assert_val(
						GNUTLS_E_INTERNAL_ERROR);
				}
				// we will not add universal excluded constraint for this type
				types_with_empty_intersection[tmp->type - 1] =
					0;
				// add intersection node to PERMITTED
				ret = name_constraints_node_list_add(permitted,
								     tmp);
				if (ret < 0) {
					gnutls_assert();
					goto cleanup;
				}
			}
		}
		// if the node from PERMITTED2 was not used for intersection, copy it to DEST
		// Beware: also copies nodes other than DNS, email, IP,
		//       since their counterpart may have been moved in phase 1.
		if (!used) {
			ret = name_constraints_node_add_copy(nc, permitted, t2);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}
		}
	}

	/* Phase 3
	 * For each type: If we have empty permitted name constraints now
	 * and we didn't have at the beginning, we have to add a new
	 * excluded constraint with universal wildcard
	 * (since the intersection of permitted is now empty). */
	for (type = 1; type <= GNUTLS_SAN_MAX; type++) {
		if (types_with_empty_intersection[type - 1] == 0)
			continue;
		_gnutls_hard_log(
			"Adding universal excluded name constraint for type %d.\n",
			type);
		switch (type) {
		case GNUTLS_SAN_IPADDRESS:
			// add universal restricted range for IPv4
			ret = name_constraints_node_add_new(
				nc, excluded, GNUTLS_SAN_IPADDRESS,
				universal_ip, 8);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}
			// add universal restricted range for IPv6
			ret = name_constraints_node_add_new(
				nc, excluded, GNUTLS_SAN_IPADDRESS,
				universal_ip, 32);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}
			break;
		case GNUTLS_SAN_DNSNAME:
		case GNUTLS_SAN_RFC822NAME:
			ret = name_constraints_node_add_new(nc, excluded, type,
							    NULL, 0);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}
			break;
		default: // do nothing, at least one node was already moved in phase 1
			break;
		}
	}
	ret = GNUTLS_E_SUCCESS;

cleanup:
	gnutls_free(removed.data);
	return ret;
}

static int name_constraints_node_list_concat(
	gnutls_x509_name_constraints_t nc,
	struct name_constraints_node_list_st *nodes,
	const struct name_constraints_node_list_st *nodes2)
{
	int ret;

	for (size_t i = 0; i < nodes2->size; i++) {
		ret = name_constraints_node_add_copy(nc, nodes,
						     nodes2->data[i]);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}
	}

	return 0;
}

/**
 * gnutls_x509_crt_get_name_constraints:
 * @crt: should contain a #gnutls_x509_crt_t type
 * @nc: The nameconstraints intermediate type
 * @flags: zero or %GNUTLS_EXT_FLAG_APPEND
 * @critical: the extension status
 *
 * This function will return an intermediate type containing
 * the name constraints of the provided CA certificate. That
 * structure can be used in combination with gnutls_x509_name_constraints_check()
 * to verify whether a server's name is in accordance with the constraints.
 *
 * When the @flags is set to %GNUTLS_EXT_FLAG_APPEND,
 * then if the @nc structure is empty this function will behave
 * identically as if the flag was not set.
 * Otherwise if there are elements in the @nc structure then the
 * constraints will be merged with the existing constraints following
 * RFC5280 p6.1.4 (excluded constraints will be appended, permitted
 * will be intersected).
 *
 * Note that @nc must be initialized prior to calling this function.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_crt_get_name_constraints(gnutls_x509_crt_t crt,
					 gnutls_x509_name_constraints_t nc,
					 unsigned int flags,
					 unsigned int *critical)
{
	int ret;
	gnutls_datum_t der = { NULL, 0 };

	if (crt == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	ret = _gnutls_x509_crt_get_extension(crt, "2.5.29.30", 0, &der,
					     critical);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (der.size == 0 || der.data == NULL)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	ret = gnutls_x509_ext_import_name_constraints(&der, nc, flags);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

cleanup:
	_gnutls_free_datum(&der);

	return ret;
}

void _gnutls_x509_name_constraints_clear(gnutls_x509_name_constraints_t nc)
{
	for (size_t i = 0; i < nc->nodes.size; i++) {
		struct name_constraints_node_st *node = nc->nodes.data[i];
		name_constraints_node_free(node);
	}
	name_constraints_node_list_clear(&nc->nodes);
	name_constraints_node_list_clear(&nc->permitted);
	name_constraints_node_list_clear(&nc->excluded);
}

/**
 * gnutls_x509_name_constraints_deinit:
 * @nc: The nameconstraints
 *
 * This function will deinitialize a name constraints type.
 *
 * Since: 3.3.0
 **/
void gnutls_x509_name_constraints_deinit(gnutls_x509_name_constraints_t nc)
{
	_gnutls_x509_name_constraints_clear(nc);
	gnutls_free(nc);
}

/**
 * gnutls_x509_name_constraints_init:
 * @nc: The nameconstraints
 *
 * This function will initialize a name constraints type.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_name_constraints_init(gnutls_x509_name_constraints_t *nc)
{
	struct gnutls_name_constraints_st *tmp;

	tmp = gnutls_calloc(1, sizeof(struct gnutls_name_constraints_st));
	if (tmp == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	*nc = tmp;
	return 0;
}

static int name_constraints_add(gnutls_x509_name_constraints_t nc,
				gnutls_x509_subject_alt_name_t type,
				const gnutls_datum_t *name, unsigned permitted)
{
	struct name_constraints_node_list_st *nodes;
	int ret;

	ret = validate_name_constraints_node(type, name);
	if (ret < 0)
		return gnutls_assert_val(ret);

	nodes = permitted ? &nc->permitted : &nc->excluded;

	ret = name_constraints_node_add_new(nc, nodes, type, name->data,
					    name->size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 0;
}

/*-
 * _gnutls_x509_name_constraints_merge:
 * @nc: The nameconstraints
 * @nc2: The name constraints to be merged with
 *
 * This function will merge the provided name constraints structures
 * as per RFC5280 p6.1.4. That is, the excluded constraints will be appended,
 * and permitted will be intersected. The intersection assumes that @nc
 * is the root CA constraints.
 *
 * The merged constraints will be placed in @nc.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.5.0
 -*/
int _gnutls_x509_name_constraints_merge(gnutls_x509_name_constraints_t nc,
					gnutls_x509_name_constraints_t nc2)
{
	int ret;

	ret = name_constraints_node_list_intersect(
		nc, &nc->permitted, &nc2->permitted, &nc->excluded);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = name_constraints_node_list_concat(nc, &nc->excluded,
						&nc2->excluded);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/**
 * gnutls_x509_name_constraints_add_permitted:
 * @nc: The nameconstraints
 * @type: The type of the constraints
 * @name: The data of the constraints
 *
 * This function will add a name constraint to the list of permitted
 * constraints. The constraints @type can be any of the following types:
 * %GNUTLS_SAN_DNSNAME, %GNUTLS_SAN_RFC822NAME, %GNUTLS_SAN_DN,
 * %GNUTLS_SAN_URI, %GNUTLS_SAN_IPADDRESS. For the latter, an IP address
 * in network byte order is expected, followed by its network mask.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_name_constraints_add_permitted(
	gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type,
	const gnutls_datum_t *name)
{
	return name_constraints_add(nc, type, name, 1);
}

/**
 * gnutls_x509_name_constraints_add_excluded:
 * @nc: The nameconstraints
 * @type: The type of the constraints
 * @name: The data of the constraints
 *
 * This function will add a name constraint to the list of excluded
 * constraints. The constraints @type can be any of the following types:
 * %GNUTLS_SAN_DNSNAME, %GNUTLS_SAN_RFC822NAME, %GNUTLS_SAN_DN,
 * %GNUTLS_SAN_URI, %GNUTLS_SAN_IPADDRESS. For the latter, an IP address
 * in network byte order is expected, followed by its network mask (which is
 * 4 bytes in IPv4 or 16-bytes in IPv6).
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_name_constraints_add_excluded(
	gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type,
	const gnutls_datum_t *name)
{
	return name_constraints_add(nc, type, name, 0);
}

/**
 * gnutls_x509_crt_set_name_constraints:
 * @crt: The certificate
 * @nc: The nameconstraints structure
 * @critical: whether this extension will be critical
 *
 * This function will set the provided name constraints to
 * the certificate extension list. This extension is always
 * marked as critical.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_crt_set_name_constraints(gnutls_x509_crt_t crt,
					 gnutls_x509_name_constraints_t nc,
					 unsigned int critical)
{
	int ret;
	gnutls_datum_t der;

	ret = gnutls_x509_ext_export_name_constraints(nc, &der);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _gnutls_x509_crt_set_extension(crt, "2.5.29.30", &der, critical);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
	crt->use_extensions = 1;

cleanup:
	_gnutls_free_datum(&der);
	return ret;
}

static unsigned dnsname_matches(const gnutls_datum_t *name,
				const gnutls_datum_t *suffix)
{
	_gnutls_hard_log("matching %.*s with DNS constraint %.*s\n", name->size,
			 name->data, suffix->size, suffix->data);

	enum name_constraint_relation rel = compare_dns_names(name, suffix);
	return rel == NC_EQUAL || rel == NC_INCLUDED_BY;
}

static unsigned email_matches(const gnutls_datum_t *name,
			      const gnutls_datum_t *suffix)
{
	_gnutls_hard_log("matching %.*s with e-mail constraint %.*s\n",
			 name->size, name->data, suffix->size, suffix->data);

	enum name_constraint_relation rel = compare_emails(name, suffix);
	return rel == NC_EQUAL || rel == NC_INCLUDED_BY;
}

/*-
 * name_constraints_intersect_nodes:
 * @nc1: name constraints node 1
 * @nc2: name constraints node 2
 * @_intersection: newly allocated node with intersected constraints,
 *		 NULL if the intersection is empty
 *
 * Inspect 2 name constraints nodes (of possibly different types) and allocate
 * a new node with intersection of given constraints.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 -*/
static int name_constraints_intersect_nodes(
	gnutls_x509_name_constraints_t nc,
	const struct name_constraints_node_st *node1,
	const struct name_constraints_node_st *node2,
	struct name_constraints_node_st **_intersection)
{
	// presume empty intersection
	struct name_constraints_node_st *intersection = NULL;
	const struct name_constraints_node_st *to_copy = NULL;
	enum name_constraint_relation rel;

	*_intersection = NULL;

	if (node1->type != node2->type) {
		return GNUTLS_E_SUCCESS;
	}
	switch (node1->type) {
	case GNUTLS_SAN_DNSNAME:
		rel = compare_dns_names(&node1->name, &node2->name);
		switch (rel) {
		case NC_EQUAL: // equal means doesn't matter which one
		case NC_INCLUDES: // node2 is more specific
			to_copy = node2;
			break;
		case NC_INCLUDED_BY: // node1 is more specific
			to_copy = node1;
			break;
		case NC_SORTS_BEFORE: // no intersection
		case NC_SORTS_AFTER: // no intersection
			return GNUTLS_E_SUCCESS;
		}
		break;
	case GNUTLS_SAN_RFC822NAME:
		rel = compare_emails(&node1->name, &node2->name);
		switch (rel) {
		case NC_EQUAL: // equal means doesn't matter which one
		case NC_INCLUDES: // node2 is more specific
			to_copy = node2;
			break;
		case NC_INCLUDED_BY: // node1 is more specific
			to_copy = node1;
			break;
		case NC_SORTS_BEFORE: // no intersection
		case NC_SORTS_AFTER: // no intersection
			return GNUTLS_E_SUCCESS;
		}
		break;
	case GNUTLS_SAN_IPADDRESS:
		rel = compare_ip_ncs(&node1->name, &node2->name);
		switch (rel) {
		case NC_EQUAL: // equal means doesn't matter which one
		case NC_INCLUDES: // node2 is more specific
			to_copy = node2;
			break;
		case NC_INCLUDED_BY: // node1 is more specific
			to_copy = node1;
			break;
		case NC_SORTS_BEFORE: // no intersection
		case NC_SORTS_AFTER: // no intersection
			return GNUTLS_E_SUCCESS;
		}
		break;
	default:
		// for other types, we don't know how to do the intersection, assume empty
		return GNUTLS_E_SUCCESS;
	}

	// copy existing node if applicable
	if (to_copy != NULL) {
		*_intersection = name_constraints_node_new(nc, to_copy->type,
							   to_copy->name.data,
							   to_copy->name.size);
		if (*_intersection == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		intersection = *_intersection;

		assert(intersection->name.data != NULL);
	}

	return GNUTLS_E_SUCCESS;
}

/*
 * Returns: true if the certification is acceptable, and false otherwise.
 */
static unsigned
check_unsupported_constraint(gnutls_x509_name_constraints_t nc,
			     gnutls_x509_subject_alt_name_t type)
{
	unsigned i;
	int ret;
	unsigned rtype;
	gnutls_datum_t rname;

	/* check if there is a restrictions with that type, if
	 * yes, then reject the name.
	 */
	i = 0;
	do {
		ret = gnutls_x509_name_constraints_get_excluded(nc, i++, &rtype,
								&rname);
		if (ret >= 0) {
			if (rtype != type)
				continue;
			else
				return gnutls_assert_val(0);
		}

	} while (ret == 0);

	return 1;
}

static unsigned check_dns_constraints(gnutls_x509_name_constraints_t nc,
				      const gnutls_datum_t *name)
{
	unsigned i;
	int ret;
	unsigned rtype;
	unsigned allowed_found = 0;
	gnutls_datum_t rname;

	/* check restrictions */
	i = 0;
	do {
		ret = gnutls_x509_name_constraints_get_excluded(nc, i++, &rtype,
								&rname);
		if (ret >= 0) {
			if (rtype != GNUTLS_SAN_DNSNAME)
				continue;

			/* a name of value 0 means that the CA shouldn't have issued
			 * a certificate with a DNSNAME. */
			if (rname.size == 0)
				return gnutls_assert_val(0);

			if (dnsname_matches(name, &rname) != 0)
				return gnutls_assert_val(0); /* rejected */
		}
	} while (ret == 0);

	/* check allowed */
	i = 0;
	do {
		ret = gnutls_x509_name_constraints_get_permitted(
			nc, i++, &rtype, &rname);
		if (ret >= 0) {
			if (rtype != GNUTLS_SAN_DNSNAME)
				continue;

			if (rname.size == 0)
				continue;

			allowed_found = 1;

			if (dnsname_matches(name, &rname) != 0)
				return 1; /* accepted */
		}
	} while (ret == 0);

	if (allowed_found !=
	    0) /* there are allowed directives but this host wasn't found */
		return gnutls_assert_val(0);

	return 1;
}

static unsigned check_email_constraints(gnutls_x509_name_constraints_t nc,
					const gnutls_datum_t *name)
{
	unsigned i;
	int ret;
	unsigned rtype;
	unsigned allowed_found = 0;
	gnutls_datum_t rname;

	/* check restrictions */
	i = 0;
	do {
		ret = gnutls_x509_name_constraints_get_excluded(nc, i++, &rtype,
								&rname);
		if (ret >= 0) {
			if (rtype != GNUTLS_SAN_RFC822NAME)
				continue;

			/* a name of value 0 means that the CA shouldn't have issued
			 * a certificate with an e-mail. */
			if (rname.size == 0)
				return gnutls_assert_val(0);

			if (email_matches(name, &rname) != 0)
				return gnutls_assert_val(0); /* rejected */
		}
	} while (ret == 0);

	/* check allowed */
	i = 0;
	do {
		ret = gnutls_x509_name_constraints_get_permitted(
			nc, i++, &rtype, &rname);
		if (ret >= 0) {
			if (rtype != GNUTLS_SAN_RFC822NAME)
				continue;

			if (rname.size == 0)
				continue;

			allowed_found = 1;

			if (email_matches(name, &rname) != 0)
				return 1; /* accepted */
		}
	} while (ret == 0);

	if (allowed_found !=
	    0) /* there are allowed directives but this host wasn't found */
		return gnutls_assert_val(0);

	return 1;
}

static unsigned check_ip_constraints(gnutls_x509_name_constraints_t nc,
				     const gnutls_datum_t *name)
{
	unsigned i;
	int ret;
	unsigned rtype;
	unsigned allowed_found = 0;
	gnutls_datum_t rname;

	/* check restrictions */
	i = 0;
	do {
		ret = gnutls_x509_name_constraints_get_excluded(nc, i++, &rtype,
								&rname);
		if (ret >= 0) {
			if (rtype != GNUTLS_SAN_IPADDRESS)
				continue;

			/* do not check IPv4 against IPv6 constraints and vice versa */
			if (name->size != rname.size / 2)
				continue;

			if (ip_in_cidr(name, &rname) != 0)
				return gnutls_assert_val(0); /* rejected */
		}
	} while (ret == 0);

	/* check allowed */
	i = 0;
	do {
		ret = gnutls_x509_name_constraints_get_permitted(
			nc, i++, &rtype, &rname);
		if (ret >= 0) {
			if (rtype != GNUTLS_SAN_IPADDRESS)
				continue;

			/* do not check IPv4 against IPv6 constraints and vice versa */
			if (name->size != rname.size / 2)
				continue;

			allowed_found = 1;

			if (ip_in_cidr(name, &rname) != 0)
				return 1; /* accepted */
		}
	} while (ret == 0);

	if (allowed_found !=
	    0) /* there are allowed directives but this host wasn't found */
		return gnutls_assert_val(0);

	return 1;
}

/**
 * gnutls_x509_name_constraints_check:
 * @nc: the extracted name constraints
 * @type: the type of the constraint to check (of type gnutls_x509_subject_alt_name_t)
 * @name: the name to be checked
 *
 * This function will check the provided name against the constraints in
 * @nc using the RFC5280 rules. Currently this function is limited to DNS
 * names, emails and IP addresses (of type %GNUTLS_SAN_DNSNAME,
 * %GNUTLS_SAN_RFC822NAME and %GNUTLS_SAN_IPADDRESS).
 *
 * Returns: zero if the provided name is not acceptable, and non-zero otherwise.
 *
 * Since: 3.3.0
 **/
unsigned gnutls_x509_name_constraints_check(gnutls_x509_name_constraints_t nc,
					    gnutls_x509_subject_alt_name_t type,
					    const gnutls_datum_t *name)
{
	if (type == GNUTLS_SAN_DNSNAME)
		return check_dns_constraints(nc, name);

	if (type == GNUTLS_SAN_RFC822NAME)
		return check_email_constraints(nc, name);

	if (type == GNUTLS_SAN_IPADDRESS)
		return check_ip_constraints(nc, name);

	return check_unsupported_constraint(nc, type);
}

/* This function checks for unsupported constraints, that we also
 * know their structure. That is it will fail only if the constraint
 * is present in the CA, _and_ the name in the end certificate contains
 * the constrained element.
 *
 * Returns: true if the certification is acceptable, and false otherwise
 */
static unsigned
check_unsupported_constraint2(gnutls_x509_crt_t cert,
			      gnutls_x509_name_constraints_t nc,
			      gnutls_x509_subject_alt_name_t type)
{
	unsigned idx, found_one;
	char name[MAX_CN];
	size_t name_size;
	unsigned san_type;
	int ret;

	found_one = 0;

	for (idx = 0;; idx++) {
		name_size = sizeof(name);
		ret = gnutls_x509_crt_get_subject_alt_name2(
			cert, idx, name, &name_size, &san_type, NULL);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		else if (ret < 0)
			return gnutls_assert_val(0);

		if (san_type != GNUTLS_SAN_URI)
			continue;

		found_one = 1;
		break;
	}

	if (found_one != 0)
		return check_unsupported_constraint(nc, type);

	/* no name was found in the certificate, so accept */
	return 1;
}

/**
 * gnutls_x509_name_constraints_check_crt:
 * @nc: the extracted name constraints
 * @type: the type of the constraint to check (of type gnutls_x509_subject_alt_name_t)
 * @cert: the certificate to be checked
 *
 * This function will check the provided certificate names against the constraints in
 * @nc using the RFC5280 rules. It will traverse all the certificate's names and
 * alternative names.
 *
 * Currently this function is limited to DNS
 * names and emails (of type %GNUTLS_SAN_DNSNAME and %GNUTLS_SAN_RFC822NAME).
 *
 * Returns: zero if the provided name is not acceptable, and non-zero otherwise.
 *
 * Since: 3.3.0
 **/
unsigned
gnutls_x509_name_constraints_check_crt(gnutls_x509_name_constraints_t nc,
				       gnutls_x509_subject_alt_name_t type,
				       gnutls_x509_crt_t cert)
{
	char name[MAX_CN];
	size_t name_size;
	int ret;
	unsigned idx, t, san_type;
	gnutls_datum_t n;
	unsigned found_one;
	size_t checks;

	if (_gnutls_x509_name_constraints_is_empty(nc, type) != 0)
		return 1; /* shortcut; no constraints to check */

	if (!INT_ADD_OK(nc->permitted.size, nc->excluded.size, &checks) ||
	    !INT_MULTIPLY_OK(checks, cert->san->size, &checks) ||
	    checks > MAX_NC_CHECKS) {
		return gnutls_assert_val(0);
	}

	if (type == GNUTLS_SAN_RFC822NAME) {
		found_one = 0;
		for (idx = 0;; idx++) {
			name_size = sizeof(name);
			ret = gnutls_x509_crt_get_subject_alt_name2(
				cert, idx, name, &name_size, &san_type, NULL);
			if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
				break;
			else if (ret < 0)
				return gnutls_assert_val(0);

			if (san_type != GNUTLS_SAN_RFC822NAME)
				continue;

			found_one = 1;
			n.data = (void *)name;
			n.size = name_size;
			t = gnutls_x509_name_constraints_check(
				nc, GNUTLS_SAN_RFC822NAME, &n);
			if (t == 0)
				return gnutls_assert_val(t);
		}

		/* there is at least a single e-mail. That means that the EMAIL field will
		 * not be used for verifying the identity of the holder. */
		if (found_one != 0)
			return 1;

		do {
			/* ensure there is only a single EMAIL, similarly to CN handling (rfc6125) */
			name_size = sizeof(name);
			ret = gnutls_x509_crt_get_dn_by_oid(
				cert, GNUTLS_OID_PKCS9_EMAIL, 1, 0, name,
				&name_size);
			if (ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
				return gnutls_assert_val(0);

			name_size = sizeof(name);
			ret = gnutls_x509_crt_get_dn_by_oid(
				cert, GNUTLS_OID_PKCS9_EMAIL, 0, 0, name,
				&name_size);
			if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
				break;
			else if (ret < 0)
				return gnutls_assert_val(0);

			found_one = 1;
			n.data = (void *)name;
			n.size = name_size;
			t = gnutls_x509_name_constraints_check(
				nc, GNUTLS_SAN_RFC822NAME, &n);
			if (t == 0)
				return gnutls_assert_val(t);
		} while (0);

		/* passed */
		if (found_one != 0)
			return 1;
		else {
			/* no name was found. According to RFC5280: 
			 * If no name of the type is in the certificate, the certificate is acceptable.
			 */
			return gnutls_assert_val(1);
		}
	} else if (type == GNUTLS_SAN_DNSNAME) {
		found_one = 0;
		for (idx = 0;; idx++) {
			name_size = sizeof(name);
			ret = gnutls_x509_crt_get_subject_alt_name2(
				cert, idx, name, &name_size, &san_type, NULL);
			if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
				break;
			else if (ret < 0)
				return gnutls_assert_val(0);

			if (san_type != GNUTLS_SAN_DNSNAME)
				continue;

			found_one = 1;
			n.data = (void *)name;
			n.size = name_size;
			t = gnutls_x509_name_constraints_check(
				nc, GNUTLS_SAN_DNSNAME, &n);
			if (t == 0)
				return gnutls_assert_val(t);
		}

		/* there is at least a single DNS name. That means that the CN will
		 * not be used for verifying the identity of the holder. */
		if (found_one != 0)
			return 1;

		/* verify the name constraints against the CN, if the certificate is
		 * not a CA. We do this check only on certificates marked as WWW server,
		 * because that's where the CN check is only performed. */
		if (_gnutls_check_key_purpose(cert, GNUTLS_KP_TLS_WWW_SERVER,
					      0) != 0)
			do {
				/* ensure there is only a single CN, according to rfc6125 */
				name_size = sizeof(name);
				ret = gnutls_x509_crt_get_dn_by_oid(
					cert, GNUTLS_OID_X520_COMMON_NAME, 1, 0,
					name, &name_size);
				if (ret !=
				    GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
					return gnutls_assert_val(0);

				name_size = sizeof(name);
				ret = gnutls_x509_crt_get_dn_by_oid(
					cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0,
					name, &name_size);
				if (ret ==
				    GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
					break;
				else if (ret < 0)
					return gnutls_assert_val(0);

				found_one = 1;
				n.data = (void *)name;
				n.size = name_size;
				t = gnutls_x509_name_constraints_check(
					nc, GNUTLS_SAN_DNSNAME, &n);
				if (t == 0)
					return gnutls_assert_val(t);
			} while (0);

		/* passed */
		if (found_one != 0)
			return 1;
		else {
			/* no name was found. According to RFC5280: 
			 * If no name of the type is in the certificate, the certificate is acceptable.
			 */
			return gnutls_assert_val(1);
		}
	} else if (type == GNUTLS_SAN_IPADDRESS) {
		found_one = 0;
		for (idx = 0;; idx++) {
			name_size = sizeof(name);
			ret = gnutls_x509_crt_get_subject_alt_name2(
				cert, idx, name, &name_size, &san_type, NULL);
			if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
				break;
			else if (ret < 0)
				return gnutls_assert_val(0);

			if (san_type != GNUTLS_SAN_IPADDRESS)
				continue;

			found_one = 1;
			n.data = (void *)name;
			n.size = name_size;
			t = gnutls_x509_name_constraints_check(
				nc, GNUTLS_SAN_IPADDRESS, &n);
			if (t == 0)
				return gnutls_assert_val(t);
		}

		/* there is at least a single IP address. */

		if (found_one != 0) {
			return 1;
		} else {
			/* no name was found. According to RFC5280:
			 * If no name of the type is in the certificate, the certificate is acceptable.
			 */
			return gnutls_assert_val(1);
		}
	} else if (type == GNUTLS_SAN_URI) {
		return check_unsupported_constraint2(cert, nc, type);
	} else
		return check_unsupported_constraint(nc, type);
}

/**
 * gnutls_x509_name_constraints_get_permitted:
 * @nc: the extracted name constraints
 * @idx: the index of the constraint
 * @type: the type of the constraint (of type gnutls_x509_subject_alt_name_t)
 * @name: the name in the constraint (of the specific type)
 *
 * This function will return an intermediate type containing
 * the name constraints of the provided CA certificate. That
 * structure can be used in combination with gnutls_x509_name_constraints_check()
 * to verify whether a server's name is in accordance with the constraints.
 *
 * The name should be treated as constant and valid for the lifetime of @nc.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_name_constraints_get_permitted(gnutls_x509_name_constraints_t nc,
					       unsigned idx, unsigned *type,
					       gnutls_datum_t *name)
{
	const struct name_constraints_node_st *tmp;

	if (idx >= nc->permitted.size)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	tmp = nc->permitted.data[idx];

	*type = tmp->type;
	*name = tmp->name;

	return 0;
}

/**
 * gnutls_x509_name_constraints_get_excluded:
 * @nc: the extracted name constraints
 * @idx: the index of the constraint
 * @type: the type of the constraint (of type gnutls_x509_subject_alt_name_t)
 * @name: the name in the constraint (of the specific type)
 *
 * This function will return an intermediate type containing
 * the name constraints of the provided CA certificate. That
 * structure can be used in combination with gnutls_x509_name_constraints_check()
 * to verify whether a server's name is in accordance with the constraints.
 *
 * The name should be treated as constant and valid for the lifetime of @nc.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_name_constraints_get_excluded(gnutls_x509_name_constraints_t nc,
					      unsigned idx, unsigned *type,
					      gnutls_datum_t *name)
{
	const struct name_constraints_node_st *tmp;

	if (idx >= nc->excluded.size)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	tmp = nc->excluded.data[idx];

	*type = tmp->type;
	*name = tmp->name;

	return 0;
}
