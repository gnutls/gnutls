/* SPDX-License-Identifier: MIT OR Unlicense */
/* Copyright (C) 2022-2025 The crypto-auditing developers. */

/* This file defines a set of low-level macros to insert probe points
 * used for crypto-auditing into the application programs. See
 * <crau/crau.h> for a higher-level and more ergonomic interface.
 *
 * Unless ENABLE_CRYPTO_AUDITING is defined, all macros turn to no-op.
 */

#ifndef CRAU_MACROS_H
#define CRAU_MACROS_H

#ifdef ENABLE_CRYPTO_AUDITING

#ifdef HAVE_SYS_SDT_H
#include <sys/sdt.h>
#endif

/* Introduce a new context CONTEXT, derived from the parent context PARENT.
 */
#define CRAU_NEW_CONTEXT(context, parent) \
	DTRACE_PROBE2(crypto_auditing, new_context, context, parent)

/* Emit an event with KEY and VALUE. The key is a NUL-terminated
 * string, while the value is an integer in the size of a machine
 * word.
 */
#define CRAU_WORD_DATA(context, key_ptr, value_ptr) \
	DTRACE_PROBE3(crypto_auditing, word_data, context, key_ptr, value_ptr)

/* Emit an event with KEY and VALUE. The key is a NUL-terminated
 * string, while the value is also a NUL-terminated string.
 */
#define CRAU_STRING_DATA(context, key_ptr, value_ptr) \
	DTRACE_PROBE3(crypto_auditing, string_data, context, key_ptr, value_ptr)

/* Emit an event with KEY and VALUE. The key is a NUL-terminated
 * string, while the value is explicitly sized binary blob of the
 * VALUE_SIZE size.
 */
#define CRAU_BLOB_DATA(context, key_ptr, value_ptr, value_size)                \
	DTRACE_PROBE4(crypto_auditing, blob_data, context, key_ptr, value_ptr, \
		      value_size)

/* Generic data structure that represents an event. The KEY_PTR field
 * points to the name of the event key, and the VALUE_PTR field points
 * to the value.
 *
 * The VALUE_SIZE field is set depending on the type of the value. If
 * the value is a machine word, it is set to 0xfffffffe (= -2).  If
 * the value is a NUL-terminated string, it is set to 0xffffffff (=
 * -1). Otherwise, it is set to the actual size of the value.
 */
struct crypto_auditing_data {
	char *key_ptr;
	void *value_ptr;
	unsigned long value_size;
};

#define CRAU_WORD(key_ptr, value_ptr) \
	{ (char *)(key_ptr), (void *)(intptr_t)(value_ptr), (unsigned long)-2 }
#define CRAU_STRING(key_ptr, value_ptr) \
	{ (char *)(key_ptr), (void *)(value_ptr), (unsigned long)-1 }
#define CRAU_BLOB(key_ptr, value_ptr, value_size) \
	{ (char *)(key_ptr), (void *)(value_ptr), value_size }

/* The maximum number of events which can be emitted at once. */
#define CRAU_MAX_DATA_ELEMS 16

/* Emit multiple events at once.
 */
#define CRAU_DATA(context, array_ptr, array_size) \
	DTRACE_PROBE3(crypto_auditing, data, context, array_ptr, array_size)

/* Emit multiple events at once through varargs.
 */
#define CRAU_DATAV(context, ...)                                             \
	({                                                                   \
		struct crypto_auditing_data __crau_data[] = { __VA_ARGS__ }; \
		CRAU_DATA(context, __crau_data,                              \
			  sizeof(__crau_data) / sizeof(__crau_data[0]));     \
	})

/* Introduce a new context CONTEXT, derived from PARENT, with optional
 * events to be emitted.
 */
#define CRAU_NEW_CONTEXT_WITH_DATA(context, parent, array_ptr, array_size)     \
	DTRACE_PROBE4(crypto_auditing, new_context_with_data, context, parent, \
		      array_ptr, array_size)

/* Introduce a new context CONTEXT, derived from PARENT, with optional
 * events to be emitted, through varargs.
 */
#define CRAU_NEW_CONTEXT_WITH_DATAV(context, parent, ...)                    \
	({                                                                   \
		struct crypto_auditing_data __crau_data[] = { __VA_ARGS__ }; \
		CRAU_NEW_CONTEXT_WITH_DATA(context, parent, __crau_data,     \
					   sizeof(__crau_data) /             \
						   sizeof(__crau_data[0]));  \
	})

#else

#define CRAU_NEW_CONTEXT(context, parent)
#define CRAU_WORD_DATA(context, key_ptr, value_ptr)
#define CRAU_STRING_DATA(context, key_ptr, value_ptr)
#define CRAU_BLOB_DATA(context, key_ptr, value_ptr, value_size)
#define CRAU_WORD(key_ptr, value_ptr)
#define CRAU_STRING(key_ptr, value_ptr)
#define CRAU_BLOB(key_ptr, value_ptr, value_size)
#define CRAU_DATA(context, array_ptr, array_size)
#define CRAU_DATAV(context, ...)
#define CRAU_NEW_CONTEXT_WITH_DATA(context, parent, array_ptr, array_size)
#define CRAU_NEW_CONTEXT_WITH_DATAV(context, parent, ...)

#endif /* ENABLE_CRYPTO_AUDITING */

#endif /* CRAU_MACROS_H */
