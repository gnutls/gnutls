/* SPDX-License-Identifier: MIT OR Unlicense */
/* Copyright (C) 2022-2025 The crypto-auditing developers. */

/* This file declares a set of high-level functions to insert probe
 * points used for crypto-auditing into the application programs. See
 * <crau/macros.h> for the low-level interface.
 *
 * As this is a header-only library, one of C files that includes
 * this file should do:
 *
 * #define CRAU_IMPLEMENTATION
 * #include "crau/crau.h"
 *
 * to get the necessary functions are defined.
 *
 * The following configuration macros can also be set to override the
 * behavior of the implementation:
 *
 * * CRAU_CONTEXT_STACK_DEPTH: depth of the thread-local context stack
 *   (default: 3)
 *
 * * CRAU_RETURN_ADDRESS: return address of the current function
 *   (default: auto-detected)
 *
 * * CRAU_THREAD_LOCAL: thread-local modifier of the C language
 *   (default: auto-detected)
 *
 * * CRAU_MAYBE_UNUSED: an attribute to suppress warnings when a
 *   function argument is not used in the function body (default:
 *   auto-detected)
 *
 * Unless ENABLE_CRYPTO_AUDITING is defined, all functions turn to
 * no-op.
 */

#ifndef CRAU_CRAU_H
#define CRAU_CRAU_H

#include <stdint.h>

/* An opaque type that represents a context (e.g., TLS handshake)
 * where crypto-auditing events occur. This should be a unique
 * identifier within a thread.
 */
typedef long crau_context_t;

/* A special context value used to represent a context which is
 * automatically assigned based on the current call frame.
 */
#ifndef CRAU_AUTO_CONTEXT
# ifdef __GNUC__
#  define CRAU_AUTO_CONTEXT (crau_context_t)(intptr_t)(char *)__builtin_return_address(0)
# elif defined(__CC_ARM)
#  define CRAU_AUTO_CONTEXT (crau_context_t)(intptr_t)(char *)__return_address()
# else
#  define CRAU_AUTO_CONTEXT CRAU_ORPHANED_CONTEXT
# endif
#endif /* CRAU_AUTO_CONTEXT */

/* A special context value used to represent a context which is not
 * associated with any parent nor children.
 */
#define CRAU_ORPHANED_CONTEXT ((crau_context_t)-1)

/* Types of crypto-auditing event data. CRAU_WORD means an integer in
 * a machine word, CRAU_STRING means a NUL-terminated
 * string. CRAU_BLOB means an explicitly sized binary blob.
 */
enum crau_data_type_t {
	CRAU_WORD,
	CRAU_STRING,
	CRAU_BLOB,
};

/* Push a context CONTEXT onto the thread-local context stack. If the
 * depth of the stack exceeds CRAU_CONTEXT_STACK_DEPTH, the older
 * element will be removed.
 *
 * This call shall be followed by a `crau_pop_context`.
 */
void crau_push_context(crau_context_t context);

/* Pop a context from the thread-local context stack. If the stack is
 * empty, it returns a CRAU_ORPHANED_CONTEXT.
 */
crau_context_t crau_pop_context(void);

/* Return the context currently active for this thread. If there is no
 * active context, it returns a CRAU_ORPHANED_CONTEXT.
 */
crau_context_t crau_current_context(void);

/* Push a context CONTEXT onto the thread-local context stack,
 * optionally emitting events through varargs.
 *
 * If the depth of the stack exceeds CRAU_CONTEXT_STACK_DEPTH, the
 * older element will be removed.  This call shall be followed by a
 * `crau_pop_context`.
 */
void crau_push_context_with_data(crau_context_t context, ...);

/* Push a new context (inferred from the current call stack) onto the
 * thread-local context stack, optionally emitting events through
 * varargs.
 *
 * Typical usage example is as follows:
 *
 * crau_new_context_with_data(
 *   "name", CRAU_STRING, "pk::sign",
 *   "pk::algorithm", CRAU_STRING, "mldsa",
 *   "pk::bits", CRAU_WORD, 1952 * 8,
 *   NULL);
 *
 * If the depth of the stack exceeds CRAU_CONTEXT_STACK_DEPTH, the
 * older element will be removed.  This call shall be followed by a
 * `crau_pop_context`.
 */
#define crau_new_context_with_data(...) \
	crau_push_context_with_data(CRAU_AUTO_CONTEXT, __VA_ARGS__)

/* Emit events through varargs, under the current thread-local
 * context. Unlike `crau_new_context_with_data`, this does not push a
 * new context.
 */
void crau_data(const char *first_key_ptr, ...);

#ifdef CRAU_IMPLEMENTATION

#include "macros.h"

/* Avoid name clash with crau_data_type_t */
#undef CRAU_WORD
#undef CRAU_STRING
#undef CRAU_BLOB

#include <stdarg.h>
#include <stddef.h>

# ifdef ENABLE_CRYPTO_AUDITING

#  ifndef CRAU_CONTEXT_STACK_DEPTH
#   define CRAU_CONTEXT_STACK_DEPTH 3
#  endif /* CRAU_CONTEXT_STACK_DEPTH */

#  ifndef CRAU_THREAD_LOCAL
#   ifdef thread_local
#    define CRAU_THREAD_LOCAL thread_local
#   elif __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#    define CRAU_THREAD_LOCAL _Thread_local
#   elif defined(_MSC_VER)
#    define CRAU_THREAD_LOCAL __declspec(thread)
#   elif defined(__GNUC__)
#    define CRAU_THREAD_LOCAL __thread
#   else
#    error "thread_local support is required; define CRAU_THREAD_LOCAL"
#   endif
#  endif /* CRAU_THREAD_LOCAL */

static CRAU_THREAD_LOCAL crau_context_t context_stack[CRAU_CONTEXT_STACK_DEPTH] = {
	0,
};
static CRAU_THREAD_LOCAL size_t context_stack_top = 0;

static inline void push_context(crau_context_t context)
{
	context_stack[context_stack_top++ % CRAU_CONTEXT_STACK_DEPTH] = context;
}

void crau_push_context(crau_context_t context)
{
	CRAU_NEW_CONTEXT(context, crau_current_context());
	push_context(context);
}

crau_context_t crau_pop_context(void)
{
	return context_stack_top == 0 ? CRAU_ORPHANED_CONTEXT : context_stack[--context_stack_top];
}

crau_context_t crau_current_context(void)
{
	return context_stack_top == 0 ? CRAU_ORPHANED_CONTEXT : context_stack[context_stack_top - 1];
}

static inline unsigned long
crau_accumulate_datav(struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS],
		      va_list ap,
		      char *key_ptr)
{
	unsigned long count = 0;

	for (; key_ptr != NULL && count < CRAU_MAX_DATA_ELEMS;
	     key_ptr = va_arg(ap, char *), count++) {
		data[count].key_ptr = key_ptr;

		switch (va_arg(ap, enum crau_data_type_t)) {
		case CRAU_WORD:
			data[count].value_ptr = (void *)va_arg(ap, intptr_t);
			data[count].value_size = (unsigned long)-2;
			break;
		case CRAU_STRING:
			data[count].value_ptr = (void *)va_arg(ap, char *);
			data[count].value_size = (unsigned long)-1;
			break;
		case CRAU_BLOB:
			data[count].value_ptr = va_arg(ap, void *);
			data[count].value_size = va_arg(ap, unsigned long);
			break;
		}
	}

	return count;
}

void crau_push_context_with_data(crau_context_t context, ...)
{
	struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS];
	unsigned long count;
	va_list ap;

	va_start(ap, context);
	count = crau_accumulate_datav(data, ap, va_arg(ap, char *));
	va_end(ap);

	CRAU_NEW_CONTEXT_WITH_DATA(context, crau_current_context(), data,
				   count);
	push_context(context);
}

void crau_data(const char *first_key_ptr, ...)
{
	struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS];
	size_t count;
	va_list ap;

	va_start(ap, first_key_ptr);
	count = crau_accumulate_datav(data, ap, (char *)first_key_ptr);
	va_end(ap);

	CRAU_DATA(crau_current_context(), data, count);
}

# else

#  ifndef CRAU_MAYBE_UNUSED
#   if defined(__has_c_attribute) && \
    __has_c_attribute (__maybe_unused__)
#    define CRAU_MAYBE_UNUSED [[__maybe_unused__]]
#   elif defined(__GNUC__)
#    define CRAU_MAYBE_UNUSED __attribute__((__unused__))
#   endif
#  endif /* CRAU_MAYBE_UNUSED */

void crau_push_context(crau_context_t context CRAU_MAYBE_UNUSED)
{
}

crau_context_t crau_pop_context(void)
{
	return CRAU_ORPHANED_CONTEXT;
}

crau_context_t crau_current_context(void)
{
	return CRAU_ORPHANED_CONTEXT;
}

void crau_push_context_with_data(crau_context_t context CRAU_MAYBE_UNUSED, ...)
{
}

void crau_data(const char *first_key_ptr CRAU_MAYBE_UNUSED, ...)
{
}

# endif /* ENABLE_CRYPTO_AUDITING */

#endif /* CRAU_IMPLEMENTATION */

#endif /* CRAU_CRAU_H */
