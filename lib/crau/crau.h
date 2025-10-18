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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/* A special context value used to represent a context which is
 * automatically assigned based on the current call frame.
 */
#ifndef CRAU_AUTO_CONTEXT
# ifdef __GNUC__
#  define CRAU_AUTO_CONTEXT (long)(intptr_t)(char *)__builtin_return_address(0)
# elif defined(__CC_ARM)
#  define CRAU_AUTO_CONTEXT (long)(intptr_t)(char *)__return_address()
# else
#  define CRAU_AUTO_CONTEXT CRAU_ORPHANED_CONTEXT
# endif
#endif /* CRAU_AUTO_CONTEXT */

/* A special context value used to represent a context which is not
 * associated with any parent nor children.
 */
#define CRAU_ORPHANED_CONTEXT ((long)-1)

#ifndef CRAU_CONTEXT_STACK_DEPTH
# define CRAU_CONTEXT_STACK_DEPTH 3
#endif /* CRAU_CONTEXT_STACK_DEPTH */

struct crau_context_stack_st {
	long stack[CRAU_CONTEXT_STACK_DEPTH];
	size_t top;
};

/* Types of crypto-auditing event data. CRAU_WORD means an integer in
 * a machine word, CRAU_STRING means a NUL-terminated
 * string. CRAU_BLOB means an explicitly sized binary blob.
 */
enum crau_data_type_t {
	CRAU_WORD,
	CRAU_STRING,
	CRAU_BLOB,
};

/* Push a context CONTEXT onto the given context stack STACK. If the depth of
 * the stack exceeds CRAU_CONTEXT_STACK_DEPTH, the older element will be
 * removed.
 *
 * This call shall be followed by a `crau_pop_context`.
 */
void crau_push_context(struct crau_context_stack_st *stack,
		       long context);

/* Pop a context from the given context stack STACK. If the stack is empty, it
 * returns a CRAU_ORPHANED_CONTEXT.
 */
long crau_pop_context(struct crau_context_stack_st *stack);

/* Return the context currently active in the given context stack STACK. If
 * there is no active context, it returns a CRAU_ORPHANED_CONTEXT.
 */
long crau_current_context(struct crau_context_stack_st *stack);

/* Push a context CONTEXT onto the given context stack STACK,
 * optionally emitting events through varargs.
 *
 * If the depth of the stack exceeds CRAU_CONTEXT_STACK_DEPTH, the
 * older element will be removed.  This call shall be followed by a
 * `crau_pop_context`.
 */
void crau_push_context_with_data(struct crau_context_stack_st *stack,
				 long context, ...);

void crau_push_context_with_datav(struct crau_context_stack_st *stack,
				  long context, va_list ap);

/* Push a new context (inferred from the current call stack) onto the given
 * context stack STACK, optionally emitting events through varargs.
 *
 * Typical usage example is as follows:
 *
 * crau_new_context_with_data(
 *   stack,
 *   "name", CRAU_STRING, "pk::sign",
 *   "pk::algorithm", CRAU_STRING, "mldsa",
 *   "pk::bits", CRAU_WORD, 1952 * 8,
 *   NULL);
 *
 * If the depth of the stack exceeds CRAU_CONTEXT_STACK_DEPTH, the
 * older element will be removed.  This call shall be followed by a
 * `crau_pop_context`.
 */
#define crau_new_context_with_data(stack, ...)				\
	crau_push_context_with_data((stack), CRAU_AUTO_CONTEXT, __VA_ARGS__)

#define crau_new_context_with_datav(stack, ap)				\
	crau_push_context_with_datav((stack), CRAU_AUTO_CONTEXT, (ap))

/* Emit events through varargs, under the currently active context in the given
 * context stack STACK. Unlike `crau_new_context_with_data`, this does not push
 * a new context.
 */
void crau_data(struct crau_context_stack_st *stack, ...);

void crau_datav(struct crau_context_stack_st *stack, va_list ap);

#ifdef CRAU_IMPLEMENTATION

#include "macros.h"

/* Avoid name clash with crau_data_type_t */
#undef CRAU_WORD
#undef CRAU_STRING
#undef CRAU_BLOB

# ifdef ENABLE_CRYPTO_AUDITING

static inline void push_context(struct crau_context_stack_st *stack,
				long context)
{
	stack->stack[stack->top++ % CRAU_CONTEXT_STACK_DEPTH] = context;
}

void crau_push_context(struct crau_context_stack_st *stack,
		       long context)
{
	CRAU_NEW_CONTEXT(context, crau_current_context(stack));
	push_context(stack, context);
}

long crau_pop_context(struct crau_context_stack_st *stack)
{
	return stack->top == 0 ? CRAU_ORPHANED_CONTEXT :
		stack->stack[--stack->top];
}

long crau_current_context(struct crau_context_stack_st *stack)
{
	return stack->top == 0 ? CRAU_ORPHANED_CONTEXT :
		stack->stack[stack->top - 1];
}

static inline unsigned long
crau_accumulate_datav(struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS],
		      va_list ap)
{
	unsigned long count = 0;
	char *key_ptr;

	for (key_ptr = va_arg(ap, char *);
	     key_ptr != NULL && count < CRAU_MAX_DATA_ELEMS;
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

void crau_push_context_with_datav(struct crau_context_stack_st *stack,
				  long context, va_list ap)
{
	struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS];
	unsigned long count;

	count = crau_accumulate_datav(data, ap);

	CRAU_NEW_CONTEXT_WITH_DATA(context, crau_current_context(stack), data,
				   count);
	push_context(stack, context);
}

void crau_push_context_with_data(struct crau_context_stack_st *stack,
				 long context, ...)
{
	va_list ap;

	va_start(ap, context);
	crau_push_context_with_datav(stack, context, ap);
	va_end(ap);
}

void crau_datav(struct crau_context_stack_st *stack, va_list ap)
{
	struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS];
	size_t count;

	count = crau_accumulate_datav(data, ap);

	CRAU_DATA(crau_current_context(stack), data, count);
}

void crau_data(struct crau_context_stack_st *stack, ...)
{
	va_list ap;

	va_start(ap, stack);
	crau_datav(stack, ap);
	va_end(ap);
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

void crau_push_context(struct crau_context_stack_st *stack CRAU_MAYBE_UNUSED,
		       long context CRAU_MAYBE_UNUSED)
{
}

long
crau_pop_context(struct crau_context_stack_st *stack CRAU_MAYBE_UNUSED)
{
	return CRAU_ORPHANED_CONTEXT;
}

long
crau_current_context(struct crau_context_stack_st *stack CRAU_MAYBE_UNUSED)
{
	return CRAU_ORPHANED_CONTEXT;
}

void crau_push_context_with_datav(struct crau_context_stack_st *stack CRAU_MAYBE_UNUSED,
				  long context CRAU_MAYBE_UNUSED,
				  va_list ap CRAU_MAYBE_UNUSED)
{
}

void crau_push_context_with_data(struct crau_context_stack_st *stack CRAU_MAYBE_UNUSED,
				 long context CRAU_MAYBE_UNUSED, ...)
{
}

void crau_datav(struct crau_context_stack_st *stack CRAU_MAYBE_UNUSED,
		va_list ap CRAU_MAYBE_UNUSED)
{
}

void crau_data(struct crau_context_stack_st *stack CRAU_MAYBE_UNUSED, ...)
{
}

# endif /* ENABLE_CRYPTO_AUDITING */

#endif /* CRAU_IMPLEMENTATION */

#endif /* CRAU_CRAU_H */
