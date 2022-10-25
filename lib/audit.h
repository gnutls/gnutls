/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2022-2023 The crypto-auditing developers. */

/* This file defines probe points used by crypto-auditing. */

#ifdef ENABLE_CRYPTO_AUDITING

# ifdef HAVE_SYS_SDT_H
#  include <sys/sdt.h>
# endif

/* Introduce a new context CONTEXT, derived from PARENT */
# define CRYPTO_AUDITING_NEW_CONTEXT(context, parent)				\
	DTRACE_PROBE2(crypto_auditing, new_context, context, parent)

/* Assert an event with KEY and VALUE. The key is treated as a
 * NUL-terminated string, while the value is in the size of machine
 * word
 */
# define CRYPTO_AUDITING_WORD_DATA(context, key_ptr, value_ptr)			\
	DTRACE_PROBE3(crypto_auditing, word_data, context, key_ptr, value_ptr)

/* Assert an event with KEY and VALUE. Both the key and value are
 * treated as a NUL-terminated string
 */
# define CRYPTO_AUDITING_STRING_DATA(context, key_ptr, value_ptr)			\
	DTRACE_PROBE3(crypto_auditing, string_data, context, key_ptr, value_ptr)

/* Assert an event with KEY and VALUE. The key is treated as a
 * NUL-terminated string, while the value is explicitly sized with
 * VALUE_SIZE
 */
# define CRYPTO_AUDITING_BLOB_DATA(key_ptr, context, value_ptr, value_size)	\
	DTRACE_PROBE4(crypto_auditing, blob_data, context, key_ptr, value_ptr, value_size)

#else

# define CRYPTO_AUDITING_NEW_CONTEXT(context, parent)
# define CRYPTO_AUDITING_WORD_DATA(context, key_ptr, value_ptr)
# define CRYPTO_AUDITING_STRING_DATA(context, key_ptr, value_ptr)
# define CRYPTO_AUDITING_BLOB_DATA(context, key_ptr, value_ptr, value_size)

#endif				/* ENABLE_CRYPTO_AUDITING */
