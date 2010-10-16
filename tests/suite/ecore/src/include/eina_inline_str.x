/* EINA - EFL data type library
 * Copyright (C) 2002-2008 Gustavo Sverzut Barbieri
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
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EINA_STR_INLINE_H_
#define EINA_STR_INLINE_H_

/**
 * @addtogroup Eina_String_Group String
 *
 * @{
 */

/**
 * @brief Count up to a given amount of bytes of the given string.
 *
 * @param str The string pointer.
 * @param maxlen The maximum length to allow.
 * @return the string size or (size_t)-1 if greater than @a maxlen.
 *
 * This function returns the size of @p str, up to @p maxlen
 * characters. It avoid needless iterations after that size. @p str
 * must be a valid pointer and MUST not be @c NULL, otherwise this
 * function will crash. This function returns the string size, or
 * (size_t)-1 if the size is greater than @a maxlen.
 */
static inline size_t
eina_strlen_bounded(const char *str, size_t maxlen)
{
   const char *itr, *str_maxend = str + maxlen;
   for (itr = str; *itr != '\0'; itr++)
     if (itr == str_maxend) return (size_t)-1;
   return itr - str;
}

/**
 * @brief Join two strings of known length.
 *
 * @param dst The buffer to store the result.
 * @param size Size (in byte) of the buffer.
 * @param sep The separator character to use.
 * @param a First string to use, before @p sep.
 * @param b Second string to use, after @p sep.
 * @return The number of characters printed.
 *
 * This function is similar to eina_str_join_len(), but will compute
 * the length of @p a  and @p b using strlen().
 *
 * @see eina_str_join_len()
 * @see eina_str_join_static()
 */
static inline size_t
eina_str_join(char *dst, size_t size, char sep, const char *a, const char *b)
{
   return eina_str_join_len(dst, size, sep, a, strlen(a), b, strlen(b));
}

/**
 * @}
 */

#endif /* EINA_STR_INLINE_H_ */
