/* acconfig.h - used by autoheader to make config.h.in
 */
#ifndef GPA_CONFIG_H
#define GPA_CONFIG_H

/* Need this, because some autoconf tests rely on this (e.g. stpcpy)
 * and it should be used for new programs anyway. */
#define _GNU_SOURCE  1

@TOP@

#undef HAVE_BYTE_TYPEDEF


@BOTTOM@


#endif /*GPA_CONFIG_H*/
