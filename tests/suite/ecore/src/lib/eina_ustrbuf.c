#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eina_strbuf_common.h"
#include "eina_unicode.h"
#include "eina_ustrbuf.h"

/*============================================================================*
 *                                  Local                                     *
 *============================================================================*/

/**
 * @cond LOCAL
 */

#ifdef _STRBUF_DATA_TYPE
#undef _STRBUF_DATA_TYPE
#endif

#ifdef _STRBUF_CSIZE
#undef _STRBUF_CSIZE
#endif

#ifdef _STRBUF_STRUCT_NAME
#undef _STRBUF_STRUCT_NAME
#endif

#ifdef _STRBUF_STRLEN_FUNC
#undef _STRBUF_STRLEN_FUNC
#endif

#ifdef _STRBUF_STRESCAPE_FUNC
#undef _STRBUF_STRESCAPE_FUNC
#endif

#ifdef _STRBUF_MAGIC
#undef _STRBUF_MAGIC
#endif

#ifdef _STRBUF_MAGIC_STR
#undef _STRBUF_MAGIC_STR
#endif

#ifdef _FUNC_EXPAND
#undef _FUNC_EXPAND
#endif

#define _STRBUF_DATA_TYPE         Eina_Unicode
#define _STRBUF_CSIZE             sizeof(_STRBUF_DATA_TYPE)
#define _STRBUF_STRUCT_NAME       Eina_UStrbuf
#define _STRBUF_STRLEN_FUNC(x)    eina_unicode_strlen(x)
#define _STRBUF_STRESCAPE_FUNC(x) eina_unicode_escape(x)
#define _STRBUF_MAGIC             EINA_MAGIC_USTRBUF
#define _STRBUF_MAGIC_STR         __USTRBUF_MAGIC_STR
static const char __USTRBUF_MAGIC_STR[] = "Eina UStrbuf";

#define _FUNC_EXPAND(y) eina_ustrbuf_ ## y

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
 * @addtogroup Eina_Unicode_String_Buffer_Group Unicode String Buffer
 *
 * @brief These functions provide unicode string buffers management.
 *
 * The Unicode String Buffer data type is designed to be a mutable string,
 * allowing to append, prepend or insert a string to a buffer.
 *
 * @{
 */

#include "eina_strbuf_template_c.x"

/**
 * @}
 */
