#ifndef EINA_STRBUF_COMMON_H
#define EINA_STRBUF_COMMON_H

#include <stdlib.h>

#include "eina_private.h"
#include "eina_magic.h"
#include "eina_strbuf.h"

struct _Eina_Strbuf {
	void *buf;
	size_t len;
	size_t size;
	size_t step;

 EINA_MAGIC};

#define EINA_MAGIC_CHECK_STRBUF(d, ...)                         \
   do {                                                         \
        if (!EINA_MAGIC_CHECK((d), _STRBUF_MAGIC))              \
          {                                                     \
             EINA_MAGIC_FAIL((d), _STRBUF_MAGIC);               \
             return __VA_ARGS__;                                \
          }                                                     \
     } while (0)

Eina_Bool eina_strbuf_common_init(void);

Eina_Bool eina_strbuf_common_shutdown(void);
Eina_Strbuf *eina_strbuf_common_new(size_t csize);
void eina_strbuf_common_free(Eina_Strbuf * buf);
void eina_strbuf_common_reset(size_t csize, Eina_Strbuf * buf);
Eina_Bool
eina_strbuf_common_append(size_t csize,
			  Eina_Strbuf * buf, const void *str, size_t len);
Eina_Bool
eina_strbuf_common_append_escaped(size_t csize,
				  Eina_Strbuf * buf, const void *str);
Eina_Bool
eina_strbuf_common_append_n(size_t csize,
			    Eina_Strbuf * buf,
			    const void *str, size_t len, size_t maxlen);
Eina_Bool
eina_strbuf_common_append_length(size_t csize,
				 Eina_Strbuf * buf,
				 const void *str, size_t length);
Eina_Bool
eina_strbuf_common_insert(size_t csize,
			  Eina_Strbuf * buf,
			  const void *str, size_t len, size_t pos);
Eina_Bool
eina_strbuf_common_insert_escaped(size_t csize,
				  Eina_Strbuf * buf,
				  const void *str, size_t len, size_t pos);
Eina_Bool
eina_strbuf_common_insert_n(size_t csize,
			    Eina_Strbuf * buf,
			    const void *str,
			    size_t len, size_t maxlen, size_t pos);
Eina_Bool
eina_strbuf_common_insert_length(size_t csize,
				 Eina_Strbuf * buf,
				 const void *str,
				 size_t length, size_t pos);
Eina_Bool
eina_strbuf_common_append_char(size_t csize, Eina_Strbuf * buf,
			       const void *c);
Eina_Bool eina_strbuf_common_insert_char(size_t csize, Eina_Strbuf * buf,
					 const void *c, size_t pos);
Eina_Bool eina_strbuf_common_remove(size_t csize, Eina_Strbuf * buf,
				    size_t start, size_t end);
const void *eina_strbuf_common_string_get(const Eina_Strbuf * buf);
void *eina_strbuf_common_string_steal(size_t csize, Eina_Strbuf * buf);
void eina_strbuf_common_string_free(size_t csize, Eina_Strbuf * buf);
size_t eina_strbuf_common_length_get(const Eina_Strbuf * buf);

Eina_Bool
_eina_strbuf_common_grow(size_t csize, Eina_Strbuf * buf, size_t size);
/**
 * @}
 */

#endif
