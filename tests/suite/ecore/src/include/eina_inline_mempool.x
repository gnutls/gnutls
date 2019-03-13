/* EINA - EFL data type library
 * Copyright (C) 2008 Cedric Bail
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
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef EINA_INLINE_MEMPOOL_X_
#define EINA_INLINE_MEMPOOL_X_

/**
 * @addtogroup Eina_Memory_Pool_Group Memory Pool
 *
 * @{
 */

/* Memory Pool */
struct _Eina_Mempool_Backend
{
   const char *name;
   void *(*init)(const char *context, const char *options, va_list args);
   void (*free)(void *data, void *element);
   void *(*alloc)(void *data, unsigned int size);
   void *(*realloc)(void *data, void *element, unsigned int size);
   void (*garbage_collect)(void *data);
   void (*statistics)(void *data);
   void (*shutdown)(void *data);
};

struct _Eina_Mempool
{
   Eina_Mempool_Backend backend;
   void *backend_data;
};

/**
 * @brief Re-allocate a amount memory by the given mempool.
 *
 * @param mp The mempool.
 * @param element The element to re-allocate.
 * @param size The size in bytes to re-allocate.
 * @return The newly re-allocated data.
 *
 * This function re-allocates @p element with @p size bytes, using the
 * mempool @p mp and returns the allocated data. If not used anymore,
 * the data must be freed with eina_mempool_free(). No check is done
 * on @p mp, so it must be a valid mempool.
 */
static inline void *
eina_mempool_realloc(Eina_Mempool *mp, void *element, unsigned int size)
{
   return mp->backend.realloc(mp->backend_data, element, size);
}

/**
 * @brief Allocate a amount memory by the given mempool.
 *
 * @param mp The mempool.
 * @param size The size in bytes to allocate.
 * @return The newly allocated data.
 *
 * This function allocates @p size bytes, using the mempool @p mp and
 * returns the allocated data. If not used anymore, the data must be
 * freed with eina_mempool_free(). No check is done on @p mp, so it
 * must be a valid mempool.
 */
static inline void *
eina_mempool_malloc(Eina_Mempool *mp, unsigned int size)
{
   return mp->backend.alloc(mp->backend_data, size);
}

/**
 * @brief Free the allocated ressources by the given mempool.
 *
 * @param mp The mempool.
 * @param element The data to free.
 *
 * This function frees @p element allocated by @p mp. @p element must
 * have been obtained by eina_mempool_malloc() or
 * eina_mempool_realloc(). No check is done on @p mp, so it must be a
 * valid mempool.
 */
static inline void
eina_mempool_free(Eina_Mempool *mp, void *element)
{
   mp->backend.free(mp->backend_data, element);
}

/**
 * @}
 */

#endif
