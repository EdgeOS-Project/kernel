/* SPDX-License-Identifier: BSD-3-Clause */
/* Minimal functional UMA zones used by imported drivers. */

#ifndef _VM_UMA_H_
#define _VM_UMA_H_

#include <stddef.h>

struct uma_zone;
typedef struct uma_zone *uma_zone_t;
typedef int (*uma_ctor)(void *, int, void *, int);
typedef void (*uma_dtor)(void *, int, void *);
typedef int (*uma_init)(void *, int, int);
typedef void (*uma_fini)(void *, int);

#define UMA_ALIGN_PTR (sizeof(void *) - 1u)
#define UMA_ZONE_ZINIT 0x0002
#define UMA_ZONE_NODUMP 0x0004

uma_zone_t uma_zcreate(const char *name, size_t size, uma_ctor ctor,
    uma_dtor dtor, uma_init init, uma_fini fini, unsigned int alignment,
    unsigned int flags);
void uma_zdestroy(uma_zone_t zone);
void *uma_zalloc_arg(uma_zone_t zone, void *argument, int flags);
void uma_zfree_arg(uma_zone_t zone, void *item, void *argument);
static inline void *
uma_zalloc(uma_zone_t zone, int flags)
{
    return uma_zalloc_arg(zone, 0, flags);
}
static inline void
uma_zfree(uma_zone_t zone, void *item)
{
    uma_zfree_arg(zone, item, 0);
}
void uma_prealloc(uma_zone_t zone, int item_count);
void uma_zone_reserve(uma_zone_t zone, int item_count);
int uma_zone_get_cur(uma_zone_t zone);

#endif
