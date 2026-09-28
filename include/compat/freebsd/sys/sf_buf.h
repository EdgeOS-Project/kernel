/* SPDX-License-Identifier: BSD-2-Clause */
/* Direct-map page access for imported FreeBSD drivers. */

#ifndef _SYS_SF_BUF_H_
#define _SYS_SF_BUF_H_

#include <vm/vm_page.h>

#define SFB_CATCH 1
#define SFB_CPUPRIVATE 2
#define SFB_DEFAULT 0
#define SFB_NOWAIT 4

struct sf_buf;

static inline struct sf_buf *
sf_buf_alloc(struct vm_page *page, int flags)
{
    (void)flags;
    return page && page->edgeos_page ? (struct sf_buf *)page : 0;
}

static inline void
sf_buf_free(struct sf_buf *buffer)
{
    (void)buffer;
}

static inline void
sf_buf_ref(struct sf_buf *buffer)
{
    (void)buffer;
}

static inline void *
sf_buf_kva(struct sf_buf *buffer)
{
    vm_page_t page = (vm_page_t)buffer;

    return page ? page->edgeos_page : 0;
}

static inline vm_page_t
sf_buf_page(struct sf_buf *buffer)
{
    return (vm_page_t)buffer;
}

#endif
