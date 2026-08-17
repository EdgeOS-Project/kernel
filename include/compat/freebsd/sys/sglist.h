/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD-compatible scatter/gather lists for imported drivers. */

#ifndef __SGLIST_H__
#define __SGLIST_H__

#include <stddef.h>
#include <stdint.h>

struct sglist_seg {
    uint64_t ss_paddr;
    size_t ss_len;
};

struct sglist {
    struct sglist_seg *sg_segs;
    volatile unsigned int sg_refs;
    unsigned short sg_nseg;
    unsigned short sg_maxseg;
};

struct bio;
struct mbuf;
struct thread;
struct uio;
struct vm_page;

static __inline void
sglist_init(struct sglist *sg, unsigned short maxsegs,
    struct sglist_seg *segs)
{
    sg->sg_segs = segs;
    sg->sg_refs = 1;
    sg->sg_nseg = 0;
    sg->sg_maxseg = maxsegs;
}

static __inline void
sglist_reset(struct sglist *sg)
{
    sg->sg_nseg = 0;
}

static __inline struct sglist *
sglist_hold(struct sglist *sg)
{
    (void)__atomic_fetch_add(&sg->sg_refs, 1, __ATOMIC_RELAXED);
    return sg;
}

struct sglist *sglist_alloc(int nsegs, int mflags);
int sglist_append(struct sglist *sg, void *buffer, size_t length);
int sglist_append_bio(struct sglist *sg, struct bio *bio);
int sglist_append_mbuf(struct sglist *sg, struct mbuf *mbuf);
int sglist_append_mbuf_epg(struct sglist *sg, struct mbuf *mbuf,
    size_t offset, size_t length);
int sglist_append_phys(struct sglist *sg, uint64_t physical_address,
    size_t length);
int sglist_append_sglist(struct sglist *sg, struct sglist *source,
    size_t offset, size_t length);
int sglist_append_single_mbuf(struct sglist *sg, struct mbuf *mbuf);
int sglist_append_uio(struct sglist *sg, struct uio *uio);
int sglist_append_user(struct sglist *sg, void *buffer, size_t length,
    struct thread *thread);
int sglist_append_vmpages(struct sglist *sg, struct vm_page **pages,
    size_t page_offset, size_t length);
struct sglist *sglist_build(void *buffer, size_t length, int mflags);
struct sglist *sglist_clone(struct sglist *sg, int mflags);
int sglist_consume_uio(struct sglist *sg, struct uio *uio, size_t residual);
int sglist_count(void *buffer, size_t length);
int sglist_count_mbuf_epg(struct mbuf *mbuf, size_t offset, size_t length);
int sglist_count_vmpages(struct vm_page **pages, size_t page_offset,
    size_t length);
void sglist_free(struct sglist *sg);
int sglist_join(struct sglist *first, struct sglist *second);
size_t sglist_length(struct sglist *sg);
int sglist_slice(struct sglist *original, struct sglist **slice,
    size_t offset, size_t length, int mflags);
int sglist_split(struct sglist *original, struct sglist **head,
    size_t length, int mflags);

#endif
