/* SPDX-License-Identifier: MPL-2.0 */
/* Shared scatter/gather runtime for imported BSD drivers. */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/sys/bio.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/sys/sglist.h"
#include "compat/freebsd/sys/uio.h"
#include "compat/freebsd/vm/vm_page.h"

#define BSD_SGLIST_PAGE_SIZE PAGE_SIZE
#define BSD_SGLIST_ENOMEM 12
#define BSD_SGLIST_EINVAL 22
#define BSD_SGLIST_EFBIG 27
#define BSD_SGLIST_EOPNOTSUPP 45
#define BSD_SGLIST_EDOOFUS 88

struct sglist_save {
    struct sglist_seg last;
    unsigned short nseg;
};

static struct sglist_save
sglist_save_state(const struct sglist *sg)
{
    struct sglist_save save = {
        .nseg = sg->sg_nseg,
    };

    if (save.nseg != 0)
        save.last = sg->sg_segs[save.nseg - 1];
    return save;
}

static void
sglist_restore_state(struct sglist *sg, const struct sglist_save *save)
{
    sg->sg_nseg = save->nseg;
    if (save->nseg != 0)
        sg->sg_segs[save->nseg - 1] = save->last;
}

static int
sglist_append_range(struct sglist *sg, uint64_t physical_address,
    size_t length)
{
    struct sglist_seg *segment;

    if (!sg)
        return BSD_SGLIST_EINVAL;
    if (length == 0)
        return 0;
    if (physical_address > UINT64_MAX - (length - 1))
        return BSD_SGLIST_EINVAL;
    if (sg->sg_nseg != 0) {
        segment = &sg->sg_segs[sg->sg_nseg - 1];
        if (segment->ss_paddr <= UINT64_MAX - segment->ss_len &&
            segment->ss_paddr + segment->ss_len == physical_address &&
            segment->ss_len <= SIZE_MAX - length) {
            segment->ss_len += length;
            return 0;
        }
    }
    if (sg->sg_nseg >= sg->sg_maxseg)
        return BSD_SGLIST_EFBIG;
    segment = &sg->sg_segs[sg->sg_nseg++];
    segment->ss_paddr = physical_address;
    segment->ss_len = length;
    return 0;
}

struct sglist *
sglist_alloc(int nsegs, int mflags)
{
    struct sglist *sg;
    size_t bytes;

    if (nsegs <= 0 || nsegs > UINT16_MAX ||
        (size_t)nsegs > (SIZE_MAX - sizeof(*sg)) /
        sizeof(struct sglist_seg))
        return 0;
    bytes = sizeof(*sg) + (size_t)nsegs * sizeof(struct sglist_seg);
    sg = bsd_malloc(bytes, M_TEMP, mflags | M_ZERO);
    if (!sg)
        return 0;
    sglist_init(sg, (unsigned short)nsegs,
        (struct sglist_seg *)(void *)(sg + 1));
    return sg;
}

int
sglist_append(struct sglist *sg, void *buffer, size_t length)
{
    uint8_t *cursor = buffer;
    struct sglist_save save;

    if (!sg || (!buffer && length != 0) ||
        (uintptr_t)buffer > UINTPTR_MAX - length)
        return BSD_SGLIST_EINVAL;
    save = sglist_save_state(sg);
    while (length != 0) {
        size_t page_length = BSD_SGLIST_PAGE_SIZE -
            ((uintptr_t)cursor & (BSD_SGLIST_PAGE_SIZE - 1));
        uint64_t physical_address;
        int error;

        if (page_length > length)
            page_length = length;
        if (bsd_bus_dma_physical_address(cursor, &physical_address) != 0) {
            sglist_restore_state(sg, &save);
            return BSD_SGLIST_EINVAL;
        }
        error = sglist_append_range(sg, physical_address, page_length);
        if (error) {
            sglist_restore_state(sg, &save);
            return error;
        }
        cursor += page_length;
        length -= page_length;
    }
    return 0;
}

int
sglist_append_phys(struct sglist *sg, uint64_t physical_address,
    size_t length)
{
    return sglist_append_range(sg, physical_address, length);
}

int
sglist_count(void *buffer, size_t length)
{
    uint8_t *cursor = buffer;
    uint64_t previous_end = 0;
    int count = 0;

    if ((!buffer && length != 0) ||
        (uintptr_t)buffer > UINTPTR_MAX - length)
        return 0;
    while (length != 0) {
        size_t page_length = BSD_SGLIST_PAGE_SIZE -
            ((uintptr_t)cursor & (BSD_SGLIST_PAGE_SIZE - 1));
        uint64_t physical_address;

        if (page_length > length)
            page_length = length;
        if (bsd_bus_dma_physical_address(cursor, &physical_address) != 0)
            return 0;
        if (count == 0 || physical_address != previous_end) {
            if (count == INT_MAX)
                return 0;
            count++;
        }
        if (physical_address > UINT64_MAX - page_length)
            return 0;
        previous_end = physical_address + page_length;
        cursor += page_length;
        length -= page_length;
    }
    return count;
}

struct sglist *
sglist_build(void *buffer, size_t length, int mflags)
{
    struct sglist *sg;
    int count = sglist_count(buffer, length);

    if (count <= 0)
        return 0;
    sg = sglist_alloc(count, mflags);
    if (!sg)
        return 0;
    if (length != 0 && sglist_append(sg, buffer, length) != 0) {
        sglist_free(sg);
        return 0;
    }
    return sg;
}

void
sglist_free(struct sglist *sg)
{
    if (!sg)
        return;
    if (__atomic_sub_fetch(&sg->sg_refs, 1, __ATOMIC_ACQ_REL) == 0)
        bsd_free(sg, M_TEMP);
}

struct sglist *
sglist_clone(struct sglist *source, int mflags)
{
    struct sglist *clone;

    if (!source)
        return 0;
    clone = sglist_alloc(source->sg_maxseg, mflags);
    if (!clone)
        return 0;
    clone->sg_nseg = source->sg_nseg;
    for (unsigned int index = 0; index < source->sg_nseg; ++index)
        clone->sg_segs[index] = source->sg_segs[index];
    return clone;
}

size_t
sglist_length(struct sglist *sg)
{
    size_t length = 0;

    if (!sg)
        return 0;
    for (unsigned int index = 0; index < sg->sg_nseg; ++index) {
        if (length > SIZE_MAX - sg->sg_segs[index].ss_len)
            return SIZE_MAX;
        length += sg->sg_segs[index].ss_len;
    }
    return length;
}

int
sglist_append_sglist(struct sglist *sg, struct sglist *source,
    size_t offset, size_t length)
{
    struct sglist_save save;
    size_t source_length;

    if (!sg || !source)
        return BSD_SGLIST_EINVAL;
    source_length = sglist_length(source);
    if (offset > source_length || length > source_length - offset)
        return BSD_SGLIST_EINVAL;
    save = sglist_save_state(sg);
    for (unsigned int index = 0;
        index < source->sg_nseg && length != 0; ++index) {
        struct sglist_seg *segment = &source->sg_segs[index];
        size_t portion;
        int error;

        if (offset >= segment->ss_len) {
            offset -= segment->ss_len;
            continue;
        }
        portion = segment->ss_len - offset;
        if (portion > length)
            portion = length;
        error = sglist_append_range(sg, segment->ss_paddr + offset,
            portion);
        if (error) {
            sglist_restore_state(sg, &save);
            return error;
        }
        length -= portion;
        offset = 0;
    }
    return 0;
}

int
sglist_join(struct sglist *first, struct sglist *second)
{
    unsigned int merged = 0;
    unsigned int required;

    if (!first || !second || first == second)
        return BSD_SGLIST_EINVAL;
    if (second->sg_nseg == 0)
        return 0;
    if (first->sg_nseg != 0) {
        struct sglist_seg *last = &first->sg_segs[first->sg_nseg - 1];
        struct sglist_seg *next = &second->sg_segs[0];

        if (last->ss_paddr <= UINT64_MAX - last->ss_len &&
            last->ss_paddr + last->ss_len == next->ss_paddr) {
            if (last->ss_len > SIZE_MAX - next->ss_len)
                return BSD_SGLIST_EINVAL;
            merged = 1;
        }
    }
    required = first->sg_nseg + second->sg_nseg - merged;
    if (required > first->sg_maxseg)
        return BSD_SGLIST_EFBIG;
    if (merged != 0)
        first->sg_segs[first->sg_nseg - 1].ss_len +=
            second->sg_segs[0].ss_len;
    for (unsigned int index = merged; index < second->sg_nseg; ++index)
        first->sg_segs[first->sg_nseg++] = second->sg_segs[index];
    sglist_reset(second);
    return 0;
}

int
sglist_slice(struct sglist *original, struct sglist **slice,
    size_t offset, size_t length, int mflags)
{
    struct sglist *result;
    size_t total;
    size_t skipped = 0;
    unsigned int count = 0;
    unsigned int first_segment = 0;
    size_t first_offset = 0;

    if (!slice || !original)
        return BSD_SGLIST_EINVAL;
    if (length == 0)
        return 0;
    total = sglist_length(original);
    if (offset > total || length > total - offset)
        return BSD_SGLIST_EINVAL;

    for (unsigned int index = 0; index < original->sg_nseg; ++index) {
        size_t segment_length = original->sg_segs[index].ss_len;

        if (offset >= skipped + segment_length) {
            skipped += segment_length;
            continue;
        }
        if (count == 0) {
            first_segment = index;
            first_offset = offset - skipped;
        }
        count++;
        if (skipped + segment_length >= offset + length)
            break;
        skipped += segment_length;
    }

    result = *slice;
    if (!result) {
        result = sglist_alloc((int)count, mflags);
        if (!result)
            return BSD_SGLIST_ENOMEM;
        *slice = result;
    } else {
        if (result->sg_nseg != 0)
            return BSD_SGLIST_EINVAL;
        if (result->sg_maxseg < count)
            return BSD_SGLIST_EFBIG;
    }

    for (unsigned int index = 0; index < count; ++index)
        result->sg_segs[index] =
            original->sg_segs[first_segment + index];
    result->sg_nseg = (unsigned short)count;
    result->sg_segs[0].ss_paddr += first_offset;
    result->sg_segs[0].ss_len -= first_offset;
    total = sglist_length(result);
    if (total > length)
        result->sg_segs[count - 1].ss_len -= total - length;
    return 0;
}

static void
sglist_remove_front(struct sglist *sg, unsigned int count)
{
    for (unsigned int index = count; index < sg->sg_nseg; ++index)
        sg->sg_segs[index - count] = sg->sg_segs[index];
    sg->sg_nseg -= (unsigned short)count;
}

int
sglist_split(struct sglist *original, struct sglist **head,
    size_t length, int mflags)
{
    struct sglist *result;
    size_t consumed_before = 0;
    size_t total;
    size_t last_consumed;
    unsigned int count = 0;

    if (!original || !head)
        return BSD_SGLIST_EINVAL;
    if (original->sg_refs > 1)
        return BSD_SGLIST_EDOOFUS;
    if (length == 0 || original->sg_nseg == 0)
        return 0;

    total = sglist_length(original);
    for (unsigned int index = 0; index < original->sg_nseg; ++index) {
        count++;
        if (consumed_before + original->sg_segs[index].ss_len >= length)
            break;
        consumed_before += original->sg_segs[index].ss_len;
    }

    result = *head;
    if (!result) {
        result = sglist_alloc((int)count, mflags);
        if (!result)
            return BSD_SGLIST_ENOMEM;
        *head = result;
    } else {
        if (result->sg_nseg != 0)
            return BSD_SGLIST_EINVAL;
        if (result->sg_maxseg < count)
            return BSD_SGLIST_EFBIG;
    }
    for (unsigned int index = 0; index < count; ++index)
        result->sg_segs[index] = original->sg_segs[index];
    result->sg_nseg = (unsigned short)count;

    if (length >= total) {
        original->sg_nseg = 0;
        return 0;
    }
    last_consumed = length - consumed_before;
    result->sg_segs[count - 1].ss_len = last_consumed;
    if (last_consumed == original->sg_segs[count - 1].ss_len) {
        sglist_remove_front(original, count);
    } else {
        original->sg_segs[count - 1].ss_paddr += last_consumed;
        original->sg_segs[count - 1].ss_len -= last_consumed;
        sglist_remove_front(original, count - 1);
    }
    return 0;
}

int
sglist_append_user(struct sglist *sg, void *buffer, size_t length,
    struct thread *thread)
{
    (void)thread;
    return sglist_append(sg, buffer, length);
}

int
sglist_append_bio(struct sglist *sg, struct bio *bio)
{
    if (!bio || (bio->bio_flags & BIO_UNMAPPED) != 0 ||
        !bio->bio_data || bio->bio_bcount <= 0)
        return BSD_SGLIST_EINVAL;
    return sglist_append(sg, bio->bio_data, (size_t)bio->bio_bcount);
}

int
sglist_append_mbuf(struct sglist *sg, struct mbuf *mbuf)
{
    unsigned short saved;
    int error;

    if (!sg || !mbuf)
        return BSD_SGLIST_EINVAL;
    saved = sg->sg_nseg;
    for (; mbuf; mbuf = mbuf->m_next) {
        if (mbuf->m_len < 0 || (!mbuf->m_data && mbuf->m_len != 0)) {
            sg->sg_nseg = saved;
            return BSD_SGLIST_EINVAL;
        }
        if (mbuf->m_len == 0)
            continue;
        error = sglist_append(sg, mbuf->m_data, (size_t)mbuf->m_len);
        if (error != 0) {
            sg->sg_nseg = saved;
            return error;
        }
    }
    return sg->sg_nseg == saved ? BSD_SGLIST_EINVAL : 0;
}

int
sglist_append_mbuf_epg(struct sglist *sg, struct mbuf *mbuf,
    size_t offset, size_t length)
{
    unsigned short saved;
    size_t remaining = length;
    int error;

    if (!sg || !mbuf || length == 0)
        return BSD_SGLIST_EINVAL;
    saved = sg->sg_nseg;
    while (mbuf) {
        if (mbuf->m_len < 0 || (!mbuf->m_data && mbuf->m_len != 0)) {
            sg->sg_nseg = saved;
            return BSD_SGLIST_EINVAL;
        }
        if (offset < (size_t)mbuf->m_len)
            break;
        offset -= (size_t)mbuf->m_len;
        mbuf = mbuf->m_next;
    }
    while (mbuf && remaining != 0) {
        size_t available;
        size_t take;

        if (mbuf->m_len < 0 || !mbuf->m_data) {
            sg->sg_nseg = saved;
            return BSD_SGLIST_EINVAL;
        }
        available = (size_t)mbuf->m_len - offset;
        take = available < remaining ? available : remaining;
        if (take != 0) {
            error = sglist_append(sg, mbuf->m_data + offset, take);
            if (error != 0) {
                sg->sg_nseg = saved;
                return error;
            }
            remaining -= take;
        }
        offset = 0;
        mbuf = mbuf->m_next;
    }
    if (remaining != 0) {
        sg->sg_nseg = saved;
        return BSD_SGLIST_EINVAL;
    }
    return 0;
}

int
sglist_append_single_mbuf(struct sglist *sg, struct mbuf *mbuf)
{
    return sglist_append_mbuf(sg, mbuf);
}

int
sglist_append_uio(struct sglist *sg, struct uio *uio)
{
    struct sglist_save save;
    size_t residual;

    if (!sg || !uio || uio->uio_iovcnt < 0 ||
        uio->uio_iovcnt > UIO_MAXIOV || uio->uio_resid < 0 ||
        (uio->uio_iovcnt != 0 && !uio->uio_iov) ||
        (uio->uio_segflg == UIO_USERSPACE && !uio->uio_td))
        return BSD_SGLIST_EINVAL;
    residual = (size_t)uio->uio_resid;
    save = sglist_save_state(sg);
    for (int index = 0;
        index < uio->uio_iovcnt && residual != 0; ++index) {
        size_t length = uio->uio_iov[index].iov_len;
        int error;

        if (length > residual)
            length = residual;
        error = sglist_append(sg, uio->uio_iov[index].iov_base, length);
        if (error) {
            sglist_restore_state(sg, &save);
            return error;
        }
        residual -= length;
    }
    return 0;
}

int
sglist_append_vmpages(struct sglist *sg, struct vm_page **pages,
    size_t page_offset, size_t length)
{
    struct sglist_save save;
    size_t page_index = 0;

    if (!sg || (length != 0 && !pages) ||
        (length != 0 && page_offset >= BSD_SGLIST_PAGE_SIZE))
        return BSD_SGLIST_EINVAL;
    save = sglist_save_state(sg);
    while (length != 0) {
        size_t segment_length = BSD_SGLIST_PAGE_SIZE - page_offset;
        uint64_t physical_address;
        int error;

        if (!pages[page_index]) {
            sglist_restore_state(sg, &save);
            return BSD_SGLIST_EINVAL;
        }
        if (segment_length > length)
            segment_length = length;
        physical_address = VM_PAGE_TO_PHYS(pages[page_index]);
        if (physical_address > UINT64_MAX - page_offset) {
            sglist_restore_state(sg, &save);
            return BSD_SGLIST_EINVAL;
        }
        error = sglist_append_range(sg,
            physical_address + page_offset, segment_length);
        if (error) {
            sglist_restore_state(sg, &save);
            return error;
        }
        length -= segment_length;
        page_offset = 0;
        page_index++;
    }
    return 0;
}

static int
sglist_append_partial(struct sglist *sg, void *buffer, size_t length,
    size_t *consumed)
{
    uint8_t *cursor = buffer;

    *consumed = 0;
    if ((!buffer && length != 0) ||
        (uintptr_t)buffer > UINTPTR_MAX - length)
        return BSD_SGLIST_EINVAL;
    while (length != 0) {
        size_t page_length = BSD_SGLIST_PAGE_SIZE -
            ((uintptr_t)cursor & (BSD_SGLIST_PAGE_SIZE - 1));
        uint64_t physical_address;
        int error;

        if (page_length > length)
            page_length = length;
        if (bsd_bus_dma_physical_address(cursor, &physical_address) != 0)
            return BSD_SGLIST_EINVAL;
        error = sglist_append_range(sg, physical_address, page_length);
        if (error)
            return error;
        *consumed += page_length;
        cursor += page_length;
        length -= page_length;
    }
    return 0;
}

int
sglist_consume_uio(struct sglist *sg, struct uio *uio, size_t residual)
{
    if (!sg || !uio || uio->uio_iovcnt < 0 ||
        uio->uio_iovcnt > UIO_MAXIOV || uio->uio_resid < 0 ||
        (uio->uio_iovcnt != 0 && !uio->uio_iov) ||
        (uio->uio_segflg == UIO_USERSPACE && !uio->uio_td))
        return BSD_SGLIST_EINVAL;
    while (residual != 0 && uio->uio_resid != 0 &&
        uio->uio_iovcnt != 0) {
        struct iovec *vector = uio->uio_iov;
        size_t length = vector->iov_len;
        size_t consumed;
        int error;

        if (length == 0) {
            uio->uio_iov++;
            uio->uio_iovcnt--;
            continue;
        }
        if (length > residual)
            length = residual;
        if (length > (size_t)uio->uio_resid)
            length = (size_t)uio->uio_resid;
        error = sglist_append_partial(sg, vector->iov_base,
            length, &consumed);
        vector->iov_base = (uint8_t *)vector->iov_base + consumed;
        vector->iov_len -= consumed;
        uio->uio_resid -= (intptr_t)consumed;
        uio->uio_offset += (int64_t)consumed;
        residual -= consumed;
        if (error)
            break;
    }
    return 0;
}

int
sglist_count_mbuf_epg(struct mbuf *mbuf, size_t offset, size_t length)
{
    struct sglist scratch;
    struct sglist_seg segments[64];
    int error;

    sglist_init(&scratch, 64, segments);
    error = sglist_append_mbuf_epg(&scratch, mbuf, offset, length);
    return error == 0 ? scratch.sg_nseg : error;
}

int
sglist_count_vmpages(struct vm_page **pages, size_t page_offset,
    size_t length)
{
    uint64_t previous_end = 0;
    size_t page_index = 0;
    int count = 0;

    if ((length != 0 && !pages) ||
        (length != 0 && page_offset >= BSD_SGLIST_PAGE_SIZE))
        return 0;
    while (length != 0) {
        size_t segment_length = BSD_SGLIST_PAGE_SIZE - page_offset;
        uint64_t physical_address;

        if (!pages[page_index])
            return 0;
        if (segment_length > length)
            segment_length = length;
        physical_address = VM_PAGE_TO_PHYS(pages[page_index]);
        if (physical_address > UINT64_MAX - page_offset)
            return 0;
        physical_address += page_offset;
        if (count == 0 || physical_address != previous_end) {
            if (count == INT_MAX)
                return 0;
            count++;
        }
        if (physical_address > UINT64_MAX - segment_length)
            return 0;
        previous_end = physical_address + segment_length;
        length -= segment_length;
        page_offset = 0;
        page_index++;
    }
    return count;
}
