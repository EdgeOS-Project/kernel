/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared BSD scatter/gather runtime. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/sys/bio.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/sys/sglist.h"
#include "compat/freebsd/sys/uio.h"
#include "compat/freebsd/vm/vm_page.h"

#define TEST_EFBIG 27

static int g_use_gapped_translation;

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U,
        (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static int
test_physical_address(const void *pointer, uint64_t *physical_address,
    void *context)
{
    uintptr_t value = (uintptr_t)pointer;

    (void)context;
    if (g_use_gapped_translation)
        *physical_address = ((uint64_t)(value >> 12) << 13) |
            (value & 4095U);
    else
        *physical_address = (uint64_t)value;
    return 0;
}

static void *
test_dma_allocate_pages(uint64_t page_count, uint32_t flags, void *context)
{
    (void)flags;
    return test_allocate_pages(page_count, context);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    bsd_bus_dma_ops_t dma_operations = {
        .allocate_pages = test_dma_allocate_pages,
        .release_pages = test_release_pages,
        .physical_address = test_physical_address,
    };
    uint8_t *buffer;
    struct sglist *list;
    struct sglist *slice;
    struct sglist *clone;
    struct sglist *head;
    struct sglist *split;
    struct sglist *transaction;
    struct sglist *pages_list;
    struct vm_page page_descriptors[3] = {
        { .phys_addr = 0x1000 },
        { .phys_addr = 0x2000 },
        { .phys_addr = 0x5000 },
    };
    vm_page_t pages[3] = {
        &page_descriptors[0],
        &page_descriptors[1],
        &page_descriptors[2],
    };
    struct iovec vectors[2];
    struct uio request;
    struct bio bio;
    struct mbuf first_mbuf = {0};
    struct mbuf second_mbuf = {0};
    struct sglist *mbuf_list;
    uint8_t *second_buffer;

    assert(bsd_allocator_initialize(&allocator_operations) == 0);
    assert(bsd_bus_dma_initialize(&dma_operations) == 0);
    assert(sglist_count(0, 0) == 0);
    assert(sglist_build(0, 0, M_WAITOK) == 0);
    assert(sglist_append_phys(0, 0, 0) != 0);

    buffer = bsd_malloc_aligned(8192, 4096, M_TEMP, M_WAITOK | M_ZERO);
    assert(buffer != 0);
    list = sglist_build(buffer + 4000, 4200, M_WAITOK);
    assert(list != 0);
    assert(list->sg_nseg == 1);
    assert(sglist_length(list) == 4200);

    clone = sglist_clone(list, M_WAITOK);
    assert(clone != 0);
    assert(clone->sg_nseg == 1);
    assert(clone->sg_segs[0].ss_paddr ==
        list->sg_segs[0].ss_paddr);

    slice = 0;
    assert(sglist_slice(list, &slice, 100, 500, M_WAITOK) == 0);
    assert(slice != 0);
    assert(sglist_length(slice) == 500);
    assert(slice->sg_segs[0].ss_paddr ==
        list->sg_segs[0].ss_paddr + 100);

    split = sglist_alloc(4, M_WAITOK);
    assert(split != 0);
    assert(sglist_append_phys(split, 0x1000, 100) == 0);
    assert(sglist_append_phys(split, 0x3000, 200) == 0);
    assert(sglist_append_phys(split, 0x5000, 300) == 0);
    head = sglist_alloc(4, M_WAITOK);
    assert(head != 0);
    assert(sglist_split(split, &head, 150, M_WAITOK) == 0);
    assert(head != 0);
    assert(head->sg_nseg == 2);
    assert(head->sg_segs[1].ss_len == 50);
    assert(split->sg_nseg == 2);
    assert(split->sg_segs[0].ss_paddr == 0x3032);
    assert(split->sg_segs[0].ss_len == 150);
    assert(sglist_join(head, split) == 0);
    assert(split->sg_nseg == 0);
    assert(head->sg_nseg == 3);
    assert(sglist_length(head) == 600);

    assert(sglist_count_vmpages(pages, 100, 8292) == 2);
    pages_list = sglist_alloc(2, M_WAITOK);
    assert(pages_list != 0);
    assert(sglist_append_vmpages(pages_list, pages, 100, 8292) == 0);
    assert(pages_list->sg_nseg == 2);
    assert(pages_list->sg_segs[0].ss_paddr == 0x1064);
    assert(pages_list->sg_segs[0].ss_len == 8092);
    assert(pages_list->sg_segs[1].ss_paddr == 0x5000);
    assert(pages_list->sg_segs[1].ss_len == 200);
    assert(sglist_append_vmpages(pages_list, pages, 4096, 1) != 0);

    transaction = sglist_alloc(1, M_WAITOK);
    assert(transaction != 0);
    assert(sglist_append_vmpages(transaction, pages, 0, 8193) ==
        TEST_EFBIG);
    assert(transaction->sg_nseg == 0);
    g_use_gapped_translation = 1;
    assert(sglist_append(transaction, buffer + 4000, 4200) ==
        TEST_EFBIG);
    assert(transaction->sg_nseg == 0);
    g_use_gapped_translation = 0;

    bio = (struct bio) {
        .bio_data = (char *)(void *)buffer,
        .bio_bcount = 4096,
    };
    sglist_reset(transaction);
    assert(sglist_append_bio(transaction, &bio) == 0);
    assert(sglist_length(transaction) == 4096);
    bio.bio_flags = BIO_UNMAPPED;
    assert(sglist_append_bio(transaction, &bio) != 0);
    assert(sglist_length(transaction) == 4096);

    second_buffer = bsd_malloc_aligned(4096, 4096, M_TEMP,
        M_WAITOK | M_ZERO);
    assert(second_buffer != 0);
    first_mbuf.m_data = (char *)buffer;
    first_mbuf.m_len = 96;
    first_mbuf.m_next = &second_mbuf;
    second_mbuf.m_data = (char *)second_buffer;
    second_mbuf.m_len = 64;
    mbuf_list = sglist_alloc(8, M_WAITOK);
    assert(mbuf_list != 0);
    assert(sglist_append_mbuf(mbuf_list, &first_mbuf) == 0);
    assert(sglist_length(mbuf_list) == 160);
    sglist_reset(mbuf_list);
    assert(sglist_append_mbuf_epg(mbuf_list, &first_mbuf, 32, 96) == 0);
    assert(sglist_length(mbuf_list) == 96);
    assert(sglist_count_mbuf_epg(&first_mbuf, 32, 96) > 0);
    sglist_free(mbuf_list);
    vectors[0].iov_base = buffer;
    vectors[0].iov_len = 128;
    vectors[1].iov_base = second_buffer;
    vectors[1].iov_len = 256;
    request = (struct uio) {
        .uio_iov = vectors,
        .uio_iovcnt = 2,
        .uio_offset = 0,
        .uio_resid = 384,
        .uio_segflg = UIO_SYSSPACE,
        .uio_rw = UIO_WRITE,
    };
    sglist_reset(transaction);
    g_use_gapped_translation = 1;
    assert(sglist_append_uio(transaction, &request) == TEST_EFBIG);
    assert(transaction->sg_nseg == 0);

    assert(sglist_consume_uio(transaction, &request, 384) == 0);
    assert(transaction->sg_nseg == 1);
    assert(request.uio_resid > 0);
    assert(request.uio_resid < 384);
    assert(request.uio_offset > 0);
    g_use_gapped_translation = 0;

    bsd_free(second_buffer, M_TEMP);
    sglist_free(transaction);
    sglist_free(pages_list);
    sglist_free(head);
    sglist_free(split);
    sglist_free(slice);
    sglist_free(clone);
    sglist_free(list);
    bsd_free(buffer, M_TEMP);
    return 0;
}
