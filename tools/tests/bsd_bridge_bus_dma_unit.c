/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD Driver Bridge bus-DMA implementation. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/machine/bus.h"
#include "compat/freebsd/sys/bio.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/sys/uio.h"
#include "compat/freebsd/vm/pmap.h"

#define TEST_PAGE_SIZE 4096U

typedef struct {
    int sync_count;
    bus_dmasync_op_t last_sync;
    int callback_count;
    int callback_error;
    int callback_segments;
    bus_size_t callback_length;
    bus_dma_segment_t segments[4];
} test_context_t;

static void *
test_allocate_pages(uint64_t page_count, uint32_t flags, void *context)
{
    void *memory = 0;

    (void)flags;
    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
            (size_t)page_count * TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0xa5, (size_t)page_count * TEST_PAGE_SIZE);
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
test_physical_address(const void *pointer, uint64_t *physical, void *context)
{
    (void)context;
    *physical = (uint64_t)(uintptr_t)pointer;
    return 0;
}

static int
test_virtual_address(uint64_t physical, size_t length, void **virtual_address,
    void *context)
{
    (void)context;
    if (!physical || length == 0 || !virtual_address)
        return -1;
    *virtual_address = (void *)(uintptr_t)physical;
    return 0;
}

static void
test_sync(void *buffer, size_t length, int operation, void *opaque_context)
{
    test_context_t *context = opaque_context;

    assert(buffer != 0);
    assert(length != 0);
    context->sync_count++;
    context->last_sync = operation;
}

static void
test_load_callback(void *opaque_context, bus_dma_segment_t *segments,
    int segment_count, int error)
{
    test_context_t *context = opaque_context;

    context->callback_count++;
    context->callback_error = error;
    context->callback_segments = segment_count;
    for (int index = 0; index < segment_count; ++index)
        context->segments[index] = segments[index];
}

static void
test_load_callback2(void *opaque_context, bus_dma_segment_t *segments,
    int segment_count, bus_size_t length, int error)
{
    test_context_t *context = opaque_context;

    test_load_callback(context, segments, segment_count, error);
    context->callback_length = length;
}

static void *
allocator_allocate_pages(uint64_t page_count, void *context)
{
    return test_allocate_pages(page_count, 0, context);
}

static void
test_dma_contract(test_context_t *context)
{
    bus_dma_tag_t tag;
    bus_dmamap_t map;
    uint8_t *buffer;

    assert(bus_dma_tag_create(0, TEST_PAGE_SIZE, 0, BUS_SPACE_MAXADDR,
        BUS_SPACE_MAXADDR, 0, 0, TEST_PAGE_SIZE * 2, 2,
        TEST_PAGE_SIZE * 2, BUS_DMA_COHERENT, 0, 0, &tag) == 0);
    assert(bus_dmamem_alloc(tag, (void **)&buffer,
        BUS_DMA_NOWAIT | BUS_DMA_ZERO | BUS_DMA_COHERENT, &map) == 0);
    assert(((uintptr_t)buffer & (TEST_PAGE_SIZE - 1)) == 0);
    for (size_t index = 0; index < TEST_PAGE_SIZE * 2; ++index)
        assert(buffer[index] == 0);

    assert(bus_dmamap_load(tag, map, buffer, TEST_PAGE_SIZE * 2,
        test_load_callback, context, BUS_DMA_NOWAIT) == 0);
    assert(context->callback_count == 1);
    assert(context->callback_error == 0);
    assert(context->callback_segments == 1);
    assert(context->segments[0].ds_len == TEST_PAGE_SIZE * 2);

    bus_dmamap_sync(tag, map, BUS_DMASYNC_PREWRITE);
    assert(context->sync_count == 1);
    assert(context->last_sync == BUS_DMASYNC_PREWRITE);

    bus_dmamap_unload(tag, map);
    bus_dmamem_free(tag, buffer, map);
    assert(bus_dma_tag_destroy(tag) == 0);
}

static void
test_segment_limit(test_context_t *context)
{
    bus_dma_tag_t tag;
    bus_dmamap_t map;
    uint8_t *buffer;

    assert(posix_memalign((void **)&buffer, TEST_PAGE_SIZE,
        TEST_PAGE_SIZE * 3) == 0);
    assert(bus_dma_tag_create(0, 1, 0, BUS_SPACE_MAXADDR,
        BUS_SPACE_MAXADDR, 0, 0, TEST_PAGE_SIZE * 3, 2,
        TEST_PAGE_SIZE, 0, 0, 0, &tag) == 0);
    assert(bus_dmamap_create(tag, BUS_DMA_NOWAIT, &map) == 0);
    context->callback_count = 0;
    assert(bus_dmamap_load(tag, map, buffer, TEST_PAGE_SIZE * 3,
        test_load_callback, context, BUS_DMA_NOWAIT) == 27);
    assert(context->callback_count == 1);
    assert(context->callback_error == 27);
    assert(context->callback_segments == 0);
    assert(bus_dmamap_destroy(tag, map) == 0);
    assert(bus_dma_tag_destroy(tag) == 0);
    free(buffer);
}

static void
test_tag_and_map_lifecycle(test_context_t *context)
{
    bus_dma_tag_t parent;
    bus_dma_tag_t child;
    bus_dmamap_t map;
    uint8_t *buffer;
    int iommu;
    int domain;

    assert(posix_memalign((void **)&buffer, TEST_PAGE_SIZE,
        TEST_PAGE_SIZE) == 0);
    assert(bus_dma_tag_create(0, 1, 0, BUS_SPACE_MAXADDR,
        BUS_SPACE_MAXADDR, 0, 0, TEST_PAGE_SIZE, 1,
        TEST_PAGE_SIZE, 0, 0, 0, &parent) == 0);
    assert(bus_dma_tag_create(parent, 1, 0, BUS_SPACE_MAXADDR,
        BUS_SPACE_MAXADDR, 0, 0, TEST_PAGE_SIZE, 1,
        TEST_PAGE_SIZE, 0, 0, 0, &child) == 0);
    assert(bus_dma_tag_destroy(parent) == 16);
    assert(bus_dma_tag_set_iommu(child, 0, 0) == 0);
    assert(bus_dma_tag_set_iommu(child, &iommu, 0) == 22);
    assert(bus_dma_tag_set_iommu(child, &iommu, &domain) == 95);

    assert(bus_dmamap_create(child, BUS_DMA_NOWAIT, &map) == 0);
    assert(bus_dma_tag_destroy(child) == 16);
    assert(bus_dma_tag_set_domain(child, 1) == 16);
    assert(bus_dma_tag_set_iommu(child, 0, 0) == 16);
    context->callback_count = 0;
    assert(bus_dmamap_load(child, map, buffer, TEST_PAGE_SIZE,
        test_load_callback, context, BUS_DMA_NOWAIT) == 0);
    assert(bus_dmamap_load(child, map, buffer, TEST_PAGE_SIZE,
        test_load_callback, context, BUS_DMA_NOWAIT) == 16);
    assert(context->callback_count == 2);
    assert(context->callback_error == 16);
    assert(bus_dmamap_destroy(child, map) == 16);

    context->sync_count = 0;
    bus_dmamap_sync(child, map, BUS_DMASYNC_PREREAD);
    assert(context->sync_count == 1);
    bus_dmamap_unload(child, map);
    assert(bus_dmamap_destroy(child, map) == 0);
    assert(bus_dma_tag_set_domain(child, 1) == 0);
    assert(bus_dma_tag_destroy(child) == 0);
    assert(bus_dma_tag_destroy(parent) == 0);
    free(buffer);
}

static void
test_exclusion_and_rollback(test_context_t *context)
{
    bus_dma_tag_t tag;
    bus_dmamap_t map;
    uint8_t *buffer;
    bus_addr_t physical;

    assert(posix_memalign((void **)&buffer, TEST_PAGE_SIZE,
        TEST_PAGE_SIZE) == 0);
    physical = (bus_addr_t)(uintptr_t)buffer;
    assert(bus_dma_tag_create(0, 1, 0, physical + 1023,
        BUS_SPACE_MAXADDR, 0, 0, TEST_PAGE_SIZE, 2,
        TEST_PAGE_SIZE, 0, 0, 0, &tag) == 0);
    assert(bus_dmamap_create(tag, BUS_DMA_NOWAIT, &map) == 0);

    context->callback_count = 0;
    assert(bus_dmamap_load(tag, map, buffer, TEST_PAGE_SIZE,
        test_load_callback, context, BUS_DMA_NOWAIT) == 27);
    assert(context->callback_count == 1);
    assert(context->callback_error == 27);
    assert(context->callback_segments == 0);
    assert(bus_dmamap_load(tag, map, buffer, 512,
        test_load_callback, context, BUS_DMA_NOWAIT) == 0);
    bus_dmamap_unload(tag, map);

    assert(bus_dmamap_destroy(tag, map) == 0);
    assert(bus_dma_tag_destroy(tag) == 0);
    free(buffer);
}

static void
test_bio_load(test_context_t *context)
{
    bus_dma_tag_t tag;
    bus_dmamap_t map;
    struct bio bio = {0};
    uint8_t *buffer;

    assert(posix_memalign((void **)&buffer, TEST_PAGE_SIZE,
        TEST_PAGE_SIZE) == 0);
    assert(bus_dma_tag_create(0, 1, 0, BUS_SPACE_MAXADDR,
        BUS_SPACE_MAXADDR, 0, 0, TEST_PAGE_SIZE, 2,
        TEST_PAGE_SIZE, 0, 0, 0, &tag) == 0);
    assert(bus_dmamap_create(tag, BUS_DMA_NOWAIT, &map) == 0);
    bio.bio_data = (char *)(void *)buffer;
    bio.bio_bcount = TEST_PAGE_SIZE;
    context->callback_count = 0;
    assert(bus_dmamap_load_bio(tag, map, &bio, test_load_callback,
        context, BUS_DMA_NOWAIT) == 0);
    assert(context->callback_count == 1);
    assert(context->callback_error == 0);
    bus_dmamap_unload(tag, map);

    bio.bio_flags = BIO_UNMAPPED;
    context->callback_count = 0;
    assert(bus_dmamap_load_bio(tag, map, &bio, test_load_callback,
        context, BUS_DMA_NOWAIT) == 22);
    assert(context->callback_count == 1);
    assert(context->callback_error == 22);
    assert(bus_dmamap_destroy(tag, map) == 0);
    assert(bus_dma_tag_destroy(tag) == 0);
    free(buffer);
}

static void
test_mbuf_mapping(test_context_t *context)
{
    bus_dma_tag_t tag;
    bus_dmamap_t map;
    bus_dma_segment_t segments[4];
    struct mbuf first = {0};
    struct mbuf second = {0};
    uint8_t first_data[32];
    uint8_t second_data[48];
    int segment_count = 0;
    int previous_sync_count = context->sync_count;

    first.m_data = (char *)first_data;
    first.m_len = sizeof(first_data);
    first.m_flags = M_PKTHDR;
    first.m_pkthdr.len = sizeof(first_data) + sizeof(second_data);
    first.m_next = &second;
    second.m_data = (char *)second_data;
    second.m_len = sizeof(second_data);

    assert(bus_dma_tag_create(0, 1, 0, BUS_SPACE_MAXADDR,
        BUS_SPACE_MAXADDR, 0, 0, sizeof(first_data) + sizeof(second_data),
        4, TEST_PAGE_SIZE, 0, 0, 0, &tag) == 0);
    assert(bus_dmamap_create(tag, BUS_DMA_NOWAIT, &map) == 0);
    assert(bus_dmamap_load_mbuf_sg(tag, map, &first, segments,
        &segment_count, BUS_DMA_NOWAIT) == 0);
    assert(segment_count >= 1 && segment_count <= 4);
    bus_dmamap_sync(tag, map, BUS_DMASYNC_PREWRITE);
    assert(context->sync_count == previous_sync_count + 2);
    bus_dmamap_unload(tag, map);

    context->callback_count = 0;
    context->callback_length = 0;
    assert(bus_dmamap_load_mbuf(tag, map, &first, test_load_callback2,
        context, BUS_DMA_NOWAIT) == 0);
    assert(context->callback_count == 1);
    assert(context->callback_error == 0);
    assert(context->callback_segments >= 1);
    assert(context->callback_length ==
        sizeof(first_data) + sizeof(second_data));
    bus_dmamap_unload(tag, map);

    first.m_flags = 0;
    context->callback_count = 0;
    context->callback_length = 1;
    assert(bus_dmamap_load_mbuf(tag, map, &first, test_load_callback2,
        context, BUS_DMA_NOWAIT) == 22);
    assert(context->callback_count == 1);
    assert(context->callback_error == 22);
    assert(context->callback_segments == 0);
    assert(context->callback_length == 0);

    assert(bus_dmamap_destroy(tag, map) == 0);
    assert(bus_dma_tag_destroy(tag) == 0);
}

static void
test_template_and_uio(test_context_t *context)
{
    bus_dma_template_t template;
    bus_dma_template_t clone;
    bus_dma_tag_t tag;
    bus_dma_tag_t cloned_tag;
    bus_dmamap_t map;
    struct iovec vectors[2];
    struct uio uio = {0};
    _Alignas(16) uint8_t first[256];
    _Alignas(16) uint8_t second[512];

    bus_dma_template_init(&template, 0);
    BUS_DMA_TEMPLATE_FILL(&template,
        BD_ALIGNMENT(16),
        BD_MAXSIZE(sizeof(first) + 128),
        BD_NSEGMENTS(4),
        BD_MAXSEGSIZE(TEST_PAGE_SIZE),
        BD_FLAGS(BUS_DMA_COHERENT),
        BD_NAME("uio-test"));
    assert(template.alignment == 16);
    assert(template.maxsize == sizeof(first) + 128);
    assert(template.nsegments == 4);
    assert(template.maxsegsize == TEST_PAGE_SIZE);
    assert(template.flags == BUS_DMA_COHERENT);
    assert(strcmp(template.name, "uio-test") == 0);
    assert(bus_dma_template_tag(&template, &tag) == 0);

    bus_dma_template_init(&clone, 0);
    bus_dma_template_clone(&clone, tag);
    assert(clone.alignment == 16);
    assert(clone.maxsize == sizeof(first) + 128);
    assert(clone.nsegments == 4);
    assert(clone.maxsegsize == TEST_PAGE_SIZE);
    assert(clone.flags == BUS_DMA_COHERENT);
    assert(bus_dma_template_tag(&clone, &cloned_tag) == 0);
    assert(bus_dma_tag_destroy(cloned_tag) == 0);

    assert(bus_dmamap_create(tag, BUS_DMA_NOWAIT, &map) == 0);
    vectors[0].iov_base = first;
    vectors[0].iov_len = sizeof(first);
    vectors[1].iov_base = second;
    vectors[1].iov_len = sizeof(second);
    uio.uio_iov = vectors;
    uio.uio_iovcnt = 2;
    uio.uio_resid = sizeof(first) + 128;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_rw = UIO_READ;
    context->callback_count = 0;
    context->callback_length = 0;
    assert(bus_dmamap_load_uio(tag, map, &uio, test_load_callback2,
        context, BUS_DMA_NOWAIT) == 0);
    assert(context->callback_count == 1);
    assert(context->callback_error == 0);
    assert(context->callback_length == (bus_size_t)uio.uio_resid);
    assert(context->callback_segments >= 1);
    bus_dmamap_unload(tag, map);
    assert(bus_dmamap_destroy(tag, map) == 0);
    assert(bus_dma_tag_destroy(tag) == 0);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_ops = {
        .allocate_pages = allocator_allocate_pages,
        .release_pages = test_release_pages,
    };
    test_context_t context = {0};
    bsd_bus_dma_ops_t dma_ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
        .physical_address = test_physical_address,
        .virtual_address = test_virtual_address,
        .sync = test_sync,
        .context = &context,
    };

    assert(bsd_allocator_initialize(&allocator_ops) == 0);
    assert(bsd_bus_dma_initialize(&dma_ops) == 0);
    assert(pmap_kextract((uintptr_t)&context) == (uintptr_t)&context);
    assert(PHYS_TO_DMAP((uintptr_t)&context) == &context);
    assert(DMAP_TO_PHYS(&context) == (uintptr_t)&context);
    void *translated = 0;
    assert(bsd_bus_dma_virtual_address((uintptr_t)&context,
        sizeof(context), &translated) == 0);
    assert(translated == &context);
    test_dma_contract(&context);
    test_segment_limit(&context);
    test_tag_and_map_lifecycle(&context);
    test_exclusion_and_rollback(&context);
    test_bio_load(&context);
    test_mbuf_mapping(&context);
    test_template_and_uio(&context);
    return 0;
}
