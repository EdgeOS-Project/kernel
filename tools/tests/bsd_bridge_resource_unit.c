/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for BSD bridge resource allocation and activation. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/machine/bus.h"
#include "compat/freebsd/machine/resource.h"
#include "compat/freebsd/sys/rman.h"

typedef struct {
    uint8_t memory[64];
    int map_count;
    int unmap_count;
    int last_memory_attribute;
} test_context_t;

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U, (size_t)page_count * 4096U) != 0)
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
test_map(void *opaque_context, bus_addr_t address, bus_size_t size,
    int flags, bus_space_handle_t *handle)
{
    test_context_t *context = opaque_context;

    (void)flags;
    if (address > sizeof(context->memory) ||
        size > sizeof(context->memory) - address)
        return 22;
    context->map_count++;
    *handle = (bus_space_handle_t)(uintptr_t)&context->memory[address];
    return 0;
}

static int
test_map_attr(void *opaque_context, bus_addr_t address, bus_size_t size,
    int flags, int memory_attribute, bus_space_handle_t *handle)
{
    test_context_t *context = opaque_context;

    context->last_memory_attribute = memory_attribute;
    return test_map(opaque_context, address, size, flags, handle);
}

static void
test_unmap(void *opaque_context, bus_space_handle_t handle, bus_size_t size)
{
    test_context_t *context = opaque_context;

    (void)handle;
    (void)size;
    context->unmap_count++;
}

static uint64_t
test_read(void *opaque_context, bus_space_handle_t handle, bus_size_t offset,
    unsigned int width)
{
    uint64_t value = 0;

    (void)opaque_context;
    memcpy(&value, (void *)(uintptr_t)(handle + offset), width);
    return value;
}

static void
test_write(void *opaque_context, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t value)
{
    (void)opaque_context;
    memcpy((void *)(uintptr_t)(handle + offset), &value, width);
}

int
main(void)
{
    test_context_t context = {0};
    bsd_allocator_ops_t allocator_ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    bsd_bus_space_ops_t ops = {
        .map = test_map,
        .map_attr = test_map_attr,
        .unmap = test_unmap,
        .read = test_read,
        .write = test_write,
        .context = &context,
    };
    device_t device = (device_t)(uintptr_t)1;
    struct resource *resource;
    struct resource *unmapped_resource;
    struct resource_map mapping;
    struct resource_map second_mapping;
    struct resource_map_request request;
    struct resource *group_resources[3];
    struct resource_spec optional_group[] = {
        {SYS_RES_MEMORY, 5, RF_ACTIVE},
        {SYS_RES_IRQ, 1, RF_ACTIVE | RF_OPTIONAL},
        RESOURCE_SPEC_END,
    };
    struct resource_spec rollback_group[] = {
        {SYS_RES_MEMORY, 5, RF_ACTIVE},
        {SYS_RES_IRQ, 2, RF_ACTIVE},
        RESOURCE_SPEC_END,
    };
    rman_res_t start;
    rman_res_t count;

    assert(bsd_allocator_initialize(&allocator_ops) == 0);
    assert(bsd_bus_space_initialize(&ops, 0) == 0);
    assert(bsd_device_add_resource(device, SYS_RES_MEMORY, 0, 8, 16,
        RF_PREFETCHABLE, bsd_bus_space_memory_tag()) == 0);
    assert(bus_get_resource(device, SYS_RES_MEMORY, 0, &start, &count) == 0);
    assert(start == 8);
    assert(count == 16);
    assert(bus_get_resource(
        device, SYS_RES_MEMORY, 0, 0, 0) == 0);
    assert(bus_set_resource(device, SYS_RES_MEMORY, 0, 9, 7) == 0);
    assert(bus_get_resource(device, SYS_RES_MEMORY, 0, &start, &count) == 0);
    assert(start == 9);
    assert(count == 7);
    assert(bus_set_resource(device, SYS_RES_MEMORY, 0, 8, 16) == 0);

    resource = bus_alloc_resource(device, SYS_RES_MEMORY, 0, 0,
        RM_MAX_END, 1, RF_ACTIVE);
    assert(resource != 0);
    assert(context.map_count == 1);
    assert(rman_get_start(resource) == 8);
    assert(rman_get_size(resource) == 16);
    assert(bus_set_resource(device, SYS_RES_MEMORY, 0, 9, 7) == 16);
    assert(rman_get_type(resource) == SYS_RES_MEMORY);
    assert(rman_get_virtual(resource) != 0);
    bus_space_write_4(resource->r_bustag, resource->r_bushandle, 0,
        UINT32_C(0x12345678));
    assert(bus_space_read_4(resource->r_bustag,
        resource->r_bushandle, 0) == UINT32_C(0x12345678));

    assert(bus_release_resource(device, resource) == 0);
    assert(context.unmap_count == 1);
    bus_delete_resource(device, SYS_RES_MEMORY, 0);
    assert(bus_get_resource(device, SYS_RES_MEMORY, 0,
        &start, &count) == 2);

    assert(bsd_device_add_resource(device, SYS_RES_MEMORY, 2, 16, 32,
        RF_PREFETCHABLE | RF_UNMAPPED,
        bsd_bus_space_memory_tag()) == 0);
    unmapped_resource = bus_alloc_resource(device, SYS_RES_MEMORY, 2, 0,
        RM_MAX_END, 1, RF_ACTIVE | RF_UNMAPPED);
    assert(unmapped_resource != 0);
    assert(context.map_count == 1);

    resource_init_map_request_impl(&request, sizeof(request));
    request.offset = 4;
    request.length = 8;
    request.memattr = VM_MEMATTR_DEVICE_NP;
    assert(bus_map_resource_old(device, SYS_RES_MEMORY, unmapped_resource,
        &request, &mapping) == 0);
    assert(context.map_count == 2);
    assert(context.last_memory_attribute == VM_MEMATTR_DEVICE_NP);
    assert(mapping.r_size == 8);
    assert(mapping.r_vaddr == (void *)(uintptr_t)mapping.r_bushandle);
    bus_space_write_4(mapping.r_bustag, mapping.r_bushandle, 0,
        UINT32_C(0xaabbccdd));
    assert(bus_space_read_4(mapping.r_bustag,
        mapping.r_bushandle, 0) == UINT32_C(0xaabbccdd));

    request.offset = 20;
    request.length = 4;
    assert(bus_map_resource(device, unmapped_resource, &request,
        &second_mapping) == 0);
    assert(context.map_count == 3);
    assert(bus_release_resource(device, unmapped_resource) == 16);
    assert(bus_unmap_resource(device, unmapped_resource,
        &second_mapping) == 0);
    assert(second_mapping.r_size == 0);
    assert(bus_unmap_resource_old(device, SYS_RES_MEMORY,
        unmapped_resource, &mapping) == 0);
    assert(context.unmap_count == 3);
    assert(bus_release_resource_old(device, SYS_RES_MEMORY, 2,
        unmapped_resource) == 0);
    bus_delete_resource(device, SYS_RES_MEMORY, 2);

    assert(bsd_device_add_resource(device, SYS_RES_MEMORY, 3, 32, 8,
        RF_UNMAPPED, bsd_bus_space_memory_tag()) == 0);
    unmapped_resource = bus_alloc_resource(device, SYS_RES_MEMORY, 3, 0,
        RM_MAX_END, 1, RF_ACTIVE | RF_UNMAPPED);
    assert(unmapped_resource != 0);
    resource_init_map_request_impl(&request, sizeof(request));
    request.offset = 8;
    request.length = 1;
    assert(bus_map_resource(device, unmapped_resource, &request,
        &mapping) == 22);
    request.offset = 4;
    request.length = 5;
    assert(bus_map_resource(device, unmapped_resource, &request,
        &mapping) == 22);
    request.offset = 1;
    request.length = 0;
    assert(bus_map_resource(device, unmapped_resource, &request,
        &mapping) == 22);
    assert(bus_release_resource(device, unmapped_resource) == 0);
    bus_delete_resource(device, SYS_RES_MEMORY, 3);

    assert(bsd_device_add_resource(device, SYS_RES_MEMORY, 4, 8, 16,
        RF_UNMAPPED, bsd_bus_space_memory_tag()) == 0);
    resource = bus_alloc_resource(device, SYS_RES_MEMORY, 4, 0,
        RM_MAX_END, 1, RF_UNMAPPED);
    assert(resource != 0);
    assert(bus_adjust_resource(device, resource, 10, 20) == 0);
    assert(rman_get_start(resource) == 10);
    assert(rman_get_end(resource) == 20);
    assert(bus_adjust_resource(device, resource, 7, 20) == 22);
    assert(bus_adjust_resource(device, resource, 10, 24) == 22);
    assert(bus_adjust_resource(device, resource, 9, 22) == 0);
    assert(bus_get_resource(device, SYS_RES_MEMORY, 4,
        &start, &count) == 0);
    assert(start == 8);
    assert(count == 16);
    assert(bus_release_resource(device, resource) == 0);
    resource = bus_alloc_resource(device, SYS_RES_MEMORY, 4, 0,
        RM_MAX_END, 1, RF_UNMAPPED);
    assert(resource != 0);
    assert(rman_get_start(resource) == 8);
    assert(rman_get_end(resource) == 23);
    assert(bus_release_resource(device, resource) == 0);
    bus_delete_resource(device, SYS_RES_MEMORY, 4);

    assert(bsd_device_add_resource(device, SYS_RES_MEMORY, 5, 40, 8,
        0, bsd_bus_space_memory_tag()) == 0);
    assert(bus_alloc_resources(device, optional_group, group_resources) == 0);
    assert(group_resources[0] != 0);
    assert(group_resources[1] == 0);
    assert(bsd_resource_is_allocated(
        device, SYS_RES_MEMORY, 5) == 1);
    bus_release_resources(device, optional_group, group_resources);
    assert(group_resources[0] == 0);
    assert(bsd_resource_is_allocated(
        device, SYS_RES_MEMORY, 5) == 0);

    assert(bus_alloc_resources(device, rollback_group, group_resources) == 6);
    assert(group_resources[0] == 0);
    assert(group_resources[1] == 0);
    assert(bsd_resource_is_allocated(
        device, SYS_RES_MEMORY, 5) == 0);
    bus_delete_resource(device, SYS_RES_MEMORY, 5);
    return 0;
}
