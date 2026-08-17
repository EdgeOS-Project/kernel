/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD bridge bus-space implementation. */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/machine/bus.h"

typedef struct {
    uint8_t memory[128];
    int map_count;
    int unmap_count;
    int barrier_count;
    int read_count;
    int write_count;
    bus_size_t failed_probe_offset;
} test_context_t;

static int g_post_write_count;
static unsigned int g_post_write_width;
static bus_size_t g_post_write_offset;
static uint64_t g_post_write_value;
static int g_post_write_saw_backend_write;
static int g_post_read_count;

static void
test_post_write(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t value, void *context)
{
    test_context_t *test = context;

    (void)tag;
    (void)handle;
    g_post_write_count++;
    g_post_write_width = width;
    g_post_write_offset = offset;
    g_post_write_value = value;
    g_post_write_saw_backend_write = test->write_count != 0;
}

static void
test_post_read(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t *value, void *context)
{
    (void)tag;
    (void)handle;
    (void)offset;
    (void)width;
    (void)context;
    g_post_read_count++;
    if (*value == UINT32_C(0x89abcdef))
        *value = UINT32_C(0x12345678);
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
    test_context_t *context = opaque_context;

    context->read_count++;
    memcpy(&value, (const void *)(uintptr_t)(handle + offset), width);
    return value;
}

static void
test_write(void *opaque_context, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t value)
{
    test_context_t *context = opaque_context;

    context->write_count++;
    memcpy((void *)(uintptr_t)(handle + offset), &value, width);
}

static void
test_barrier(void *opaque_context, bus_space_handle_t handle,
    bus_size_t offset, bus_size_t length, int flags)
{
    test_context_t *context = opaque_context;

    (void)handle;
    (void)offset;
    (void)length;
    (void)flags;
    context->barrier_count++;
}

static int
test_peek(void *opaque_context, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t *value)
{
    test_context_t *context = opaque_context;

    if (offset == context->failed_probe_offset)
        return 6;
    *value = test_read(opaque_context, handle, offset, width);
    return 0;
}

static int
test_poke(void *opaque_context, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t value)
{
    test_context_t *context = opaque_context;

    if (offset == context->failed_probe_offset)
        return 6;
    test_write(opaque_context, handle, offset, width, value);
    return 0;
}

static uint8_t
test_derived_read_1(void *opaque_parent, bus_space_handle_t handle,
    bus_size_t offset)
{
    return bus_space_read_1(opaque_parent, handle, offset + 4);
}

static void
test_derived_write_1(void *opaque_parent, bus_space_handle_t handle,
    bus_size_t offset, uint8_t value)
{
    bus_space_write_1(opaque_parent, handle, offset + 4, value);
}

int
main(void)
{
    test_context_t context = {
        .failed_probe_offset = 24,
    };
    bsd_bus_space_ops_t ops = {
        .map = test_map,
        .unmap = test_unmap,
        .read = test_read,
        .write = test_write,
        .barrier = test_barrier,
        .peek = test_peek,
        .poke = test_poke,
        .context = &context,
    };
    bus_space_tag_t tag;
    struct bus_space derived_tag = {0};
    bus_space_handle_t handle;
    bus_space_handle_t subregion;
    uint16_t output[3];
    const uint16_t values[3] = { 0x1122, 0x3344, 0x5566 };
    uint8_t overlap_expected[16];
    uint32_t probe_value;
    int write_count;

    assert(bsd_bus_space_initialize(&ops, 0) == 0);
    assert(bsd_bus_space_post_write_hook_register(
        test_post_write, &context) == 0);
    assert(bsd_bus_space_post_write_hook_register(
        test_post_write, &context) == 0);
    assert(bsd_bus_space_post_read_hook_register(
        test_post_read, &context) == 0);
    tag = bsd_bus_space_memory_tag();
    assert(tag != 0);
    assert(bus_space_map(tag, 8, 32, 0, &handle) == 0);
    assert(context.map_count == 1);

    bus_space_write_4(tag, handle, 0, UINT32_C(0x89abcdef));
    assert(g_post_write_count == 1);
    assert(g_post_write_width == 4);
    assert(g_post_write_offset == 0);
    assert(g_post_write_value == UINT32_C(0x89abcdef));
    assert(g_post_write_saw_backend_write != 0);
    assert(bus_space_read_4(tag, handle, 0) == UINT32_C(0x12345678));
    assert(g_post_read_count == 1);
    assert(bus_space_subregion(tag, handle, 8, 16, &subregion) == 0);
    assert(bus_space_subregion(tag, handle, 0, 0, &subregion) == 22);
    bus_space_write_region_2(tag, subregion, 0, values, 3);
    bus_space_read_region_2(tag, subregion, 0, output, 3);
    assert(memcmp(values, output, sizeof(values)) == 0);

    bus_space_set_region_1(tag, handle, 0, 0x5a, 16);
    memset(overlap_expected, 0x5a, sizeof(overlap_expected));
    for (size_t index = 0; index < 8; ++index) {
        bus_space_write_1(tag, handle, index, (uint8_t)index);
        overlap_expected[index] = (uint8_t)index;
    }
    memmove(overlap_expected + 2, overlap_expected, 8);
    bus_space_copy_region_1(tag, handle, 0, handle, 2, 8);
    assert(memcmp(&context.memory[8], overlap_expected,
        sizeof(overlap_expected)) == 0);

    write_count = context.write_count;
    bus_space_set_region_4(tag, handle, UINT64_MAX - 1, 0, 2);
    assert(context.write_count == write_count);
    bus_space_set_multi_2(tag, handle, 20, 0xa55a, 3);
    assert(bus_space_read_2(tag, handle, 20) == 0xa55a);

    probe_value = 0xfeedface;
    assert(bus_space_peek_4(tag, handle, 24, &probe_value) == 6);
    assert(probe_value == 0xfeedface);
    assert(bus_space_poke_4(tag, handle, 24, 0x12345678) == 6);
    assert(bus_space_poke_4(tag, handle, 16, 0x12345678) == 0);
    probe_value = 0;
    assert(bus_space_peek_4(tag, handle, 16, &probe_value) == 0);
    assert(probe_value == 0x12345678);

    derived_tag.bs_cookie = tag;
    derived_tag.bs_r_1 = test_derived_read_1;
    derived_tag.bs_w_1 = test_derived_write_1;
    write_count = g_post_write_count;
    bus_space_write_1(&derived_tag, handle, 1, 0xa6);
    assert(context.memory[13] == 0xa6);
    assert(g_post_write_count == write_count + 1);
    assert(g_post_write_offset == 5);
    assert(bus_space_read_1(&derived_tag, handle, 1) == 0xa6);

    bus_space_barrier(tag, handle, 0, 16,
        BUS_SPACE_BARRIER_READ | BUS_SPACE_BARRIER_WRITE);
    assert(context.barrier_count == 1);
    bus_space_unmap(tag, handle, 32);
    assert(context.unmap_count == 1);
    return 0;
}
