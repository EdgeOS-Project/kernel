/* SPDX-License-Identifier: MPL-2.0 */
/* Shared bus-space implementation for BSD drivers on EdgeOS. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/machine/bus.h"

#ifndef BSD_BRIDGE_HOST_TEST
#include "kernel/arch_cpu.h"
#if defined(__x86_64__)
#include "sys/mmio.h"
#endif
#endif

#define BSD_BUS_SPACE_EINVAL 22
#define BSD_BUS_SPACE_ENXIO 6
#define BSD_BUS_SPACE_ENOMEM 12
#define BSD_BUS_SPACE_EEXIST 17
#define BSD_BUS_SPACE_POST_WRITE_HOOK_CAPACITY 8

typedef struct {
    bsd_bus_space_post_write_fn function;
    void *context;
} bsd_bus_space_post_write_hook_t;

typedef struct {
    bsd_bus_space_post_read_fn function;
    void *context;
} bsd_bus_space_post_read_hook_t;

struct bus_space memmap_bus;
static struct bus_space g_io_tag;
static uint8_t g_bus_space_init_state;
static bsd_bus_space_post_write_hook_t
    g_post_write_hooks[BSD_BUS_SPACE_POST_WRITE_HOOK_CAPACITY];
static size_t g_post_write_hook_count;
static bsd_bus_space_post_read_hook_t
    g_post_read_hooks[BSD_BUS_SPACE_POST_WRITE_HOOK_CAPACITY];
static size_t g_post_read_hook_count;
static volatile unsigned int g_post_write_hook_guard;

static void
post_write_hook_guard_lock(void)
{
    while (__atomic_test_and_set(&g_post_write_hook_guard,
        __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
post_write_hook_guard_unlock(void)
{
    __atomic_clear(&g_post_write_hook_guard, __ATOMIC_RELEASE);
}

int
bsd_bus_space_post_write_hook_register(
    bsd_bus_space_post_write_fn function, void *context)
{
    size_t count;

    if (!function)
        return BSD_BUS_SPACE_EINVAL;
    post_write_hook_guard_lock();
    count = __atomic_load_n(&g_post_write_hook_count, __ATOMIC_ACQUIRE);
    for (size_t index = 0; index < count; ++index) {
        if (g_post_write_hooks[index].function != function)
            continue;
        if (g_post_write_hooks[index].context == context) {
            post_write_hook_guard_unlock();
            return 0;
        }
        post_write_hook_guard_unlock();
        return BSD_BUS_SPACE_EEXIST;
    }
    if (count >= BSD_BUS_SPACE_POST_WRITE_HOOK_CAPACITY) {
        post_write_hook_guard_unlock();
        return BSD_BUS_SPACE_ENOMEM;
    }
    g_post_write_hooks[count].function = function;
    g_post_write_hooks[count].context = context;
    __atomic_store_n(&g_post_write_hook_count, count + 1,
        __ATOMIC_RELEASE);
    post_write_hook_guard_unlock();
    return 0;
}

int
bsd_bus_space_post_read_hook_register(
    bsd_bus_space_post_read_fn function, void *context)
{
    size_t count;

    if (!function)
        return BSD_BUS_SPACE_EINVAL;
    post_write_hook_guard_lock();
    count = __atomic_load_n(&g_post_read_hook_count, __ATOMIC_ACQUIRE);
    for (size_t index = 0; index < count; ++index) {
        if (g_post_read_hooks[index].function != function)
            continue;
        if (g_post_read_hooks[index].context == context) {
            post_write_hook_guard_unlock();
            return 0;
        }
        post_write_hook_guard_unlock();
        return BSD_BUS_SPACE_EEXIST;
    }
    if (count >= BSD_BUS_SPACE_POST_WRITE_HOOK_CAPACITY) {
        post_write_hook_guard_unlock();
        return BSD_BUS_SPACE_ENOMEM;
    }
    g_post_read_hooks[count].function = function;
    g_post_read_hooks[count].context = context;
    __atomic_store_n(&g_post_read_hook_count, count + 1,
        __ATOMIC_RELEASE);
    post_write_hook_guard_unlock();
    return 0;
}

static void
bus_space_post_read_notify(bus_space_tag_t tag,
    bus_space_handle_t handle, bus_size_t offset, unsigned int width,
    uint64_t *value)
{
    size_t count =
        __atomic_load_n(&g_post_read_hook_count, __ATOMIC_ACQUIRE);

    for (size_t index = 0; index < count; ++index) {
        g_post_read_hooks[index].function(tag, handle, offset, width,
            value, g_post_read_hooks[index].context);
    }
}

static void
bus_space_post_write_notify(bus_space_tag_t tag,
    bus_space_handle_t handle, bus_size_t offset, unsigned int width,
    uint64_t value)
{
    size_t count =
        __atomic_load_n(&g_post_write_hook_count, __ATOMIC_ACQUIRE);

    for (size_t index = 0; index < count; ++index) {
        g_post_write_hooks[index].function(tag, handle, offset, width,
            value, g_post_write_hooks[index].context);
    }
}


#ifndef BSD_BRIDGE_HOST_TEST
typedef enum {
    BSD_DEFAULT_BUS_SPACE_MEMORY,
    BSD_DEFAULT_BUS_SPACE_IO,
} bsd_default_bus_space_kind_t;

static bsd_default_bus_space_kind_t g_memory_kind =
    BSD_DEFAULT_BUS_SPACE_MEMORY;
static bsd_default_bus_space_kind_t g_io_kind = BSD_DEFAULT_BUS_SPACE_IO;

static int
default_map(void *opaque_kind, bus_addr_t address, bus_size_t size,
    int flags, bus_space_handle_t *handle)
{
    bsd_default_bus_space_kind_t kind =
        *(bsd_default_bus_space_kind_t *)opaque_kind;

    (void)flags;
    if (!handle || size == 0 || address > UINT64_MAX - (size - 1))
        return BSD_BUS_SPACE_EINVAL;
    if (kind == BSD_DEFAULT_BUS_SPACE_IO) {
#if defined(__x86_64__)
        if (address > UINT16_MAX || size - 1 > UINT16_MAX - address)
            return BSD_BUS_SPACE_EINVAL;
        *handle = (bus_space_handle_t)address;
        return 0;
#else
        return BSD_BUS_SPACE_ENXIO;
#endif
    }
#if defined(__x86_64__)
    if (!edge_mmio_phys_range_mapped(address, size))
        return BSD_BUS_SPACE_ENXIO;
    *handle = (bus_space_handle_t)edge_mmio_low_alias(address);
#else
    *handle = (bus_space_handle_t)address;
#endif
    return 0;
}

static void
default_unmap(void *opaque_kind, bus_space_handle_t handle, bus_size_t size)
{
    (void)opaque_kind;
    (void)handle;
    (void)size;
}

static uint64_t
default_read(void *opaque_kind, bus_space_handle_t handle, bus_size_t offset,
    unsigned int width)
{
    bsd_default_bus_space_kind_t kind =
        *(bsd_default_bus_space_kind_t *)opaque_kind;

    if (kind == BSD_DEFAULT_BUS_SPACE_IO) {
#if defined(__x86_64__)
        uint16_t port = (uint16_t)(handle + offset);
        uint32_t value;

        if (width == 1) {
            uint8_t byte;
            __asm__ __volatile__("inb %1, %0" : "=a"(byte) : "Nd"(port));
            return byte;
        }
        if (width == 2) {
            uint16_t word;
            __asm__ __volatile__("inw %1, %0" : "=a"(word) : "Nd"(port));
            return word;
        }
        __asm__ __volatile__("inl %1, %0" : "=a"(value) : "Nd"(port));
        return value;
#else
        return 0;
#endif
    }
    if (width == 1)
        return *(volatile uint8_t *)(handle + offset);
    if (width == 2)
        return *(volatile uint16_t *)(handle + offset);
    if (width == 4)
        return *(volatile uint32_t *)(handle + offset);
    return *(volatile uint64_t *)(handle + offset);
}

static void
default_write(void *opaque_kind, bus_space_handle_t handle,
    bus_size_t offset, unsigned int width, uint64_t value)
{
    bsd_default_bus_space_kind_t kind =
        *(bsd_default_bus_space_kind_t *)opaque_kind;

    if (kind == BSD_DEFAULT_BUS_SPACE_IO) {
#if defined(__x86_64__)
        uint16_t port = (uint16_t)(handle + offset);

        if (width == 1)
            __asm__ __volatile__("outb %0, %1" :
                : "a"((uint8_t)value), "Nd"(port));
        else if (width == 2)
            __asm__ __volatile__("outw %0, %1" :
                : "a"((uint16_t)value), "Nd"(port));
        else
            __asm__ __volatile__("outl %0, %1" :
                : "a"((uint32_t)value), "Nd"(port));
#else
        (void)handle;
        (void)offset;
        (void)width;
        (void)value;
#endif
        return;
    }
    if (width == 1)
        *(volatile uint8_t *)(handle + offset) = (uint8_t)value;
    else if (width == 2)
        *(volatile uint16_t *)(handle + offset) = (uint16_t)value;
    else if (width == 4)
        *(volatile uint32_t *)(handle + offset) = (uint32_t)value;
    else
        *(volatile uint64_t *)(handle + offset) = value;
}

static void
default_barrier(void *opaque_kind, bus_space_handle_t handle,
    bus_size_t offset, bus_size_t length, int flags)
{
    (void)opaque_kind;
    (void)handle;
    (void)offset;
    (void)length;
    (void)flags;
    arch_cpu_memory_barrier();
}
#endif

static int
bus_space_ops_valid(const bsd_bus_space_ops_t *ops)
{
    return ops && ops->map && ops->unmap && ops->read && ops->write;
}

static int
bus_space_access_valid(bus_space_handle_t handle, bus_size_t offset,
    bus_size_t width)
{
    return width != 0 && offset <= UINT64_MAX - (width - 1) &&
        handle <= UINTPTR_MAX - offset &&
        handle + (uintptr_t)offset <= UINTPTR_MAX - (width - 1);
}

static int
bus_space_sequence_valid(bus_space_handle_t handle, bus_size_t offset,
    bus_size_t count, bus_size_t width)
{
    bus_size_t final_offset;

    if (count == 0)
        return 1;
    if (width == 0 || count - 1 > (UINT64_MAX - offset) / width)
        return 0;
    final_offset = offset + (count - 1) * width;
    return bus_space_access_valid(handle, final_offset, width);
}

int
bsd_bus_space_initialize(const bsd_bus_space_ops_t *memory_ops,
    const bsd_bus_space_ops_t *io_ops)
{
    uint8_t expected = 0;

    if (!bus_space_ops_valid(memory_ops) ||
        (io_ops && !bus_space_ops_valid(io_ops)))
        return -1;
    if (!__atomic_compare_exchange_n(&g_bus_space_init_state, &expected, 1,
        0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -1;
    memmap_bus.ops = *memory_ops;
    if (io_ops)
        g_io_tag.ops = *io_ops;
    __atomic_store_n(&g_bus_space_init_state, 2, __ATOMIC_RELEASE);
    return 0;
}

int
bsd_bus_space_is_initialized(void)
{
    return __atomic_load_n(&g_bus_space_init_state, __ATOMIC_ACQUIRE) == 2;
}

int
bsd_bus_space_ensure_initialized(void)
{
    uint8_t state =
        __atomic_load_n(&g_bus_space_init_state, __ATOMIC_ACQUIRE);

    if (state == 2)
        return 0;
    if (state == 1) {
        do {
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
            state = __atomic_load_n(
                &g_bus_space_init_state, __ATOMIC_ACQUIRE);
        } while (state == 1);
        return state == 2 ? 0 : -1;
    }
#ifdef BSD_BRIDGE_HOST_TEST
    return -1;
#else
    bsd_bus_space_ops_t memory_ops = {
        .map = default_map,
        .unmap = default_unmap,
        .read = default_read,
        .write = default_write,
        .barrier = default_barrier,
        .context = &g_memory_kind,
    };
    bsd_bus_space_ops_t io_ops = {
        .map = default_map,
        .unmap = default_unmap,
        .read = default_read,
        .write = default_write,
        .barrier = default_barrier,
        .context = &g_io_kind,
    };

    if (bsd_bus_space_initialize(&memory_ops, &io_ops) == 0)
        return 0;
    while (__atomic_load_n(
        &g_bus_space_init_state, __ATOMIC_ACQUIRE) == 1) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
    return bsd_bus_space_is_initialized() ? 0 : -1;
#endif
}

bus_space_tag_t
bsd_bus_space_memory_tag(void)
{
    return bsd_bus_space_ensure_initialized() == 0 ? &memmap_bus : 0;
}

bus_space_tag_t
bsd_bus_space_io_tag(void)
{
    return bsd_bus_space_ensure_initialized() == 0 &&
        g_io_tag.ops.map ? &g_io_tag : 0;
}

int
bus_space_map(bus_space_tag_t tag, bus_addr_t address, bus_size_t size,
    int flags, bus_space_handle_t *handle)
{
    if (!tag || !handle || size == 0 ||
        address > UINT64_MAX - (size - 1))
        return BSD_BUS_SPACE_EINVAL;
    if (tag->bs_map)
        return tag->bs_map(tag->bs_cookie, address, size, flags, handle);
    if (!tag->ops.map)
        return BSD_BUS_SPACE_ENXIO;
    return tag->ops.map(tag->ops.context, address, size, flags, handle);
}

int
bsd_bus_space_map_attr(bus_space_tag_t tag, bus_addr_t address,
    bus_size_t size, int flags, int memory_attribute,
    bus_space_handle_t *handle)
{
    if (!tag || !handle || size == 0 ||
        address > UINT64_MAX - (size - 1))
        return BSD_BUS_SPACE_EINVAL;
    if (tag->ops.map_attr) {
        return tag->ops.map_attr(tag->ops.context, address, size, flags,
            memory_attribute, handle);
    }
    return bus_space_map(tag, address, size, flags, handle);
}

void
bus_space_unmap(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t size)
{
    if (tag && tag->bs_unmap)
        tag->bs_unmap(tag->bs_cookie, handle, size);
    else if (tag && tag->ops.unmap)
        tag->ops.unmap(tag->ops.context, handle, size);
}

int
bus_space_subregion(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, bus_size_t size, bus_space_handle_t *new_handle)
{
    if (!tag || !new_handle || size == 0 ||
        offset > UINT64_MAX - (size - 1) ||
        !bus_space_access_valid(handle, offset, size))
        return BSD_BUS_SPACE_EINVAL;
    if (tag->bs_subregion) {
        return tag->bs_subregion(tag->bs_cookie, handle, offset, size,
            new_handle);
    }
    *new_handle = handle + (uintptr_t)offset;
    return 0;
}

void *
bus_space_vaddr(bus_space_tag_t tag, bus_space_handle_t handle)
{
    return tag ? (void *)(uintptr_t)handle : 0;
}

void
bus_space_barrier(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, bus_size_t length, int flags)
{
    if (!tag || length == 0 ||
        !bus_space_access_valid(handle, offset, length))
        return;
    if (tag->bs_barrier)
        tag->bs_barrier(tag->bs_cookie, handle, offset, length, flags);
    else if (tag->ops.barrier)
        tag->ops.barrier(tag->ops.context, handle, offset, length, flags);
    else
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

#define DEFINE_BUS_SPACE_ACCESS(width, type)                             \
type                                                                    \
bus_space_read_##width(bus_space_tag_t tag, bus_space_handle_t handle,  \
    bus_size_t offset)                                                  \
{                                                                       \
    uint64_t value;                                                     \
                                                                        \
    if (!tag || !bus_space_access_valid(handle, offset, width))         \
        return 0;                                                       \
    if (tag->bs_r_##width)                                              \
        return tag->bs_r_##width(tag->bs_cookie, handle, offset);       \
    if (tag->ops.read)                                                  \
        value = tag->ops.read(tag->ops.context, handle, offset, width); \
    else                                                                \
        return 0;                                                       \
    bus_space_post_read_notify(tag, handle, offset, width, &value);      \
    return (type)value;                                                 \
}                                                                       \
                                                                        \
void                                                                    \
bus_space_write_##width(bus_space_tag_t tag, bus_space_handle_t handle, \
    bus_size_t offset, type value)                                      \
{                                                                       \
    if (tag && bus_space_access_valid(handle, offset, width)) {         \
        if (tag->bs_w_##width) {                                        \
            tag->bs_w_##width(tag->bs_cookie, handle, offset, value);   \
            return;                                                     \
        }                                                               \
        if (tag->ops.write)                                             \
            tag->ops.write(tag->ops.context, handle, offset, width,     \
                value);                                                 \
        else                                                            \
            return;                                                     \
        bus_space_post_write_notify(                                    \
            tag, handle, offset, width, value);                          \
    }                                                                   \
}                                                                       \
                                                                        \
void                                                                    \
bus_space_read_multi_##width(bus_space_tag_t tag,                       \
    bus_space_handle_t handle, bus_size_t offset, type *destination,    \
    bus_size_t count)                                                   \
{                                                                       \
    if (!tag || (!destination && count != 0) ||                         \
        !bus_space_access_valid(handle, offset, width))                 \
        return;                                                         \
    if (tag->bs_rm_##width) {                                           \
        tag->bs_rm_##width(tag->bs_cookie, handle, offset, destination, \
            count);                                                     \
        return;                                                         \
    }                                                                   \
    for (bus_size_t index = 0; index < count; ++index)                  \
        destination[index] = bus_space_read_##width(tag, handle, offset);\
}                                                                       \
                                                                        \
void                                                                    \
bus_space_read_region_##width(bus_space_tag_t tag,                      \
    bus_space_handle_t handle, bus_size_t offset, type *destination,    \
    bus_size_t count)                                                   \
{                                                                       \
    if (!tag || (!destination && count != 0) ||                         \
        !bus_space_sequence_valid(handle, offset, count, width))        \
        return;                                                         \
    if (tag->bs_rr_##width) {                                           \
        tag->bs_rr_##width(tag->bs_cookie, handle, offset, destination, \
            count);                                                     \
        return;                                                         \
    }                                                                   \
    for (bus_size_t index = 0; index < count; ++index)                  \
        destination[index] = bus_space_read_##width(                    \
            tag, handle, offset + index * width);                       \
}                                                                       \
                                                                        \
void                                                                    \
bus_space_write_multi_##width(bus_space_tag_t tag,                      \
    bus_space_handle_t handle, bus_size_t offset, const type *source,   \
    bus_size_t count)                                                   \
{                                                                       \
    if (!tag || (!source && count != 0) ||                              \
        !bus_space_access_valid(handle, offset, width))                 \
        return;                                                         \
    if (tag->bs_wm_##width) {                                           \
        tag->bs_wm_##width(tag->bs_cookie, handle, offset, source,      \
            count);                                                     \
        return;                                                         \
    }                                                                   \
    for (bus_size_t index = 0; index < count; ++index)                  \
        bus_space_write_##width(tag, handle, offset, source[index]);    \
}                                                                       \
                                                                        \
void                                                                    \
bus_space_write_region_##width(bus_space_tag_t tag,                     \
    bus_space_handle_t handle, bus_size_t offset, const type *source,   \
    bus_size_t count)                                                   \
{                                                                       \
    if (!tag || (!source && count != 0) ||                              \
        !bus_space_sequence_valid(handle, offset, count, width))        \
        return;                                                         \
    if (tag->bs_wr_##width) {                                           \
        tag->bs_wr_##width(tag->bs_cookie, handle, offset, source,      \
            count);                                                     \
        return;                                                         \
    }                                                                   \
    for (bus_size_t index = 0; index < count; ++index)                  \
        bus_space_write_##width(                                        \
            tag, handle, offset + index * width, source[index]);        \
}                                                                       \
                                                                        \
void                                                                    \
bus_space_set_multi_##width(bus_space_tag_t tag,                        \
    bus_space_handle_t handle, bus_size_t offset, type value,           \
    bus_size_t count)                                                   \
{                                                                       \
    if (!tag || !bus_space_access_valid(handle, offset, width))         \
        return;                                                         \
    if (tag->bs_sm_##width) {                                           \
        tag->bs_sm_##width(tag->bs_cookie, handle, offset, value,       \
            count);                                                     \
        return;                                                         \
    }                                                                   \
    for (bus_size_t index = 0; index < count; ++index)                  \
        bus_space_write_##width(tag, handle, offset, value);            \
}                                                                       \
                                                                        \
void                                                                    \
bus_space_set_region_##width(bus_space_tag_t tag,                       \
    bus_space_handle_t handle, bus_size_t offset, type value,           \
    bus_size_t count)                                                   \
{                                                                       \
    if (!tag ||                                                         \
        !bus_space_sequence_valid(handle, offset, count, width))        \
        return;                                                         \
    if (tag->bs_sr_##width) {                                           \
        tag->bs_sr_##width(tag->bs_cookie, handle, offset, value,       \
            count);                                                     \
        return;                                                         \
    }                                                                   \
    for (bus_size_t index = 0; index < count; ++index)                  \
        bus_space_write_##width(                                        \
            tag, handle, offset + index * width, value);                \
}                                                                       \
                                                                        \
void                                                                    \
bus_space_copy_region_##width(bus_space_tag_t tag,                      \
    bus_space_handle_t source_handle, bus_size_t source_offset,         \
    bus_space_handle_t destination_handle,                              \
    bus_size_t destination_offset, bus_size_t count)                    \
{                                                                       \
    uintptr_t source_start;                                             \
    uintptr_t destination_start;                                        \
                                                                        \
    if (count == 0)                                                     \
        return;                                                         \
    if (!tag ||                                                         \
        !bus_space_sequence_valid(                                      \
            source_handle, source_offset, count, width) ||              \
        !bus_space_sequence_valid(                                      \
            destination_handle, destination_offset, count, width))      \
        return;                                                         \
    if (tag->bs_c_##width) {                                            \
        tag->bs_c_##width(tag->bs_cookie, source_handle, source_offset, \
            destination_handle, destination_offset, count);            \
        return;                                                         \
    }                                                                   \
    source_start = source_handle + (uintptr_t)source_offset;            \
    destination_start = destination_handle +                            \
        (uintptr_t)destination_offset;                                  \
    if (source_start >= destination_start) {                            \
        for (bus_size_t index = 0; index < count; ++index) {            \
            type value = bus_space_read_##width(tag, source_handle,     \
                source_offset + index * width);                         \
            bus_space_write_##width(tag, destination_handle,           \
                destination_offset + index * width, value);             \
        }                                                               \
    } else {                                                            \
        for (bus_size_t index = count; index != 0; --index) {           \
            bus_size_t current = index - 1;                             \
            type value = bus_space_read_##width(tag, source_handle,     \
                source_offset + current * width);                       \
            bus_space_write_##width(tag, destination_handle,           \
                destination_offset + current * width, value);           \
        }                                                               \
    }                                                                   \
}                                                                       \
                                                                        \
int                                                                     \
bus_space_peek_##width(bus_space_tag_t tag, bus_space_handle_t handle,  \
    bus_size_t offset, type *value)                                     \
{                                                                       \
    uint64_t raw_value;                                                 \
    int error;                                                          \
                                                                        \
    if (!tag || !value ||                                               \
        !bus_space_access_valid(handle, offset, width))                 \
        return BSD_BUS_SPACE_EINVAL;                                    \
    if (tag->bs_peek_##width)                                           \
        return tag->bs_peek_##width(tag->bs_cookie, handle, offset,     \
            value);                                                     \
    if (tag->ops.peek) {                                                \
        error = tag->ops.peek(tag->ops.context, handle, offset, width,  \
            &raw_value);                                                \
        if (error != 0)                                                 \
            return error;                                               \
        *value = (type)raw_value;                                       \
        return 0;                                                       \
    }                                                                   \
    *value = bus_space_read_##width(tag, handle, offset);               \
    return 0;                                                           \
}                                                                       \
                                                                        \
int                                                                     \
bus_space_poke_##width(bus_space_tag_t tag, bus_space_handle_t handle,  \
    bus_size_t offset, type value)                                      \
{                                                                       \
    if (!tag || !bus_space_access_valid(handle, offset, width))         \
        return BSD_BUS_SPACE_EINVAL;                                    \
    if (tag->bs_poke_##width)                                           \
        return tag->bs_poke_##width(tag->bs_cookie, handle, offset,     \
            value);                                                     \
    if (tag->ops.poke)                                                  \
        return tag->ops.poke(                                           \
            tag->ops.context, handle, offset, width, value);            \
    bus_space_write_##width(tag, handle, offset, value);                \
    return 0;                                                           \
}

DEFINE_BUS_SPACE_ACCESS(1, uint8_t)
DEFINE_BUS_SPACE_ACCESS(2, uint16_t)
DEFINE_BUS_SPACE_ACCESS(4, uint32_t)
DEFINE_BUS_SPACE_ACCESS(8, uint64_t)
