/* SPDX-License-Identifier: MPL-2.0 */
/* Backend contract for BSD bus-space access on EdgeOS. */

#ifndef EDGEOS_COMPAT_FREEBSD_BUS_SPACE_H
#define EDGEOS_COMPAT_FREEBSD_BUS_SPACE_H

#include <stdint.h>

#include "../machine/_bus.h"

typedef int (*bsd_bus_space_map_fn)(void *context, bus_addr_t address,
    bus_size_t size, int flags, bus_space_handle_t *handle);
typedef int (*bsd_bus_space_map_attr_fn)(void *context, bus_addr_t address,
    bus_size_t size, int flags, int memory_attribute,
    bus_space_handle_t *handle);
typedef void (*bsd_bus_space_unmap_fn)(void *context,
    bus_space_handle_t handle, bus_size_t size);
typedef uint64_t (*bsd_bus_space_read_fn)(void *context,
    bus_space_handle_t handle, bus_size_t offset, unsigned int width);
typedef void (*bsd_bus_space_write_fn)(void *context,
    bus_space_handle_t handle, bus_size_t offset, unsigned int width,
    uint64_t value);
typedef void (*bsd_bus_space_barrier_fn)(void *context,
    bus_space_handle_t handle, bus_size_t offset, bus_size_t length,
    int flags);
typedef int (*bsd_bus_space_peek_fn)(void *context,
    bus_space_handle_t handle, bus_size_t offset, unsigned int width,
    uint64_t *value);
typedef int (*bsd_bus_space_poke_fn)(void *context,
    bus_space_handle_t handle, bus_size_t offset, unsigned int width,
    uint64_t value);
typedef void (*bsd_bus_space_post_write_fn)(bus_space_tag_t tag,
    bus_space_handle_t handle, bus_size_t offset, unsigned int width,
    uint64_t value, void *context);
typedef void (*bsd_bus_space_post_read_fn)(bus_space_tag_t tag,
    bus_space_handle_t handle, bus_size_t offset, unsigned int width,
    uint64_t *value, void *context);

typedef struct {
    bsd_bus_space_map_fn map;
    bsd_bus_space_map_attr_fn map_attr;
    bsd_bus_space_unmap_fn unmap;
    bsd_bus_space_read_fn read;
    bsd_bus_space_write_fn write;
    bsd_bus_space_barrier_fn barrier;
    bsd_bus_space_peek_fn peek;
    bsd_bus_space_poke_fn poke;
    void *context;
} bsd_bus_space_ops_t;

/*
 * Native BSD controller frontends can derive a bus-space tag by overriding
 * selected operations and forwarding the rest through bs_cookie.  The EdgeOS
 * backend uses ops for its root memory and I/O tags; derived tags leave ops
 * zeroed and provide the native callbacks they need.
 */
struct bus_space {
    bsd_bus_space_ops_t ops;
    void *bs_cookie;

    int (*bs_map)(void *, bus_addr_t, bus_size_t, int,
        bus_space_handle_t *);
    void (*bs_unmap)(void *, bus_space_handle_t, bus_size_t);
    int (*bs_subregion)(void *, bus_space_handle_t, bus_size_t,
        bus_size_t, bus_space_handle_t *);
    int (*bs_alloc)(void *, bus_addr_t, bus_addr_t, bus_size_t,
        bus_size_t, bus_size_t, int, bus_addr_t *, bus_space_handle_t *);
    void (*bs_free)(void *, bus_space_handle_t, bus_size_t);
    void (*bs_barrier)(void *, bus_space_handle_t, bus_size_t,
        bus_size_t, int);

#define BSD_BUS_SPACE_TAG_READ_FIELD(width, type)                       \
    type (*bs_r_##width)(void *, bus_space_handle_t, bus_size_t)
    BSD_BUS_SPACE_TAG_READ_FIELD(1, uint8_t);
    BSD_BUS_SPACE_TAG_READ_FIELD(2, uint16_t);
    BSD_BUS_SPACE_TAG_READ_FIELD(4, uint32_t);
    BSD_BUS_SPACE_TAG_READ_FIELD(8, uint64_t);
#undef BSD_BUS_SPACE_TAG_READ_FIELD

#define BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(prefix, width, type)           \
    void (*bs_##prefix##_##width)(void *, bus_space_handle_t,           \
        bus_size_t, type *, bus_size_t)
    BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(rm, 1, uint8_t);
    BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(rm, 2, uint16_t);
    BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(rm, 4, uint32_t);
    BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(rm, 8, uint64_t);
    BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(rr, 1, uint8_t);
    BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(rr, 2, uint16_t);
    BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(rr, 4, uint32_t);
    BSD_BUS_SPACE_TAG_SEQUENCE_FIELD(rr, 8, uint64_t);
#undef BSD_BUS_SPACE_TAG_SEQUENCE_FIELD

#define BSD_BUS_SPACE_TAG_WRITE_FIELD(width, type)                      \
    void (*bs_w_##width)(void *, bus_space_handle_t, bus_size_t, type)
    BSD_BUS_SPACE_TAG_WRITE_FIELD(1, uint8_t);
    BSD_BUS_SPACE_TAG_WRITE_FIELD(2, uint16_t);
    BSD_BUS_SPACE_TAG_WRITE_FIELD(4, uint32_t);
    BSD_BUS_SPACE_TAG_WRITE_FIELD(8, uint64_t);
#undef BSD_BUS_SPACE_TAG_WRITE_FIELD

#define BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(prefix, width, type)     \
    void (*bs_##prefix##_##width)(void *, bus_space_handle_t,           \
        bus_size_t, const type *, bus_size_t)
    BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(wm, 1, uint8_t);
    BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(wm, 2, uint16_t);
    BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(wm, 4, uint32_t);
    BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(wm, 8, uint64_t);
    BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(wr, 1, uint8_t);
    BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(wr, 2, uint16_t);
    BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(wr, 4, uint32_t);
    BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD(wr, 8, uint64_t);
#undef BSD_BUS_SPACE_TAG_WRITE_SEQUENCE_FIELD

#define BSD_BUS_SPACE_TAG_SET_FIELD(prefix, width, type)                \
    void (*bs_##prefix##_##width)(void *, bus_space_handle_t,           \
        bus_size_t, type, bus_size_t)
    BSD_BUS_SPACE_TAG_SET_FIELD(sm, 1, uint8_t);
    BSD_BUS_SPACE_TAG_SET_FIELD(sm, 2, uint16_t);
    BSD_BUS_SPACE_TAG_SET_FIELD(sm, 4, uint32_t);
    BSD_BUS_SPACE_TAG_SET_FIELD(sm, 8, uint64_t);
    BSD_BUS_SPACE_TAG_SET_FIELD(sr, 1, uint8_t);
    BSD_BUS_SPACE_TAG_SET_FIELD(sr, 2, uint16_t);
    BSD_BUS_SPACE_TAG_SET_FIELD(sr, 4, uint32_t);
    BSD_BUS_SPACE_TAG_SET_FIELD(sr, 8, uint64_t);
#undef BSD_BUS_SPACE_TAG_SET_FIELD

#define BSD_BUS_SPACE_TAG_COPY_FIELD(width, type)                       \
    void (*bs_c_##width)(void *, bus_space_handle_t, bus_size_t,        \
        bus_space_handle_t, bus_size_t, bus_size_t)
    BSD_BUS_SPACE_TAG_COPY_FIELD(1, uint8_t);
    BSD_BUS_SPACE_TAG_COPY_FIELD(2, uint16_t);
    BSD_BUS_SPACE_TAG_COPY_FIELD(4, uint32_t);
    BSD_BUS_SPACE_TAG_COPY_FIELD(8, uint64_t);
#undef BSD_BUS_SPACE_TAG_COPY_FIELD

#define BSD_BUS_SPACE_TAG_PROBE_FIELDS(width, type)                     \
    int (*bs_peek_##width)(void *, bus_space_handle_t, bus_size_t,      \
        type *);                                                        \
    int (*bs_poke_##width)(void *, bus_space_handle_t, bus_size_t, type)
    BSD_BUS_SPACE_TAG_PROBE_FIELDS(1, uint8_t);
    BSD_BUS_SPACE_TAG_PROBE_FIELDS(2, uint16_t);
    BSD_BUS_SPACE_TAG_PROBE_FIELDS(4, uint32_t);
    BSD_BUS_SPACE_TAG_PROBE_FIELDS(8, uint64_t);
#undef BSD_BUS_SPACE_TAG_PROBE_FIELDS
};

int bsd_bus_space_initialize(const bsd_bus_space_ops_t *memory_ops,
    const bsd_bus_space_ops_t *io_ops);
int bsd_bus_space_is_initialized(void);
int bsd_bus_space_ensure_initialized(void);
bus_space_tag_t bsd_bus_space_memory_tag(void);
bus_space_tag_t bsd_bus_space_io_tag(void);
int bsd_bus_space_map_attr(bus_space_tag_t tag, bus_addr_t address,
    bus_size_t size, int flags, int memory_attribute,
    bus_space_handle_t *handle);
int bsd_bus_space_post_write_hook_register(
    bsd_bus_space_post_write_fn function, void *context);
int bsd_bus_space_post_read_hook_register(
    bsd_bus_space_post_read_fn function, void *context);

#endif
