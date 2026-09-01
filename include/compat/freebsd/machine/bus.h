/* SPDX-License-Identifier: MPL-2.0 */
/* Shared bus-space and bus-DMA interface for BSD drivers on EdgeOS. */

#ifndef _MACHINE_BUS_H_
#define _MACHINE_BUS_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "_bus.h"
#include "../edgeos/bus_space.h"
#include "../sys/_bus_dma.h"

#ifdef EDGEOS_BSD_FULL_IOMMU
#include "../vm/pmap.h"
#endif

typedef int bus_dma_filter_t(void *, bus_addr_t);

typedef struct bus_dma_segment {
    bus_addr_t ds_addr;
    bus_size_t ds_len;
} bus_dma_segment_t;

typedef void bus_dmamap_callback_t(void *, bus_dma_segment_t *, int, int);
typedef void bus_dmamap_callback2_t(void *, bus_dma_segment_t *, int,
    bus_size_t, int);

struct bio;
struct mbuf;
struct memdesc;
struct uio;
union ccb;

#define BUS_SPACE_MAXADDR_24BIT 0x00ffffffULL
#define BUS_SPACE_MAXADDR_32BIT 0xffffffffULL
#define BUS_SPACE_MAXADDR_36BIT 0x0fffffffffULL
#define BUS_SPACE_MAXADDR_40BIT 0xffffffffffULL
#define BUS_SPACE_MAXADDR_46BIT 0x3fffffffffffULL
#define BUS_SPACE_MAXADDR_48BIT 0xffffffffffffULL
#define BUS_SPACE_MAXADDR 0xffffffffffffffffULL
#define BUS_SPACE_MAXSIZE_24BIT 0x00ffffffULL
#define BUS_SPACE_MAXSIZE_32BIT 0xffffffffULL
#define BUS_SPACE_MAXSIZE BUS_SPACE_MAXADDR
#define BUS_SPACE_UNRESTRICTED (~0)

#define BUS_SPACE_MAP_CACHEABLE 0x01
#define BUS_SPACE_MAP_LINEAR 0x02
#define BUS_SPACE_MAP_PREFETCHABLE 0x04
#define BUS_SPACE_MAP_NONPOSTED 0x08

#define BUS_SPACE_BARRIER_READ 0x01
#define BUS_SPACE_BARRIER_WRITE 0x02

#define X86_BUS_SPACE_MEM bsd_bus_space_memory_tag()
#define X86_BUS_SPACE_IO bsd_bus_space_io_tag()

int bus_space_map(bus_space_tag_t tag, bus_addr_t address, bus_size_t size,
    int flags, bus_space_handle_t *handle);
void bus_space_unmap(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t size);
int bus_space_subregion(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, bus_size_t size, bus_space_handle_t *new_handle);
void *bus_space_vaddr(bus_space_tag_t tag, bus_space_handle_t handle);
void bus_space_barrier(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, bus_size_t length, int flags);

uint8_t bus_space_read_1(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset);
uint16_t bus_space_read_2(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset);
uint32_t bus_space_read_4(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset);
uint64_t bus_space_read_8(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset);
void bus_space_write_1(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, uint8_t value);
void bus_space_write_2(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, uint16_t value);
void bus_space_write_4(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, uint32_t value);
void bus_space_write_8(bus_space_tag_t tag, bus_space_handle_t handle,
    bus_size_t offset, uint64_t value);

#define BSD_BUS_SPACE_DECLARE_SEQUENCE(operation, width, type)           \
    void bus_space_##operation##_multi_##width(bus_space_tag_t tag,      \
        bus_space_handle_t handle, bus_size_t offset, type *values,      \
        bus_size_t count);                                               \
    void bus_space_##operation##_region_##width(bus_space_tag_t tag,     \
        bus_space_handle_t handle, bus_size_t offset, type *values,      \
        bus_size_t count)

BSD_BUS_SPACE_DECLARE_SEQUENCE(read, 1, uint8_t);
BSD_BUS_SPACE_DECLARE_SEQUENCE(read, 2, uint16_t);
BSD_BUS_SPACE_DECLARE_SEQUENCE(read, 4, uint32_t);
BSD_BUS_SPACE_DECLARE_SEQUENCE(read, 8, uint64_t);
#undef BSD_BUS_SPACE_DECLARE_SEQUENCE

#define BSD_BUS_SPACE_DECLARE_WRITE_SEQUENCE(width, type)                \
    void bus_space_write_multi_##width(bus_space_tag_t tag,              \
        bus_space_handle_t handle, bus_size_t offset,                    \
        const type *values, bus_size_t count);                           \
    void bus_space_write_region_##width(bus_space_tag_t tag,             \
        bus_space_handle_t handle, bus_size_t offset,                    \
        const type *values, bus_size_t count)

BSD_BUS_SPACE_DECLARE_WRITE_SEQUENCE(1, uint8_t);
BSD_BUS_SPACE_DECLARE_WRITE_SEQUENCE(2, uint16_t);
BSD_BUS_SPACE_DECLARE_WRITE_SEQUENCE(4, uint32_t);
BSD_BUS_SPACE_DECLARE_WRITE_SEQUENCE(8, uint64_t);
#undef BSD_BUS_SPACE_DECLARE_WRITE_SEQUENCE

#define BSD_BUS_SPACE_DECLARE_SET_SEQUENCE(width, type)                  \
    void bus_space_set_multi_##width(bus_space_tag_t tag,               \
        bus_space_handle_t handle, bus_size_t offset, type value,       \
        bus_size_t count);                                               \
    void bus_space_set_region_##width(bus_space_tag_t tag,              \
        bus_space_handle_t handle, bus_size_t offset, type value,       \
        bus_size_t count);                                               \
    void bus_space_copy_region_##width(bus_space_tag_t tag,             \
        bus_space_handle_t source_handle, bus_size_t source_offset,     \
        bus_space_handle_t destination_handle,                          \
        bus_size_t destination_offset, bus_size_t count)

BSD_BUS_SPACE_DECLARE_SET_SEQUENCE(1, uint8_t);
BSD_BUS_SPACE_DECLARE_SET_SEQUENCE(2, uint16_t);
BSD_BUS_SPACE_DECLARE_SET_SEQUENCE(4, uint32_t);
BSD_BUS_SPACE_DECLARE_SET_SEQUENCE(8, uint64_t);
#undef BSD_BUS_SPACE_DECLARE_SET_SEQUENCE

#define BSD_BUS_SPACE_DECLARE_PROBE(width, type)                         \
    int bus_space_peek_##width(bus_space_tag_t tag,                      \
        bus_space_handle_t handle, bus_size_t offset, type *value);      \
    int bus_space_poke_##width(bus_space_tag_t tag,                      \
        bus_space_handle_t handle, bus_size_t offset, type value)

BSD_BUS_SPACE_DECLARE_PROBE(1, uint8_t);
BSD_BUS_SPACE_DECLARE_PROBE(2, uint16_t);
BSD_BUS_SPACE_DECLARE_PROBE(4, uint32_t);
BSD_BUS_SPACE_DECLARE_PROBE(8, uint64_t);
#undef BSD_BUS_SPACE_DECLARE_PROBE

#define bus_space_read_stream_1 bus_space_read_1
#define bus_space_read_stream_2 bus_space_read_2
#define bus_space_read_stream_4 bus_space_read_4
#define bus_space_read_stream_8 bus_space_read_8
#define bus_space_write_stream_1 bus_space_write_1
#define bus_space_write_stream_2 bus_space_write_2
#define bus_space_write_stream_4 bus_space_write_4
#define bus_space_write_stream_8 bus_space_write_8
#define bus_space_read_multi_stream_1 bus_space_read_multi_1
#define bus_space_read_multi_stream_2 bus_space_read_multi_2
#define bus_space_read_multi_stream_4 bus_space_read_multi_4
#define bus_space_read_multi_stream_8 bus_space_read_multi_8
#define bus_space_read_region_stream_1 bus_space_read_region_1
#define bus_space_read_region_stream_2 bus_space_read_region_2
#define bus_space_read_region_stream_4 bus_space_read_region_4
#define bus_space_read_region_stream_8 bus_space_read_region_8
#define bus_space_write_multi_stream_1 bus_space_write_multi_1
#define bus_space_write_multi_stream_2 bus_space_write_multi_2
#define bus_space_write_multi_stream_4 bus_space_write_multi_4
#define bus_space_write_multi_stream_8 bus_space_write_multi_8
#define bus_space_write_region_stream_1 bus_space_write_region_1
#define bus_space_write_region_stream_2 bus_space_write_region_2
#define bus_space_write_region_stream_4 bus_space_write_region_4
#define bus_space_write_region_stream_8 bus_space_write_region_8
#define bus_space_set_multi_stream_1 bus_space_set_multi_1
#define bus_space_set_multi_stream_2 bus_space_set_multi_2
#define bus_space_set_multi_stream_4 bus_space_set_multi_4
#define bus_space_set_multi_stream_8 bus_space_set_multi_8
#define bus_space_set_region_stream_1 bus_space_set_region_1
#define bus_space_set_region_stream_2 bus_space_set_region_2
#define bus_space_set_region_stream_4 bus_space_set_region_4
#define bus_space_set_region_stream_8 bus_space_set_region_8
#define bus_space_copy_region_stream_1 bus_space_copy_region_1
#define bus_space_copy_region_stream_2 bus_space_copy_region_2
#define bus_space_copy_region_stream_4 bus_space_copy_region_4
#define bus_space_copy_region_stream_8 bus_space_copy_region_8

#define BUS_DMA_WAITOK 0x00
#define BUS_DMA_NOWAIT 0x01
#define BUS_DMA_ALLOCNOW 0x02
#define BUS_DMA_COHERENT 0x04
#define BUS_DMA_ZERO 0x08
#define BUS_DMA_NOWRITE 0x100
#define BUS_DMA_NOCACHE 0x200
#define BUS_DMA_KEEP_PG_OFFSET 0x400
#define BUS_DMA_LOAD_MBUF 0x800

#define BUS_DMASYNC_PREREAD 1
#define BUS_DMASYNC_POSTREAD 2
#define BUS_DMASYNC_PREWRITE 4
#define BUS_DMASYNC_POSTWRITE 8

typedef struct bus_dma_template {
    bus_dma_tag_t parent;
    bus_size_t alignment;
    bus_addr_t boundary;
    bus_addr_t lowaddr;
    bus_addr_t highaddr;
    bus_size_t maxsize;
    int nsegments;
    bus_size_t maxsegsize;
    int flags;
    bus_dma_lock_t *lockfunc;
    void *lockfuncarg;
    const char *name;
} bus_dma_template_t;

typedef enum bus_dma_param_key {
    BD_PARAM_INVALID = 0,
    BD_PARAM_PARENT = 1,
    BD_PARAM_ALIGNMENT = 2,
    BD_PARAM_BOUNDARY = 3,
    BD_PARAM_LOWADDR = 4,
    BD_PARAM_HIGHADDR = 5,
    BD_PARAM_MAXSIZE = 6,
    BD_PARAM_NSEGMENTS = 7,
    BD_PARAM_MAXSEGSIZE = 8,
    BD_PARAM_FLAGS = 9,
    BD_PARAM_LOCKFUNC = 10,
    BD_PARAM_LOCKFUNCARG = 11,
    BD_PARAM_NAME = 12,
} bus_dma_param_key_t;

typedef struct bus_dma_param {
    bus_dma_param_key_t key;
    union {
        void *ptr;
        bus_addr_t pa;
        uintmax_t num;
    };
} bus_dma_param_t;

#define BD_PARENT(value) { BD_PARAM_PARENT, .ptr = (value) }
#define BD_ALIGNMENT(value) { BD_PARAM_ALIGNMENT, .num = (value) }
#define BD_BOUNDARY(value) { BD_PARAM_BOUNDARY, .num = (value) }
#define BD_LOWADDR(value) { BD_PARAM_LOWADDR, .pa = (value) }
#define BD_HIGHADDR(value) { BD_PARAM_HIGHADDR, .pa = (value) }
#define BD_MAXSIZE(value) { BD_PARAM_MAXSIZE, .num = (value) }
#define BD_NSEGMENTS(value) { BD_PARAM_NSEGMENTS, .num = (value) }
#define BD_MAXSEGSIZE(value) { BD_PARAM_MAXSEGSIZE, .num = (value) }
#define BD_FLAGS(value) { BD_PARAM_FLAGS, .num = (value) }
#define BD_LOCKFUNC(value) { BD_PARAM_LOCKFUNC, .ptr = (value) }
#define BD_LOCKFUNCARG(value) { BD_PARAM_LOCKFUNCARG, .ptr = (value) }
#define BD_NAME(value) { BD_PARAM_NAME, .ptr = (value) }

#define BUS_DMA_TEMPLATE_FILL(template, ...) do {                       \
    bus_dma_param_t parameters[] = { __VA_ARGS__ };                     \
    bus_dma_template_fill((template), parameters,                       \
        (unsigned int)(sizeof(parameters) / sizeof(parameters[0])));     \
} while (0)

int bus_dma_tag_create(bus_dma_tag_t parent, bus_size_t alignment,
    bus_addr_t boundary, bus_addr_t lowaddr, bus_addr_t highaddr,
    bus_dma_filter_t *filter, void *filter_argument, bus_size_t maxsize,
    int nsegments, bus_size_t max_segment_size, int flags,
    bus_dma_lock_t *lock_function, void *lock_argument,
    bus_dma_tag_t *result);
int bus_dma_tag_destroy(bus_dma_tag_t tag);
int bus_dma_tag_set_domain(bus_dma_tag_t tag, int domain);
int bus_dma_tag_set_iommu(bus_dma_tag_t tag, void *iommu, void *domain);
bool bus_dma_id_mapped(bus_dma_tag_t tag, bus_addr_t physical_address,
    bus_size_t length);
void bus_dma_template_init(bus_dma_template_t *template,
    bus_dma_tag_t parent);
int bus_dma_template_tag(bus_dma_template_t *template,
    bus_dma_tag_t *result);
void bus_dma_template_clone(bus_dma_template_t *template,
    bus_dma_tag_t tag);
void bus_dma_template_fill(bus_dma_template_t *template,
    bus_dma_param_t *parameters, unsigned int count);

int bus_dmamap_create(bus_dma_tag_t tag, int flags, bus_dmamap_t *result);
int bus_dmamap_destroy(bus_dma_tag_t tag, bus_dmamap_t map);
int bus_dmamem_alloc(bus_dma_tag_t tag, void **virtual_address, int flags,
    bus_dmamap_t *result);
void bus_dmamem_free(bus_dma_tag_t tag, void *virtual_address,
    bus_dmamap_t map);
int bus_dmamap_load(bus_dma_tag_t tag, bus_dmamap_t map, void *buffer,
    bus_size_t length, bus_dmamap_callback_t *callback,
    void *callback_argument, int flags);
int _bus_dmamap_load_phys(bus_dma_tag_t tag, bus_dmamap_t map,
    bus_addr_t physical_address, bus_size_t length, int flags,
    bus_dma_segment_t *segments, int *segment_index);
int bus_dmamap_load_bio(bus_dma_tag_t tag, bus_dmamap_t map,
    struct bio *bio, bus_dmamap_callback_t *callback,
    void *callback_argument, int flags);
int bus_dmamap_load_uio(bus_dma_tag_t tag, bus_dmamap_t map,
    struct uio *uio, bus_dmamap_callback2_t *callback,
    void *callback_argument, int flags);
int bus_dmamap_load_mem(bus_dma_tag_t tag, bus_dmamap_t map,
    struct memdesc *memory, bus_dmamap_callback_t *callback,
    void *callback_argument, int flags);
int bus_dmamap_load_mbuf(bus_dma_tag_t tag, bus_dmamap_t map,
    struct mbuf *mbuf, bus_dmamap_callback2_t *callback,
    void *callback_argument, int flags);
int bus_dmamap_load_mbuf_sg(bus_dma_tag_t tag, bus_dmamap_t map,
    struct mbuf *mbuf, bus_dma_segment_t *segments, int *segment_count,
    int flags);
void bus_dmamap_sync(bus_dma_tag_t tag, bus_dmamap_t map,
    bus_dmasync_op_t operation);
int bus_dmamap_load_ccb(bus_dma_tag_t tag, bus_dmamap_t map,
    union ccb *ccb, bus_dmamap_callback_t *callback,
    void *callback_argument, int flags);
void bus_dmamap_unload(bus_dma_tag_t tag, bus_dmamap_t map);

void busdma_lock_mutex(void *argument, bus_dma_lock_op_t operation);
void _busdma_dflt_lock(void *argument, bus_dma_lock_op_t operation);

#ifdef EDGEOS_BSD_FULL_IOMMU
#include <machine/specialreg.h>
#include <x86/include/busdma_impl.h>
#endif

#endif
