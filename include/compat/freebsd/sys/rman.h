/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD-compatible resource interface backed by the EdgeOS BSD bridge. */

#ifndef _SYS_RMAN_H_
#define _SYS_RMAN_H_

#include <stddef.h>
#include <stdint.h>

#include "../machine/bus.h"
#include "../machine/resource.h"

#ifndef _RMAN_RES_T_DECLARED
#define _RMAN_RES_T_DECLARED
typedef uint64_t rman_res_t;
#endif

#define RF_ALLOCATED 0x0001
#define RF_ACTIVE 0x0002
#define RF_SHAREABLE 0x0004
#define RF_SPARE1 0x0008
#define RF_SPARE2 0x0010
#define RF_FIRSTSHARE 0x0020
#define RF_PREFETCHABLE 0x0040
#define RF_OPTIONAL 0x0080
#define RF_UNMAPPED 0x0100

#define RF_ALIGNMENT_SHIFT 10
#define RF_ALIGNMENT_MASK (0x003fU << RF_ALIGNMENT_SHIFT)
#define RF_ALIGNMENT_LOG2(value) ((value) << RF_ALIGNMENT_SHIFT)
#define RF_ALIGNMENT(value) \
    (((value) & RF_ALIGNMENT_MASK) >> RF_ALIGNMENT_SHIFT)

#define RM_MAX_END (~(rman_res_t)0)
#define RMAN_IS_DEFAULT_RANGE(start, end) \
    ((start) == 0 && (end) == RM_MAX_END)

#define RMAN_UNINIT 0
#define RMAN_GAUGE 1
#define RMAN_ARRAY 2

struct resource_i;
struct rman {
    void *rm_private;
    rman_res_t rm_start;
    rman_res_t rm_end;
    int rm_type;
    const char *rm_descr;
};

struct resource {
    struct resource_i *__r_i;
    bus_space_tag_t r_bustag;
    bus_space_handle_t r_bushandle;
    void *r_virtual;
    uint64_t start;
    uint64_t end;
    const char *name;
    unsigned long flags;
};

struct _device;
typedef struct _device *device_t;
struct resource_map;

int rman_activate_resource(struct resource *resource);
int rman_deactivate_resource(struct resource *resource);
int rman_init(struct rman *manager);
int rman_fini(struct rman *manager);
int rman_manage_region(struct rman *manager, rman_res_t start,
    rman_res_t end);
int rman_first_free_region(struct rman *manager, rman_res_t *start,
    rman_res_t *end);
int rman_last_free_region(struct rman *manager, rman_res_t *start,
    rman_res_t *end);
struct resource *rman_reserve_resource(struct rman *manager,
    rman_res_t start, rman_res_t end, rman_res_t count,
    unsigned int flags, device_t device);
int rman_release_resource(struct resource *resource);
int rman_adjust_resource(struct resource *resource, rman_res_t start,
    rman_res_t end);
int rman_is_region_manager(const struct resource *resource,
    const struct rman *manager);
uint32_t rman_make_alignment_flags(uint32_t size);
rman_res_t rman_get_start(const struct resource *resource);
rman_res_t rman_get_end(const struct resource *resource);
rman_res_t rman_get_size(const struct resource *resource);
unsigned int rman_get_flags(const struct resource *resource);
int rman_get_rid(const struct resource *resource);
int rman_get_type(const struct resource *resource);
device_t rman_get_device(const struct resource *resource);
void *rman_get_virtual(const struct resource *resource);
bus_space_tag_t rman_get_bustag(const struct resource *resource);
bus_space_handle_t rman_get_bushandle(const struct resource *resource);
void *rman_get_irq_cookie(const struct resource *resource);
int rman_claim_irq_cookie(struct resource *resource, void *expected,
    void *replacement);

void rman_set_device(struct resource *resource, device_t device);
void rman_set_rid(struct resource *resource, int rid);
void rman_set_type(struct resource *resource, int type);
void rman_set_bustag(struct resource *resource, bus_space_tag_t tag);
void rman_set_bushandle(struct resource *resource,
    bus_space_handle_t handle);
void rman_set_virtual(struct resource *resource, void *virtual_address);
void rman_set_mapping(struct resource *resource,
    struct resource_map *mapping);
void rman_get_mapping(const struct resource *resource,
    struct resource_map *mapping);
void rman_set_irq_cookie(struct resource *resource, void *cookie);

#endif
