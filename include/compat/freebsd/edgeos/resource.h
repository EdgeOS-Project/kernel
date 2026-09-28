/* SPDX-License-Identifier: MPL-2.0 */
/* Resource discovery contract for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_RESOURCE_H
#define EDGEOS_COMPAT_FREEBSD_RESOURCE_H

#include <stdint.h>

#include "newbus.h"
#include "../machine/vm.h"
#include "../sys/rman.h"

#ifndef _SYS_BUS_H_
struct resource_map {
    bus_space_tag_t r_bustag;
    bus_space_handle_t r_bushandle;
    bus_size_t r_size;
    void *r_vaddr;
};

struct resource_map_request {
    size_t size;
    rman_res_t offset;
    rman_res_t length;
    char memattr;
};

struct resource_spec {
    int type;
    int rid;
    int flags;
};
#define RESOURCE_SPEC_END {-1, 0, 0}
#endif

#ifndef BSD_RESOURCE_INTERRUPT_SOURCE_OPS_DEFINED
#define BSD_RESOURCE_INTERRUPT_SOURCE_OPS_DEFINED
typedef struct {
    int (*enable)(void *context);
    int (*disable)(void *context);
    void *context;
    uint32_t interrupt_flags;
} bsd_resource_interrupt_source_ops_t;
#endif

int bsd_device_add_resource(device_t device, int type, int rid,
    rman_res_t start, rman_res_t count, unsigned int flags,
    bus_space_tag_t tag);
void bsd_resource_release_device(device_t device);
int bsd_resource_set_interrupt_source(device_t device, int rid,
    const bsd_resource_interrupt_source_ops_t *operations);
int bsd_resource_set_interrupt_flags(device_t device, int rid,
    uint32_t interrupt_flags);
uint32_t bsd_resource_get_interrupt_flags(const struct resource *resource);
struct rman *bsd_resource_get_manager(const struct resource *resource);
int bsd_resource_is_allocated(device_t device, int type, int rid);
int bsd_resource_enable_interrupt(struct resource *resource);
int bsd_resource_disable_interrupt(struct resource *resource);

#ifndef _SYS_BUS_H_
struct resource *bus_alloc_resource(device_t device, int type, int rid,
    rman_res_t start, rman_res_t end, rman_res_t count,
    unsigned int flags);
int bus_alloc_resources(device_t device, struct resource_spec *specifications,
    struct resource **resources);
void bus_release_resources(device_t device,
    const struct resource_spec *specifications, struct resource **resources);
int bus_adjust_resource(device_t device, struct resource *resource,
    rman_res_t start, rman_res_t end);
int bus_adjust_resource_old(device_t device, int type,
    struct resource *resource, rman_res_t start, rman_res_t end);
int bus_activate_resource(device_t device, struct resource *resource);
int bus_deactivate_resource(device_t device, struct resource *resource);
void resource_init_map_request_impl(struct resource_map_request *request,
    size_t size);
int resource_validate_map_request(struct resource *resource,
    struct resource_map_request *input, struct resource_map_request *output,
    rman_res_t *start, rman_res_t *length);
int bus_map_resource(device_t device, struct resource *resource,
    struct resource_map_request *request, struct resource_map *mapping);
int bus_map_resource_old(device_t device, int type,
    struct resource *resource, struct resource_map_request *request,
    struct resource_map *mapping);
int bus_unmap_resource(device_t device, struct resource *resource,
    struct resource_map *mapping);
int bus_unmap_resource_old(device_t device, int type,
    struct resource *resource, struct resource_map *mapping);
int bus_release_resource(device_t device, struct resource *resource);
int bus_release_resource_old(device_t device, int type, int rid,
    struct resource *resource);
int bus_free_resource(device_t device, int type, struct resource *resource);
int bus_set_resource(device_t device, int type, int rid,
    rman_res_t start, rman_res_t count);
int bus_get_resource(device_t device, int type, int rid,
    rman_res_t *start, rman_res_t *count);
rman_res_t bus_get_resource_start(device_t device, int type, int rid);
rman_res_t bus_get_resource_count(device_t device, int type, int rid);
void bus_delete_resource(device_t device, int type, int rid);
#endif

#endif
