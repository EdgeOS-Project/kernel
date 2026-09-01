/* SPDX-License-Identifier: MPL-2.0 */
/* Shared newbus contract implemented by the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_NEWBUS_H
#define EDGEOS_COMPAT_FREEBSD_NEWBUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_KERNEL) && !defined(BSD_BRIDGE_HOST_TEST)
#include <sys/bus.h>
#endif

#include "../machine/bus.h"
#include "../sys/kobj.h"

struct _device;
struct devclass;
struct module;
struct resource;
typedef struct _device *device_t;
typedef struct devclass *devclass_t;
typedef struct kobj_class driver_t;

#ifndef _SYS_BUS_H_
typedef enum device_state {
    DS_NOTPRESENT = 10,
    DS_ALIVE = 20,
    DS_ATTACHING = 25,
    DS_ATTACHED = 30,
} device_state_t;
#endif

#define DEVICE_UNIT_ANY (-1)

#define BUS_PROBE_SPECIFIC 0
#define BUS_PROBE_VENDOR (-10)
#define BUS_PROBE_DEFAULT (-20)
#define BUS_PROBE_LOW_PRIORITY (-40)
#define BUS_PROBE_GENERIC (-100)
#define BUS_PROBE_HOOVER (-1000000)
#define BUS_PROBE_NOWILDCARD (-2000000000)

extern device_t root_bus;
extern devclass_t root_devclass;

void bus_topo_lock(void);
void bus_topo_unlock(void);
void bus_topo_assert(void);

typedef struct bsd_driver_module_data {
    int (*chain_event)(struct module *, int, void *);
    void *chain_argument;
    const char *bus_name;
    kobj_class_t driver;
    devclass_t *driver_class;
    int pass;
} bsd_driver_module_data_t;

device_t bsd_newbus_create_root(const char *name, int unit,
    driver_t *driver);
int bsd_newbus_attach_synthetic(device_t parent, const char *name, int unit,
    driver_t *driver, device_t *result);
void bsd_device_set_dma_tag(device_t device, bus_dma_tag_t tag);

devclass_t devclass_create(const char *class_name);
devclass_t devclass_find(const char *class_name);
const char *devclass_get_name(devclass_t device_class);
int devclass_add_driver(devclass_t device_class, driver_t *driver,
    int pass, devclass_t *result);
int devclass_delete_driver(devclass_t device_class, driver_t *driver);
device_t devclass_get_device(devclass_t device_class, int unit);
void *devclass_get_softc(devclass_t device_class, int unit);
int devclass_get_devices(devclass_t device_class, device_t **devices,
    int *count);
int devclass_get_drivers(devclass_t device_class, driver_t ***drivers,
    int *count);
int devclass_get_count(devclass_t device_class);
int devclass_get_maxunit(devclass_t device_class);
int devclass_find_free_unit(devclass_t device_class, int unit);
void devclass_set_parent(devclass_t device_class, devclass_t parent);
devclass_t devclass_get_parent(devclass_t device_class);

device_t device_add_child(device_t parent, const char *name, int unit);
device_t device_add_child_ordered(device_t parent, unsigned int order,
    const char *name, int unit);
device_t bus_generic_add_child(device_t parent, unsigned int order,
    const char *name, int unit);
int device_delete_child(device_t parent, device_t child);
int device_delete_children(device_t parent);
int device_get_children(device_t device, device_t **children, int *count);
device_t device_find_child(device_t parent, const char *class_name, int unit);
void device_busy(device_t device);
void device_unbusy(device_t device);
void bsd_device_identify_children(device_t device);

int device_probe(device_t device);
int device_probe_child(device_t parent, device_t child);
int device_attach(device_t device);
int device_probe_and_attach(device_t device);
int device_detach(device_t device);
int device_shutdown(device_t device);
int device_suspend(device_t device);
int device_resume(device_t device);
int bus_detach_children(device_t device);
int bus_generic_detach(device_t device);
int bus_generic_shutdown(device_t device);
int bus_generic_suspend_child(device_t bus, device_t child);
int bus_generic_resume_child(device_t bus, device_t child);
int bus_generic_suspend(device_t device);
int bus_generic_resume(device_t device);

const char *device_get_name(device_t device);
const char *device_get_nameunit(device_t device);
const char *device_get_desc(device_t device);
device_t device_get_parent(device_t device);
driver_t *device_get_driver(device_t device);
devclass_t device_get_devclass(device_t device);
void *device_get_softc(device_t device);
void *device_get_ivars(device_t device);
void *bsd_device_get_firmware_metadata(device_t device);
int device_get_unit(device_t device);
device_state_t device_get_state(device_t device);
uint32_t device_get_flags(device_t device);
int device_is_alive(device_t device);
int device_is_attached(device_t device);
int device_is_enabled(device_t device);
int device_is_suspended(device_t device);
int device_is_quiet(device_t device);
int device_has_quiet_children(device_t device);
bool device_has_children(device_t device);
bool bsd_device_is_registered(device_t device);
bool bsd_device_implements_method(device_t device,
    struct kobjop_desc *descriptor);
struct resource *bsd_bus_alloc_resource_from_parent(device_t child,
    int type, int rid, uint64_t start, uint64_t end, uint64_t count,
    unsigned int flags);
int bsd_bus_release_resource_to_parent(device_t child,
    struct resource *resource);

int device_set_driver(device_t device, driver_t *driver);
int device_set_devclass(device_t device, const char *class_name);
int device_set_devclass_fixed(device_t device, const char *class_name);
bool device_is_devclass_fixed(device_t device);
int device_set_unit(device_t device, int unit);
void device_set_softc(device_t device, void *softc);
void device_claim_softc(device_t device);
void device_free_softc(void *softc);
void device_set_ivars(device_t device, void *ivars);
void bsd_device_set_ivars_owned(device_t device, void *ivars);
void bsd_device_set_firmware_metadata_owned(device_t device,
    void *metadata);
void device_set_flags(device_t device, uint32_t flags);
void device_set_desc(device_t device, const char *description);
void device_set_desc_copy(device_t device, const char *description);
void device_set_descf(device_t device, const char *format, ...);
void device_enable(device_t device);
void device_disable(device_t device);
void device_quiet(device_t device);
void device_quiet_children(device_t device);
void device_verbose(device_t device);
int device_print_prettyname(device_t device);
int device_printf(device_t device, const char *format, ...);

bus_dma_tag_t bus_get_dma_tag(device_t device);
int driver_module_handler(struct module *module, int event, void *argument);

#endif
