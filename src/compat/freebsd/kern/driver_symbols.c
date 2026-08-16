/* SPDX-License-Identifier: MPL-2.0 */
/* Stable kernel symbols available to source-built BSD driver modules. */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef INTRNG
#define INTRNG 1
#endif

#include <sys/bus.h>
#include <sys/intr.h>

#include "compat/freebsd/edgeos/driver_loader.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/random/randomdev.h"
#include "compat/freebsd/dev/ofw/ofw_bus.h"
#include "compat/freebsd/dev/ofw/ofw_bus_subr.h"
#include "compat/freebsd/sys/eventhandler.h"
#include "compat/freebsd/sys/module.h"
#include "compat/freebsd/sys/sglist.h"
#include <sys/firmware.h>
#include <sys/watchdog.h>
#include "device_if.h"

struct virtqueue;
struct vq_alloc_info;
struct bus_space;

extern struct bus_space memmap_bus;

void virtio_read_ivar(device_t device, int ivar, uintptr_t *value);
void virtio_write_ivar(device_t device, int ivar, uintptr_t value);
uint64_t virtio_negotiate_features(device_t device, uint64_t features);
int virtio_finalize_features(device_t device);
int virtio_alloc_virtqueues(device_t device, int count,
    struct vq_alloc_info *information);
bool virtqueue_empty(struct virtqueue *queue);
void virtqueue_notify(struct virtqueue *queue);
int virtqueue_enqueue(struct virtqueue *queue, void *cookie,
    struct sglist *segments, int readable, int writable);
void *virtqueue_dequeue(struct virtqueue *queue, uint32_t *length);
void *virtqueue_poll(struct virtqueue *queue, uint32_t *length);

struct bsd_driver_symbol {
    const char *name;
    const void *address;
};

#define BSD_DRIVER_FUNCTION(symbol) \
    { #symbol, (const void *)(uintptr_t)&symbol }
#define BSD_DRIVER_NAMED_FUNCTION(name, symbol) \
    { (name), (const void *)(uintptr_t)&symbol }
#define BSD_DRIVER_OBJECT(symbol) \
    { #symbol, (const void *)(uintptr_t)&symbol }

static const struct bsd_driver_symbol g_driver_symbols[] = {
    BSD_DRIVER_OBJECT(M_DEVBUF),
    BSD_DRIVER_FUNCTION(bsd_bridge_panic_stop),
    BSD_DRIVER_FUNCTION(bsd_free),
    BSD_DRIVER_FUNCTION(bsd_malloc_aligned),
    BSD_DRIVER_FUNCTION(bsd_memcpy),
    BSD_DRIVER_FUNCTION(bsd_snprintf),
    BSD_DRIVER_OBJECT(device_attach_desc),
    BSD_DRIVER_OBJECT(device_detach_desc),
    BSD_DRIVER_FUNCTION(device_get_nameunit),
    BSD_DRIVER_FUNCTION(device_get_softc),
    BSD_DRIVER_FUNCTION(device_printf),
    BSD_DRIVER_OBJECT(device_probe_desc),
    BSD_DRIVER_FUNCTION(device_set_desc),
    BSD_DRIVER_OBJECT(device_shutdown_desc),
    BSD_DRIVER_FUNCTION(driver_module_handler),
    BSD_DRIVER_FUNCTION(eventhandler_deregister),
    BSD_DRIVER_FUNCTION(eventhandler_find_list),
    BSD_DRIVER_FUNCTION(eventhandler_register),
    BSD_DRIVER_FUNCTION(firmware_register),
    BSD_DRIVER_FUNCTION(firmware_unregister),
    BSD_DRIVER_FUNCTION(intr_alloc_msi),
    BSD_DRIVER_FUNCTION(intr_alloc_msix),
    BSD_DRIVER_FUNCTION(intr_map_msi),
    BSD_DRIVER_FUNCTION(intr_msi_register),
    BSD_DRIVER_FUNCTION(intr_release_msi),
    BSD_DRIVER_FUNCTION(intr_release_msix),
    BSD_DRIVER_FUNCTION(module_register_init),
    BSD_DRIVER_FUNCTION(OF_canon),
    BSD_DRIVER_FUNCTION(OF_child),
    BSD_DRIVER_FUNCTION(OF_device_from_xref),
    BSD_DRIVER_FUNCTION(OF_device_register_xref),
    BSD_DRIVER_FUNCTION(OF_device_unregister_xref),
    BSD_DRIVER_FUNCTION(OF_finddevice),
    BSD_DRIVER_FUNCTION(OF_getencprop),
    BSD_DRIVER_FUNCTION(OF_getencprop_alloc),
    BSD_DRIVER_FUNCTION(OF_getencprop_alloc_multi),
    BSD_DRIVER_FUNCTION(OF_getprop),
    BSD_DRIVER_FUNCTION(OF_getprop_alloc),
    BSD_DRIVER_FUNCTION(OF_getprop_alloc_multi),
    BSD_DRIVER_FUNCTION(OF_getproplen),
    BSD_DRIVER_FUNCTION(OF_hasprop),
    BSD_DRIVER_FUNCTION(OF_init),
    BSD_DRIVER_FUNCTION(OF_install),
    BSD_DRIVER_FUNCTION(OF_instance_to_package),
    BSD_DRIVER_FUNCTION(OF_instance_to_path),
    BSD_DRIVER_FUNCTION(OF_nextprop),
    BSD_DRIVER_FUNCTION(OF_node_from_xref),
    BSD_DRIVER_FUNCTION(OF_package_to_path),
    BSD_DRIVER_FUNCTION(OF_parent),
    BSD_DRIVER_FUNCTION(OF_peer),
    BSD_DRIVER_FUNCTION(OF_prop_free),
    BSD_DRIVER_FUNCTION(OF_searchencprop),
    BSD_DRIVER_FUNCTION(OF_searchprop),
    BSD_DRIVER_FUNCTION(OF_setprop),
    BSD_DRIVER_FUNCTION(OF_test),
    BSD_DRIVER_FUNCTION(OF_xref_from_device),
    BSD_DRIVER_FUNCTION(OF_xref_from_node),
    BSD_DRIVER_FUNCTION(ofw_bus_find_child),
    BSD_DRIVER_FUNCTION(ofw_bus_find_child_device_by_phandle),
    BSD_DRIVER_FUNCTION(ofw_bus_find_compatible),
    BSD_DRIVER_FUNCTION(ofw_bus_destroy_iinfo),
    BSD_DRIVER_FUNCTION(ofw_bus_get_compat),
    BSD_DRIVER_FUNCTION(ofw_bus_get_model),
    BSD_DRIVER_FUNCTION(ofw_bus_get_name),
    BSD_DRIVER_FUNCTION(ofw_bus_get_node),
    BSD_DRIVER_FUNCTION(ofw_bus_get_status),
    BSD_DRIVER_FUNCTION(ofw_bus_get_type),
    BSD_DRIVER_FUNCTION(ofw_bus_has_prop),
    BSD_DRIVER_FUNCTION(ofw_bus_is_compatible),
    BSD_DRIVER_FUNCTION(ofw_bus_is_compatible_strict),
    BSD_DRIVER_FUNCTION(ofw_bus_is_machine_compatible),
    BSD_DRIVER_FUNCTION(ofw_bus_iommu_map),
    BSD_DRIVER_FUNCTION(ofw_bus_lookup_imap),
    BSD_DRIVER_FUNCTION(ofw_bus_msimap),
    BSD_DRIVER_FUNCTION(ofw_bus_node_is_compatible),
    BSD_DRIVER_FUNCTION(ofw_bus_node_status_okay),
    BSD_DRIVER_FUNCTION(ofw_bus_search_compatible),
    BSD_DRIVER_FUNCTION(ofw_bus_search_intrmap),
    BSD_DRIVER_FUNCTION(ofw_bus_setup_iinfo),
    BSD_DRIVER_FUNCTION(ofw_bus_status_okay),
    BSD_DRIVER_FUNCTION(bsd_ofw_fdt_find_compatible),
    BSD_DRIVER_FUNCTION(bsd_ofw_fdt_get_interrupt_count),
    BSD_DRIVER_FUNCTION(bsd_ofw_fdt_get_interrupt),
    BSD_DRIVER_FUNCTION(bsd_ofw_fdt_get_reg_count),
    BSD_DRIVER_FUNCTION(bsd_ofw_fdt_get_reg),
    BSD_DRIVER_OBJECT(memmap_bus),
    BSD_DRIVER_NAMED_FUNCTION("printf", bsd_printf),
    BSD_DRIVER_FUNCTION(random_source_deregister),
    BSD_DRIVER_FUNCTION(random_source_register),
    BSD_DRIVER_FUNCTION(sglist_build),
    BSD_DRIVER_FUNCTION(sglist_free),
    BSD_DRIVER_FUNCTION(wdog_control),
    BSD_DRIVER_FUNCTION(wdog_kern_last_timeout),
    BSD_DRIVER_FUNCTION(wdog_kern_last_timeout_sbt),
    BSD_DRIVER_FUNCTION(wdog_kern_pat),
    BSD_DRIVER_FUNCTION(wdog_kern_pat_sbt),
    BSD_DRIVER_FUNCTION(virtio_alloc_virtqueues),
    BSD_DRIVER_FUNCTION(virtio_finalize_features),
    BSD_DRIVER_FUNCTION(virtio_negotiate_features),
    BSD_DRIVER_FUNCTION(virtio_read_ivar),
    BSD_DRIVER_FUNCTION(virtio_write_ivar),
    BSD_DRIVER_FUNCTION(virtqueue_dequeue),
    BSD_DRIVER_FUNCTION(virtqueue_empty),
    BSD_DRIVER_FUNCTION(virtqueue_enqueue),
    BSD_DRIVER_FUNCTION(virtqueue_notify),
    BSD_DRIVER_FUNCTION(virtqueue_poll),
};

int
bsd_driver_symbol_resolve(const char *name, uint64_t *address,
    void *context)
{
    (void)context;
    if (!name || !address)
        return -1;
    for (size_t index = 0;
        index < sizeof(g_driver_symbols) / sizeof(g_driver_symbols[0]);
        ++index) {
        if (bsd_strcmp(g_driver_symbols[index].name, name) == 0) {
            *address = (uint64_t)(uintptr_t)g_driver_symbols[index].address;
            return 0;
        }
    }
    return -1;
}

size_t
bsd_driver_symbol_count(void)
{
    return sizeof(g_driver_symbols) / sizeof(g_driver_symbols[0]);
}
