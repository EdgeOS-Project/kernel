/* SPDX-License-Identifier: MPL-2.0 */
/* Shared PCI contract for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_PCI_H
#define EDGEOS_COMPAT_FREEBSD_PCI_H

#include <stddef.h>
#include <stdint.h>

#include "newbus.h"

#define BSD_PCI_MAX_VECTORS 32

typedef struct {
    uint32_t domain;
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
} bsd_pci_location_t;

typedef struct {
    bsd_pci_location_t location;
    uint16_t vendor;
    uint16_t device;
    uint16_t subvendor;
    uint16_t subdevice;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t progif;
    uint8_t revision;
} bsd_pci_device_identity_t;

typedef int (*bsd_pci_select_device_t)(void *context,
    const bsd_pci_device_identity_t *identity);

typedef struct {
    bsd_pci_select_device_t select_device;
    void *context;
    int location_filter_enabled;
    uint32_t domain;
    uint8_t first_bus;
    uint8_t last_bus;
} bsd_pci_attach_options_t;

typedef struct {
    size_t discovered;
    size_t selected;
    size_t attached;
    size_t unclaimed;
} bsd_pci_bus_status_t;

typedef struct {
    uint32_t (*read_config)(void *context,
        const bsd_pci_location_t *location, uint16_t register_offset,
        unsigned int width);
    void (*write_config)(void *context,
        const bsd_pci_location_t *location, uint16_t register_offset,
        uint32_t value, unsigned int width);
    size_t (*function_count)(void *context);
    int (*function_at)(void *context, size_t index,
        bsd_pci_location_t *location);
    int (*prepare_device)(void *context,
        const bsd_pci_location_t *location);
    int (*translate_resource)(void *context,
        const bsd_pci_location_t *location, int resource_type,
        uint64_t bus_address, uint64_t size, uint64_t *host_address);
    int (*legacy_interrupt)(void *context,
        const bsd_pci_location_t *location, uint8_t interrupt_line,
        uint32_t *interrupt, uint32_t *interrupt_flags);
    int (*allocate_vectors)(void *context, unsigned int requested,
        int contiguous, uint32_t *vectors, unsigned int *allocated);
    void (*release_vectors)(void *context, const uint32_t *vectors,
        unsigned int count);
    int (*enable_msi)(void *context,
        const bsd_pci_location_t *location, const uint32_t *vectors,
        unsigned int count);
    int (*disable_msi)(void *context,
        const bsd_pci_location_t *location);
    int (*enable_msix)(void *context,
        const bsd_pci_location_t *location, unsigned int table_index,
        uint32_t vector);
    int (*disable_msix)(void *context,
        const bsd_pci_location_t *location, unsigned int table_index);
    int (*disable_msix_all)(void *context,
        const bsd_pci_location_t *location);
    void *context;
} bsd_pci_backend_ops_t;

int bsd_pci_initialize(const bsd_pci_backend_ops_t *operations);
int bsd_pci_is_initialized(void);
int bsd_pci_ensure_initialized(void);
int bsd_pci_read_config_at(const bsd_pci_location_t *location,
    uint16_t register_offset, unsigned int width, uint32_t *value);
int bsd_pci_write_config_at(const bsd_pci_location_t *location,
    uint16_t register_offset, unsigned int width, uint32_t value);
device_t bsd_pci_attach_bus(device_t parent);
device_t bsd_pci_attach_bus_selected(device_t parent,
    const bsd_pci_attach_options_t *options);
int bsd_pci_bus_get_status(device_t bus,
    bsd_pci_bus_status_t *status);
int bsd_pci_get_location(device_t device, bsd_pci_location_t *location);

uint32_t bsd_pci_read_config(device_t device, int register_offset,
    int width);
void bsd_pci_write_config(device_t device, int register_offset,
    uint32_t value, int width);
int bsd_pci_find_capability(device_t device, int capability,
    int start, int *capability_register);
int bsd_pci_alloc_msi(device_t device, int *count);
int bsd_pci_alloc_msix(device_t device, int *count);
int bsd_pci_release_msi(device_t device);
int bsd_pci_msi_count(device_t device);
int bsd_pci_msix_count(device_t device);
int bsd_pci_msix_table_bar(device_t device);
int bsd_pci_msix_pba_bar(device_t device);
int bsd_pci_reprogram_interrupts(void);
int pci_get_max_read_req(device_t device);
int pci_set_max_read_req(device_t device, int size);
void pci_save_state(device_t device);
void pci_restore_state(device_t device);

#endif
