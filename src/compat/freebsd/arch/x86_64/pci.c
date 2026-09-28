/* SPDX-License-Identifier: MPL-2.0 */
/* x86-64 PCI adapter for the EdgeOS BSD Driver Bridge. */

#include <stddef.h>
#include <stdint.h>

#include "arch/x86_64/isr.h"
#include "compat/freebsd/edgeos/pci.h"
#include "drivers/apic.h"
#include "drivers/pci.h"

static uint32_t
bsd_x86_pci_read_config(void *context,
    const bsd_pci_location_t *location, uint16_t register_offset,
    unsigned int width)
{
    (void)context;
    if (location->domain != 0 || register_offset > UINT8_MAX)
        return UINT32_MAX;
    if (width == 1) {
        return pci_cfg_read8(location->bus, location->slot,
            location->function, (uint8_t)register_offset);
    }
    if (width == 2) {
        return pci_cfg_read16(location->bus, location->slot,
            location->function, (uint8_t)register_offset);
    }
    return pci_cfg_read32(location->bus, location->slot,
        location->function, (uint8_t)register_offset);
}

static void
bsd_x86_pci_write_config(void *context,
    const bsd_pci_location_t *location, uint16_t register_offset,
    uint32_t value, unsigned int width)
{
    (void)context;
    if (location->domain != 0 || register_offset > UINT8_MAX)
        return;
    if (width == 1) {
        pci_cfg_write8(location->bus, location->slot,
            location->function, (uint8_t)register_offset,
            (uint8_t)value);
    } else if (width == 2) {
        pci_cfg_write16(location->bus, location->slot,
            location->function, (uint8_t)register_offset,
            (uint16_t)value);
    } else {
        pci_cfg_write32(location->bus, location->slot,
            location->function, (uint8_t)register_offset, value);
    }
}

static size_t
bsd_x86_pci_function_count(void *context)
{
    (void)context;
    return pci_function_count();
}

static int
bsd_x86_pci_function_at(void *context, size_t index,
    bsd_pci_location_t *location)
{
    uint8_t bus;
    uint8_t slot;
    uint8_t function;

    (void)context;
    if (!location || index > UINT32_MAX ||
        pci_function_at((uint32_t)index, &bus, &slot, &function) != 0)
        return 2;
    location->domain = 0;
    location->bus = bus;
    location->slot = slot;
    location->function = function;
    return 0;
}

static int
bsd_x86_pci_legacy_interrupt(void *context,
    const bsd_pci_location_t *location, uint8_t interrupt_line,
    uint32_t *interrupt, uint32_t *interrupt_flags)
{
    (void)context;
    (void)location;
    if (!interrupt || !interrupt_flags || interrupt_line >= 224)
        return 22;
    *interrupt = IRQ_BASE + interrupt_line;
    *interrupt_flags = 0;
    return 0;
}

static int
bsd_x86_pci_allocate_vectors(void *context, unsigned int requested,
    int contiguous, uint32_t *vectors, unsigned int *allocated)
{
    (void)context;
    if (!allocated || *allocated < requested)
        return 22;
    if (apic_allocate_msi_vectors(requested, contiguous, vectors) != 0)
        return 28;
    *allocated = requested;
    return 0;
}

static void
bsd_x86_pci_release_vectors(void *context, const uint32_t *vectors,
    unsigned int count)
{
    (void)context;
    apic_release_msi_vectors(vectors, count);
}

static int
bsd_x86_pci_enable_msi(void *context,
    const bsd_pci_location_t *location, const uint32_t *vectors,
    unsigned int count)
{
    (void)context;
    return pci_enable_msi_vectors(location->bus, location->slot,
        location->function, vectors, count) == 0 ? 0 : 6;
}

static int
bsd_x86_pci_disable_msi(void *context,
    const bsd_pci_location_t *location)
{
    (void)context;
    return pci_disable_msi_vectors(location->bus, location->slot,
        location->function) == 0 ? 0 : 6;
}

static int
bsd_x86_pci_enable_msix(void *context,
    const bsd_pci_location_t *location, unsigned int table_index,
    uint32_t vector)
{
    (void)context;
    if (table_index > UINT16_MAX || vector > UINT8_MAX)
        return 22;
    return pci_enable_msix_vector(location->bus, location->slot,
        location->function, (uint16_t)table_index,
        (uint8_t)vector) == 0 ? 0 : 6;
}

static int
bsd_x86_pci_disable_msix(void *context,
    const bsd_pci_location_t *location, unsigned int table_index)
{
    (void)context;
    if (table_index > UINT16_MAX)
        return 22;
    return pci_disable_msix_vector(location->bus, location->slot,
        location->function, (uint16_t)table_index) == 0 ? 0 : 6;
}

static int
bsd_x86_pci_disable_msix_all(void *context,
    const bsd_pci_location_t *location)
{
    (void)context;
    return pci_disable_msix_vectors(location->bus, location->slot,
        location->function) == 0 ? 0 : 6;
}

int
bsd_pci_arch_initialize(void)
{
    bsd_pci_backend_ops_t operations = {
        .read_config = bsd_x86_pci_read_config,
        .write_config = bsd_x86_pci_write_config,
        .function_count = bsd_x86_pci_function_count,
        .function_at = bsd_x86_pci_function_at,
        .legacy_interrupt = bsd_x86_pci_legacy_interrupt,
        .allocate_vectors = bsd_x86_pci_allocate_vectors,
        .release_vectors = bsd_x86_pci_release_vectors,
        .enable_msi = bsd_x86_pci_enable_msi,
        .disable_msi = bsd_x86_pci_disable_msi,
        .enable_msix = bsd_x86_pci_enable_msix,
        .disable_msix = bsd_x86_pci_disable_msix,
        .disable_msix_all = bsd_x86_pci_disable_msix_all,
    };

    return bsd_pci_initialize(&operations);
}
