/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS platform discovery used by imported FreeBSD x86 IOMMU drivers. */

#include <stdint.h>

#include "compat/freebsd/dev/acpica/acpivar.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/pci.h"
#include "compat/freebsd/sys/bus.h"
#include "compat/freebsd/x86/apicvar.h"
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
#include "drivers/apic.h"
#endif

int x2apic_mode;
int apic_ext_dest_id;
extern int mp_ncpus;

unsigned int
apic_cpuid(unsigned int apic_id)
{
    if (mp_ncpus <= 1)
        return 0;
    return apic_id < (unsigned int)mp_ncpus ? apic_id : 0;
}

int
ioapic_get_rid(unsigned int apic_id, uint16_t *rid)
{
    device_t device;
    uint32_t value;

    if (!rid)
        return 22;
    device = ioapic_get_dev(apic_id);
    if (!device || bsd_bus_get_property(device_get_parent(device), device,
        "pci-rid", &value, sizeof(value), DEVICE_PROP_UINT32) !=
        (ssize_t)sizeof(value) || value > UINT16_MAX)
        return 2;
    *rid = (uint16_t)value;
    return 0;
}

device_t
ioapic_get_dev(unsigned int apic_id)
{
    if (!root_bus || apic_id > INT32_MAX)
        return 0;
    return device_find_child(root_bus, "ioapic", (int)apic_id);
}

uint32_t
hpet_get_uid(device_t device)
{
    ACPI_HANDLE handle;
    UINT32 uid;
    int unit;

    if (!device)
        return UINT32_MAX;
    handle = acpi_get_handle(device);
    if (handle && ACPI_SUCCESS(acpi_GetInteger(handle, "_UID", &uid)))
        return uid;
    unit = device_get_unit(device);
    return unit >= 0 ? (uint32_t)unit : UINT32_MAX;
}

void
intr_reprogram(void)
{
    (void)bsd_pci_reprogram_interrupts();
}

int
lapic_enable_pcint(void)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    return apic_enable_performance_interrupt();
#else
    return 0;
#endif
}

void
lapic_disable_pcint(void)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    apic_disable_performance_interrupt();
#endif
}

void
lapic_reenable_pcint(void)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    apic_reenable_performance_interrupt();
#endif
}
