/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS-owned Linux VFIO facade translated to FreeBSD bhyve ppt. */

#include <stdint.h>
#include <string.h>

#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/pci.h"
#include "compat/freebsd/edgeos/resource.h"
#include "kernel/edge_kvm_bhyve.h"
#include "kernel/edge_vfio_bhyve.h"
#include "kernel/edge_vfio_runtime.h"
#include "kernel/eventfd.h"
#include "kernel/linux_errno.h"

#include <sys/bus.h>
#include <sys/rman.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <machine/vmm.h>

#define EDGE_VFIO_BHYVE_REGION_SHIFT 40u
#define EDGE_VFIO_BHYVE_REGION_MASK ((UINT64_C(1) << 40) - 1u)
#define EDGE_VFIO_BHYVE_MAX_GROUPS EDGE_VFIO_MAX_GROUPS
#define EDGE_VFIO_BHYVE_MAX_DEVICES EDGE_VFIO_MAX_DEVICES

typedef struct edge_vfio_bhyve_group edge_vfio_bhyve_group_t;

typedef struct edge_vfio_bhyve_irq {
    uint8_t active;
    uint8_t masked;
    uint16_t reserved;
    int32_t event_id;
    int32_t rid;
    struct resource *resource;
    void *cookie;
} edge_vfio_bhyve_irq_t;

typedef struct edge_vfio_bhyve_device {
    uint8_t active;
    uint8_t assigned;
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
    uint8_t reserved[3];
    device_t device;
    edge_vfio_bhyve_group_t *group;
    uint32_t irq_index;
    uint32_t irq_count;
    edge_vfio_bhyve_irq_t irqs[BSD_PCI_MAX_VECTORS];
} edge_vfio_bhyve_device_t;

struct edge_vfio_bhyve_group {
    uint8_t active;
    uint8_t reserved[3];
    uint32_t group_id;
    uint64_t vm_cookie;
    struct vm *vm;
    edge_vfio_bhyve_device_t *devices[EDGE_VFIO_BHYVE_MAX_DEVICES];
    uint32_t device_count;
};

static edge_vfio_bhyve_group_t g_groups[EDGE_VFIO_BHYVE_MAX_GROUPS];
static edge_vfio_bhyve_device_t g_devices[EDGE_VFIO_BHYVE_MAX_DEVICES];

static int
edge_vfio_bhyve_error(int error)
{
    switch (error) {
    case 0: return 0;
    case 2: return -EDGE_LINUX_ENOENT;
    case 6: return -EDGE_LINUX_ENXIO;
    case 12: return -EDGE_LINUX_ENOMEM;
    case 16: return -EDGE_LINUX_EBUSY;
    case 17: return -EDGE_LINUX_EEXIST;
    case 22: return -EDGE_LINUX_EINVAL;
    case 28: return -EDGE_LINUX_ENOSPC;
    default: return -EDGE_LINUX_EIO;
    }
}

static int
edge_vfio_bhyve_parse_name(const char *name, uint32_t *domain,
    uint8_t *bus, uint8_t *slot, uint8_t *function)
{
    uint32_t values[4] = { 0, 0, 0, 0 };
    uint32_t digits[4] = { 4, 2, 2, 1 };
    char separators[3] = { ':', ':', '.' };

    if (!name || !domain || !bus || !slot || !function)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t field = 0; field < 4; ++field) {
        for (uint32_t digit = 0; digit < digits[field]; ++digit) {
            uint8_t value;
            char character = *name++;
            if (character >= '0' && character <= '9')
                value = (uint8_t)(character - '0');
            else if (character >= 'a' && character <= 'f')
                value = (uint8_t)(character - 'a' + 10);
            else if (character >= 'A' && character <= 'F')
                value = (uint8_t)(character - 'A' + 10);
            else
                return -EDGE_LINUX_EINVAL;
            values[field] = (values[field] << 4) | value;
        }
        if (field != 3 && *name++ != separators[field])
            return -EDGE_LINUX_EINVAL;
    }
    if (*name != '\0' || values[2] > 31u || values[3] > 7u)
        return -EDGE_LINUX_EINVAL;
    *domain = values[0];
    *bus = (uint8_t)values[1];
    *slot = (uint8_t)values[2];
    *function = (uint8_t)values[3];
    return 0;
}

static uint32_t
edge_vfio_bhyve_rid(uint8_t bus, uint8_t slot, uint8_t function)
{
    return ((uint32_t)bus << 8) | ((uint32_t)slot << 3) | function;
}

static int
edge_vfio_bhyve_is_ppt(device_t device)
{
    const char *name = device ? device_get_name(device) : 0;
    return name && name[0] == 'p' && name[1] == 'p' && name[2] == 't' &&
        name[3] == '\0';
}

static int
edge_vfio_bhyve_container_set_iommu(void *context, uint32_t iommu_type,
    uint64_t *container_cookie)
{
    (void)context;
    if (!container_cookie || (iommu_type != EDGE_VFIO_TYPE1_IOMMU &&
        iommu_type != EDGE_VFIO_TYPE1_V2_IOMMU))
        return -EDGE_LINUX_EINVAL;
    *container_cookie = iommu_type;
    return 0;
}

static int
edge_vfio_bhyve_container_clear_iommu(void *context,
    uint64_t container_cookie)
{
    (void)context;
    (void)container_cookie;
    return 0;
}

static int
edge_vfio_bhyve_group_open(void *context, uint32_t group_id, int *viable,
    uint64_t *group_cookie)
{
    edge_vfio_bhyve_group_t *group = 0;
    uint8_t bus = (uint8_t)(group_id >> 8);
    uint8_t slot = (uint8_t)((group_id >> 3) & 31u);
    uint8_t function = (uint8_t)(group_id & 7u);
    device_t device;

    (void)context;
    if (!viable || !group_cookie || group_id > UINT16_MAX)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_VFIO_BHYVE_MAX_GROUPS; ++index) {
        if (g_groups[index].active && g_groups[index].group_id == group_id)
            return -EDGE_LINUX_EBUSY;
        if (!group && !g_groups[index].active)
            group = &g_groups[index];
    }
    if (!group)
        return -EDGE_LINUX_ENOSPC;
    device = pci_find_dbsf(0, bus, slot, function);
    *viable = edge_vfio_bhyve_is_ppt(device);
    memset(group, 0, sizeof(*group));
    group->active = 1;
    group->group_id = group_id;
    *group_cookie = (uint64_t)(uintptr_t)group;
    return 0;
}

static void
edge_vfio_bhyve_group_close(void *context, uint64_t group_cookie)
{
    edge_vfio_bhyve_group_t *group =
        (edge_vfio_bhyve_group_t *)(uintptr_t)group_cookie;
    (void)context;
    if (group && group->active && group->device_count == 0)
        memset(group, 0, sizeof(*group));
}

static int
edge_vfio_bhyve_group_attach(void *context, uint64_t group_cookie,
    uint64_t container_cookie)
{
    edge_vfio_bhyve_group_t *group =
        (edge_vfio_bhyve_group_t *)(uintptr_t)group_cookie;
    (void)context;
    if (!group || !group->active || (container_cookie != EDGE_VFIO_TYPE1_IOMMU &&
        container_cookie != EDGE_VFIO_TYPE1_V2_IOMMU))
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static void
edge_vfio_bhyve_group_detach(void *context, uint64_t group_cookie,
    uint64_t container_cookie)
{
    (void)context;
    (void)group_cookie;
    (void)container_cookie;
}

static int
edge_vfio_bhyve_assign(edge_vfio_bhyve_device_t *device, struct vm *vm)
{
    int error;
    if (device->assigned)
        return 0;
    error = vm_assign_pptdev(vm, device->bus, device->slot,
        device->function);
    if (error == 0)
        device->assigned = 1;
    return edge_vfio_bhyve_error(error);
}

static int
edge_vfio_bhyve_unassign(edge_vfio_bhyve_device_t *device, struct vm *vm)
{
    int error;
    if (!device->assigned)
        return 0;
    error = vm_unassign_pptdev(vm, device->bus, device->slot,
        device->function);
    if (error == 0)
        device->assigned = 0;
    return edge_vfio_bhyve_error(error);
}

static int
edge_vfio_bhyve_irq_filter(void *argument)
{
    edge_vfio_bhyve_irq_t *irq = argument;
    if (!irq || !irq->active || irq->masked)
        return FILTER_STRAY;
    (void)kernel_eventfd_write_value(irq->event_id, 1, 1);
    return FILTER_HANDLED;
}

static void
edge_vfio_bhyve_release_irqs(edge_vfio_bhyve_device_t *device)
{
    if (!device || !device->active)
        return;
    for (uint32_t index = 0; index < BSD_PCI_MAX_VECTORS; ++index) {
        edge_vfio_bhyve_irq_t *irq = &device->irqs[index];
        if (!irq->active)
            continue;
        if (irq->cookie)
            (void)bus_teardown_intr(
                device->device, irq->resource, irq->cookie);
        if (irq->resource)
            (void)bus_release_resource(device->device, SYS_RES_IRQ,
                irq->rid, irq->resource);
        kernel_eventfd_release(irq->event_id);
        memset(irq, 0, sizeof(*irq));
    }
    if (device->irq_index == EDGE_VFIO_PCI_MSI_IRQ_INDEX ||
        device->irq_index == EDGE_VFIO_PCI_MSIX_IRQ_INDEX)
        (void)bsd_pci_release_msi(device->device);
    device->irq_index = 0;
    device->irq_count = 0;
}

static int
edge_vfio_bhyve_group_bind_vm(void *context, uint64_t group_cookie,
    uint64_t vm_cookie)
{
    edge_vfio_bhyve_group_t *group =
        (edge_vfio_bhyve_group_t *)(uintptr_t)group_cookie;
    struct vm *vm = edge_kvm_bhyve_x86_native_vm(vm_cookie);
    uint32_t assigned = 0;
    int status;

    (void)context;
    if (!group || !group->active || !vm)
        return -EDGE_LINUX_EINVAL;
    if (group->vm && group->vm != vm)
        return -EDGE_LINUX_EBUSY;
    for (; assigned < group->device_count; ++assigned) {
        status = edge_vfio_bhyve_assign(group->devices[assigned], vm);
        if (status < 0) {
            while (assigned != 0)
                (void)edge_vfio_bhyve_unassign(
                    group->devices[--assigned], vm);
            return status;
        }
    }
    group->vm_cookie = vm_cookie;
    group->vm = vm;
    return 0;
}

static int
edge_vfio_bhyve_group_unbind_vm(void *context, uint64_t group_cookie,
    uint64_t vm_cookie)
{
    edge_vfio_bhyve_group_t *group =
        (edge_vfio_bhyve_group_t *)(uintptr_t)group_cookie;
    int first_error = 0;

    (void)context;
    if (!group || !group->active || !group->vm ||
        group->vm_cookie != vm_cookie)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = group->device_count; index != 0; --index) {
        int status = edge_vfio_bhyve_unassign(
            group->devices[index - 1], group->vm);
        if (status < 0 && first_error == 0)
            first_error = status;
    }
    if (first_error == 0) {
        group->vm = 0;
        group->vm_cookie = 0;
    }
    return first_error;
}

static int
edge_vfio_bhyve_device_open(void *context, uint64_t group_cookie,
    uint64_t vm_cookie, const char *name, uint64_t *device_cookie)
{
    edge_vfio_bhyve_group_t *group =
        (edge_vfio_bhyve_group_t *)(uintptr_t)group_cookie;
    edge_vfio_bhyve_device_t *backend_device = 0;
    uint32_t domain;
    uint8_t bus, slot, function;
    device_t device;
    int status;

    (void)context;
    (void)vm_cookie;
    if (!group || !group->active || !device_cookie)
        return -EDGE_LINUX_EINVAL;
    status = edge_vfio_bhyve_parse_name(
        name, &domain, &bus, &slot, &function);
    if (status < 0)
        return status;
    if (domain != 0 || edge_vfio_bhyve_rid(bus, slot, function) !=
        group->group_id)
        return -EDGE_LINUX_EINVAL;
    device = pci_find_dbsf(domain, bus, slot, function);
    if (!edge_vfio_bhyve_is_ppt(device))
        return -EDGE_LINUX_ENODEV;
    for (uint32_t index = 0; index < EDGE_VFIO_BHYVE_MAX_DEVICES; ++index) {
        if (g_devices[index].active && g_devices[index].device == device)
            return -EDGE_LINUX_EBUSY;
        if (!backend_device && !g_devices[index].active)
            backend_device = &g_devices[index];
    }
    if (!backend_device || group->device_count == EDGE_VFIO_BHYVE_MAX_DEVICES)
        return -EDGE_LINUX_ENOSPC;
    memset(backend_device, 0, sizeof(*backend_device));
    backend_device->active = 1;
    backend_device->bus = bus;
    backend_device->slot = slot;
    backend_device->function = function;
    backend_device->device = device;
    backend_device->group = group;
    if (group->vm) {
        status = edge_vfio_bhyve_assign(backend_device, group->vm);
        if (status < 0) {
            memset(backend_device, 0, sizeof(*backend_device));
            return status;
        }
    }
    group->devices[group->device_count++] = backend_device;
    *device_cookie = (uint64_t)(uintptr_t)backend_device;
    return 0;
}

static void
edge_vfio_bhyve_device_close(void *context, uint64_t device_cookie)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    edge_vfio_bhyve_group_t *group;

    (void)context;
    if (!device || !device->active)
        return;
    group = device->group;
    edge_vfio_bhyve_release_irqs(device);
    if (group && group->vm)
        (void)edge_vfio_bhyve_unassign(device, group->vm);
    if (group) {
        for (uint32_t index = 0; index < group->device_count; ++index) {
            if (group->devices[index] != device)
                continue;
            group->devices[index] = group->devices[--group->device_count];
            break;
        }
    }
    memset(device, 0, sizeof(*device));
}

static int
edge_vfio_bhyve_device_get_info(void *context, uint64_t device_cookie,
    edge_vfio_device_info_t *info)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    (void)context;
    if (!device || !device->active || !info)
        return -EDGE_LINUX_EINVAL;
    info->flags = EDGE_VFIO_DEVICE_FLAGS_PCI | EDGE_VFIO_DEVICE_FLAGS_RESET;
    info->num_regions = EDGE_VFIO_PCI_NUM_REGIONS;
    info->num_irqs = EDGE_VFIO_PCI_NUM_IRQS;
    info->cap_offset = 0;
    info->padding = 0;
    return 0;
}

static struct pci_map *
edge_vfio_bhyve_bar(edge_vfio_bhyve_device_t *device, uint32_t index)
{
    if (index >= 6u)
        return 0;
    return pci_find_bar(device->device, PCIR_BAR(index));
}

static int
edge_vfio_bhyve_device_get_region_info(void *context,
    uint64_t device_cookie, edge_vfio_region_info_t *info)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    struct pci_map *bar;

    (void)context;
    if (!device || !device->active || !info ||
        info->index >= EDGE_VFIO_PCI_NUM_REGIONS)
        return -EDGE_LINUX_EINVAL;
    info->flags = 0;
    info->size = 0;
    info->offset = (uint64_t)info->index << EDGE_VFIO_BHYVE_REGION_SHIFT;
    info->cap_offset = 0;
    if (info->index == EDGE_VFIO_PCI_CONFIG_REGION_INDEX) {
        info->flags = EDGE_VFIO_REGION_INFO_FLAG_READ |
            EDGE_VFIO_REGION_INFO_FLAG_WRITE;
        info->size = 4096u;
        return 0;
    }
    bar = edge_vfio_bhyve_bar(device, info->index);
    if (!bar)
        return 0;
    info->size = (uint64_t)1u << bar->pm_size;
    info->flags = EDGE_VFIO_REGION_INFO_FLAG_READ |
        EDGE_VFIO_REGION_INFO_FLAG_WRITE;
    if (PCI_BAR_MEM(bar->pm_value))
        info->flags |= EDGE_VFIO_REGION_INFO_FLAG_MMAP;
    return 0;
}

static int
edge_vfio_bhyve_device_get_irq_info(void *context, uint64_t device_cookie,
    edge_vfio_irq_info_t *info)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    int count = 0;

    (void)context;
    if (!device || !device->active || !info ||
        info->index >= EDGE_VFIO_PCI_NUM_IRQS)
        return -EDGE_LINUX_EINVAL;
    info->flags = 0;
    if (info->index == EDGE_VFIO_PCI_INTX_IRQ_INDEX)
        count = 1;
    else if (info->index == EDGE_VFIO_PCI_MSI_IRQ_INDEX)
        count = bsd_pci_msi_count(device->device);
    else if (info->index == EDGE_VFIO_PCI_MSIX_IRQ_INDEX)
        count = bsd_pci_msix_count(device->device);
    if (count > 0) {
        info->flags = EDGE_VFIO_IRQ_INFO_EVENTFD |
            EDGE_VFIO_IRQ_INFO_NORESIZE;
        if (info->index == EDGE_VFIO_PCI_INTX_IRQ_INDEX)
            info->flags |= EDGE_VFIO_IRQ_INFO_MASKABLE |
                EDGE_VFIO_IRQ_INFO_AUTOMASKED;
    }
    info->count = count > 0 ? (uint32_t)count : 0;
    return 0;
}

static int
edge_vfio_bhyve_device_set_irqs(void *context, uint64_t device_cookie,
    const edge_vfio_irq_set_t *set, const void *data, uint32_t data_size)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    const int32_t *event_ids = data;
    int requested;
    int flags;

    (void)context;
    if (!device || !device->active || !set ||
        set->index > EDGE_VFIO_PCI_MSIX_IRQ_INDEX)
        return -EDGE_LINUX_EINVAL;
    if ((set->flags & EDGE_VFIO_IRQ_SET_ACTION_TRIGGER) == 0) {
        if ((set->flags & (EDGE_VFIO_IRQ_SET_ACTION_MASK |
            EDGE_VFIO_IRQ_SET_ACTION_UNMASK)) == 0 ||
            set->start > device->irq_count ||
            set->count > device->irq_count - set->start)
            return -EDGE_LINUX_EINVAL;
        for (uint32_t index = 0; index < set->count; ++index) {
            edge_vfio_bhyve_irq_t *irq =
                &device->irqs[set->start + index];
            irq->masked =
                (set->flags & EDGE_VFIO_IRQ_SET_ACTION_MASK) != 0;
            if (irq->resource) {
                if (irq->masked)
                    (void)bsd_resource_disable_interrupt(irq->resource);
                else
                    (void)bsd_resource_enable_interrupt(irq->resource);
            }
        }
        return 0;
    }
    if (set->count == 0) {
        edge_vfio_bhyve_release_irqs(device);
        return 0;
    }
    if ((set->flags & EDGE_VFIO_IRQ_SET_DATA_EVENTFD) == 0 || !event_ids ||
        data_size != set->count * sizeof(*event_ids) || set->start != 0 ||
        set->count > BSD_PCI_MAX_VECTORS)
        return -EDGE_LINUX_EINVAL;
    edge_vfio_bhyve_release_irqs(device);
    requested = (int)set->count;
    flags = RF_ACTIVE;
    if (set->index == EDGE_VFIO_PCI_INTX_IRQ_INDEX) {
        if (set->count != 1)
            return -EDGE_LINUX_EINVAL;
        flags |= RF_SHAREABLE;
    } else {
        int status = set->index == EDGE_VFIO_PCI_MSI_IRQ_INDEX ?
            bsd_pci_alloc_msi(device->device, &requested) :
            bsd_pci_alloc_msix(device->device, &requested);
        if (status != 0)
            return edge_vfio_bhyve_error(status);
        if (requested != (int)set->count) {
            (void)bsd_pci_release_msi(device->device);
            return -EDGE_LINUX_ENOSPC;
        }
    }
    device->irq_index = set->index;
    for (uint32_t index = 0; index < set->count; ++index) {
        edge_vfio_bhyve_irq_t *irq = &device->irqs[index];
        int status;
        if (event_ids[index] < 0 ||
            kernel_eventfd_retain(event_ids[index]) < 0) {
            edge_vfio_bhyve_release_irqs(device);
            return -EDGE_LINUX_EBADF;
        }
        irq->event_id = event_ids[index];
        irq->rid = set->index == EDGE_VFIO_PCI_INTX_IRQ_INDEX ?
            0 : (int)index + 1;
        irq->resource = bus_alloc_resource_any(device->device,
            SYS_RES_IRQ, &irq->rid, flags);
        if (!irq->resource) {
            kernel_eventfd_release(irq->event_id);
            memset(irq, 0, sizeof(*irq));
            edge_vfio_bhyve_release_irqs(device);
            return -EDGE_LINUX_ENXIO;
        }
        irq->active = 1;
        status = bus_setup_intr(device->device, irq->resource,
            INTR_TYPE_MISC | INTR_MPSAFE, edge_vfio_bhyve_irq_filter,
            0, irq, &irq->cookie);
        if (status != 0) {
            edge_vfio_bhyve_release_irqs(device);
            return edge_vfio_bhyve_error(status);
        }
        ++device->irq_count;
    }
    return 0;
}

static int
edge_vfio_bhyve_device_reset(void *context, uint64_t device_cookie)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    (void)context;
    if (!device || !device->active)
        return -EDGE_LINUX_EINVAL;
    pci_save_state(device->device);
    (void)pci_power_reset(device->device);
    pci_restore_state(device->device);
    return 0;
}

static int64_t
edge_vfio_bhyve_device_read(void *context, uint64_t device_cookie,
    uint64_t offset, void *buffer, uint32_t size)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    uint32_t region = (uint32_t)(offset >> EDGE_VFIO_BHYVE_REGION_SHIFT);
    uint64_t region_offset = offset & EDGE_VFIO_BHYVE_REGION_MASK;
    uint8_t *bytes = buffer;

    (void)context;
    if (!device || !device->active || !buffer || size == 0 ||
        region != EDGE_VFIO_PCI_CONFIG_REGION_INDEX ||
        region_offset > 4096u || size > 4096u - region_offset)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < size; ++index)
        bytes[index] = (uint8_t)bsd_pci_read_config(device->device,
            (int)(region_offset + index), 1);
    return size;
}

static int64_t
edge_vfio_bhyve_device_write(void *context, uint64_t device_cookie,
    uint64_t offset, const void *buffer, uint32_t size)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    uint32_t region = (uint32_t)(offset >> EDGE_VFIO_BHYVE_REGION_SHIFT);
    uint64_t region_offset = offset & EDGE_VFIO_BHYVE_REGION_MASK;
    const uint8_t *bytes = buffer;

    (void)context;
    if (!device || !device->active || !buffer || size == 0 ||
        region != EDGE_VFIO_PCI_CONFIG_REGION_INDEX ||
        region_offset > 4096u || size > 4096u - region_offset)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < size; ++index)
        bsd_pci_write_config(device->device,
            (int)(region_offset + index), bytes[index], 1);
    return size;
}

static int
edge_vfio_bhyve_device_mmap(void *context, uint64_t device_cookie,
    uint64_t offset, uint64_t size, uint32_t protection,
    uint64_t *physical_address)
{
    edge_vfio_bhyve_device_t *device =
        (edge_vfio_bhyve_device_t *)(uintptr_t)device_cookie;
    uint32_t region = (uint32_t)(offset >> EDGE_VFIO_BHYVE_REGION_SHIFT);
    uint64_t region_offset = offset & EDGE_VFIO_BHYVE_REGION_MASK;
    struct pci_map *bar;
    uint64_t bar_size;

    (void)context;
    (void)protection;
    if (!device || !device->active || !physical_address || size == 0)
        return -EDGE_LINUX_EINVAL;
    bar = edge_vfio_bhyve_bar(device, region);
    if (!bar || !PCI_BAR_MEM(bar->pm_value))
        return -EDGE_LINUX_ENXIO;
    bar_size = (uint64_t)1u << bar->pm_size;
    if (region_offset > bar_size || size > bar_size - region_offset)
        return -EDGE_LINUX_EINVAL;
    *physical_address = (bar->pm_value & PCIM_BAR_MEM_BASE) + region_offset;
    return 0;
}

static int
edge_vfio_bhyve_dma_map(void *context, uint64_t container_cookie,
    uint64_t vm_cookie, uint64_t iova, uint64_t userspace_address,
    uint64_t size, uint32_t flags)
{
    (void)context;
    (void)container_cookie;
    if (!edge_kvm_bhyve_x86_native_vm(vm_cookie))
        return -EDGE_LINUX_EINVAL;
    /* ppt uses the native VM address space, so IOVA must match guest GPA. */
    return edge_kvm_bhyve_x86_validate_dma_mapping(vm_cookie, iova,
        userspace_address, size, flags);
}

static int
edge_vfio_bhyve_dma_unmap(void *context, uint64_t container_cookie,
    uint64_t vm_cookie, uint64_t iova, uint64_t size)
{
    (void)context;
    (void)container_cookie;
    (void)vm_cookie;
    (void)iova;
    (void)size;
    return 0;
}

int
edge_vfio_bhyve_x86_register(void)
{
    edge_vfio_backend_ops_t backend = {
        .container_set_iommu = edge_vfio_bhyve_container_set_iommu,
        .container_clear_iommu = edge_vfio_bhyve_container_clear_iommu,
        .group_open = edge_vfio_bhyve_group_open,
        .group_close = edge_vfio_bhyve_group_close,
        .group_attach = edge_vfio_bhyve_group_attach,
        .group_detach = edge_vfio_bhyve_group_detach,
        .group_bind_vm = edge_vfio_bhyve_group_bind_vm,
        .group_unbind_vm = edge_vfio_bhyve_group_unbind_vm,
        .device_open = edge_vfio_bhyve_device_open,
        .device_close = edge_vfio_bhyve_device_close,
        .device_get_info = edge_vfio_bhyve_device_get_info,
        .device_get_region_info = edge_vfio_bhyve_device_get_region_info,
        .device_get_irq_info = edge_vfio_bhyve_device_get_irq_info,
        .device_set_irqs = edge_vfio_bhyve_device_set_irqs,
        .device_reset = edge_vfio_bhyve_device_reset,
        .device_read = edge_vfio_bhyve_device_read,
        .device_write = edge_vfio_bhyve_device_write,
        .device_mmap = edge_vfio_bhyve_device_mmap,
        .dma_map = edge_vfio_bhyve_dma_map,
        .dma_unmap = edge_vfio_bhyve_dma_unmap,
    };

    memset(g_groups, 0, sizeof(g_groups));
    memset(g_devices, 0, sizeof(g_devices));
    return kernel_edge_vfio_backend_register(&backend);
}
