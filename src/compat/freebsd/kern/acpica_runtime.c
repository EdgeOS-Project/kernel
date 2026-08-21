/* SPDX-License-Identifier: MPL-2.0 */
/* Shared ACPICA subsystem and namespace startup for EdgeOS. */

#include <stddef.h>
#include <stdint.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/devctl.h>
#include <sys/rman.h>
#include <sys/sbuf.h>

#include <isa/isavar.h>

#if defined(__x86_64__)
#include <machine/cputypes.h>
#include <machine/md_var.h>
#endif

#include "compat/freebsd/edgeos/acpica.h"
#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/acpica/acpivar.h"
#include "kernel/system_runtime.h"

#define BSD_ACPICA_ENXIO 6
#define BSD_ACPICA_ENOENT 2
#define BSD_ACPICA_ENOMEM 12
#define BSD_ACPICA_EINVAL 22
#define BSD_ACPICA_EOPNOTSUPP 95
#define BSD_ACPICA_MAX_DEVICES 512

int bsd_device_add_resource(device_t device, int type, int rid,
    rman_res_t start, rman_res_t count, unsigned int flags,
    bus_space_tag_t tag);

typedef enum bsd_acpica_state {
    BSD_ACPICA_UNINITIALIZED,
    BSD_ACPICA_INITIALIZING,
    BSD_ACPICA_READY,
    BSD_ACPICA_FAILED,
} bsd_acpica_state_t;

static volatile int g_acpica_state;
struct mtx acpi_mutex;
#if defined(__x86_64__)
int acpi_override_isa_irq_polarity;
#endif
static bsd_acpica_runtime_status_t g_acpica_status;
static device_t g_acpica_bus;
static struct acpi_softc g_acpica_softc = {
    .acpi_stype = POWER_STYPE_AWAKE,
    .acpi_power_button_stype = POWER_STYPE_UNKNOWN,
    .acpi_sleep_button_stype = POWER_STYPE_UNKNOWN,
    .acpi_lid_switch_stype = POWER_STYPE_UNKNOWN,
    .acpi_standby_sx = ACPI_STATE_S1,
};

typedef struct bsd_acpica_device_mapping {
    ACPI_HANDLE handle;
    device_t device;
} bsd_acpica_device_mapping_t;

static bsd_acpica_device_mapping_t
    g_acpica_devices[BSD_ACPICA_MAX_DEVICES];
static uint32_t g_acpica_device_mapping_count;

typedef struct bsd_acpica_resource_context {
    device_t device;
    int memory_rid;
    int io_rid;
    int irq_rid;
} bsd_acpica_resource_context_t;

static int
acpica_bridge_bus_probe(device_t device)
{
    device_set_desc(device, "ACPI namespace");
    return BUS_PROBE_DEFAULT;
}

static int
acpica_bridge_bus_attach(device_t device)
{
    (void)device;
    return 0;
}

static int
acpica_bridge_bus_get_resource(device_t bus, device_t child,
    int type, int rid, rman_res_t *start, rman_res_t *count)
{
    rman_res_t ignored_start;
    rman_res_t ignored_count;

    (void)bus;
    return bus_get_resource(child, type, rid,
        start ? start : &ignored_start,
        count ? count : &ignored_count);
}

static struct resource_list *
acpica_bridge_bus_get_resource_list(device_t bus, device_t child)
{
    struct acpi_device *device_context;

    (void)bus;
    device_context = device_get_ivars(child);
    return device_context ? &device_context->ad_rl : 0;
}

static int
acpica_bridge_bus_set_resource(device_t bus, device_t child,
    int type, int rid, rman_res_t start, rman_res_t count)
{
    (void)bus;
    return bus_set_resource(child, type, rid, start, count);
}

static void
acpica_bridge_bus_delete_resource(device_t bus, device_t child,
    int type, int rid)
{
    (void)bus;
    bus_delete_resource(child, type, rid);
}

static int
acpica_bridge_isa_pnp_probe(device_t bus, device_t child,
    struct isa_pnp_id *identifiers)
{
    (void)bus;
    while (identifiers && identifiers->ip_id) {
        const char *identifier = pnp_eisaformat(identifiers->ip_id);

        if (identifier &&
            bsd_firmware_acpi_match(child, identifier)) {
            if (identifiers->ip_desc)
                device_set_desc(child, identifiers->ip_desc);
            return 0;
        }
        identifiers++;
    }
    return BSD_ACPICA_ENXIO;
}

static device_method_t acpica_bridge_bus_methods[] = {
    DEVMETHOD(device_probe, acpica_bridge_bus_probe),
    DEVMETHOD(device_attach, acpica_bridge_bus_attach),
    DEVMETHOD(device_detach, bus_generic_detach),
    DEVMETHOD(device_shutdown, bus_generic_shutdown),
    DEVMETHOD(device_suspend, bus_generic_suspend),
    DEVMETHOD(device_resume, bus_generic_resume),
    DEVMETHOD(bus_add_child, bus_generic_add_child),
    DEVMETHOD(bus_get_resource_list, acpica_bridge_bus_get_resource_list),
    DEVMETHOD(bus_get_resource, acpica_bridge_bus_get_resource),
    DEVMETHOD(bus_set_resource, acpica_bridge_bus_set_resource),
    DEVMETHOD(bus_delete_resource, acpica_bridge_bus_delete_resource),
    DEVMETHOD(bus_alloc_resource, bus_generic_alloc_resource),
    DEVMETHOD(bus_adjust_resource, bus_generic_adjust_resource),
    DEVMETHOD(bus_release_resource, bus_generic_release_resource),
    DEVMETHOD(bus_activate_resource, bus_generic_activate_resource),
    DEVMETHOD(bus_deactivate_resource, bus_generic_deactivate_resource),
    DEVMETHOD(bus_map_resource, bus_generic_map_resource),
    DEVMETHOD(bus_unmap_resource, bus_generic_unmap_resource),
    DEVMETHOD(bus_setup_intr, bus_generic_setup_intr),
    DEVMETHOD(bus_teardown_intr, bus_generic_teardown_intr),
    DEVMETHOD(isa_pnp_probe, acpica_bridge_isa_pnp_probe),
    DEVMETHOD_END
};

static driver_t acpica_bridge_bus_driver = {
    "acpi",
    acpica_bridge_bus_methods,
    0,
};

static int
acpica_child_bind(device_t child,
    const bsd_firmware_description_t *firmware)
{
    struct acpi_device *device_context;
    int error;

    if (!child || !firmware || device_get_ivars(child))
        return BSD_ACPICA_EINVAL;
    device_context = bsd_malloc(sizeof(*device_context), M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!device_context)
        return BSD_ACPICA_ENOMEM;
    device_context->ad_handle = firmware->acpi_handle;
    device_context->ad_domain = ACPI_DEV_DOMAIN_UNKNOWN;
    resource_list_init(&device_context->ad_rl);
    bsd_device_set_ivars_owned(child, device_context);
    error = bsd_firmware_bind(child, firmware);
    if (error != 0)
        device_set_ivars(child, 0);
    return error;
}

static void
acpica_child_discard(device_t child)
{
    struct acpi_device *device_context;

    if (!child)
        return;
    device_context = device_get_ivars(child);
    if (device_context) {
        resource_list_free(&device_context->ad_rl);
        device_set_ivars(child, 0);
    }
    if (g_acpica_bus)
        (void)device_delete_child(g_acpica_bus, child);
}

static ACPI_STATUS
acpica_add_resource(bsd_acpica_resource_context_t *context,
    int type, int *rid, uint64_t start, uint64_t count,
    unsigned int flags)
{
    struct acpi_device *device_context;
    struct resource_list_entry *entry;

    if (count == 0 || start > UINT64_MAX - (count - 1))
        return AE_OK;
    device_context = device_get_ivars(context->device);
    if (!device_context)
        return AE_BAD_PARAMETER;
    if (bsd_device_add_resource(context->device, type, *rid,
        start, count, flags, 0) != 0)
        return AE_NO_MEMORY;
    entry = resource_list_add(&device_context->ad_rl, type, *rid,
        start, start + count - 1, count);
    if (!entry) {
        bus_delete_resource(context->device, type, *rid);
        return AE_NO_MEMORY;
    }
    if ((flags & RF_PREFETCHABLE) != 0)
        entry->flags |= RLE_PREFETCH;
    (*rid)++;
    return AE_OK;
}

static ACPI_STATUS
acpica_add_interrupts(bsd_acpica_resource_context_t *context,
    const UINT32 *interrupts, UINT8 count, UINT8 shareable)
{
    unsigned int flags =
        shareable == ACPI_SHARED ? RF_SHAREABLE : 0;

    for (UINT8 index = 0; index < count; ++index) {
        ACPI_STATUS status = acpica_add_resource(
            context, SYS_RES_IRQ, &context->irq_rid,
            interrupts[index], 1, flags);

        if (ACPI_FAILURE(status))
            return status;
    }
    return AE_OK;
}

static ACPI_STATUS
acpica_register_resource(ACPI_RESOURCE *resource, void *opaque_context)
{
    bsd_acpica_resource_context_t *context = opaque_context;
    uint64_t start;
    uint64_t count;
    int type;

    switch (resource->Type) {
    case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
        return acpica_add_resource(context, SYS_RES_MEMORY,
            &context->memory_rid,
            resource->Data.FixedMemory32.Address,
            resource->Data.FixedMemory32.AddressLength, 0);
    case ACPI_RESOURCE_TYPE_MEMORY24:
        return acpica_add_resource(context, SYS_RES_MEMORY,
            &context->memory_rid, resource->Data.Memory24.Minimum,
            resource->Data.Memory24.AddressLength, 0);
    case ACPI_RESOURCE_TYPE_MEMORY32:
        return acpica_add_resource(context, SYS_RES_MEMORY,
            &context->memory_rid, resource->Data.Memory32.Minimum,
            resource->Data.Memory32.AddressLength, 0);
    case ACPI_RESOURCE_TYPE_FIXED_IO:
        return acpica_add_resource(context, SYS_RES_IOPORT,
            &context->io_rid, resource->Data.FixedIo.Address,
            resource->Data.FixedIo.AddressLength, 0);
    case ACPI_RESOURCE_TYPE_IO:
        return acpica_add_resource(context, SYS_RES_IOPORT,
            &context->io_rid, resource->Data.Io.Minimum,
            resource->Data.Io.AddressLength, 0);
    case ACPI_RESOURCE_TYPE_IRQ: {
        UINT32 interrupts[256];
        UINT8 interrupt_count =
            resource->Data.Irq.InterruptCount;

        for (UINT8 index = 0; index < interrupt_count; ++index)
            interrupts[index] = resource->Data.Irq.Interrupts[index];
        return acpica_add_interrupts(context, interrupts,
            interrupt_count, resource->Data.Irq.Shareable);
    }
    case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
        if (resource->Data.ExtendedIrq.ProducerConsumer !=
            ACPI_CONSUMER)
            return AE_OK;
        return acpica_add_interrupts(context,
            resource->Data.ExtendedIrq.Interrupts,
            resource->Data.ExtendedIrq.InterruptCount,
            resource->Data.ExtendedIrq.Shareable);
    case ACPI_RESOURCE_TYPE_ADDRESS16:
        if (resource->Data.Address16.ProducerConsumer != ACPI_CONSUMER)
            return AE_OK;
        type = resource->Data.Address16.ResourceType ==
            ACPI_MEMORY_RANGE ? SYS_RES_MEMORY :
            resource->Data.Address16.ResourceType == ACPI_IO_RANGE ?
            SYS_RES_IOPORT : -1;
        start = resource->Data.Address16.Address.Minimum;
        count = resource->Data.Address16.Address.AddressLength;
        break;
    case ACPI_RESOURCE_TYPE_ADDRESS32:
        if (resource->Data.Address32.ProducerConsumer != ACPI_CONSUMER)
            return AE_OK;
        type = resource->Data.Address32.ResourceType ==
            ACPI_MEMORY_RANGE ? SYS_RES_MEMORY :
            resource->Data.Address32.ResourceType == ACPI_IO_RANGE ?
            SYS_RES_IOPORT : -1;
        start = resource->Data.Address32.Address.Minimum;
        count = resource->Data.Address32.Address.AddressLength;
        break;
    case ACPI_RESOURCE_TYPE_ADDRESS64:
        if (resource->Data.Address64.ProducerConsumer != ACPI_CONSUMER)
            return AE_OK;
        type = resource->Data.Address64.ResourceType ==
            ACPI_MEMORY_RANGE ? SYS_RES_MEMORY :
            resource->Data.Address64.ResourceType == ACPI_IO_RANGE ?
            SYS_RES_IOPORT : -1;
        start = resource->Data.Address64.Address.Minimum;
        count = resource->Data.Address64.Address.AddressLength;
        break;
    case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
        if (resource->Data.ExtAddress64.ProducerConsumer !=
            ACPI_CONSUMER)
            return AE_OK;
        type = resource->Data.ExtAddress64.ResourceType ==
            ACPI_MEMORY_RANGE ? SYS_RES_MEMORY :
            resource->Data.ExtAddress64.ResourceType == ACPI_IO_RANGE ?
            SYS_RES_IOPORT : -1;
        start = resource->Data.ExtAddress64.Address.Minimum;
        count = resource->Data.ExtAddress64.Address.AddressLength;
        break;
    default:
        return AE_OK;
    }
    if (type == SYS_RES_MEMORY) {
        return acpica_add_resource(context, type,
            &context->memory_rid, start, count, 0);
    }
    if (type == SYS_RES_IOPORT) {
        return acpica_add_resource(context, type,
            &context->io_rid, start, count, 0);
    }
    return AE_OK;
}

static ACPI_STATUS
acpica_register_device_resources(ACPI_HANDLE handle, device_t device)
{
    bsd_acpica_resource_context_t context = {
        .device = device,
    };
    ACPI_STATUS status =
        AcpiWalkResources(handle, "_CRS",
            acpica_register_resource, &context);

    return status == AE_NOT_FOUND ? AE_OK : status;
}

static ACPI_STATUS
acpica_count_device(ACPI_HANDLE object, UINT32 depth, void *context,
    void **return_value)
{
    uint32_t *count = context;

    (void)object;
    (void)depth;
    (void)return_value;
    if (*count != UINT32_MAX)
        (*count)++;
    return AE_OK;
}

static uint64_t
acpica_device_status(ACPI_HANDLE handle)
{
    ACPI_OBJECT object;
    ACPI_BUFFER buffer = {
        .Length = sizeof(object),
        .Pointer = &object,
    };
    ACPI_STATUS status;

    status = AcpiEvaluateObject(handle, "_STA", 0, &buffer);
    if (ACPI_FAILURE(status) || object.Type != ACPI_TYPE_INTEGER)
        return ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_ENABLED |
            ACPI_STA_DEVICE_FUNCTIONING;
    return object.Integer.Value;
}

static void
acpica_name_string(UINT32 name, char output[5])
{
    output[0] = (char)(name & 0xff);
    output[1] = (char)((name >> 8) & 0xff);
    output[2] = (char)((name >> 16) & 0xff);
    output[3] = (char)((name >> 24) & 0xff);
    output[4] = '\0';
}

static int
acpica_mapping_add(ACPI_HANDLE handle, device_t device)
{
    uint32_t index = g_acpica_device_mapping_count;

    if (!handle || !device)
        return BSD_ACPICA_ENXIO;
    for (uint32_t existing = 0; existing < index; ++existing) {
        if (g_acpica_devices[existing].handle != handle)
            continue;
        g_acpica_devices[existing].device = device;
        return 0;
    }
    if (index >= BSD_ACPICA_MAX_DEVICES)
        return BSD_ACPICA_ENXIO;
    g_acpica_devices[index].handle = handle;
    g_acpica_devices[index].device = device;
    g_acpica_device_mapping_count = index + 1;
    return 0;
}

static ACPI_STATUS
acpica_register_device(ACPI_HANDLE handle, UINT32 depth, void *context,
    void **return_value)
{
    ACPI_DEVICE_INFO *info = 0;
    bsd_firmware_description_t firmware = {
        .kind = BSD_FIRMWARE_ACPI,
    };
    const char *compatible[64];
    const char *hardware_id = 0;
    device_t child;
    ACPI_STATUS status;
    uint64_t device_status;
    uint32_t compatible_count = 0;
    char name[5];
    int error;

    (void)depth;
    (void)context;
    (void)return_value;
    if (g_acpica_device_mapping_count >= BSD_ACPICA_MAX_DEVICES)
        return AE_LIMIT;
    status = AcpiGetObjectInfo(handle, &info);
    if (ACPI_FAILURE(status) || !info)
        return AE_OK;

    if ((info->Valid & ACPI_VALID_HID) != 0 &&
        info->HardwareId.String && info->HardwareId.String[0] != '\0')
        hardware_id = info->HardwareId.String;
    if ((info->Valid & ACPI_VALID_CID) != 0) {
        uint32_t count = info->CompatibleIdList.Count;

        if (count > sizeof(compatible) / sizeof(compatible[0]))
            count = sizeof(compatible) / sizeof(compatible[0]);
        for (uint32_t index = 0; index < count; ++index) {
            const char *identifier =
                info->CompatibleIdList.Ids[index].String;

            if (!identifier || identifier[0] == '\0')
                continue;
            compatible[compatible_count++] = identifier;
            if (!hardware_id)
                hardware_id = identifier;
        }
    }
    if (!hardware_id) {
        ACPI_FREE(info);
        return AE_OK;
    }

    device_status = acpica_device_status(handle);
    firmware.enabled =
        (device_status & ACPI_STA_DEVICE_PRESENT) != 0;
    firmware.acpi_handle = handle;
    firmware.hardware_id = hardware_id;
    firmware.compatible = compatible;
    firmware.compatible_count = compatible_count;

    child = device_add_child(g_acpica_bus, 0, DEVICE_UNIT_ANY);
    if (!child) {
        ACPI_FREE(info);
        return AE_NO_MEMORY;
    }
    error = acpica_child_bind(child, &firmware);
    status = error == 0 ?
        acpica_register_device_resources(handle, child) :
        AE_NO_MEMORY;
    if (error != 0 || ACPI_FAILURE(status)) {
        acpica_child_discard(child);
        ACPI_FREE(info);
        return error != 0 ? AE_NO_MEMORY : status;
    }
    if (acpica_mapping_add(handle, child) != 0) {
        acpica_child_discard(child);
        ACPI_FREE(info);
        return AE_NO_MEMORY;
    }

    acpica_name_string(info->Name, name);
    device_set_descf(child, "ACPI %s (%s)", hardware_id, name);
    g_acpica_status.registered_device_count++;
    if (firmware.enabled)
        g_acpica_status.present_device_count++;
    /* PCI ownership changes only through the bridge handoff transaction. */
    if (firmware.enabled &&
        (info->Flags & ACPI_PCI_ROOT_BRIDGE) == 0) {
        if (device_probe_and_attach(child) == 0)
            g_acpica_status.matched_device_count++;
    }
    ACPI_FREE(info);
    return AE_OK;
}

static const char *
acpica_object_description(ACPI_OBJECT_TYPE type)
{
    switch (type) {
    case ACPI_TYPE_PROCESSOR:
        return "Processor";
    case ACPI_TYPE_THERMAL:
        return "Thermal Zone";
    case ACPI_TYPE_POWER:
        return "Power Resource";
    default:
        return "Namespace Object";
    }
}

static ACPI_STATUS
acpica_register_special_object(ACPI_HANDLE handle, UINT32 depth,
    void *context, void **return_value)
{
    ACPI_DEVICE_INFO *info = 0;
    bsd_firmware_description_t firmware = {
        .kind = BSD_FIRMWARE_ACPI,
        .enabled = 1,
        .acpi_handle = handle,
    };
    ACPI_OBJECT_TYPE type;
    device_t child;
    ACPI_STATUS status;
    char name[5];

    (void)depth;
    (void)context;
    (void)return_value;
    if (g_acpica_device_mapping_count >= BSD_ACPICA_MAX_DEVICES)
        return AE_LIMIT;
    status = AcpiGetType(handle, &type);
    if (ACPI_FAILURE(status) ||
        (type != ACPI_TYPE_PROCESSOR &&
         type != ACPI_TYPE_THERMAL &&
         type != ACPI_TYPE_POWER))
        return AE_OK;
    status = AcpiGetObjectInfo(handle, &info);
    if (ACPI_FAILURE(status) || !info)
        return AE_OK;

    child = device_add_child(g_acpica_bus, 0, DEVICE_UNIT_ANY);
    if (!child) {
        ACPI_FREE(info);
        return AE_NO_MEMORY;
    }
    if (acpica_child_bind(child, &firmware) != 0) {
        acpica_child_discard(child);
        ACPI_FREE(info);
        return AE_NO_MEMORY;
    }
    status = acpica_register_device_resources(handle, child);
    if (ACPI_FAILURE(status) ||
        acpica_mapping_add(handle, child) != 0) {
        acpica_child_discard(child);
        ACPI_FREE(info);
        return ACPI_FAILURE(status) ? status : AE_LIMIT;
    }

    acpica_name_string(info->Name, name);
    device_set_descf(child, "ACPI %s (%s)",
        acpica_object_description(type), name);
    g_acpica_status.registered_device_count++;
    g_acpica_status.present_device_count++;
    if (device_probe_and_attach(child) == 0)
        g_acpica_status.matched_device_count++;
    ACPI_FREE(info);
    return AE_OK;
}

static ACPI_STATUS
acpica_register_fixed_button(const char *hardware_id,
    const char *description)
{
    bsd_firmware_description_t firmware = {
        .kind = BSD_FIRMWARE_ACPI,
        .enabled = 1,
        .hardware_id = hardware_id,
    };
    device_t child;

    child = device_add_child(g_acpica_bus, 0, DEVICE_UNIT_ANY);
    if (!child)
        return AE_NO_MEMORY;
    if (acpica_child_bind(child, &firmware) != 0) {
        acpica_child_discard(child);
        return AE_NO_MEMORY;
    }
    device_set_desc(child, description);
    g_acpica_status.registered_device_count++;
    g_acpica_status.present_device_count++;
    if (device_probe_and_attach(child) == 0) {
        g_acpica_status.matched_device_count++;
        bsd_printf("[acpica] %s attached\n", description);
    }
    return AE_OK;
}

static ACPI_STATUS
acpica_prepare_bus(void)
{
    int error;

    if (!root_bus)
        return AE_NOT_EXIST;
    if (!g_acpica_bus) {
        g_acpica_bus = device_find_child(root_bus, "acpi", 0);
        if (!g_acpica_bus)
            g_acpica_bus = device_add_child(root_bus, "acpi", 0);
    }
    if (!g_acpica_bus)
        return AE_NO_MEMORY;
    device_set_desc(g_acpica_bus, "ACPI namespace");
    if (!g_acpica_softc.acpi_dev)
        resource_list_init(&g_acpica_softc.sysres_rl);
    g_acpica_softc.acpi_dev = g_acpica_bus;
    if (!g_acpica_softc.acpi_sysctl_tree) {
        (void)sysctl_ctx_init(&g_acpica_softc.acpi_sysctl_ctx);
        g_acpica_softc.acpi_sysctl_tree = SYSCTL_ADD_NODE(
            &g_acpica_softc.acpi_sysctl_ctx,
            SYSCTL_CHILDREN(&sysctl___hw), OID_AUTO, "acpi",
            CTLFLAG_RD | CTLFLAG_MPSAFE, 0, "ACPI runtime");
        if (!g_acpica_softc.acpi_sysctl_tree)
            return AE_NO_MEMORY;
    }
    if (!device_get_driver(g_acpica_bus)) {
        error = device_set_driver(
            g_acpica_bus, &acpica_bridge_bus_driver);
        if (error != 0)
            return AE_ERROR;
        device_set_softc(g_acpica_bus, &g_acpica_softc);
    } else if (device_get_driver(g_acpica_bus) !=
        &acpica_bridge_bus_driver) {
        return AE_ALREADY_EXISTS;
    }
    if (!device_is_attached(g_acpica_bus) &&
        device_probe_and_attach(g_acpica_bus) != 0)
        return AE_ERROR;
    return AE_OK;
}

static ACPI_STATUS
acpica_register_namespace_devices(void)
{
    ACPI_STATUS status;

    status = acpica_prepare_bus();
    if (ACPI_FAILURE(status))
        return status;
    if ((AcpiGbl_FADT.Flags & ACPI_FADT_POWER_BUTTON) == 0) {
        status = acpica_register_fixed_button(
            "ACPI_FPB", "Power Button (fixed)");
        if (ACPI_FAILURE(status))
            return status;
    }
    if ((AcpiGbl_FADT.Flags & ACPI_FADT_SLEEP_BUTTON) == 0) {
        status = acpica_register_fixed_button(
            "ACPI_FSB", "Sleep Button (fixed)");
        if (ACPI_FAILURE(status))
            return status;
    }
    status = AcpiWalkNamespace(ACPI_TYPE_PROCESSOR, ACPI_ROOT_OBJECT,
        100, acpica_register_special_object, 0, 0, 0);
    if (ACPI_FAILURE(status))
        return status;
    status = AcpiWalkNamespace(ACPI_TYPE_THERMAL, ACPI_ROOT_OBJECT,
        100, acpica_register_special_object, 0, 0, 0);
    if (ACPI_FAILURE(status))
        return status;
    status = AcpiWalkNamespace(ACPI_TYPE_POWER, ACPI_ROOT_OBJECT,
        100, acpica_register_special_object, 0, 0, 0);
    if (ACPI_FAILURE(status))
        return status;
    return AcpiGetDevices(0, acpica_register_device, 0, 0);
}

static int
acpica_fail(ACPI_STATUS status)
{
    g_acpica_status.failure_status = status;
    __atomic_store_n(&g_acpica_state, BSD_ACPICA_FAILED, __ATOMIC_RELEASE);
    bsd_printf("[acpica] initialization failed status=0x%x\n",
        (uint32_t)status);
    return BSD_ACPICA_ENXIO;
}

int
bsd_acpica_runtime_initialize(void)
{
    int expected = BSD_ACPICA_UNINITIALIZED;
    ACPI_STATUS status;

    if (!__atomic_compare_exchange_n(&g_acpica_state, &expected,
        BSD_ACPICA_INITIALIZING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        while (expected == BSD_ACPICA_INITIALIZING) {
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
            expected = __atomic_load_n(&g_acpica_state, __ATOMIC_ACQUIRE);
        }
        return expected == BSD_ACPICA_READY ? 0 : BSD_ACPICA_ENXIO;
    }

    g_acpica_status = (bsd_acpica_runtime_status_t){0};
#if defined(__x86_64__)
    acpi_override_isa_irq_polarity =
        cpu_vendor_id == CPU_VENDOR_INTEL ? 1 : 0;
#endif
    if (!mtx_initialized(&acpi_mutex))
        mtx_init(&acpi_mutex, "ACPI global lock", 0, MTX_DEF);
    if (AcpiOsGetRootPointer() == 0)
        return acpica_fail(AE_NOT_EXIST);

    status = AcpiInitializeSubsystem();
    if (ACPI_FAILURE(status))
        return acpica_fail(status);
    status = AcpiInitializeTables(0, 32, FALSE);
    if (ACPI_FAILURE(status))
        return acpica_fail(status);
    status = AcpiLoadTables();
    if (ACPI_FAILURE(status))
        return acpica_fail(status);
    g_acpica_status.namespace_loaded = 1;

    status = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(status))
        return acpica_fail(status);
    status = acpica_prepare_bus();
    if (ACPI_FAILURE(status))
        return acpica_fail(status);
#if defined(__x86_64__) && defined(CONFIG_ACPI_EC)
    acpi_ec_ecdt_probe(g_acpica_bus);
#endif
    status = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(status))
        return acpica_fail(status);
    g_acpica_status.objects_initialized = 1;

    status = AcpiGetDevices(0, acpica_count_device,
        &g_acpica_status.device_count, 0);
    if (ACPI_FAILURE(status))
        return acpica_fail(status);
    status = acpica_register_namespace_devices();
    if (ACPI_FAILURE(status))
        return acpica_fail(status);

    g_acpica_status.initialized = 1;
    __atomic_store_n(&g_acpica_state, BSD_ACPICA_READY, __ATOMIC_RELEASE);
    bsd_printf("[acpica] namespace ready devices=%u registered=%u "
        "present=%u matched=%u\n", g_acpica_status.device_count,
        g_acpica_status.registered_device_count,
        g_acpica_status.present_device_count,
        g_acpica_status.matched_device_count);
    return 0;
}

ACPI_STATUS
acpi_EvaluateOSC(ACPI_HANDLE handle, uint8_t *uuid, int revision,
    int count, uint32_t *capabilities_in, uint32_t *capabilities_out,
    bool query)
{
    ACPI_OBJECT arguments[4];
    ACPI_OBJECT *result;
    ACPI_OBJECT_LIST argument_list;
    ACPI_BUFFER buffer = {
        .Length = ACPI_ALLOCATE_BUFFER,
    };
    ACPI_STATUS status;

    if (!handle || !uuid || count <= 0 || !capabilities_in)
        return AE_BAD_PARAMETER;
    argument_list.Pointer = arguments;
    argument_list.Count = 4;
    arguments[0].Type = ACPI_TYPE_BUFFER;
    arguments[0].Buffer.Length = ACPI_UUID_LENGTH;
    arguments[0].Buffer.Pointer = uuid;
    arguments[1].Type = ACPI_TYPE_INTEGER;
    arguments[1].Integer.Value = (UINT64)revision;
    arguments[2].Type = ACPI_TYPE_INTEGER;
    arguments[2].Integer.Value = (UINT64)count;
    arguments[3].Type = ACPI_TYPE_BUFFER;
    arguments[3].Buffer.Length =
        (UINT32)count * (UINT32)sizeof(*capabilities_in);
    arguments[3].Buffer.Pointer = (uint8_t *)capabilities_in;
    capabilities_in[0] = query ? 1u : 0u;
    status = AcpiEvaluateObjectTyped(handle, "_OSC", &argument_list,
        &buffer, ACPI_TYPE_BUFFER);
    if (ACPI_FAILURE(status))
        return status;
    result = buffer.Pointer;
    if (capabilities_out) {
        if (result->Buffer.Length !=
            (UINT32)count * (UINT32)sizeof(*capabilities_out)) {
            AcpiOsFree(buffer.Pointer);
            return AE_BUFFER_OVERFLOW;
        }
        bsd_memcpy(capabilities_out, result->Buffer.Pointer,
            result->Buffer.Length);
    }
    AcpiOsFree(buffer.Pointer);
    return AE_OK;
}

void
bsd_acpica_runtime_get_status(bsd_acpica_runtime_status_t *status)
{
    if (status)
        *status = g_acpica_status;
}

void *
bsd_acpica_device_for_handle(void *handle)
{
    void *attached = 0;

    if (handle &&
        ACPI_SUCCESS(AcpiGetData((ACPI_HANDLE)handle,
            acpi_fake_objhandler, &attached)) && attached)
        return attached;
    for (uint32_t index = 0;
        index < g_acpica_device_mapping_count; ++index) {
        if (g_acpica_devices[index].handle == (ACPI_HANDLE)handle)
            return g_acpica_devices[index].device;
    }
    if (bsd_device_is_registered((device_t)handle) &&
        bsd_firmware_get_kind((device_t)handle) == BSD_FIRMWARE_ACPI)
        return handle;
    return 0;
}

int
bsd_acpica_handle_match(void *handle, const char *hardware_id)
{
    device_t device = bsd_acpica_device_for_handle(handle);

    if (!device)
        return -1;
    return bsd_firmware_acpi_match(device, hardware_id);
}

void
acpi_fake_objhandler(ACPI_HANDLE handle, void *data)
{
    (void)handle;
    (void)data;
}

int
bsd_acpica_bind_device_handle(void *opaque_device, void *opaque_handle)
{
    device_t device = opaque_device;
    ACPI_HANDLE handle = opaque_handle;
    ACPI_DEVICE_INFO *info = 0;
    bsd_firmware_description_t firmware = {
        .kind = BSD_FIRMWARE_ACPI,
        .enabled = 1,
        .acpi_handle = opaque_handle,
    };
    const char *compatible[64];
    ACPI_STATUS status;

    if (!device || !handle)
        return BSD_ACPICA_ENXIO;
    status = AcpiGetObjectInfo(handle, &info);
    if (ACPI_FAILURE(status) || !info)
        return BSD_ACPICA_ENXIO;
    if ((info->Valid & ACPI_VALID_HID) != 0)
        firmware.hardware_id = info->HardwareId.String;
    if ((info->Valid & ACPI_VALID_CID) != 0) {
        uint32_t count = info->CompatibleIdList.Count;

        if (count > sizeof(compatible) / sizeof(compatible[0]))
            count = sizeof(compatible) / sizeof(compatible[0]);
        for (uint32_t index = 0; index < count; ++index) {
            const char *identifier =
                info->CompatibleIdList.Ids[index].String;

            if (!identifier || identifier[0] == '\0')
                continue;
            compatible[firmware.compatible_count++] = identifier;
            if (!firmware.hardware_id)
                firmware.hardware_id = identifier;
        }
    }
    firmware.compatible = compatible;
    firmware.enabled =
        (acpica_device_status(handle) & ACPI_STA_DEVICE_PRESENT) != 0;
    if (!firmware.hardware_id ||
        (bsd_firmware_is_bound(device) ?
            bsd_firmware_set_acpi_handle(device, handle) :
            bsd_firmware_bind(device, &firmware)) != 0) {
        ACPI_FREE(info);
        return BSD_ACPICA_ENXIO;
    }
    status = acpica_mapping_add(handle, device) == 0 ?
        AE_OK : AE_LIMIT;
    ACPI_FREE(info);
    return ACPI_SUCCESS(status) ? 0 : BSD_ACPICA_ENXIO;
}

int
acpi_has_hid(ACPI_HANDLE handle)
{
    ACPI_DEVICE_INFO *info = 0;
    ACPI_STATUS status;
    int present;

    status = AcpiGetObjectInfo(handle, &info);
    if (ACPI_FAILURE(status) || !info)
        return 0;
    present = (info->Valid & (ACPI_VALID_HID | ACPI_VALID_CID)) != 0;
    ACPI_FREE(info);
    return present;
}

ACPI_STATUS
acpi_GetInteger(ACPI_HANDLE handle, char *path, UINT32 *number)
{
    ACPI_OBJECT object;
    ACPI_BUFFER buffer = {
        .Length = sizeof(object),
        .Pointer = &object,
    };
    ACPI_STATUS status;

    if (!path || !number)
        return AE_BAD_PARAMETER;
    if (!handle)
        handle = ACPI_ROOT_OBJECT;
    status = AcpiEvaluateObject(handle, path, 0, &buffer);
    if (ACPI_SUCCESS(status)) {
        if (object.Type != ACPI_TYPE_INTEGER)
            return AE_TYPE;
        *number = (UINT32)object.Integer.Value;
        return AE_OK;
    }
    if (status != AE_BUFFER_OVERFLOW)
        return status;
    buffer.Pointer = AcpiOsAllocate(buffer.Length);
    if (!buffer.Pointer)
        return AE_NO_MEMORY;
    status = AcpiEvaluateObject(handle, path, 0, &buffer);
    if (ACPI_SUCCESS(status)) {
        ACPI_OBJECT *result = buffer.Pointer;

        if (result->Type == ACPI_TYPE_INTEGER) {
            *number = (UINT32)result->Integer.Value;
        } else if (result->Type == ACPI_TYPE_BUFFER &&
            result->Buffer.Length <= sizeof(*number)) {
            *number = 0;
            for (UINT32 index = 0; index < result->Buffer.Length; ++index)
                *number |= (UINT32)result->Buffer.Pointer[index] <<
                    (index * 8);
        } else {
            status = result->Type == ACPI_TYPE_BUFFER ?
                AE_BAD_DATA : AE_TYPE;
        }
    }
    AcpiOsFree(buffer.Pointer);
    return status;
}

ACPI_STATUS
acpi_SetInteger(ACPI_HANDLE handle, char *path, UINT32 number)
{
    ACPI_OBJECT argument = {
        .Integer = {
            .Type = ACPI_TYPE_INTEGER,
            .Value = number,
        },
    };
    ACPI_OBJECT_LIST arguments = {
        .Count = 1,
        .Pointer = &argument,
    };

    if (!path)
        return AE_BAD_PARAMETER;
    if (!handle)
        handle = ACPI_ROOT_OBJECT;
    return AcpiEvaluateObject(handle, path, &arguments, 0);
}

#define BSD_ACPICA_INITIAL_RESOURCE_BUFFER_SIZE 512

ACPI_STATUS
acpi_AppendBufferResource(ACPI_BUFFER *buffer, ACPI_RESOURCE *resource)
{
    ACPI_RESOURCE *current;
    void *expanded;

    if (!buffer)
        return AE_BAD_PARAMETER;
    if (!buffer->Pointer) {
        buffer->Length = BSD_ACPICA_INITIAL_RESOURCE_BUFFER_SIZE;
        buffer->Pointer = AcpiOsAllocate(buffer->Length);
        if (!buffer->Pointer)
            return AE_NO_MEMORY;
        current = buffer->Pointer;
        current->Type = ACPI_RESOURCE_TYPE_END_TAG;
        current->Length = ACPI_RS_SIZE_MIN;
    }
    if (!resource)
        return AE_OK;

    current = buffer->Pointer;
    for (;;) {
        if ((uint8_t *)current >=
            (uint8_t *)buffer->Pointer + buffer->Length)
            return AE_BAD_PARAMETER;
        if (current->Type == ACPI_RESOURCE_TYPE_END_TAG ||
            current->Length == 0)
            break;
        current = ACPI_NEXT_RESOURCE(current);
    }

    while (((uint8_t *)current - (uint8_t *)buffer->Pointer) +
        resource->Length + ACPI_RS_SIZE_NO_DATA + ACPI_RS_SIZE_MIN >=
        buffer->Length) {
        if (buffer->Length > ((ACPI_SIZE)-1) / 2)
            return AE_NO_MEMORY;
        expanded = AcpiOsAllocate(buffer->Length * 2);
        if (!expanded)
            return AE_NO_MEMORY;
        bsd_memcpy(expanded, buffer->Pointer, buffer->Length);
        current = (ACPI_RESOURCE *)((uint8_t *)expanded +
            ((uint8_t *)current - (uint8_t *)buffer->Pointer));
        AcpiOsFree(buffer->Pointer);
        buffer->Pointer = expanded;
        buffer->Length *= 2;
    }

    bsd_memcpy(current, resource,
        resource->Length + ACPI_RS_SIZE_NO_DATA);
    current = ACPI_NEXT_RESOURCE(current);
    current->Type = ACPI_RESOURCE_TYPE_END_TAG;
    current->Length = ACPI_RS_SIZE_MIN;
    return AE_OK;
}

ACPI_STATUS
acpi_ForeachPackageObject(ACPI_OBJECT *object,
    void (*function)(ACPI_OBJECT *component, void *argument),
    void *argument)
{
    ACPI_OBJECT *component;

    if (!object || object->Type != ACPI_TYPE_PACKAGE || !function)
        return AE_BAD_PARAMETER;
    component = object->Package.Elements;
    if (object->Package.Count != 0 && !component)
        return AE_BAD_DATA;
    for (UINT32 index = 0; index < object->Package.Count; ++index)
        function(&component[index], argument);
    return AE_OK;
}

uint8_t
acpi_BatteryIsPresent(device_t device)
{
    ACPI_HANDLE handle;
    UINT32 status;

    if (!device)
        return FALSE;
    handle = acpi_get_handle(device);
    if (!handle)
        return FALSE;
    if (ACPI_FAILURE(acpi_GetInteger(handle, "_STA", &status)))
        return TRUE;
    return (status & ACPI_STA_BATTERY_PRESENT) != 0 ? TRUE : FALSE;
}

ACPI_STATUS
acpi_EvaluateDSMTyped(ACPI_HANDLE handle, const uint8_t *uuid,
    int revision, UINT64 function, ACPI_OBJECT *package,
    ACPI_BUFFER *out_buffer, ACPI_OBJECT_TYPE type)
{
    ACPI_OBJECT arguments[4];
    ACPI_OBJECT_LIST argument_list;

    if (!handle || !uuid || !out_buffer)
        return AE_BAD_PARAMETER;
    arguments[0].Type = ACPI_TYPE_BUFFER;
    arguments[0].Buffer.Length = ACPI_UUID_LENGTH;
    arguments[0].Buffer.Pointer = (uint8_t *)(uintptr_t)uuid;
    arguments[1].Type = ACPI_TYPE_INTEGER;
    arguments[1].Integer.Value = (UINT64)revision;
    arguments[2].Type = ACPI_TYPE_INTEGER;
    arguments[2].Integer.Value = function;
    if (package) {
        arguments[3] = *package;
    } else {
        arguments[3].Type = ACPI_TYPE_PACKAGE;
        arguments[3].Package.Count = 0;
        arguments[3].Package.Elements = 0;
    }
    argument_list.Count = 4;
    argument_list.Pointer = arguments;
    out_buffer->Length = ACPI_ALLOCATE_BUFFER;
    out_buffer->Pointer = 0;
    return AcpiEvaluateObjectTyped(handle, "_DSM", &argument_list,
        out_buffer, type);
}

ACPI_STATUS
acpi_EvaluateDSM(ACPI_HANDLE handle, const uint8_t *uuid,
    int revision, UINT64 function, ACPI_OBJECT *package,
    ACPI_BUFFER *out_buffer)
{
    return acpi_EvaluateDSMTyped(handle, uuid, revision, function,
        package, out_buffer, ACPI_TYPE_ANY);
}

char *
acpi_name(ACPI_HANDLE handle)
{
    static char names[16][256];
    static volatile uint32_t next_name;
    char *name = names[
        __atomic_fetch_add(&next_name, 1, __ATOMIC_RELAXED) %
        (sizeof(names) / sizeof(names[0]))];
    ACPI_BUFFER buffer = {
        .Length = sizeof(names[0]),
        .Pointer = name,
    };

    if (handle &&
        ACPI_SUCCESS(AcpiGetName(handle, ACPI_FULL_PATHNAME, &buffer)))
        return name;
    return "(unknown)";
}

int
acpi_pnpinfo(ACPI_HANDLE handle, struct sbuf *buffer)
{
    ACPI_DEVICE_INFO *info = 0;

    if (!buffer)
        return BSD_ACPICA_ENXIO;
    if (!handle ||
        ACPI_FAILURE(AcpiGetObjectInfo(handle, &info)) || !info) {
        (void)sbuf_printf(buffer, "unknown");
        return 0;
    }
    (void)sbuf_printf(buffer, "_HID=%s _UID=%s _CID=%s",
        (info->Valid & ACPI_VALID_HID) ?
            info->HardwareId.String : "none",
        (info->Valid & ACPI_VALID_UID) ?
            info->UniqueId.String : "none",
        (info->Valid & ACPI_VALID_CID) &&
            info->CompatibleIdList.Count != 0 ?
            info->CompatibleIdList.Ids[0].String : "none");
    ACPI_FREE(info);
    return 0;
}

int
acpi_get_acpi_device_path(device_t bus, device_t child,
    const char *locator, struct sbuf *buffer)
{
    ACPI_HANDLE handle;

    if (!locator || !buffer)
        return 22;
    if (bsd_strcmp(locator, BUS_LOCATOR_ACPI) != 0)
        return bus_generic_get_device_path(bus, child, locator, buffer);
    handle = acpi_get_handle(child);
    if (handle)
        (void)sbuf_printf(buffer, "%s", acpi_name(handle));
    return 0;
}

int
acpi_set_powerstate(device_t child, int state)
{
    ACPI_HANDLE handle = acpi_get_handle(child);
    char method[5] = "_PS0";
    ACPI_STATUS status;

    if (state < ACPI_STATE_D0 || state > ACPI_D_STATES_MAX)
        return 22;
    if (!handle)
        return 0;
    method[3] = state >= ACPI_STATE_D3_HOT ? '3' :
        (char)('0' + state);
    status = AcpiEvaluateObject(handle, method, 0, 0);
    if (status != AE_OK && status != AE_NOT_FOUND)
        bsd_printf("[acpica] %s %s failed status=0x%x\n",
            acpi_name(handle), method, (uint32_t)status);
    return 0;
}

int
acpi_bus_alloc_gas(device_t device, int *type, int rid,
    ACPI_GENERIC_ADDRESS *address, struct resource **resource,
    u_int flags)
{
    int resource_type;
    uint32_t width;

    if (!device || !type || !address || !resource)
        return BSD_ACPICA_EINVAL;
    switch (address->SpaceId) {
    case ACPI_ADR_SPACE_SYSTEM_MEMORY:
        resource_type = SYS_RES_MEMORY;
        break;
    case ACPI_ADR_SPACE_SYSTEM_IO:
        resource_type = SYS_RES_IOPORT;
        break;
    default:
        return BSD_ACPICA_EOPNOTSUPP;
    }
    width = address->BitWidth;
    if (width != 0 && width < 8)
        width = 8;
    if (address->Address == 0 || width == 0)
        return BSD_ACPICA_EINVAL;
    if (bus_set_resource(device, resource_type, rid,
        address->Address, width / 8) != 0)
        return BSD_ACPICA_ENOMEM;
    *resource = bus_alloc_resource_any(device, resource_type, rid,
        RF_ACTIVE | flags);
    if (!*resource) {
        bus_delete_resource(device, resource_type, rid);
        return BSD_ACPICA_ENOMEM;
    }
    *type = resource_type;
    return 0;
}

static ACPI_HANDLE
acpica_object_reference(ACPI_HANDLE scope, ACPI_OBJECT *object)
{
    ACPI_HANDLE handle;

    if (!object)
        return 0;
    if (object->Type == ACPI_TYPE_LOCAL_REFERENCE ||
        object->Type == ACPI_TYPE_ANY)
        return object->Reference.Handle;
    if (object->Type != ACPI_TYPE_STRING || !object->String.Pointer)
        return 0;
    if (ACPI_FAILURE(AcpiGetHandle(
        scope, object->String.Pointer, &handle)))
        return 0;
    return handle;
}

int
acpi_parse_prw(ACPI_HANDLE handle, struct acpi_prw_data *prw)
{
    ACPI_BUFFER buffer = {
        .Length = ACPI_ALLOCATE_BUFFER,
    };
    ACPI_OBJECT *result;
    ACPI_OBJECT *gpe_package;
    ACPI_STATUS status;
    int power_count;
    int error = BSD_ACPICA_EINVAL;

    if (!handle || !prw)
        return BSD_ACPICA_EINVAL;
    *prw = (struct acpi_prw_data){0};
    status = AcpiEvaluateObject(handle, "_PRW", 0, &buffer);
    if (ACPI_FAILURE(status))
        return BSD_ACPICA_ENOENT;
    result = buffer.Pointer;
    if (!result)
        return BSD_ACPICA_ENOENT;
    if (result->Type != ACPI_TYPE_PACKAGE ||
        result->Package.Count < 2 ||
        result->Package.Elements[1].Type != ACPI_TYPE_INTEGER)
        goto out;

    prw->lowest_wake =
        (int)(UINT32)result->Package.Elements[1].Integer.Value;
    if (result->Package.Elements[0].Type == ACPI_TYPE_INTEGER) {
        prw->gpe_bit =
            (int)(UINT32)result->Package.Elements[0].Integer.Value;
    } else if (result->Package.Elements[0].Type == ACPI_TYPE_PACKAGE) {
        gpe_package = &result->Package.Elements[0];
        if (gpe_package->Package.Count < 2 ||
            gpe_package->Package.Elements[1].Type != ACPI_TYPE_INTEGER)
            goto out;
        prw->gpe_handle = acpica_object_reference(
            0, &gpe_package->Package.Elements[0]);
        if (!prw->gpe_handle)
            goto out;
        prw->gpe_bit =
            (int)(UINT32)gpe_package->Package.Elements[1].Integer.Value;
    } else {
        goto out;
    }

    power_count = (int)result->Package.Count - 2;
    if (power_count > ACPI_PRW_MAX_POWERRES) {
        bsd_printf("[acpica] %s has %d wake power resources; maximum=%d\n",
            acpi_name(handle), power_count, ACPI_PRW_MAX_POWERRES);
        power_count = ACPI_PRW_MAX_POWERRES;
    }
    prw->power_res_count = power_count;
    for (int index = 0; index < power_count; ++index)
        prw->power_res[index] = result->Package.Elements[index + 2];
    error = 0;

out:
    AcpiOsFree(buffer.Pointer);
    return error;
}

int
acpi_wake_set_enable(device_t device, int enable)
{
    struct acpi_prw_data prw;
    ACPI_STATUS status;
    uint32_t flags;

    if (!device || (enable != 0 && enable != 1))
        return BSD_ACPICA_EINVAL;
    if (acpi_parse_prw(acpi_get_handle(device), &prw) != 0)
        return BSD_ACPICA_ENXIO;
    status = AcpiSetGpeWakeMask(prw.gpe_handle, (UINT32)prw.gpe_bit,
        enable ? ACPI_GPE_ENABLE : ACPI_GPE_DISABLE);
    if (ACPI_FAILURE(status)) {
        device_printf(device, "%s wake failed: %s\n",
            enable ? "enable" : "disable",
            AcpiFormatException(status));
        return BSD_ACPICA_ENXIO;
    }
    flags = bsd_firmware_acpi_get_flags(device);
    if (enable)
        flags |= ACPI_FLAG_WAKE_ENABLED;
    else
        flags &= ~ACPI_FLAG_WAKE_ENABLED;
    return bsd_firmware_acpi_set_flags(device, flags) == 0 ?
        0 : BSD_ACPICA_ENXIO;
}

void
acpi_UserNotify(const char *subsystem, ACPI_HANDLE handle, uint8_t notify)
{
    ACPI_BUFFER path = {
        .Length = ACPI_ALLOCATE_BUFFER,
    };
    const char *path_name;
    char data[24];

    if (!subsystem)
        return;
    if (__atomic_load_n(&g_acpica_state, __ATOMIC_ACQUIRE) !=
        BSD_ACPICA_READY) {
        /*
         * Late SYSINIT handlers can publish root-level policy events before
         * EdgeOS starts ACPICA.  The root path is firmware-independent and
         * must not enter ACPICA while its namespace mutexes are unavailable.
         */
        if (handle && handle != ACPI_ROOT_OBJECT)
            return;
        path_name = "\\";
    } else {
        if (ACPI_FAILURE(AcpiGetName(
            handle ? handle : ACPI_ROOT_OBJECT,
            ACPI_FULL_PATHNAME, &path)))
            return;
        path_name = path.Pointer;
    }
    bsd_snprintf(data, sizeof(data), "notify=0x%02x", notify);
    devctl_notify("ACPI", subsystem, path_name, data);
    if (path.Pointer)
        AcpiOsFree(path.Pointer);
}

void
acpi_invoke_sleep_eventhandler(const enum power_stype *stype)
{
    if (stype)
        EVENTHANDLER_INVOKE(acpi_sleep_event, *stype);
}

void
acpi_invoke_wake_eventhandler(const enum power_stype *stype)
{
    if (stype)
        EVENTHANDLER_INVOKE(acpi_wakeup_event, *stype);
}

static int
acpica_stype_to_sstate(const struct acpi_softc *softc,
    enum power_stype stype)
{
    switch (stype) {
    case POWER_STYPE_AWAKE:
        return ACPI_STATE_S0;
    case POWER_STYPE_STANDBY:
        return softc->acpi_standby_sx;
    case POWER_STYPE_FW_SUSPEND:
        return ACPI_STATE_S3;
    case POWER_STYPE_FW_HIBERNATE:
        return ACPI_STATE_S4;
    case POWER_STYPE_POWEROFF:
        return ACPI_STATE_S5;
    case POWER_STYPE_SUSPEND_TO_IDLE:
    case POWER_STYPE_UNKNOWN:
        return ACPI_STATE_UNKNOWN;
    }
    return ACPI_STATE_UNKNOWN;
}

static int
acpica_device_pwr_for_sleep_sxd(device_t bus, ACPI_HANDLE handle,
    int state, int *dstate)
{
    ACPI_STATUS status;
    UINT32 device_state;
    char method[8];

    bsd_snprintf(method, sizeof(method), "_S%dD", state);
    status = acpi_GetInteger(handle, method, &device_state);
    if (ACPI_FAILURE(status) && status != AE_NOT_FOUND) {
        device_printf(bus, "failed to get %s on %s: %s\n", method,
            acpi_name(handle), AcpiFormatException(status));
        return BSD_ACPICA_ENXIO;
    }
    if (ACPI_SUCCESS(status))
        *dstate = (int)device_state;
    return 0;
}

int
acpi_device_pwr_for_sleep(device_t bus, device_t device, int *dstate)
{
    const struct acpi_softc *softc;
    ACPI_HANDLE handle;
    int state;

    if (!bus || !device || !dstate)
        return BSD_ACPICA_EINVAL;
    softc = device_get_softc(bus);
    handle = acpi_get_handle(device);
    if (!softc || !handle ||
        acpi_MatchHid(handle, "PNP0500") ||
        acpi_MatchHid(handle, "PNP0501") ||
        acpi_MatchHid(handle, "PNP0502") ||
        acpi_MatchHid(handle, "PNP0510") ||
        acpi_MatchHid(handle, "PNP0511"))
        return BSD_ACPICA_ENXIO;

    if (softc->acpi_stype == POWER_STYPE_SUSPEND_TO_IDLE)
        state = ACPI_STATE_S3;
    else
        state = acpica_stype_to_sstate(softc, softc->acpi_stype);
    if (state == ACPI_STATE_UNKNOWN)
        return BSD_ACPICA_ENOENT;
    return acpica_device_pwr_for_sleep_sxd(bus, handle, state, dstate);
}

int
acpi_ReqSleepState(struct acpi_softc *softc, enum power_stype stype)
{
    if (!softc || stype < POWER_STYPE_AWAKE ||
        stype >= POWER_STYPE_COUNT)
        return BSD_ACPICA_EINVAL;
    if (stype == POWER_STYPE_POWEROFF) {
        (void)kernel_system_power_action(KERNEL_POWER_OFF);
        return BSD_ACPICA_ENXIO;
    }

    /*
     * Firmware sleep needs coordinated CPU, interrupt-controller, device,
     * and wake-vector state.  The bridge must report that dependency
     * honestly until the shared platform suspend core is available.
     */
    return BSD_ACPICA_EOPNOTSUPP;
}

static UINT32
acpica_schedule_power_event(
    void (*callback)(const enum power_stype *),
    enum power_stype *stype)
{
    ACPI_STATUS status;

    if (!callback || !stype)
        return ACPI_INTERRUPT_NOT_HANDLED;
    status = AcpiOsExecute(OSL_NOTIFY_HANDLER,
        (ACPI_OSD_EXEC_CALLBACK)callback, stype);
    return ACPI_SUCCESS(status) ?
        ACPI_INTERRUPT_HANDLED : ACPI_INTERRUPT_NOT_HANDLED;
}

UINT32
acpi_event_power_button_sleep(struct acpi_softc *softc)
{
    return softc ? acpica_schedule_power_event(
        acpi_invoke_sleep_eventhandler,
        &softc->acpi_power_button_stype) :
        ACPI_INTERRUPT_NOT_HANDLED;
}

UINT32
acpi_event_power_button_wake(struct acpi_softc *softc)
{
    return softc ? acpica_schedule_power_event(
        acpi_invoke_wake_eventhandler,
        &softc->acpi_power_button_stype) :
        ACPI_INTERRUPT_NOT_HANDLED;
}

UINT32
acpi_event_sleep_button_sleep(struct acpi_softc *softc)
{
    return softc ? acpica_schedule_power_event(
        acpi_invoke_sleep_eventhandler,
        &softc->acpi_sleep_button_stype) :
        ACPI_INTERRUPT_NOT_HANDLED;
}

UINT32
acpi_event_sleep_button_wake(struct acpi_softc *softc)
{
    return softc ? acpica_schedule_power_event(
        acpi_invoke_wake_eventhandler,
        &softc->acpi_sleep_button_stype) :
        ACPI_INTERRUPT_NOT_HANDLED;
}
