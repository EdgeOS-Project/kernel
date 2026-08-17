/* SPDX-License-Identifier: MPL-2.0 */
/* Transactional x86-64 PCI ownership for imported FreeBSD drivers. */

#include "compat/freebsd/edgeos/x86_64_handoff.h"

#include "drivers/e1000.h"
#include "drivers/usb_handoff.h"
#include "net/lwip_stack.h"
#include "net/native_netdev.h"
#include "net/netdev.h"

#define BSD_X86_HANDOFF_ENOENT 2
#define BSD_X86_HANDOFF_EBUSY 16
#define BSD_X86_HANDOFF_EINVAL 22

typedef struct x86_pci_handoff_context {
    edge_netdev_handle_t before[EDGE_NETDEV_MAX];
    size_t before_count;
    edge_netdev_handle_t previous_bound;
    edge_netdev_handle_t bsd_handle;
    usb_handoff_state_t usb;
    int native_matched;
    int native_suspended;
    int native_was_bound;
} x86_pci_handoff_context_t;

static x86_pci_handoff_context_t g_x86_handoff;
static bsd_bridge_handoff_config_t g_x86_reservations;

static uint32_t
x86_usb_locations(const bsd_pci_location_t *locations, size_t count,
    usb_handoff_location_t converted[USB_HANDOFF_MAX_LOCATIONS])
{
    uint32_t converted_count = (uint32_t)count;

    if (converted_count > USB_HANDOFF_MAX_LOCATIONS)
        converted_count = USB_HANDOFF_MAX_LOCATIONS;
    for (uint32_t index = 0; index < converted_count; ++index) {
        converted[index] = (usb_handoff_location_t){
            .domain = locations[index].domain,
            .bus = locations[index].bus,
            .slot = locations[index].slot,
            .function = locations[index].function,
        };
    }
    return converted_count;
}

static int
x86_location_equal(const bsd_pci_location_t *location,
    uint8_t bus, uint8_t slot, uint8_t function)
{
    return location->domain == 0 && location->bus == bus &&
        location->slot == slot && location->function == function;
}

static int
x86_handle_in_snapshot(edge_netdev_handle_t handle,
    const edge_netdev_handle_t *snapshot, size_t count)
{
    for (size_t index = 0; index < count; ++index) {
        if (snapshot[index] == handle)
            return 1;
    }
    return 0;
}

static edge_netdev_handle_t
x86_find_added_netdev(const x86_pci_handoff_context_t *context)
{
    edge_netdev_handle_t after[EDGE_NETDEV_MAX];
    edge_netdev_handle_t added = 0;
    size_t after_count = 0;

    if (edge_netdev_snapshot(after, EDGE_NETDEV_MAX,
        &after_count) != 0)
        return 0;
    for (size_t index = 0; index < after_count; ++index) {
        if (x86_handle_in_snapshot(after[index],
            context->before, context->before_count))
            continue;
        if (added)
            return 0;
        added = after[index];
    }
    return added;
}

static int
x86_restore_native(x86_pci_handoff_context_t *context)
{
    int error = 0;
    int reservation_error;
    int usb_error;

    if (context->native_suspended) {
        error = e1000_resume();
        if (error == 0)
            error = edge_native_netdev_register();
        if (error == 0 && context->native_was_bound)
            error = lwip_stack_bind_netdev(
                edge_native_netdev_get_handle());
        if (error == 0) {
            context->native_suspended = 0;
            context->native_matched = 0;
            context->native_was_bound = 0;
        }
    }
    usb_error = usb_handoff_restore(&context->usb);
    if (error == 0)
        error = usb_error;
    reservation_error =
        bsd_bridge_x86_64_release_reserved_native_devices();
    if (error == 0)
        error = reservation_error;
    return error;
}

static void
x86_abort_prepare(x86_pci_handoff_context_t *context)
{
    (void)usb_handoff_restore(&context->usb);
    *context = (x86_pci_handoff_context_t){0};
}

static int
x86_pci_prepare(void *opaque_context,
    const bsd_pci_location_t *locations, size_t count)
{
    x86_pci_handoff_context_t *context = opaque_context;
    usb_handoff_location_t usb_locations[USB_HANDOFF_MAX_LOCATIONS];
    edge_netdev_handle_t native;
    uint32_t usb_location_count;
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
    int error;

    if (!context || !locations || count == 0 ||
        context->before_count != 0 || context->previous_bound ||
        context->native_suspended || context->bsd_handle ||
        context->usb.controller_mask != 0)
        return BSD_X86_HANDOFF_EINVAL;
    usb_location_count = x86_usb_locations(
        locations, count, usb_locations);
    error = usb_handoff_prepare_locations(
        usb_locations, usb_location_count, &context->usb);
    if (error != 0) {
        *context = (x86_pci_handoff_context_t){0};
        return error;
    }
    if (edge_netdev_snapshot(context->before, EDGE_NETDEV_MAX,
        &context->before_count) != 0) {
        x86_abort_prepare(context);
        return BSD_X86_HANDOFF_EBUSY;
    }
    context->previous_bound = lwip_stack_get_netdev();
    if (e1000_get_pci_location(&bus, &slot, &function) != 0)
        return 0;
    for (size_t index = 0; index < count; ++index) {
        if (x86_location_equal(&locations[index],
            bus, slot, function)) {
            context->native_matched = 1;
            break;
        }
    }
    if (!context->native_matched)
        return 0;
    native = edge_native_netdev_get_handle();
    if (!native) {
        x86_abort_prepare(context);
        return BSD_X86_HANDOFF_ENOENT;
    }
    context->native_was_bound =
        lwip_stack_get_netdev() == native;
    if (context->native_was_bound &&
        lwip_stack_unbind_netdev(native) != 0) {
        x86_abort_prepare(context);
        return BSD_X86_HANDOFF_EBUSY;
    }
    error = edge_native_netdev_unregister();
    if (error != 0) {
        if (context->native_was_bound)
            (void)lwip_stack_bind_netdev(native);
        x86_abort_prepare(context);
        return error;
    }
    error = e1000_stop();
    if (error != 0) {
        (void)e1000_resume();
        (void)edge_native_netdev_register();
        if (context->native_was_bound)
            (void)lwip_stack_bind_netdev(
                edge_native_netdev_get_handle());
        x86_abort_prepare(context);
        return error;
    }
    context->native_suspended = 1;
    return 0;
}

static int
x86_pci_activate(void *opaque_context)
{
    x86_pci_handoff_context_t *context = opaque_context;
    edge_netdev_handle_t handle;

    if (!context)
        return BSD_X86_HANDOFF_EINVAL;
    handle = x86_find_added_netdev(context);
    if (!handle)
        return context->native_suspended ? BSD_X86_HANDOFF_ENOENT : 0;
    if (lwip_stack_bind_netdev(handle) != 0)
        return BSD_X86_HANDOFF_ENOENT;
    context->bsd_handle = handle;
    return 0;
}

static int
x86_pci_deactivate(void *opaque_context)
{
    x86_pci_handoff_context_t *context = opaque_context;

    if (!context)
        return BSD_X86_HANDOFF_EINVAL;
    if (!context->bsd_handle)
        return 0;
    if (lwip_stack_get_netdev() == context->bsd_handle &&
        lwip_stack_unbind_netdev(context->bsd_handle) != 0)
        return BSD_X86_HANDOFF_EBUSY;
    if (!context->native_suspended && context->previous_bound &&
        lwip_stack_bind_netdev(context->previous_bound) != 0) {
        (void)lwip_stack_bind_netdev(context->bsd_handle);
        return BSD_X86_HANDOFF_EBUSY;
    }
    context->bsd_handle = 0;
    return 0;
}

static int
x86_pci_restore(void *opaque_context)
{
    x86_pci_handoff_context_t *context = opaque_context;
    int error;

    if (!context)
        return BSD_X86_HANDOFF_EINVAL;
    error = x86_restore_native(context);
    if (error != 0)
        return error;
    *context = (x86_pci_handoff_context_t){0};
    return 0;
}

int
bsd_bridge_x86_64_reserve_native_devices(const char *command_line)
{
    bsd_bridge_handoff_config_t config;
    usb_handoff_location_t locations[USB_HANDOFF_MAX_LOCATIONS];
    uint32_t location_count;
    int error;

    error = bsd_bridge_handoff_parse_command_line(
        command_line, &config);
    if (error != 0)
        return error;
    g_x86_reservations = (bsd_bridge_handoff_config_t){0};
    location_count = x86_usb_locations(config.pci_locations,
        config.pci_location_count, locations);
    error = usb_handoff_reserve_locations(
        locations, location_count);
    if (error == 0)
        g_x86_reservations = config;
    return error;
}

int
bsd_bridge_x86_64_native_pci_reserved(
    uint8_t bus, uint8_t slot, uint8_t function)
{
    for (size_t index = 0;
         index < g_x86_reservations.pci_location_count; ++index) {
        if (x86_location_equal(
            &g_x86_reservations.pci_locations[index],
            bus, slot, function))
            return 1;
    }
    return 0;
}

int
bsd_bridge_x86_64_release_reserved_native_devices(void)
{
    int error = usb_handoff_release_reservations();

    if (error == 0)
        g_x86_reservations = (bsd_bridge_handoff_config_t){0};
    return error;
}

int
bsd_bridge_x86_64_handoff_start(const char *command_line,
    bsd_bridge_handoff_status_t *status)
{
    bsd_bridge_handoff_config_t config;
    bsd_bridge_pci_handoff_ops_t operations = {
        .prepare = x86_pci_prepare,
        .activate = x86_pci_activate,
        .deactivate = x86_pci_deactivate,
        .restore = x86_pci_restore,
        .context = &g_x86_handoff,
    };
    int error;

    error = bsd_bridge_handoff_parse_command_line(
        command_line, &config);
    if (error != 0) {
        (void)bsd_bridge_x86_64_release_reserved_native_devices();
        return error;
    }
    error = bsd_bridge_handoff_start_with_ops(
        &config, &operations, 0, status);
    if (error != 0)
        (void)bsd_bridge_x86_64_release_reserved_native_devices();
    return error;
}
