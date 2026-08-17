/* SPDX-License-Identifier: MPL-2.0 */
/* Shared opt-in handoff manager for imported FreeBSD drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/bootstrap.h"
#include "compat/freebsd/edgeos/cam.h"
#include "compat/freebsd/edgeos/handoff.h"
#ifdef CONFIG_NET
#include "net/lwip_stack.h"
#include "net/netdev.h"
#endif

#define BSD_HANDOFF_ENOENT 2
#define BSD_HANDOFF_ENXIO 6
#define BSD_HANDOFF_EBUSY 16
#define BSD_HANDOFF_EINVAL 22

#define BSD_HANDOFF_PCI_OPTION "bsd_bridge.pci="
#define BSD_HANDOFF_PCI_OPTION_LENGTH 15
#define BSD_HANDOFF_PLATFORM_OPTION "bsd_bridge.platform="
#define BSD_HANDOFF_PLATFORM_OPTION_LENGTH 20
#define BSD_HANDOFF_VIRTIO_MMIO_PREFIX "virtio-mmio:"
#define BSD_HANDOFF_VIRTIO_MMIO_PREFIX_LENGTH 12

static device_t g_handoff_root;
static device_t g_handoff_pci_bus;
static device_t g_handoff_platform_devices[
    BSD_BRIDGE_HANDOFF_MAX_PLATFORM_DEVICES];
static size_t g_handoff_platform_device_count;
static bsd_bridge_platform_handoff_ops_t g_handoff_platform_ops;
static bsd_bridge_pci_handoff_ops_t g_handoff_pci_ops;
static int g_handoff_pci_prepared;
static int g_handoff_pci_active;

#ifdef CONFIG_NET
typedef struct handoff_pci_netdev_context {
    edge_netdev_handle_t before[EDGE_NETDEV_MAX];
    size_t before_count;
    edge_netdev_handle_t previous_bound;
    edge_netdev_handle_t added_bound;
} handoff_pci_netdev_context_t;

static handoff_pci_netdev_context_t g_handoff_pci_netdev;

static int
handoff_netdev_in_snapshot(edge_netdev_handle_t handle,
    const edge_netdev_handle_t *snapshot, size_t count)
{
    for (size_t index = 0; index < count; ++index) {
        if (snapshot[index] == handle)
            return 1;
    }
    return 0;
}

static edge_netdev_handle_t
handoff_find_added_netdev(const handoff_pci_netdev_context_t *context,
    size_t *added_count)
{
    edge_netdev_handle_t after[EDGE_NETDEV_MAX];
    edge_netdev_handle_t added = 0;
    size_t after_count = 0;
    size_t count = 0;

    if (edge_netdev_snapshot(after, EDGE_NETDEV_MAX,
        &after_count) != 0)
        return 0;
    for (size_t index = 0; index < after_count; ++index) {
        if (handoff_netdev_in_snapshot(after[index],
            context->before, context->before_count))
            continue;
        added = after[index];
        count++;
    }
    if (added_count)
        *added_count = count;
    return count == 1 ? added : 0;
}

static int
handoff_pci_netdev_prepare(void *opaque_context,
    const bsd_pci_location_t *locations, size_t count)
{
    handoff_pci_netdev_context_t *context = opaque_context;

    if (!context || !locations || count == 0 ||
        context->added_bound || context->before_count != 0)
        return BSD_HANDOFF_EINVAL;
    if (edge_netdev_snapshot(context->before, EDGE_NETDEV_MAX,
        &context->before_count) != 0) {
        *context = (handoff_pci_netdev_context_t){0};
        return BSD_HANDOFF_EBUSY;
    }
    context->previous_bound = lwip_stack_get_netdev();
    return 0;
}

static int
handoff_pci_netdev_activate(void *opaque_context)
{
    handoff_pci_netdev_context_t *context = opaque_context;
    edge_netdev_handle_t added;
    size_t added_count = 0;

    if (!context)
        return BSD_HANDOFF_EINVAL;
    added = handoff_find_added_netdev(context, &added_count);
    if (added_count == 0)
        return 0;
    if (!added || added_count != 1)
        return BSD_HANDOFF_EBUSY;
    if (lwip_stack_bind_netdev(added) != 0)
        return BSD_HANDOFF_ENOENT;
    context->added_bound = added;
    return 0;
}

static int
handoff_pci_netdev_deactivate(void *opaque_context)
{
    handoff_pci_netdev_context_t *context = opaque_context;

    if (!context)
        return BSD_HANDOFF_EINVAL;
    if (!context->added_bound)
        return 0;
    if (lwip_stack_get_netdev() == context->added_bound &&
        lwip_stack_unbind_netdev(context->added_bound) != 0)
        return BSD_HANDOFF_EBUSY;
    if (context->previous_bound &&
        lwip_stack_bind_netdev(context->previous_bound) != 0) {
        (void)lwip_stack_bind_netdev(context->added_bound);
        return BSD_HANDOFF_EBUSY;
    }
    context->added_bound = 0;
    return 0;
}

static int
handoff_pci_netdev_restore(void *opaque_context)
{
    handoff_pci_netdev_context_t *context = opaque_context;

    if (!context || context->added_bound)
        return BSD_HANDOFF_EBUSY;
    *context = (handoff_pci_netdev_context_t){0};
    return 0;
}

static const bsd_bridge_pci_handoff_ops_t
g_handoff_pci_netdev_ops = {
    .prepare = handoff_pci_netdev_prepare,
    .activate = handoff_pci_netdev_activate,
    .deactivate = handoff_pci_netdev_deactivate,
    .restore = handoff_pci_netdev_restore,
    .context = &g_handoff_pci_netdev,
};
#endif

static int
handoff_hex_digit(char character, uint32_t *value)
{
    if (character >= '0' && character <= '9') {
        *value = (uint32_t)(character - '0');
        return 0;
    }
    if (character >= 'a' && character <= 'f') {
        *value = (uint32_t)(character - 'a') + 10u;
        return 0;
    }
    if (character >= 'A' && character <= 'F') {
        *value = (uint32_t)(character - 'A') + 10u;
        return 0;
    }
    return BSD_HANDOFF_EINVAL;
}

static int
handoff_parse_hex(const char **cursor, const char *end,
    unsigned int minimum_digits, unsigned int maximum_digits,
    uint32_t maximum_value, uint32_t *value)
{
    const char *current = *cursor;
    uint32_t parsed = 0;
    unsigned int digits = 0;

    while (current < end && digits < maximum_digits) {
        uint32_t digit;

        if (handoff_hex_digit(*current, &digit) != 0)
            break;
        if (parsed > (maximum_value - digit) / 16u)
            return BSD_HANDOFF_EINVAL;
        parsed = parsed * 16u + digit;
        current++;
        digits++;
    }
    if (digits < minimum_digits || parsed > maximum_value)
        return BSD_HANDOFF_EINVAL;
    *cursor = current;
    *value = parsed;
    return 0;
}

static int
handoff_parse_pci_location(const char *begin, const char *end,
    bsd_pci_location_t *location)
{
    const char *cursor = begin;
    uint32_t domain;
    uint32_t bus;
    uint32_t slot;
    uint32_t function;

    if (!begin || !end || !location || begin >= end ||
        handoff_parse_hex(&cursor, end, 1, 8, UINT32_MAX,
            &domain) != 0 ||
        cursor == end || *cursor++ != ':' ||
        handoff_parse_hex(&cursor, end, 1, 2, UINT8_MAX,
            &bus) != 0 ||
        cursor == end || *cursor++ != ':' ||
        handoff_parse_hex(&cursor, end, 1, 2, 31,
            &slot) != 0 ||
        cursor == end || *cursor++ != '.' ||
        handoff_parse_hex(&cursor, end, 1, 1, 7,
            &function) != 0 ||
        cursor != end)
        return BSD_HANDOFF_EINVAL;

    location->domain = domain;
    location->bus = (uint8_t)bus;
    location->slot = (uint8_t)slot;
    location->function = (uint8_t)function;
    return 0;
}

static int
handoff_location_equal(const bsd_pci_location_t *left,
    const bsd_pci_location_t *right)
{
    return left->domain == right->domain &&
        left->bus == right->bus &&
        left->slot == right->slot &&
        left->function == right->function;
}

static int
handoff_add_pci_location(bsd_bridge_handoff_config_t *config,
    const bsd_pci_location_t *location)
{
    for (size_t index = 0; index < config->pci_location_count; ++index) {
        if (handoff_location_equal(&config->pci_locations[index],
            location))
            return 0;
    }
    if (config->pci_location_count >=
        BSD_BRIDGE_HANDOFF_MAX_PCI_DEVICES)
        return BSD_HANDOFF_EINVAL;
    config->pci_locations[config->pci_location_count++] = *location;
    return 0;
}

static int
handoff_platform_request_equal(
    const bsd_bridge_platform_request_t *left,
    const bsd_bridge_platform_request_t *right)
{
    return left->kind == right->kind &&
        left->device == right->device &&
        left->instance == right->instance;
}

static int
handoff_add_platform_request(bsd_bridge_handoff_config_t *config,
    const bsd_bridge_platform_request_t *request)
{
    for (size_t index = 0; index < config->platform_request_count;
         ++index) {
        if (handoff_platform_request_equal(
            &config->platform_requests[index], request))
            return 0;
    }
    if (config->platform_request_count >=
        BSD_BRIDGE_HANDOFF_MAX_PLATFORM_DEVICES)
        return BSD_HANDOFF_EINVAL;
    config->platform_requests[config->platform_request_count++] = *request;
    return 0;
}

static int
handoff_token_has_prefix(const char *begin, const char *end,
    const char *prefix, size_t prefix_length)
{
    if ((size_t)(end - begin) < prefix_length)
        return 0;
    for (size_t index = 0; index < prefix_length; ++index) {
        if (begin[index] != prefix[index])
            return 0;
    }
    return 1;
}

static int
handoff_parse_platform_request(const char *begin, const char *end,
    bsd_bridge_platform_request_t *request)
{
    const char *cursor = begin;
    uint32_t device;
    uint32_t instance;

    if (!begin || !end || !request || begin >= end ||
        !handoff_token_has_prefix(begin, end,
            BSD_HANDOFF_VIRTIO_MMIO_PREFIX,
            BSD_HANDOFF_VIRTIO_MMIO_PREFIX_LENGTH))
        return BSD_HANDOFF_EINVAL;
    cursor += BSD_HANDOFF_VIRTIO_MMIO_PREFIX_LENGTH;
    if (handoff_parse_hex(&cursor, end, 1, 8, UINT32_MAX,
            &device) != 0 ||
        cursor == end || *cursor++ != ':' ||
        handoff_parse_hex(&cursor, end, 1, 8, UINT32_MAX,
            &instance) != 0 ||
        cursor != end || device == 0)
        return BSD_HANDOFF_EINVAL;
    request->kind = BSD_BRIDGE_PLATFORM_VIRTIO_MMIO;
    request->device = device;
    request->instance = instance;
    return 0;
}

int
bsd_bridge_handoff_parse_command_line(const char *command_line,
    bsd_bridge_handoff_config_t *config)
{
    const char *cursor;

    if (!config)
        return BSD_HANDOFF_EINVAL;
    config->pci_location_count = 0;
    config->platform_request_count = 0;
    if (!command_line)
        return 0;

    cursor = command_line;
    while (*cursor) {
        const char *begin;
        const char *end;
        bsd_pci_location_t location;
        bsd_bridge_platform_request_t platform_request;
        int error;

        while (*cursor == ' ')
            cursor++;
        if (!*cursor)
            break;
        begin = cursor;
        while (*cursor && *cursor != ' ')
            cursor++;
        end = cursor;
        if (handoff_token_has_prefix(begin, end,
            BSD_HANDOFF_PCI_OPTION,
            BSD_HANDOFF_PCI_OPTION_LENGTH)) {
            begin += BSD_HANDOFF_PCI_OPTION_LENGTH;
            error = handoff_parse_pci_location(begin, end, &location);
            if (error)
                return error;
            error = handoff_add_pci_location(config, &location);
            if (error)
                return error;
        } else if (handoff_token_has_prefix(begin, end,
            BSD_HANDOFF_PLATFORM_OPTION,
            BSD_HANDOFF_PLATFORM_OPTION_LENGTH)) {
            begin += BSD_HANDOFF_PLATFORM_OPTION_LENGTH;
            error = handoff_parse_platform_request(begin, end,
                &platform_request);
            if (error)
                return error;
            error = handoff_add_platform_request(config,
                &platform_request);
            if (error)
                return error;
        }
    }
    return 0;
}

static int
handoff_select_pci_device(void *opaque_config,
    const bsd_pci_device_identity_t *identity)
{
    const bsd_bridge_handoff_config_t *config = opaque_config;

    for (size_t index = 0; index < config->pci_location_count; ++index) {
        if (handoff_location_equal(&config->pci_locations[index],
            &identity->location))
            return 1;
    }
    return 0;
}

static void
handoff_status_clear(bsd_bridge_handoff_status_t *status)
{
    if (!status)
        return;
    status->enabled = 0;
    status->pci_bus = 0;
    status->pci.discovered = 0;
    status->pci.selected = 0;
    status->pci.attached = 0;
    status->pci.unclaimed = 0;
    status->platform_selected = 0;
    status->platform_attached = 0;
}

static int
handoff_remove_pci_bus(device_t root, device_t bus)
{
    int error;

    bus_topo_lock();
    error = device_detach(bus);
    if (error) {
        bus_topo_unlock();
        return error;
    }
    error = device_delete_child(root, bus);
    bus_topo_unlock();
    return error;
}

static int
handoff_remove_platform_devices(device_t root,
    const bsd_bridge_platform_handoff_ops_t *operations,
    device_t *devices, size_t *count)
{
    while (*count != 0) {
        size_t index = *count - 1;
        int error = operations->detach(operations->context, root,
            devices[index]);

        if (error)
            return error;
        devices[index] = 0;
        *count = index;
    }
    return 0;
}

int
bsd_bridge_handoff_start_with_ops(
    const bsd_bridge_handoff_config_t *config,
    const bsd_bridge_pci_handoff_ops_t *pci_ops,
    const bsd_bridge_platform_handoff_ops_t *platform_ops,
    bsd_bridge_handoff_status_t *status)
{
    const bsd_bridge_pci_handoff_ops_t *selected_pci_ops = pci_ops;
    bsd_bridge_bootstrap_status_t bootstrap;
    bsd_pci_attach_options_t options;
    bsd_pci_bus_status_t pci_status = {0};
    device_t bus = 0;
    device_t platform_devices[
        BSD_BRIDGE_HANDOFF_MAX_PLATFORM_DEVICES] = {0};
    size_t platform_device_count = 0;
    int pci_prepared = 0;
    int pci_active = 0;
    int error;

#ifdef CONFIG_NET
    if (config && config->pci_location_count != 0 && !selected_pci_ops)
        selected_pci_ops = &g_handoff_pci_netdev_ops;
#endif
    handoff_status_clear(status);
    if (!config ||
        config->pci_location_count >
            BSD_BRIDGE_HANDOFF_MAX_PCI_DEVICES ||
        config->platform_request_count >
            BSD_BRIDGE_HANDOFF_MAX_PLATFORM_DEVICES ||
        (config->pci_location_count != 0 && selected_pci_ops &&
            (!selected_pci_ops->prepare || !selected_pci_ops->activate ||
             !selected_pci_ops->deactivate ||
             !selected_pci_ops->restore)) ||
        (config->platform_request_count != 0 &&
            (!platform_ops || !platform_ops->attach ||
             !platform_ops->detach)))
        return BSD_HANDOFF_EINVAL;
    if (config->pci_location_count == 0 &&
        config->platform_request_count == 0)
        return 0;
    if (g_handoff_pci_bus || g_handoff_pci_prepared ||
        g_handoff_platform_device_count != 0)
        return BSD_HANDOFF_EBUSY;

    bsd_bridge_bootstrap_get_status(&bootstrap);
    if (bootstrap.state != BSD_BRIDGE_BOOTSTRAP_READY ||
        !bootstrap.root)
        return BSD_HANDOFF_ENXIO;

    if (config->pci_location_count != 0) {
        if (selected_pci_ops) {
            error = selected_pci_ops->prepare(
                selected_pci_ops->context,
                config->pci_locations, config->pci_location_count);
            if (error != 0)
                return error;
            pci_prepared = 1;
        }
        options.select_device = handoff_select_pci_device;
        options.context = (void *)(uintptr_t)config;
        bus = bsd_pci_attach_bus_selected(bootstrap.root, &options);
        if (!bus) {
            if (pci_prepared)
                (void)selected_pci_ops->restore(
                    selected_pci_ops->context);
            return BSD_HANDOFF_ENXIO;
        }
        error = bsd_pci_bus_get_status(bus, &pci_status);
        if (error != 0 ||
            pci_status.selected != config->pci_location_count ||
            pci_status.attached != pci_status.selected ||
            pci_status.unclaimed != 0) {
            (void)handoff_remove_pci_bus(bootstrap.root, bus);
            if (pci_prepared)
                (void)selected_pci_ops->restore(
                    selected_pci_ops->context);
            return error != 0 ? error : BSD_HANDOFF_ENOENT;
        }
        if (pci_prepared) {
            error = selected_pci_ops->activate(
                selected_pci_ops->context);
            if (error != 0) {
                (void)selected_pci_ops->deactivate(
                    selected_pci_ops->context);
                (void)handoff_remove_pci_bus(bootstrap.root, bus);
                (void)selected_pci_ops->restore(
                    selected_pci_ops->context);
                return error;
            }
            pci_active = 1;
        }
    }

    for (size_t index = 0; index < config->platform_request_count;
         ++index) {
        device_t device = 0;

        error = platform_ops->attach(platform_ops->context,
            bootstrap.root, &config->platform_requests[index],
            (unsigned int)index, &device);
        if (error != 0 || !device) {
            (void)handoff_remove_platform_devices(bootstrap.root,
                platform_ops, platform_devices,
                &platform_device_count);
            if (pci_active)
                (void)selected_pci_ops->deactivate(
                    selected_pci_ops->context);
            if (bus)
                (void)handoff_remove_pci_bus(bootstrap.root, bus);
            if (pci_prepared)
                (void)selected_pci_ops->restore(
                    selected_pci_ops->context);
            return error != 0 ? error : BSD_HANDOFF_ENXIO;
        }
        platform_devices[platform_device_count++] = device;
    }

    error = bsd_cam_scan_pending();
    if (error != 0) {
        (void)handoff_remove_platform_devices(bootstrap.root,
            platform_ops, platform_devices, &platform_device_count);
        if (pci_active)
            (void)selected_pci_ops->deactivate(
                selected_pci_ops->context);
        if (bus)
            (void)handoff_remove_pci_bus(bootstrap.root, bus);
        if (pci_prepared)
            (void)selected_pci_ops->restore(
                selected_pci_ops->context);
        return error;
    }

    g_handoff_root = bootstrap.root;
    g_handoff_pci_bus = bus;
    for (size_t index = 0; index < platform_device_count; ++index)
        g_handoff_platform_devices[index] = platform_devices[index];
    g_handoff_platform_device_count = platform_device_count;
    if (platform_device_count != 0)
        g_handoff_platform_ops = *platform_ops;
    if (pci_prepared) {
        g_handoff_pci_ops = *selected_pci_ops;
        g_handoff_pci_prepared = 1;
        g_handoff_pci_active = pci_active;
    }
    if (status) {
        status->enabled = 1;
        status->pci_bus = bus;
        status->pci = pci_status;
        status->platform_selected = config->platform_request_count;
        status->platform_attached = platform_device_count;
    }
    return 0;
}

int
bsd_bridge_handoff_start_with_platform(
    const bsd_bridge_handoff_config_t *config,
    const bsd_bridge_platform_handoff_ops_t *platform_ops,
    bsd_bridge_handoff_status_t *status)
{
    return bsd_bridge_handoff_start_with_ops(config, 0,
        platform_ops, status);
}

int
bsd_bridge_handoff_start(const bsd_bridge_handoff_config_t *config,
    bsd_bridge_handoff_status_t *status)
{
    return bsd_bridge_handoff_start_with_platform(config, 0, status);
}

int
bsd_bridge_handoff_start_from_command_line_with_platform(
    const char *command_line,
    const bsd_bridge_platform_handoff_ops_t *platform_ops,
    bsd_bridge_handoff_status_t *status)
{
    bsd_bridge_handoff_config_t config;
    int error;

    error = bsd_bridge_handoff_parse_command_line(command_line, &config);
    return error == 0 ?
        bsd_bridge_handoff_start_with_platform(&config,
            platform_ops, status) : error;
}

int
bsd_bridge_handoff_start_from_command_line(const char *command_line,
    bsd_bridge_handoff_status_t *status)
{
    return bsd_bridge_handoff_start_from_command_line_with_platform(
        command_line, 0, status);
}

int
bsd_bridge_handoff_stop(void)
{
    device_t root = g_handoff_root;
    device_t bus = g_handoff_pci_bus;
    int error;

    if (!bus && !g_handoff_pci_prepared &&
        g_handoff_platform_device_count == 0)
        return 0;
    if (g_handoff_platform_device_count != 0) {
        error = handoff_remove_platform_devices(root,
            &g_handoff_platform_ops, g_handoff_platform_devices,
            &g_handoff_platform_device_count);
        if (error)
            return error;
    }
    g_handoff_platform_ops =
        (bsd_bridge_platform_handoff_ops_t){0};
    if (bus) {
        if (g_handoff_pci_active) {
            error = g_handoff_pci_ops.deactivate(
                g_handoff_pci_ops.context);
            if (error)
                return error;
            g_handoff_pci_active = 0;
        }
        error = handoff_remove_pci_bus(root, bus);
        if (error)
            return error;
        g_handoff_pci_bus = 0;
    }
    if (g_handoff_pci_prepared) {
        error = g_handoff_pci_ops.restore(
            g_handoff_pci_ops.context);
        if (error)
            return error;
        g_handoff_pci_prepared = 0;
    }
    g_handoff_root = 0;
    g_handoff_pci_ops = (bsd_bridge_pci_handoff_ops_t){0};
    g_handoff_pci_active = 0;
    return 0;
}
