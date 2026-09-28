/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 platform adapter for controlled BSD bridge device handoff. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/arm64_handoff.h"
#include "compat/freebsd/edgeos/platform.h"
#include "compat/freebsd/edgeos/virtio_mmio.h"
#include "drivers/virtio_net_mmio.h"
#include "net/lwip_stack.h"
#include "net/native_netdev.h"
#include "net/netdev.h"

#define BSD_ARM64_HANDOFF_ENOENT 2
#define BSD_ARM64_HANDOFF_EBUSY 16
#define BSD_ARM64_HANDOFF_EINVAL 22

typedef struct arm64_network_handoff {
    device_t device;
    edge_netdev_handle_t bsd_handle;
    uint8_t native_suspended;
    uint8_t native_was_bound;
} arm64_network_handoff_t;

typedef struct arm64_handoff_context {
    const edgeos_arm64_bootinfo_t *bootinfo;
    arm64_network_handoff_t network;
} arm64_handoff_context_t;

static arm64_handoff_context_t g_handoff_context;

static int
arm64_handle_in_snapshot(edge_netdev_handle_t handle,
    const edge_netdev_handle_t *snapshot, size_t count)
{
    for (size_t index = 0; index < count; ++index) {
        if (snapshot[index] == handle)
            return 1;
    }
    return 0;
}

static edge_netdev_handle_t
arm64_find_added_netdev(const edge_netdev_handle_t *before,
    size_t before_count)
{
    edge_netdev_handle_t after[EDGE_NETDEV_MAX];
    edge_netdev_handle_t added = 0;
    size_t after_count = 0;

    if (edge_netdev_snapshot(after, EDGE_NETDEV_MAX,
        &after_count) != 0)
        return 0;
    for (size_t index = 0; index < after_count; ++index) {
        if (arm64_handle_in_snapshot(after[index], before,
            before_count))
            continue;
        if (added)
            return 0;
        added = after[index];
    }
    return added;
}

static int
arm64_restore_native_network(arm64_handoff_context_t *context)
{
    int error;

    if (!context->network.native_suspended)
        return 0;
    error = edgeos_arm64_virtio_net_resume();
    if (error == 0)
        error = edge_native_netdev_register();
    if (error == 0 && context->network.native_was_bound)
        error = lwip_stack_bind_netdev(
            edge_native_netdev_get_handle());
    if (error == 0)
        context->network.native_suspended = 0;
    return error;
}

static int
arm64_suspend_native_network(arm64_handoff_context_t *context)
{
    edge_netdev_handle_t native = edge_native_netdev_get_handle();
    int error;

    if (!native)
        return 0;
    context->network.native_was_bound =
        lwip_stack_get_netdev() == native;
    if (context->network.native_was_bound &&
        lwip_stack_unbind_netdev(native) != 0)
        return BSD_ARM64_HANDOFF_EBUSY;
    error = edge_native_netdev_unregister();
    if (error != 0) {
        if (context->network.native_was_bound)
            (void)lwip_stack_bind_netdev(native);
        return error;
    }
    error = edgeos_arm64_virtio_net_stop();
    if (error != 0) {
        (void)edge_native_netdev_register();
        if (context->network.native_was_bound)
            (void)lwip_stack_bind_netdev(
                edge_native_netdev_get_handle());
        return error;
    }
    context->network.native_suspended = 1;
    return 0;
}

static int
arm64_handoff_attach(void *opaque_bootinfo, device_t parent,
    const bsd_bridge_platform_request_t *request,
    unsigned int unit, device_t *result)
{
    arm64_handoff_context_t *context = opaque_bootinfo;
    const edgeos_arm64_bootinfo_t *bootinfo;
    bsd_virtio_mmio_description_t description;
    edge_netdev_handle_t before[EDGE_NETDEV_MAX];
    edge_netdev_handle_t bsd_handle = 0;
    size_t before_count = 0;
    int network_request;
    int error;

    if (!context || !(bootinfo = context->bootinfo) || !parent ||
        !request || !result ||
        request->kind != BSD_BRIDGE_PLATFORM_VIRTIO_MMIO)
        return BSD_ARM64_HANDOFF_EINVAL;
    network_request = request->device == 1u;
    if (network_request && context->network.device)
        return BSD_ARM64_HANDOFF_EBUSY;
    if (network_request &&
        edge_netdev_snapshot(before, EDGE_NETDEV_MAX,
            &before_count) != 0)
        return BSD_ARM64_HANDOFF_EBUSY;
    if (network_request && request->instance == 0) {
        error = arm64_suspend_native_network(context);
        if (error != 0)
            return error;
    }
    description = (bsd_virtio_mmio_description_t) {
        .unit = unit,
    };
    if (edgeos_arm64_virtio_mmio_describe_nth(bootinfo,
        request->device, request->instance, &description.base,
        &description.size, &description.interrupt,
        &description.interrupt_flags) != 0 ||
        description.size == 0 ||
        description.interrupt == UINT32_MAX) {
        (void)arm64_restore_native_network(context);
        return BSD_ARM64_HANDOFF_ENOENT;
    }
    error = bsd_virtio_mmio_attach(parent, &description, result);
    if (error != 0) {
        (void)arm64_restore_native_network(context);
        return error;
    }
    if (!network_request)
        return 0;
    bsd_handle = arm64_find_added_netdev(before, before_count);
    if (!bsd_handle || lwip_stack_bind_netdev(bsd_handle) != 0) {
        (void)bsd_virtio_mmio_detach(parent, *result);
        *result = 0;
        (void)arm64_restore_native_network(context);
        return BSD_ARM64_HANDOFF_ENOENT;
    }
    context->network.device = *result;
    context->network.bsd_handle = bsd_handle;
    return 0;
}

static int
arm64_handoff_detach(void *opaque_bootinfo, device_t parent,
    device_t device)
{
    arm64_handoff_context_t *context = opaque_bootinfo;
    int error;

    if (!context)
        return BSD_ARM64_HANDOFF_EINVAL;
    if (context->network.device != device)
        return bsd_virtio_mmio_detach(parent, device);
    if (lwip_stack_get_netdev() == context->network.bsd_handle &&
        lwip_stack_unbind_netdev(
            context->network.bsd_handle) != 0)
        return BSD_ARM64_HANDOFF_EBUSY;
    error = bsd_virtio_mmio_detach(parent, device);
    if (error != 0) {
        (void)lwip_stack_bind_netdev(
            context->network.bsd_handle);
        return error;
    }
    context->network.device = 0;
    context->network.bsd_handle = 0;
    error = arm64_restore_native_network(context);
    context->network.native_was_bound = 0;
    return error;
}

int
bsd_bridge_arm64_handoff_start(const char *command_line,
    const edgeos_arm64_bootinfo_t *bootinfo,
    bsd_bridge_handoff_status_t *status)
{
    if (g_handoff_context.network.device)
        return BSD_ARM64_HANDOFF_EBUSY;
    g_handoff_context.bootinfo = bootinfo;
    g_handoff_context.network =
        (arm64_network_handoff_t){0};
    bsd_bridge_platform_handoff_ops_t operations = {
        .attach = arm64_handoff_attach,
        .detach = arm64_handoff_detach,
        .context = &g_handoff_context,
    };

    return bsd_bridge_handoff_start_from_command_line_with_platform(
        command_line, &operations, status);
}
