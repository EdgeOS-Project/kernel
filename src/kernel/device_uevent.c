/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux-compatible kobject uevent policy. */

#include <stdint.h>

#include "kernel/device_uevent.h"
#include "kernel/socket_runtime.h"
#include "string.h"

static uint32_t append_text(char *buffer, uint32_t capacity, uint32_t offset,
                            const char *text) {
    while (*text && offset < capacity) buffer[offset++] = *text++;
    return offset;
}

static uint32_t append_u32(char *buffer, uint32_t capacity, uint32_t offset,
                           uint32_t value) {
    char digits[10];
    uint32_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    while (count && offset < capacity) buffer[offset++] = digits[--count];
    return offset;
}

static int finish_field(char *buffer, uint32_t capacity, uint32_t *offset) {
    if (!buffer || !offset || *offset >= capacity) return -1;
    buffer[(*offset)++] = 0;
    return 0;
}

static int append_text_field(char *buffer, uint32_t capacity,
                             uint32_t *offset, const char *prefix,
                             const char *value) {
    uint32_t next;
    if (!buffer || !offset || !prefix || !value) return -1;
    next = append_text(buffer, capacity, *offset, prefix);
    next = append_text(buffer, capacity, next, value);
    *offset = next;
    return finish_field(buffer, capacity, offset);
}

static int append_number_field(char *buffer, uint32_t capacity,
                               uint32_t *offset, const char *prefix,
                               uint32_t value) {
    uint32_t next;
    if (!buffer || !offset || !prefix) return -1;
    next = append_text(buffer, capacity, *offset, prefix);
    next = append_u32(buffer, capacity, next, value);
    *offset = next;
    return finish_field(buffer, capacity, offset);
}

static uint32_t g_uevent_sequence = 1u;

static int action_is_valid(const char *action) {
    static const char *const actions[] = {
        "add", "remove", "change", "move", "online", "offline",
        "bind", "unbind"
    };
    if (!action) return 0;
    for (uint32_t index = 0; index < sizeof(actions) / sizeof(actions[0]);
         ++index)
        if (strcmp(action, actions[index]) == 0) return 1;
    return 0;
}

static int build_device_event(char *payload, uint32_t capacity,
                              const char *action, const char *path,
                              const char *subsystem, uint32_t major,
                              uint32_t minor, const char *device_name,
                              const char *driver, const char *modalias,
                              uint32_t *length_out) {
    uint32_t length = 0;
    uint32_t sequence = g_uevent_sequence++;

    if (!payload || !capacity || !action_is_valid(action) || !path ||
        !subsystem || !length_out)
        return -1;
    length = append_text(payload, capacity, length, action);
    length = append_text(payload, capacity, length, "@");
    length = append_text(payload, capacity, length, path);
    if (finish_field(payload, capacity, &length) < 0 ||
        append_text_field(payload, capacity, &length,
                          "ACTION=", action) < 0 ||
        append_text_field(payload, capacity, &length,
                          "DEVPATH=", path) < 0 ||
        append_text_field(payload, capacity, &length,
                          "SUBSYSTEM=", subsystem) < 0)
        return -1;
    if (device_name &&
        (append_number_field(payload, capacity, &length,
                             "MAJOR=", major) < 0 ||
         append_number_field(payload, capacity, &length,
                             "MINOR=", minor) < 0 ||
         append_text_field(payload, capacity, &length,
                           "DEVNAME=", device_name) < 0))
        return -1;
    if (append_number_field(payload, capacity, &length,
                            "SEQNUM=", sequence) < 0)
        return -1;
    if (driver && append_text_field(payload, capacity, &length,
                                    "DRIVER=", driver) < 0)
        return -1;
    if (modalias && append_text_field(payload, capacity, &length,
                                      "MODALIAS=", modalias) < 0)
        return -1;
    *length_out = length;
    return 0;
}

int kernel_device_uevent_emit(const char *action, const char *path,
                              const char *subsystem, uint32_t major,
                              uint32_t minor, const char *device_name,
                              const char *driver, const char *modalias) {
    char payload[512];
    uint32_t length;
    if (build_device_event(payload, sizeof(payload), action, path, subsystem,
                           major, minor, device_name, driver, modalias,
                           &length) < 0)
        return -1;
    return kernel_socket_broadcast_netlink_datagram(
        EDGE_LINUX_NETLINK_KOBJECT_UEVENT,
        EDGE_LINUX_NETLINK_KOBJECT_UEVENT_GROUP, payload, length);
}
