/* SPDX-License-Identifier: MPL-2.0 */
/* Shared device-event delivery for imported FreeBSD drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/devctl.h"
#include "compat/freebsd/sys/sbuf.h"
#include "kernel/device_uevent.h"

static send_event_f *g_devctl_notify_hook;

static int
devctl_key_value(const char *data, const char *key, char *value,
    size_t capacity)
{
    size_t key_length;

    if (!data || !key || !value || capacity < 2)
        return 0;
    key_length = bsd_strlen(key);
    while (*data) {
        const char *start;
        size_t length;

        while (*data == ' ')
            ++data;
        start = data;
        while (*data && *data != ' ' && *data != '=')
            ++data;
        if (*data != '=') {
            while (*data && *data != ' ')
                ++data;
            continue;
        }
        length = (size_t)(data - start);
        ++data;
        if (length == key_length &&
            bsd_memcmp(start, key, length) == 0) {
            size_t output = 0;

            while (*data && *data != ' ' && output + 1 < capacity)
                value[output++] = *data++;
            value[output] = '\0';
            return output != 0;
        }
        while (*data && *data != ' ')
            ++data;
    }
    return 0;
}

static void
devctl_emit_uevent(const char *system, const char *subsystem,
    const char *type, const char *data)
{
    char device[64] = "device";
    char path[160];
    const char *action = "change";
    const char *selected_subsystem =
        subsystem && subsystem[0] ? subsystem : "bsd";

    if (type && bsd_strcmp(type, "ATTACH") == 0)
        action = "add";
    else if (type && bsd_strcmp(type, "DETACH") == 0)
        action = "remove";
    if (!devctl_key_value(data, "ugen", device, sizeof(device)))
        (void)devctl_key_value(data, "device", device, sizeof(device));
    bsd_snprintf(path, sizeof(path), "/devices/bsd/%s/%s",
        system && system[0] ? system : "kernel", device);
    (void)kernel_device_uevent_emit(action, path, selected_subsystem,
        0, 0, 0, 0, 0);
}

bool
devctl_process_running(void)
{
    return __atomic_load_n(&g_devctl_notify_hook, __ATOMIC_ACQUIRE) != 0;
}

void
devctl_notify(const char *system, const char *subsystem,
    const char *type, const char *data)
{
    send_event_f *hook =
        __atomic_load_n(&g_devctl_notify_hook, __ATOMIC_ACQUIRE);

    if (hook)
        hook(system, subsystem, type, data);
    devctl_emit_uevent(system, subsystem, type, data);
}

void
devctl_safe_quote_sb(struct sbuf *buffer, const char *source)
{
    if (!buffer || !source)
        return;
    while (*source) {
        if (*source == '"' || *source == '\\')
            (void)sbuf_putc(buffer, '\\');
        (void)sbuf_putc(buffer, *source++);
    }
}

void
devctl_set_notify_hook(send_event_f *hook)
{
    __atomic_store_n(&g_devctl_notify_hook, hook, __ATOMIC_RELEASE);
}

void
devctl_unset_notify_hook(void)
{
    __atomic_store_n(&g_devctl_notify_hook, 0, __ATOMIC_RELEASE);
}
