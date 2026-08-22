/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux module UAPI policy. */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/device_uevent.h"
#include "kernel/linux_module.h"
#include "string.h"

#if defined(CONFIG_MODULES) && defined(CONFIG_BSD_DRIVER_MODULES)
#include "compat/freebsd/edgeos/driver_loader.h"
#include "compat/freebsd/edgeos/module.h"

static void kernel_linux_module_image_name(
    const void *image, uint32_t image_size, char name[32]) {
    static const char digits[] = "0123456789abcdef";
    const uint8_t *bytes = image;
    uint64_t hash = 1469598103934665603ull;
    uint32_t cursor = 0;

    for (uint32_t index = 0; index < image_size; ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ull;
    }
    name[cursor++] = 'e';
    name[cursor++] = 'd';
    name[cursor++] = 'g';
    name[cursor++] = 'e';
    name[cursor++] = '-';
    for (uint32_t shift = 0; shift < 16u; ++shift)
        name[cursor++] = digits[(hash >> ((15u - shift) * 4u)) & 0xfu];
    name[cursor] = 0;
}

static int kernel_linux_module_error(int error) {
    if (error <= 0) return error;
    if (error > 4095) return -EDGE_LINUX_EIO;
    return -error;
}

static int kernel_linux_module_append(
    char *buffer, uint32_t capacity, uint32_t *length, const char *text) {
    uint32_t cursor = 0;

    while (text[cursor]) {
        if (*length >= capacity) return -EDGE_LINUX_ENOSPC;
        buffer[(*length)++] = text[cursor++];
    }
    return 0;
}

static int kernel_linux_module_append_u64(
    char *buffer, uint32_t capacity, uint32_t *length, uint64_t value,
    uint32_t base) {
    static const char digits[] = "0123456789abcdef";
    char reversed[32];
    uint32_t count = 0;

    do {
        reversed[count++] = digits[value % base];
        value /= base;
    } while (value && count < sizeof(reversed));
    while (count) {
        if (*length >= capacity) return -EDGE_LINUX_ENOSPC;
        buffer[(*length)++] = reversed[--count];
    }
    return 0;
}

static void kernel_linux_module_emit(const char *action, const char *name) {
    char path[96];
    uint32_t length = 0;

    if (!action || !name || !name[0]) return;
    if (kernel_linux_module_append(path, sizeof(path), &length,
                                   "/module/") < 0 ||
        kernel_linux_module_append(path, sizeof(path), &length, name) < 0 ||
        length >= sizeof(path))
        return;
    path[length] = 0;
    (void)kernel_device_uevent_emit(
        action, path, "module", 0u, 0u, 0, 0, 0);
}
#endif

int kernel_linux_module_load(const void *image, uint32_t image_size,
                             const char *parameters) {
#if defined(CONFIG_MODULES) && defined(CONFIG_BSD_DRIVER_MODULES)
    char image_name[32];
    char loaded_before[64][KERNEL_LINUX_MODULE_NAME_MAX];
    bsd_module_loaded_snapshot_t snapshot;
    uint32_t before_count = 0;
    int result;

    if (!image || !image_size ||
        image_size > KERNEL_LINUX_MODULE_MAX_BYTES)
        return -EDGE_LINUX_EINVAL;
    if (!parameters) return -EDGE_LINUX_EFAULT;
    if (parameters[0]) return -EDGE_LINUX_EINVAL;
    while (before_count < sizeof(loaded_before) / sizeof(loaded_before[0]) &&
           bsd_module_loaded_snapshot_at(before_count, &snapshot) == 0) {
        memcpy(loaded_before[before_count], snapshot.name,
               sizeof(loaded_before[before_count]));
        loaded_before[before_count][sizeof(loaded_before[before_count]) - 1u] = 0;
        ++before_count;
    }
    kernel_linux_module_image_name(image, image_size, image_name);
    result = kernel_linux_module_error(bsd_driver_module_load_image(
        image, image_size, image_name, 0));
    if (result < 0) return result;
    for (uint32_t index = 0;
         bsd_module_loaded_snapshot_at(index, &snapshot) == 0; ++index) {
        uint32_t existing;

        for (existing = 0; existing < before_count; ++existing)
            if (strcmp(loaded_before[existing], snapshot.name) == 0)
                break;
        if (existing == before_count)
            kernel_linux_module_emit("add", snapshot.name);
    }
    return 0;
#else
    (void)image;
    (void)image_size;
    (void)parameters;
    return -EDGE_LINUX_ENOSYS;
#endif
}

int kernel_linux_module_unload(const char *name, uint32_t flags) {
#if defined(CONFIG_MODULES) && defined(CONFIG_BSD_DRIVER_MODULES)
    char loaded_before[64][KERNEL_LINUX_MODULE_NAME_MAX];
    bsd_module_loaded_snapshot_t snapshot;
    uint32_t before_count = 0;
    int result;

    if (flags & ~(uint32_t)(0x800u | 0x200u))
        return -EDGE_LINUX_EINVAL;
    if (!name || !name[0]) return -EDGE_LINUX_ENOENT;
    while (before_count < sizeof(loaded_before) / sizeof(loaded_before[0]) &&
           bsd_module_loaded_snapshot_at(before_count, &snapshot) == 0) {
        memcpy(loaded_before[before_count], snapshot.name,
               sizeof(loaded_before[before_count]));
        loaded_before[before_count][sizeof(loaded_before[before_count]) - 1u] = 0;
        ++before_count;
    }
    result = kernel_linux_module_error(bsd_module_deactivate_name(name));
    if (result < 0) return result;
    for (uint32_t removed = 0; removed < before_count; ++removed) {
        uint32_t index;

        for (index = 0;
             bsd_module_loaded_snapshot_at(index, &snapshot) == 0; ++index)
            if (strcmp(loaded_before[removed], snapshot.name) == 0)
                break;
        if (bsd_module_loaded_snapshot_at(index, &snapshot) != 0)
            kernel_linux_module_emit("remove", loaded_before[removed]);
    }
    return 0;
#else
    (void)name;
    (void)flags;
    return -EDGE_LINUX_ENOSYS;
#endif
}

int kernel_linux_module_snapshot_at(
    uint32_t index, kernel_linux_module_snapshot_t *snapshot) {
#if defined(CONFIG_MODULES) && defined(CONFIG_BSD_DRIVER_MODULES)
    bsd_module_loaded_snapshot_t bridge_snapshot;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    if (bsd_module_loaded_snapshot_at(index, &bridge_snapshot) != 0)
        return -EDGE_LINUX_ENOENT;
    memset(snapshot, 0, sizeof(*snapshot));
    memcpy(snapshot->name, bridge_snapshot.name, sizeof(snapshot->name));
    snapshot->name[sizeof(snapshot->name) - 1u] = 0;
    snapshot->size = bridge_snapshot.size;
    snapshot->address = bridge_snapshot.address;
    snapshot->references = bridge_snapshot.references;
    snapshot->identity = bridge_snapshot.identity;
    return 0;
#else
    (void)index;
    (void)snapshot;
    return -EDGE_LINUX_ENOENT;
#endif
}

int kernel_linux_module_find_identity(
    uint32_t identity, uint32_t *index_out,
    kernel_linux_module_snapshot_t *snapshot) {
    kernel_linux_module_snapshot_t candidate;

    if (!identity) return -EDGE_LINUX_ENOENT;
    for (uint32_t index = 0;
         kernel_linux_module_snapshot_at(index, &candidate) == 0; ++index) {
        if (candidate.identity != identity) continue;
        if (index_out) *index_out = index;
        if (snapshot) *snapshot = candidate;
        return 0;
    }
    return -EDGE_LINUX_ENOENT;
}

int kernel_linux_module_find(const char *name, uint32_t *index_out,
                             kernel_linux_module_snapshot_t *snapshot) {
    kernel_linux_module_snapshot_t candidate;

    if (!name || !name[0]) return -EDGE_LINUX_ENOENT;
    for (uint32_t index = 0;
         kernel_linux_module_snapshot_at(index, &candidate) == 0; ++index) {
        if (strcmp(candidate.name, name) != 0) continue;
        if (index_out) *index_out = index;
        if (snapshot) *snapshot = candidate;
        return 0;
    }
    return -EDGE_LINUX_ENOENT;
}

int kernel_linux_module_attribute_render(
    uint32_t index, enum kernel_linux_module_attribute attribute,
    char *buffer, uint32_t capacity) {
#if defined(CONFIG_MODULES) && defined(CONFIG_BSD_DRIVER_MODULES)
    kernel_linux_module_snapshot_t snapshot;
    uint32_t length = 0;

    if (!buffer || !capacity) return -EDGE_LINUX_EINVAL;
    if (kernel_linux_module_snapshot_at(index, &snapshot) < 0)
        return -EDGE_LINUX_ENOENT;
    switch (attribute) {
    case KERNEL_LINUX_MODULE_CORESIZE:
        if (kernel_linux_module_append_u64(
                buffer, capacity, &length, snapshot.size, 10u) < 0)
            return -EDGE_LINUX_ENOSPC;
        break;
    case KERNEL_LINUX_MODULE_INITSIZE:
        if (kernel_linux_module_append(buffer, capacity, &length, "0") < 0)
            return -EDGE_LINUX_ENOSPC;
        break;
    case KERNEL_LINUX_MODULE_REFCOUNT:
        if (kernel_linux_module_append_u64(
                buffer, capacity, &length, snapshot.references, 10u) < 0)
            return -EDGE_LINUX_ENOSPC;
        break;
    case KERNEL_LINUX_MODULE_TAINT:
        break;
    case KERNEL_LINUX_MODULE_INITSTATE:
        if (kernel_linux_module_append(
                buffer, capacity, &length, "live") < 0)
            return -EDGE_LINUX_ENOSPC;
        break;
    case KERNEL_LINUX_MODULE_SECTION_TEXT:
        if (kernel_linux_module_append(buffer, capacity, &length, "0x") < 0 ||
            kernel_linux_module_append_u64(
                buffer, capacity, &length, snapshot.address, 16u) < 0)
            return -EDGE_LINUX_ENOSPC;
        break;
    default:
        return -EDGE_LINUX_EINVAL;
    }
    if (kernel_linux_module_append(buffer, capacity, &length, "\n") < 0)
        return -EDGE_LINUX_ENOSPC;
    return (int)length;
#else
    (void)index;
    (void)attribute;
    (void)buffer;
    (void)capacity;
    return -EDGE_LINUX_ENOENT;
#endif
}

int kernel_linux_modules_render(char *buffer, uint32_t capacity) {
#if defined(CONFIG_MODULES) && defined(CONFIG_BSD_DRIVER_MODULES)
    bsd_module_loaded_snapshot_t snapshot;
    uint32_t length = 0;

    if (!buffer || !capacity) return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0;
         bsd_module_loaded_snapshot_at(index, &snapshot) == 0; ++index) {
        if (kernel_linux_module_append(
                buffer, capacity, &length, snapshot.name) < 0 ||
            kernel_linux_module_append(buffer, capacity, &length, " ") < 0 ||
            kernel_linux_module_append_u64(
                buffer, capacity, &length, snapshot.size, 10u) < 0 ||
            kernel_linux_module_append(buffer, capacity, &length, " ") < 0 ||
            kernel_linux_module_append_u64(
                buffer, capacity, &length, snapshot.references, 10u) < 0 ||
            kernel_linux_module_append(
                buffer, capacity, &length, " - Live 0x") < 0 ||
            kernel_linux_module_append_u64(
                buffer, capacity, &length, snapshot.address, 16u) < 0 ||
            kernel_linux_module_append(buffer, capacity, &length, "\n") < 0)
            return -EDGE_LINUX_ENOSPC;
    }
    return (int)length;
#else
    (void)buffer;
    (void)capacity;
    return 0;
#endif
}
