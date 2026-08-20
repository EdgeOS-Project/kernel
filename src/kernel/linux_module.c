/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux module UAPI policy. */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_module.h"

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
#endif

int kernel_linux_module_load(const void *image, uint32_t image_size,
                             const char *parameters) {
#if defined(CONFIG_MODULES) && defined(CONFIG_BSD_DRIVER_MODULES)
    char image_name[32];

    if (!image || !image_size ||
        image_size > KERNEL_LINUX_MODULE_MAX_BYTES)
        return -EDGE_LINUX_EINVAL;
    if (!parameters) return -EDGE_LINUX_EFAULT;
    if (parameters[0]) return -EDGE_LINUX_EINVAL;
    kernel_linux_module_image_name(image, image_size, image_name);
    return kernel_linux_module_error(bsd_driver_module_load_image(
        image, image_size, image_name, 0));
#else
    (void)image;
    (void)image_size;
    (void)parameters;
    return -EDGE_LINUX_ENOSYS;
#endif
}

int kernel_linux_module_unload(const char *name, uint32_t flags) {
#if defined(CONFIG_MODULES) && defined(CONFIG_BSD_DRIVER_MODULES)
    (void)flags;
    if (!name || !name[0]) return -EDGE_LINUX_ENOENT;
    return kernel_linux_module_error(bsd_module_deactivate_name(name));
#else
    (void)name;
    (void)flags;
    return -EDGE_LINUX_ENOSYS;
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
