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
