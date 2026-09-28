/* SPDX-License-Identifier: MPL-2.0 */
/* Generated-set kernel exports used by loadable BSD driver modules. */

#include <stddef.h>
#include <stdint.h>

struct bsd_driver_kernel_symbol {
    const char *name;
    const void *address;
};

#define BSD_DRIVER_KERNEL_EXPORT(symbol) extern unsigned char symbol[];
#include "driver_kernel_exports.inc"
#undef BSD_DRIVER_KERNEL_EXPORT

#define BSD_DRIVER_KERNEL_EXPORT(symbol) \
    { #symbol, (const void *)(uintptr_t)symbol },
static const struct bsd_driver_kernel_symbol g_kernel_exports[] = {
#include "driver_kernel_exports.inc"
};
#undef BSD_DRIVER_KERNEL_EXPORT

static int
export_name_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

int
bsd_driver_kernel_symbol_resolve(const char *name, uint64_t *address)
{
    if (!name || !address)
        return -1;
    for (size_t index = 0;
        index < sizeof(g_kernel_exports) / sizeof(g_kernel_exports[0]);
        ++index) {
        if (export_name_equal(g_kernel_exports[index].name, name)) {
            *address = (uint64_t)(uintptr_t)g_kernel_exports[index].address;
            return 0;
        }
    }
    return -1;
}

size_t
bsd_driver_kernel_symbol_count(void)
{
    return sizeof(g_kernel_exports) / sizeof(g_kernel_exports[0]);
}
