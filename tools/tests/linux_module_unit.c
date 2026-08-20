/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for Linux module UAPI policy. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "compat/freebsd/edgeos/module.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_module.h"

struct linker_file;

static int g_load_result;
static int g_unload_result;
static char g_image_name[32];
static char g_unload_name[64];
static bsd_module_loaded_snapshot_t g_snapshots[2];

int bsd_driver_module_load_image(
    const void *image, uint32_t image_size, const char *name,
    struct linker_file **file_out) {
    (void)file_out;
    assert(image != 0);
    assert(image_size == 4);
    strncpy(g_image_name, name, sizeof(g_image_name) - 1u);
    return g_load_result;
}

int bsd_module_deactivate_name(const char *name) {
    strncpy(g_unload_name, name, sizeof(g_unload_name) - 1u);
    return g_unload_result;
}

int bsd_module_loaded_snapshot_at(
    uint32_t index, bsd_module_loaded_snapshot_t *snapshot) {
    if (index >= 2u) return 2;
    *snapshot = g_snapshots[index];
    return 0;
}

int main(void) {
    static const uint8_t image[] = {0x7f, 'E', 'L', 'F'};
    char modules[256];
    int length;

    assert(kernel_linux_module_load(0, sizeof(image), "") ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_linux_module_load(image, 0, "") ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_linux_module_load(image, sizeof(image), 0) ==
           -EDGE_LINUX_EFAULT);
    assert(kernel_linux_module_load(image, sizeof(image), "debug=1") ==
           -EDGE_LINUX_EINVAL);

    g_load_result = 0;
    assert(kernel_linux_module_load(image, sizeof(image), "") == 0);
    assert(strncmp(g_image_name, "edge-", 5) == 0);
    g_load_result = 17;
    assert(kernel_linux_module_load(image, sizeof(image), "") ==
           -EDGE_LINUX_EEXIST);

    g_unload_result = 0;
    assert(kernel_linux_module_unload("test_driver", 0) == 0);
    assert(strcmp(g_unload_name, "test_driver") == 0);
    g_unload_result = 16;
    assert(kernel_linux_module_unload("test_driver", 0) ==
           -EDGE_LINUX_EBUSY);
    assert(kernel_linux_module_unload("", 0) == -EDGE_LINUX_ENOENT);

    strcpy(g_snapshots[0].name, "first_driver");
    g_snapshots[0].size = 4096u;
    g_snapshots[0].references = 2u;
    g_snapshots[0].address = 0x12340000u;
    strcpy(g_snapshots[1].name, "second_driver");
    g_snapshots[1].size = 8192u;
    g_snapshots[1].address = 0x56780000u;
    length = kernel_linux_modules_render(modules, sizeof(modules));
    assert(length > 0);
    modules[length] = 0;
    assert(strcmp(modules,
        "first_driver 4096 2 - Live 0x12340000\n"
        "second_driver 8192 0 - Live 0x56780000\n") == 0);

    puts("linux_module_unit: PASS");
    return 0;
}
