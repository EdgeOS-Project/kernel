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
static uint32_t g_snapshot_count;
static uint32_t g_event_count;
static char g_event_action[16];
static char g_event_path[96];

int bsd_driver_module_load_image(
    const void *image, uint32_t image_size, const char *name,
    struct linker_file **file_out) {
    (void)file_out;
    assert(image != 0);
    assert(image_size == 4);
    strncpy(g_image_name, name, sizeof(g_image_name) - 1u);
    if (g_load_result == 0 && g_snapshot_count == 0u)
        g_snapshot_count = 1u;
    return g_load_result;
}

int bsd_module_deactivate_name(const char *name) {
    strncpy(g_unload_name, name, sizeof(g_unload_name) - 1u);
    if (g_unload_result == 0)
        g_snapshot_count = 0u;
    return g_unload_result;
}

int bsd_module_loaded_snapshot_at(
    uint32_t index, bsd_module_loaded_snapshot_t *snapshot) {
    if (index >= g_snapshot_count) return 2;
    *snapshot = g_snapshots[index];
    return 0;
}

int kernel_device_uevent_emit(
    const char *action, const char *path, const char *subsystem,
    uint32_t major, uint32_t minor, const char *device_name,
    const char *driver, const char *modalias) {
    (void)major;
    (void)minor;
    (void)device_name;
    (void)driver;
    (void)modalias;
    assert(strcmp(subsystem, "module") == 0);
    strncpy(g_event_action, action, sizeof(g_event_action) - 1u);
    strncpy(g_event_path, path, sizeof(g_event_path) - 1u);
    ++g_event_count;
    return 0;
}

int main(void) {
    static const uint8_t image[] = {0x7f, 'E', 'L', 'F'};
    char modules[256];
    char attribute[64];
    kernel_linux_module_snapshot_t snapshot;
    uint32_t module_index;
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
    strcpy(g_snapshots[0].name, "test_driver");
    g_snapshots[0].size = 4096u;
    g_snapshots[0].address = 0x12340000u;
    g_snapshots[0].identity = 41u;
    assert(kernel_linux_module_load(image, sizeof(image), "") == 0);
    assert(strncmp(g_image_name, "edge-", 5) == 0);
    assert(g_event_count == 1u);
    assert(strcmp(g_event_action, "add") == 0);
    assert(strcmp(g_event_path, "/module/test_driver") == 0);
    g_load_result = 17;
    assert(kernel_linux_module_load(image, sizeof(image), "") ==
           -EDGE_LINUX_EEXIST);

    g_unload_result = 0;
    assert(kernel_linux_module_unload("test_driver", 0) == 0);
    assert(strcmp(g_unload_name, "test_driver") == 0);
    assert(g_event_count == 2u);
    assert(strcmp(g_event_action, "remove") == 0);
    assert(kernel_linux_module_unload("test_driver", 0x40000000u) ==
           -EDGE_LINUX_EINVAL);
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
    g_snapshots[1].identity = 42u;
    g_snapshot_count = 2u;
    length = kernel_linux_modules_render(modules, sizeof(modules));
    assert(length > 0);
    modules[length] = 0;
    assert(strcmp(modules,
        "first_driver 4096 2 - Live 0x12340000\n"
        "second_driver 8192 0 - Live 0x56780000\n") == 0);

    assert(kernel_linux_module_find(
        "second_driver", &module_index, &snapshot) == 0);
    assert(module_index == 1u);
    assert(snapshot.size == 8192u);
    assert(kernel_linux_module_find_identity(
        41u, &module_index, &snapshot) == 0);
    assert(module_index == 0u);
    length = kernel_linux_module_attribute_render(
        0u, KERNEL_LINUX_MODULE_CORESIZE, attribute, sizeof(attribute));
    assert(length == 5);
    attribute[length] = 0;
    assert(strcmp(attribute, "4096\n") == 0);
    length = kernel_linux_module_attribute_render(
        0u, KERNEL_LINUX_MODULE_SECTION_TEXT,
        attribute, sizeof(attribute));
    assert(length > 0);
    attribute[length] = 0;
    assert(strcmp(attribute, "0x12340000\n") == 0);

    puts("linux_module_unit: PASS");
    return 0;
}
