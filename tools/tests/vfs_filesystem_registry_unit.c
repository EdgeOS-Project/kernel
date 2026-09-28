/* SPDX-License-Identifier: MPL-2.0 */

#include "vfs/filesystem_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *arch_vm_alloc_pages(uint64_t page_count) {
    return calloc((size_t)page_count, 4096u);
}

void arch_vm_free_page(void *page) {
    free(page);
}

static int test_mount(const char *device, const char *target) {
    return device && target && strcmp(device, "device") == 0 &&
        strcmp(target, "/target") == 0 ? 73 : -1;
}

static int require(int condition, const char *message) {
    if (condition) return 0;
    fprintf(stderr, "vfs_filesystem_registry_unit: %s\n", message);
    return 1;
}

int main(void) {
    char name[16];

    vfs_filesystem_registry_reset();
    if (require(vfs_filesystem_registry_count() == 0,
                "reset did not clear the registry")) return 1;
    for (unsigned int index = 0; index < 80u; ++index) {
        snprintf(name, sizeof(name), "testfs%u", index);
        if (require(vfs_filesystem_registry_register(name, test_mount) == 0,
                    "dynamic registration failed")) return 1;
    }
    if (require(vfs_filesystem_registry_count() == 80u,
                "registry count stopped at a static limit")) return 1;
    if (require(vfs_filesystem_registry_capacity() >= 80u,
                "registry capacity did not grow")) return 1;
    if (require(vfs_filesystem_registry_mount(
                    "testfs79", "device", "/target") == 73,
                "mount dispatch failed after registry growth")) return 1;
    if (require(vfs_filesystem_registry_mount(
                    "missing", "device", "/target") == -1,
                "unknown filesystem dispatch succeeded")) return 1;
    if (require(vfs_filesystem_registry_register(
                    "filesystem-name-too-long", test_mount) == -1,
                "overlong filesystem name was accepted")) return 1;
    vfs_filesystem_registry_reset();
    if (require(vfs_filesystem_registry_count() == 0,
                "final reset did not release the registry")) return 1;

    puts("vfs_filesystem_registry_unit: PASS");
    return 0;
}
