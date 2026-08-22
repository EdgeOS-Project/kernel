/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux module UAPI policy. */

#ifndef EDGEOS_KERNEL_LINUX_MODULE_H
#define EDGEOS_KERNEL_LINUX_MODULE_H

#include <stdint.h>

#define KERNEL_LINUX_MODULE_MAX_BYTES (128u * 1024u * 1024u)
#define KERNEL_LINUX_MODULE_PARAMETERS_MAX 4096u
#define KERNEL_LINUX_MODULE_NAME_MAX 64u

typedef struct kernel_linux_module_snapshot {
    char name[KERNEL_LINUX_MODULE_NAME_MAX];
    uint64_t size;
    uint64_t address;
    uint32_t references;
    uint32_t identity;
} kernel_linux_module_snapshot_t;

enum kernel_linux_module_attribute {
    KERNEL_LINUX_MODULE_CORESIZE = 1,
    KERNEL_LINUX_MODULE_INITSIZE,
    KERNEL_LINUX_MODULE_REFCOUNT,
    KERNEL_LINUX_MODULE_TAINT,
    KERNEL_LINUX_MODULE_INITSTATE,
    KERNEL_LINUX_MODULE_SECTION_TEXT,
};

int kernel_linux_module_load(const void *image, uint32_t image_size,
                             const char *parameters);
int kernel_linux_module_unload(const char *name, uint32_t flags);
int kernel_linux_modules_render(char *buffer, uint32_t capacity);
int kernel_linux_module_snapshot_at(
    uint32_t index, kernel_linux_module_snapshot_t *snapshot);
int kernel_linux_module_find(const char *name, uint32_t *index_out,
                             kernel_linux_module_snapshot_t *snapshot);
int kernel_linux_module_find_identity(
    uint32_t identity, uint32_t *index_out,
    kernel_linux_module_snapshot_t *snapshot);
int kernel_linux_module_attribute_render(
    uint32_t index, enum kernel_linux_module_attribute attribute,
    char *buffer, uint32_t capacity);

#endif
