/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux module UAPI policy. */

#ifndef EDGEOS_KERNEL_LINUX_MODULE_H
#define EDGEOS_KERNEL_LINUX_MODULE_H

#include <stdint.h>

#define KERNEL_LINUX_MODULE_MAX_BYTES (128u * 1024u * 1024u)
#define KERNEL_LINUX_MODULE_PARAMETERS_MAX 4096u

int kernel_linux_module_load(const void *image, uint32_t image_size,
                             const char *parameters);
int kernel_linux_module_unload(const char *name, uint32_t flags);
int kernel_linux_modules_render(char *buffer, uint32_t capacity);

#endif
