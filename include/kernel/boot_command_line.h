/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS code. */

#ifndef EDGEOS_KERNEL_BOOT_COMMAND_LINE_H
#define EDGEOS_KERNEL_BOOT_COMMAND_LINE_H

#include <stddef.h>

#define EDGEOS_BOOT_COMMAND_LINE_MAX 1024u

void kernel_boot_command_line_set(const char *command_line);
const char *kernel_boot_command_line_get(void);
int kernel_boot_option_get(const char *name, char *value, size_t capacity);
int kernel_boot_option_present(const char *name);
int kernel_boot_option_enabled(const char *name, int default_value);
int kernel_boot_option_last_ordinal(const char *name);
int kernel_boot_init_path(int initramfs_root, char *path, size_t capacity);

#endif /* EDGEOS_KERNEL_BOOT_COMMAND_LINE_H */
