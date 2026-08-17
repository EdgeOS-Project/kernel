/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux-compatible console device inventory. */

#ifndef EDGEOS_KERNEL_CONSOLE_DEVICE_H
#define EDGEOS_KERNEL_CONSOLE_DEVICE_H

#include <stdint.h>

typedef struct kernel_console_device {
    char name[16];
    uint32_t major;
    uint32_t minor;
} kernel_console_device_t;

uint32_t kernel_console_device_count(void);
int kernel_console_device_at(uint32_t ordinal,
                             kernel_console_device_t *device);
int kernel_console_active_names(char *buffer, uint32_t capacity);
int kernel_console_configured_names(char *buffer, uint32_t capacity);

/* Serial naming and device numbers are genuine architecture mechanisms. */
int kernel_arch_serial_console_device(kernel_console_device_t *device);

#endif
