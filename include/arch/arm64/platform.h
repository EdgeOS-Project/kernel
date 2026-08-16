/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 firmware-described platform resources shared by all boards. */
#ifndef EDGEOS_ARCH_ARM64_PLATFORM_H
#define EDGEOS_ARCH_ARM64_PLATFORM_H

#include <stdint.h>

#include "arch/arm64/bootinfo.h"

typedef enum edgeos_arm64_platform_kind {
    EDGEOS_ARM64_PLATFORM_GENERIC = 0,
    EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_4,
    EDGEOS_ARM64_PLATFORM_RASPBERRY_PI_5,
} edgeos_arm64_platform_kind_t;

int edgeos_arm64_platform_configure(
    const edgeos_arm64_bootinfo_t *bootinfo);
edgeos_arm64_platform_kind_t edgeos_arm64_platform_kind(void);
uint64_t edgeos_arm64_platform_serial_base(void);
void edgeos_arm64_platform_serial_write(char ch);
int edgeos_arm64_platform_serial_has_input(void);
int edgeos_arm64_platform_serial_read(void);

#endif
