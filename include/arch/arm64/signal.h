/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 Linux signal-return interface. */
#ifndef EDGEOS_ARCH_ARM64_SIGNAL_H
#define EDGEOS_ARCH_ARM64_SIGNAL_H

#include <stdint.h>
#include "arch/arm64/user_layout.h"

int edgeos_arm64_signal_trampoline_install(uint64_t address_space);
uint64_t edgeos_arm64_signal_trampoline_address(void);

#endif
