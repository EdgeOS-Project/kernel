/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_USER_TYPES_H
#define EDGEOS_ARCH_USER_TYPES_H

#if defined(__aarch64__) || defined(_M_ARM64)
#include "arch/arm64/interrupt.h"
typedef edgeos_arm64_exception_frame_t arch_user_frame_t;
#elif defined(__x86_64__)
#include "arch/x86_64/interrupt.h"
typedef edgeos_x86_64_interrupt_frame_t arch_user_frame_t;
#else
#error "Unsupported EdgeOS architecture"
#endif

#endif
