/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_TASK_H
#define EDGEOS_ARCH_TASK_H

/*
 * Build-time architecture selection belongs at this single boundary.  Common
 * process code consumes cpu_context_t and edge_trap_frame_t without knowing
 * which register set implements them.
 */
#if defined(__aarch64__) || defined(_M_ARM64)
#include "arch/arm64/task.h"
typedef edgeos_arm64_cpu_context_t cpu_context_t;
typedef edgeos_arm64_trap_frame_t edge_trap_frame_t;
#elif defined(__x86_64__)
#include "arch/x86_64/task.h"
typedef edgeos_x86_64_cpu_context_t cpu_context_t;
typedef edgeos_x86_64_trap_frame_t edge_trap_frame_t;
#else
#error "Unsupported EdgeOS architecture"
#endif

#endif
