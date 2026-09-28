/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_X86_64_FPU_H
#define EDGEOS_ARCH_X86_64_FPU_H

#include <stdint.h>

#define EDGE_X86_XSAVE_MAX_SIZE 4096u
#define EDGE_X86_FXSAVE_SIZE 512u

int x86_fpu_initialize_cpu(void);
int x86_fpu_xsave_enabled(void);
uint32_t x86_fpu_extended_state_size(void);
uint64_t x86_fpu_enabled_features(void);
void x86_fpu_save_state(void *extended_state, void *legacy_state);
void x86_fpu_restore_state(void *extended_state, const void *legacy_state);

#endif
