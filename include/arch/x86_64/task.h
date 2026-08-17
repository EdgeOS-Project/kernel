/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_X86_64_TASK_H
#define EDGEOS_ARCH_X86_64_TASK_H

#include <stdint.h>
#include <stddef.h>

typedef struct edgeos_x86_64_cpu_context {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rsp;
    /*
     * The low-level switch resumes through a suspended scheduler frame.  Keep
     * a generation-tagged wrapper word and the wrapper's caller return slot
     * alongside the register image.  A fixed inner return address is not
     * sufficient: the same kernel-stack positions are reused on every yield,
     * so an obsolete context can otherwise pass validation after a later
     * scheduler frame happens to occupy those positions.
     */
    uint64_t resume_cookie_addr;
    uint64_t resume_cookie_value;
    uint64_t outer_resume_cookie_addr;
    uint64_t outer_resume_cookie_value;
} edgeos_x86_64_cpu_context_t;

_Static_assert(offsetof(edgeos_x86_64_cpu_context_t, r15) == 0x00, "switch_to r15 offset");
_Static_assert(offsetof(edgeos_x86_64_cpu_context_t, rbp) == 0x28, "switch_to rbp offset");
_Static_assert(offsetof(edgeos_x86_64_cpu_context_t, rip) == 0x30, "switch_to rip offset");
_Static_assert(offsetof(edgeos_x86_64_cpu_context_t, rsp) == 0x38, "switch_to rsp offset");
_Static_assert(offsetof(edgeos_x86_64_cpu_context_t, resume_cookie_addr) == 0x40,
               "scheduler cookie address offset");
_Static_assert(offsetof(edgeos_x86_64_cpu_context_t, outer_resume_cookie_value) == 0x58,
               "scheduler outer cookie value offset");

#define EDGEOS_X86_64_RESUME_FLAGS_MASK 0xffffULL
#define EDGEOS_X86_64_RESUME_TAG_MASK 0x0000ffffffffffffULL

/*
 * The wrapper consumes only low architectural RFLAGS bits before discarding
 * this word.  Fill the unused upper bits with task/generation identity so a
 * subsequent pushfq invalidates every older saved continuation at the same
 * stack address.
 */
static inline uint64_t edgeos_x86_64_resume_cookie(uint64_t generation,
                                                   uintptr_t task_address,
                                                   uint64_t rflags) {
    uint64_t tag = generation ^ ((uint64_t)task_address >> 4);

    return (rflags & EDGEOS_X86_64_RESUME_FLAGS_MASK) |
           ((tag & EDGEOS_X86_64_RESUME_TAG_MASK) << 16);
}

typedef struct edgeos_x86_64_trap_frame {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rbp, rdi, rsi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t int_no;
    uint64_t err_code;
    uint64_t rip, cs, rflags, rsp, ss;
} edgeos_x86_64_trap_frame_t;

#endif
