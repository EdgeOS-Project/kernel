/* SPDX-License-Identifier: MPL-2.0 */
/* Interrupt frame layouts consumed by imported BSD interrupt handlers. */

#ifndef _MACHINE_FRAME_H_
#define _MACHINE_FRAME_H_

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#if defined(__x86_64__)
struct trapframe {
    register_t tf_rdi;
    register_t tf_rsi;
    register_t tf_rdx;
    register_t tf_rcx;
    register_t tf_r8;
    register_t tf_r9;
    register_t tf_rax;
    register_t tf_rbx;
    register_t tf_rbp;
    register_t tf_r10;
    register_t tf_r11;
    register_t tf_r12;
    register_t tf_r13;
    register_t tf_r14;
    register_t tf_r15;
    uint32_t tf_trapno;
    uint16_t tf_fs;
    uint16_t tf_gs;
    register_t tf_addr;
    uint32_t tf_flags;
    uint16_t tf_es;
    uint16_t tf_ds;
    register_t tf_err;
    register_t tf_rip;
    uint16_t tf_cs;
    uint16_t tf_reserved0;
    uint32_t tf_reserved1;
    register_t tf_rflags;
    register_t tf_rsp;
    uint16_t tf_ss;
    uint16_t tf_reserved2;
    uint32_t tf_reserved3;
};
_Static_assert(offsetof(struct trapframe, tf_rdi) == 0,
    "trapframe rdi offset");
_Static_assert(offsetof(struct trapframe, tf_r15) == 112,
    "trapframe r15 offset");
_Static_assert(offsetof(struct trapframe, tf_rip) == 152,
    "trapframe rip offset");
_Static_assert(offsetof(struct trapframe, tf_ss) == 184,
    "trapframe ss offset");
#else
struct trapframe {
    uint64_t tf_sp;
    uint64_t tf_lr;
    uint64_t tf_elr;
    uint64_t tf_spsr;
    uint64_t tf_esr;
    uint64_t tf_far;
    uint64_t tf_x[30];
};
#endif

#endif
