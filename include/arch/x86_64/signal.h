/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux x86_64 signal-frame ABI.
 * Copyright (c) EdgeOS Contributors.
 *
 * These structures are userspace ABI, not kernel-private task state.  Keep
 * their offsets aligned with Linux x86_64 UAPI and musl's mcontext_t view.
 */
#ifndef EDGEOS_ARCH_X86_64_SIGNAL_H
#define EDGEOS_ARCH_X86_64_SIGNAL_H

#include <stddef.h>
#include <stdint.h>

#define EDGE_X86_64_UC_SIGCONTEXT_SS 0x2ULL
#define EDGE_X86_64_UC_STRICT_RESTORE_SS 0x4ULL
#define EDGE_X86_64_FPSTATE_SIZE 512ULL
#define EDGE_X86_64_FPSTATE_FRAME_SIZE 1024ULL
#define EDGE_X86_64_FPSTATE_ALIGN 64ULL

_Static_assert(EDGE_X86_64_FPSTATE_FRAME_SIZE >= EDGE_X86_64_FPSTATE_SIZE,
               "x86_64 signal fpstate frame reserve");

typedef struct edge_x86_64_linux_stack {
    uint64_t sp;
    int32_t flags;
    uint32_t pad;
    uint64_t size;
} edge_x86_64_linux_stack_t;

typedef struct edge_x86_64_linux_sigcontext {
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rsp;
    uint64_t rip;
    uint64_t rflags;
    uint16_t cs;
    uint16_t gs;
    uint16_t fs;
    uint16_t ss;
    uint64_t err;
    uint64_t trapno;
    uint64_t oldmask;
    uint64_t cr2;
    uint64_t fpstate;
    uint64_t reserved[8];
} edge_x86_64_linux_sigcontext_t;

typedef struct edge_x86_64_linux_ucontext {
    uint64_t flags;
    uint64_t link;
    edge_x86_64_linux_stack_t stack;
    edge_x86_64_linux_sigcontext_t mcontext;
    uint64_t sigmask;
} edge_x86_64_linux_ucontext_t;

typedef struct edge_x86_64_linux_rt_sigframe {
    uint64_t pretcode;
    edge_x86_64_linux_ucontext_t ucontext;
    uint8_t siginfo[128];
} edge_x86_64_linux_rt_sigframe_t;

_Static_assert(sizeof(edge_x86_64_linux_stack_t) == 24,
               "Linux x86_64 stack_t ABI size");
_Static_assert(sizeof(edge_x86_64_linux_sigcontext_t) == 256,
               "Linux x86_64 sigcontext ABI size");
_Static_assert(offsetof(edge_x86_64_linux_ucontext_t, mcontext) == 40,
               "Linux x86_64 mcontext ABI offset");
_Static_assert(offsetof(edge_x86_64_linux_ucontext_t, sigmask) == 296,
               "Linux x86_64 signal-mask ABI offset");
_Static_assert(sizeof(edge_x86_64_linux_ucontext_t) == 304,
               "Linux x86_64 kernel ucontext ABI size");
_Static_assert(offsetof(edge_x86_64_linux_rt_sigframe_t, ucontext) == 8,
               "Linux x86_64 ucontext frame offset");
_Static_assert(offsetof(edge_x86_64_linux_rt_sigframe_t, siginfo) == 312,
               "Linux x86_64 siginfo frame offset");
_Static_assert(sizeof(edge_x86_64_linux_rt_sigframe_t) == 440,
               "Linux x86_64 rt_sigframe ABI size");

#endif
