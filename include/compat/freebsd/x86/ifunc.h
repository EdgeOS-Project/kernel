/* SPDX-License-Identifier: MPL-2.0 */
/* Runtime resolver adapter for the pinned FreeBSD x86 VMM interface. */

#ifndef EDGEOS_COMPAT_FREEBSD_X86_IFUNC_H
#define EDGEOS_COMPAT_FREEBSD_X86_IFUNC_H

#include <sys/cdefs.h>

/*
 * The bare-metal x86_64-elf target does not emit ELF GNU IFUNC symbols.
 * Preserve the FreeBSD resolver contract with a small ABI-neutral
 * trampoline which saves all integer argument registers, invokes the
 * resolver, restores the arguments, and tail-jumps to the selected backend.
 */
#define DEFINE_IFUNC(qual, ret_type, name, args)                         \
    static ret_type (*name##_resolver(void))args __used;                 \
    qual ret_type name args;                                             \
    __asm__(                                                             \
        ".text\n"                                                       \
        ".globl " #name "\n"                                           \
        ".type " #name ",@function\n"                                  \
        #name ":\n"                                                     \
        "pushq %rdi\n"                                                  \
        "pushq %rsi\n"                                                  \
        "pushq %rdx\n"                                                  \
        "pushq %rcx\n"                                                  \
        "pushq %r8\n"                                                   \
        "pushq %r9\n"                                                   \
        "subq $8, %rsp\n"                                               \
        "call " #name "_resolver\n"                                    \
        "addq $8, %rsp\n"                                               \
        "popq %r9\n"                                                    \
        "popq %r8\n"                                                    \
        "popq %rcx\n"                                                   \
        "popq %rdx\n"                                                   \
        "popq %rsi\n"                                                   \
        "popq %rdi\n"                                                   \
        "jmp *%rax\n"                                                   \
        ".size " #name ",.-" #name "\n");                             \
    static ret_type (*name##_resolver(void))args

/* No imported VMM source currently requires user-space feature resolvers. */
#define DEFINE_UIFUNC(qual, ret_type, name, args)                        \
    static ret_type (*name##_resolver(uint32_t, uint32_t, uint32_t,      \
        uint32_t))args __used;                                           \
    static ret_type (*name##_resolver(                                   \
        uint32_t cpu_feature __unused,                                   \
        uint32_t cpu_feature2 __unused,                                  \
        uint32_t cpu_stdext_feature __unused,                            \
        uint32_t cpu_stdext_feature2 __unused))args

#endif
