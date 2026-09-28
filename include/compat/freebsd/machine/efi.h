/* SPDX-License-Identifier: MPL-2.0 */
/* Shared EFI ABI definitions for FreeBSD drivers on EdgeOS. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_EFI_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_EFI_H

#include <sys/types.h>

#if defined(__x86_64__) && (defined(__clang__) || defined(__GNUC__))
#define EFIABI_ATTR __attribute__((ms_abi))
#else
#define EFIABI_ATTR
#endif

#ifdef _KERNEL
#define ARCH_MAY_USE_EFI
#define EFI_TIME_LOCK() do { } while (0)
#define EFI_TIME_UNLOCK() do { } while (0)
#define EFI_TIME_OWNED() do { } while (0)
#define EFI_RT_HANDLE_FAULTS_DEFAULT 1
#endif

struct efirt_callinfo {
    const char *ec_name;
    register_t ec_efi_status;
    register_t ec_fptr;
    register_t ec_argcnt;
    register_t ec_arg1;
    register_t ec_arg2;
    register_t ec_arg3;
    register_t ec_arg4;
    register_t ec_arg5;
#if defined(__x86_64__)
    register_t ec_rbx;
    register_t ec_rsp;
    register_t ec_rbp;
    register_t ec_r12;
    register_t ec_r13;
    register_t ec_r14;
    register_t ec_r15;
    register_t ec_rflags;
#endif
};

#endif
