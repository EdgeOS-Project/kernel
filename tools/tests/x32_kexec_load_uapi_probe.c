/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux x32 probe for compat kexec segment conversion. */

#include <stdint.h>

#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define X32_kexec_load 528
#define EADDRNOTAVAIL 99
#define KEXEC_ARCH_X86_64 (62u << 16)

struct kexec_segment32 {
    uint32_t buffer;
    uint32_t buffer_size;
    uint32_t memory;
    uint32_t memory_size;
};

static uint8_t payload[4096] __attribute__((aligned(4096)));

static long raw_syscall6(long number, long first, long second, long third,
                         long fourth, long fifth, long sixth) {
    register long r10 __asm__("r10") = fourth;
    register long r8 __asm__("r8") = fifth;
    register long r9 __asm__("r9") = sixth;
    long result;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        X32_SYSCALL_BIT | SYS_write, 1, (long)text, text_length(text),
        0, 0, 0);
}

static int expect(const char *name, long result, long expected) {
    if (result == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

__attribute__((noreturn, force_align_arg_pointer)) void _start(void) {
    struct kexec_segment32 segment = {
        .buffer = (uint32_t)(uintptr_t)payload,
        .buffer_size = sizeof(payload),
        .memory = 0x02000000u,
        .memory_size = sizeof(payload),
    };
    long syscall_number = (long)(X32_SYSCALL_BIT | X32_kexec_load);
    int failures = 0;

    failures += expect("nondefault compat architecture",
                       raw_syscall6(syscall_number, 0, 0, 0,
                                    3u << 16, 0, 0), 0);
    failures += expect("segment copy remainder",
                       raw_syscall6(syscall_number, 0, 1, 0,
                                    KEXEC_ARCH_X86_64, 0, 0),
                       sizeof(struct kexec_segment32));
    failures += expect("stage compat segment",
                       raw_syscall6(syscall_number, segment.memory, 1,
                                    (long)&segment, KEXEC_ARCH_X86_64,
                                    0, 0), 0);
    failures += expect("unload compat image",
                       raw_syscall6(syscall_number, 0, 0, 0,
                                    KEXEC_ARCH_X86_64, 0, 0), 0);
    failures += expect("crash reservation",
                       raw_syscall6(syscall_number, segment.memory, 1,
                                    (long)&segment,
                                    KEXEC_ARCH_X86_64 | 1u, 0, 0),
                       -EADDRNOTAVAIL);
    print_text(failures ? "X32_KEXEC_LOAD_UAPI_PROBE_FAIL\n" :
                          "X32_KEXEC_LOAD_UAPI_PROBE_PASS\n");
    (void)raw_syscall6(X32_SYSCALL_BIT | SYS_exit, failures ? 1 : 0,
                       0, 0, 0, 0, 0);
    __builtin_unreachable();
}
