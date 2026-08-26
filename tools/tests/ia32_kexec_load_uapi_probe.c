/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 probe for compat kexec segment conversion. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_kexec_load 283
#define EADDRNOTAVAIL 99
#define KEXEC_ARCH_I386 (3u << 16)

struct kexec_segment32 {
    uint32_t buffer;
    uint32_t buffer_size;
    uint32_t memory;
    uint32_t memory_size;
};

static uint8_t payload[4096] __attribute__((aligned(4096)));

__attribute__((naked)) static long raw_call6(
        long number, long first, long second, long third,
        long fourth, long fifth, long sixth) {
    __asm__ volatile(
        "pushl %ebp\n"
        "pushl %edi\n"
        "pushl %esi\n"
        "pushl %ebx\n"
        "movl 20(%esp), %eax\n"
        "movl 24(%esp), %ebx\n"
        "movl 28(%esp), %ecx\n"
        "movl 32(%esp), %edx\n"
        "movl 36(%esp), %esi\n"
        "movl 40(%esp), %edi\n"
        "movl 44(%esp), %ebp\n"
        "int $0x80\n"
        "popl %ebx\n"
        "popl %esi\n"
        "popl %edi\n"
        "popl %ebp\n"
        "ret\n");
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_call6(SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
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
    int failures = 0;

    failures += expect("nondefault compat architecture",
                       raw_call6(SYS_kexec_load, 0, 0, 0,
                                 62u << 16, 0, 0), 0);
    failures += expect("segment copy remainder",
                       raw_call6(SYS_kexec_load, 0, 1, 0,
                                 KEXEC_ARCH_I386, 0, 0),
                       sizeof(struct kexec_segment32));
    failures += expect("stage compat segment",
                       raw_call6(SYS_kexec_load, segment.memory, 1,
                                 (long)&segment, KEXEC_ARCH_I386, 0, 0), 0);
    failures += expect("unload compat image",
                       raw_call6(SYS_kexec_load, 0, 0, 0,
                                 KEXEC_ARCH_I386, 0, 0), 0);
    failures += expect("crash reservation",
                       raw_call6(SYS_kexec_load, segment.memory, 1,
                                 (long)&segment, KEXEC_ARCH_I386 | 1u,
                                 0, 0), -EADDRNOTAVAIL);
    print_text(failures ? "IA32_KEXEC_LOAD_UAPI_PROBE_FAIL\n" :
                          "IA32_KEXEC_LOAD_UAPI_PROBE_PASS\n");
    (void)raw_call6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
