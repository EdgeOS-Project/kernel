/* SPDX-License-Identifier: MPL-2.0 */
/* Raw x86_64 Linux modify_ldt syscall ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "modify_ldt_abi_probe requires x86_64"
#endif

#define SYS_write 1
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_modify_ldt 154

#define EFAULT 14
#define EINVAL 22

struct user_desc {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t flags;
};

#define USER_DESC_SEG_32BIT (1u << 0)
#define USER_DESC_CONTENTS(value) ((uint32_t)(value) << 1)
#define USER_DESC_READ_EXEC_ONLY (1u << 3)
#define USER_DESC_LIMIT_IN_PAGES (1u << 4)
#define USER_DESC_SEG_NOT_PRESENT (1u << 5)
#define USER_DESC_USEABLE (1u << 6)

static uint32_t ldt_marker = UINT32_C(0x4c445431);

static long raw_syscall3(long number, long a0, long a1, long a2) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long a0, long a1, long a2, long a3) {
    register long r10 __asm__("r10") = a3;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static void print_number(long value) {
    char buffer[24];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall3(
        SYS_write, 1, (long)&buffer[position],
        (long)(sizeof(buffer) - (unsigned)position));
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static uint64_t expected_descriptor(const struct user_desc *description) {
    uint32_t contents = (description->flags >> 1) & 3u;
    uint32_t type = ((description->flags & USER_DESC_READ_EXEC_ONLY) ?
                     0u : 2u) | (contents << 2) | 1u;
    uint64_t descriptor = 0;

    descriptor |= description->limit & 0xffffu;
    descriptor |= ((uint64_t)description->base_addr & 0xffffu) << 16;
    descriptor |= ((uint64_t)(description->base_addr >> 16) & 0xffu) << 32;
    descriptor |= (uint64_t)type << 40;
    descriptor |= UINT64_C(1) << 44;
    descriptor |= UINT64_C(3) << 45;
    if (!(description->flags & USER_DESC_SEG_NOT_PRESENT))
        descriptor |= UINT64_C(1) << 47;
    descriptor |= ((uint64_t)(description->limit >> 16) & 0x0fu) << 48;
    if (description->flags & USER_DESC_USEABLE)
        descriptor |= UINT64_C(1) << 52;
    if (description->flags & USER_DESC_SEG_32BIT)
        descriptor |= UINT64_C(1) << 54;
    if (description->flags & USER_DESC_LIMIT_IN_PAGES)
        descriptor |= UINT64_C(1) << 55;
    descriptor |= ((uint64_t)(description->base_addr >> 24) & 0xffu) << 56;
    return descriptor;
}

static uint32_t read_marker_through_ldt(void) {
    uint16_t selector = (uint16_t)((1u << 3) | 4u | 3u);
    uint32_t value;

    __asm__ volatile(
        "movw %1, %%fs\n"
        "movl %%fs:0, %0\n"
        "xor %%eax, %%eax\n"
        "movw %%ax, %%fs\n"
        : "=r"(value)
        : "rm"(selector)
        : "rax", "memory");
    return value;
}

static int child_inheritance_test(uint64_t expected) {
    uint64_t entries[3] = {0, 0, 0};
    int status = -1;
    long child = raw_syscall3(SYS_fork, 0, 0, 0);

    if (child < 0) return 1;
    if (child == 0) {
        int failed = 0;
        long copied = raw_syscall3(
            SYS_modify_ldt, 0, (long)entries, sizeof(entries));
        if (copied != (long)sizeof(entries) || entries[1] != expected ||
            read_marker_through_ldt() != ldt_marker)
            failed = 1;
        (void)raw_syscall3(SYS_exit, failed, 0, 0);
        for (;;) { }
    }
    if (raw_syscall4(SYS_wait4, child, (long)&status, 0, 0) != child)
        return 1;
    return status != 0;
}

static int run_tests(void) {
    struct user_desc description;
    struct user_desc invalid;
    uint64_t entries[3] = {UINT64_MAX, UINT64_MAX, UINT64_MAX};
    uint8_t defaults[128];
    uint64_t packed;
    int failures = 0;

    failures += expect(
        "empty LDT read",
        raw_syscall3(SYS_modify_ldt, 0, 0, 64), 0);
    failures += expect(
        "write size before pointer",
        raw_syscall3(SYS_modify_ldt, 0x11, 0, 15),
        (long)(uint32_t)-EINVAL);
    failures += expect(
        "write pointer",
        raw_syscall3(SYS_modify_ldt, 0x11, 0, 16),
        (long)(uint32_t)-EFAULT);

    invalid.entry_number = 8192;
    invalid.base_addr = 0;
    invalid.limit = 0;
    invalid.flags = USER_DESC_READ_EXEC_ONLY |
                    USER_DESC_SEG_NOT_PRESENT;
    failures += expect(
        "entry range",
        raw_syscall3(SYS_modify_ldt, 0x11, (long)&invalid,
                     sizeof(invalid)),
        (long)(uint32_t)-EINVAL);
    invalid.entry_number = 0;
    invalid.flags = USER_DESC_SEG_32BIT | USER_DESC_CONTENTS(3);
    failures += expect(
        "present contents three",
        raw_syscall3(SYS_modify_ldt, 0x11, (long)&invalid,
                     sizeof(invalid)),
        (long)(uint32_t)-EINVAL);

    description.entry_number = 1;
    description.base_addr = (uint32_t)(uintptr_t)&ldt_marker;
    description.limit = 0xfffffu;
    description.flags = USER_DESC_SEG_32BIT | USER_DESC_CONTENTS(0) |
                        USER_DESC_LIMIT_IN_PAGES | USER_DESC_USEABLE;
    packed = expected_descriptor(&description);
    failures += expect(
        "write descriptor",
        raw_syscall3(SYS_modify_ldt, 0x11, (long)&description,
                     sizeof(description)),
        0);
    failures += expect(
        "read descriptor",
        raw_syscall3(SYS_modify_ldt, 0, (long)entries,
                     sizeof(entries)),
        sizeof(entries));
    failures += expect("leading entry zero", entries[0], 0);
    failures += expect("descriptor encoding", entries[1], packed);
    failures += expect("trailing zero fill", entries[2], 0);
    failures += expect(
        "read pointer after allocation",
        raw_syscall3(SYS_modify_ldt, 0, 0, sizeof(entries)),
        (long)(uint32_t)-EFAULT);
    failures += expect(
        "selector data access", read_marker_through_ldt(), ldt_marker);
    failures += expect(
        "fork inherits LDT", child_inheritance_test(packed), 0);

    for (unsigned index = 0; index < sizeof(defaults); ++index)
        defaults[index] = 0xffu;
    failures += expect(
        "default LDT read",
        raw_syscall3(SYS_modify_ldt, 2, (long)defaults,
                     sizeof(defaults) + 1u),
        sizeof(defaults));
    for (unsigned index = 0; index < sizeof(defaults); ++index) {
        if (!defaults[index]) continue;
        failures += expect("default LDT zero", defaults[index], 0);
        break;
    }
    failures += expect(
        "unknown operation return width",
        raw_syscall3(SYS_modify_ldt, 3, 0, 0),
        (long)UINT32_C(0xffffffda));

    description.base_addr = 0;
    description.limit = 0;
    description.flags = USER_DESC_READ_EXEC_ONLY |
                        USER_DESC_SEG_NOT_PRESENT;
    failures += expect(
        "clear descriptor",
        raw_syscall3(SYS_modify_ldt, 0x11, (long)&description,
                     sizeof(description)),
        0);
    entries[0] = entries[1] = entries[2] = UINT64_MAX;
    failures += expect(
        "read cleared descriptor",
        raw_syscall3(SYS_modify_ldt, 0, (long)entries,
                     sizeof(entries)),
        sizeof(entries));
    failures += expect("cleared descriptor zero", entries[1], 0);
    return failures;
}

__attribute__((noreturn, force_align_arg_pointer)) void _start(void) {
    int failures = run_tests();
    print_text(failures ? "MODIFY_LDT_ABI_PROBE_FAIL\n" :
                          "MODIFY_LDT_ABI_PROBE_PASS\n");
    (void)raw_syscall3(SYS_exit, failures ? 1 : 0, 0, 0);
    for (;;) { }
}
