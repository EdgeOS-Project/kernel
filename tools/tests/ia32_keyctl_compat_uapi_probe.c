/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 keyctl compatibility-layout ABI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_mprotect 125
#define SYS_mmap2 192
#define SYS_keyctl 288

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

#define KEYCTL_INSTANTIATE_IOV 20
#define KEYCTL_DH_COMPUTE 23

#define EPERM 1
#define EOPNOTSUPP 95
#define ENOKEY 126

struct compat_iovec {
    uint32_t base;
    uint32_t length;
};

struct keyctl_dh_params {
    int32_t private_key;
    int32_t prime;
    int32_t base;
};

struct compat_keyctl_kdf_params {
    uint32_t hash_name;
    uint32_t other_info;
    uint32_t other_info_length;
    uint32_t spare[8];
};

_Static_assert(sizeof(struct compat_iovec) == 8u,
               "Linux i386 iovec must be eight bytes");
_Static_assert(sizeof(struct compat_keyctl_kdf_params) == 44u,
               "Linux i386 keyctl KDF parameters must be 44 bytes");

static const char sha256_name[] = "sha256";
static struct keyctl_dh_params invalid_dh_params;

__attribute__((naked)) static long raw_call6(
        long number, long a0, long a1, long a2,
        long a3, long a4, long a5) {
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

#define call6(number, a0, a1, a2, a3, a4, a5) \
    raw_call6((number), \
              (long)(uintptr_t)(a0), (long)(uintptr_t)(a1), \
              (long)(uintptr_t)(a2), (long)(uintptr_t)(a3), \
              (long)(uintptr_t)(a4), (long)(uintptr_t)(a5))

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call6(SYS_write, 1, text, text_length(text), 0, 0, 0);
}

static void print_hex(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    char output[10];

    output[0] = '0';
    output[1] = 'x';
    for (uint32_t index = 0; index < 8u; ++index)
        output[index + 2u] =
            digits[(value >> ((7u - index) * 4u)) & 15u];
    call6(SYS_write, 1, output, sizeof(output), 0, 0, 0);
}

static void fail(const char *reason) {
    print_text("IA32_KEYCTL_COMPAT_UAPI_PROBE_FAIL ");
    print_text(reason);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
}

static void require_result(long actual, long expected, const char *name) {
    if (actual == expected) return;
    print_text("actual=");
    print_hex((uint32_t)actual);
    print_text(" expected=");
    print_hex((uint32_t)expected);
    print_text("\n");
    fail(name);
}

static int syscall_failed(long result) {
    return (uint32_t)result >= UINT32_C(0xfffff001);
}

__attribute__((noreturn)) void _start(void) {
    const uint32_t page_size = 4096u;
    uint8_t *mapping;
    struct compat_iovec *vector;
    struct compat_keyctl_kdf_params *kdf;
    long result;

    result = call6(SYS_mmap2, 0, page_size * 2u,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_failed(result)) fail("mmap2");
    mapping = (uint8_t *)(uintptr_t)(uint32_t)result;
    require_result(call6(SYS_mprotect, mapping + page_size, page_size,
                         PROT_NONE, 0, 0, 0), 0, "mprotect-iovec");

    vector = (struct compat_iovec *)(mapping + page_size - sizeof(*vector));
    vector->base = 0;
    vector->length = 0;
    result = call6(SYS_keyctl, KEYCTL_INSTANTIATE_IOV, 1,
                   vector, 1, 0, 0);
    require_result(result, -EPERM, "instantiate-iov-layout");

    result = call6(SYS_mmap2, 0, page_size * 2u,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_failed(result)) fail("mmap2-kdf");
    mapping = (uint8_t *)(uintptr_t)(uint32_t)result;
    require_result(call6(SYS_mprotect, mapping + page_size, page_size,
                         PROT_NONE, 0, 0, 0), 0, "mprotect-kdf");

    kdf = (struct compat_keyctl_kdf_params *)(
        mapping + page_size - sizeof(*kdf));
    kdf->hash_name = (uint32_t)(uintptr_t)sha256_name;
    kdf->other_info = 0;
    kdf->other_info_length = 0;
    for (uint32_t index = 0; index < 8u; ++index) kdf->spare[index] = 0;
    result = call6(SYS_keyctl, KEYCTL_DH_COMPUTE,
                   &invalid_dh_params, 0, 0, kdf, 0);
    if (result != -ENOKEY && result != -EOPNOTSUPP)
        require_result(result, -ENOKEY, "dh-kdf-layout");

    print_text("IA32_KEYCTL_COMPAT_UAPI_PROBE_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
