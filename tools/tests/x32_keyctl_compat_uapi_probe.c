/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 keyctl compatibility-layout ABI probe. */

#include <stdint.h>

#define X32_SYSCALL_BIT UINT64_C(0x40000000)

#define SYS_write 1
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_exit 60
#define SYS_keyctl 250

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_32BIT 0x40

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

struct x32_keyctl_kdf_params {
    uint64_t hash_name;
    uint64_t other_info;
    uint32_t other_info_length;
    uint32_t spare[8];
    uint32_t padding;
};

_Static_assert(sizeof(struct compat_iovec) == 8u,
               "Linux x32 iovec must be eight bytes");
_Static_assert(sizeof(struct x32_keyctl_kdf_params) == 56u,
               "Linux x32 keyctl KDF syscall parameters must be 56 bytes");

static const char sha256_name[] = "sha256";
static struct keyctl_dh_params invalid_dh_params;

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static long x32_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, a3, a4, a5);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    x32_syscall6(SYS_write, 1, (long)text, (long)text_length(text),
                 0, 0, 0);
}

static void print_hex(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    char output[10];

    output[0] = '0';
    output[1] = 'x';
    for (uint32_t index = 0; index < 8u; ++index)
        output[index + 2u] =
            digits[(value >> ((7u - index) * 4u)) & 15u];
    x32_syscall6(SYS_write, 1, (long)output, sizeof(output), 0, 0, 0);
}

static void fail(const char *reason) {
    print_text("X32_KEYCTL_COMPAT_UAPI_PROBE_FAIL ");
    print_text(reason);
    print_text("\n");
    x32_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
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

__attribute__((noreturn, force_align_arg_pointer)) void _start(void) {
    const unsigned long page_size = 4096u;
    unsigned char *mapping;
    struct compat_iovec *vector;
    struct x32_keyctl_kdf_params *kdf;
    long result;

    result = x32_syscall6(SYS_mmap, 0, page_size * 2u,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
                          -1, 0);
    if (syscall_failed(result)) fail("mmap-iovec");
    mapping = (unsigned char *)(uintptr_t)(uint32_t)result;
    require_result(x32_syscall6(SYS_mprotect,
                                (long)(mapping + page_size), page_size,
                                PROT_NONE, 0, 0, 0),
                   0, "mprotect-iovec");

    vector = (struct compat_iovec *)(mapping + page_size - sizeof(*vector));
    vector->base = 0;
    vector->length = 0;
    result = x32_syscall6(SYS_keyctl, KEYCTL_INSTANTIATE_IOV, 1,
                          (long)vector, 1, 0, 0);
    require_result(result, -EPERM, "instantiate-iov-layout");

    result = x32_syscall6(SYS_mmap, 0, page_size * 2u,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
                          -1, 0);
    if (syscall_failed(result)) fail("mmap-kdf");
    mapping = (unsigned char *)(uintptr_t)(uint32_t)result;
    require_result(x32_syscall6(SYS_mprotect,
                                (long)(mapping + page_size), page_size,
                                PROT_NONE, 0, 0, 0),
                   0, "mprotect-kdf");

    kdf = (struct x32_keyctl_kdf_params *)(
        mapping + page_size - sizeof(*kdf));
    kdf->hash_name = (uint64_t)(uintptr_t)sha256_name;
    kdf->other_info = 0;
    kdf->other_info_length = 0;
    for (uint32_t index = 0; index < 8u; ++index) kdf->spare[index] = 0;
    kdf->padding = 0;
    result = x32_syscall6(SYS_keyctl, KEYCTL_DH_COMPUTE,
                          (long)&invalid_dh_params, 0, 0,
                          (long)kdf, 0);
    if (result != -ENOKEY && result != -EOPNOTSUPP)
        require_result(result, -ENOKEY, "dh-kdf-layout");

    print_text("X32_KEYCTL_COMPAT_UAPI_PROBE_PASS\n");
    x32_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
