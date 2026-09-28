/* SPDX-License-Identifier: MPL-2.0 */
/* Request-key construction lifecycle ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_request_key 249
#define SYS_keyctl 250
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_request_key 218
#define SYS_keyctl 219
#else
#error "keyring_request_abi_probe requires a Linux 64-bit architecture"
#endif

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEY_SPEC_REQKEY_AUTH_KEY (-7)
#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_READ 11
#define KEYCTL_INSTANTIATE 12
#define KEYCTL_NEGATE 13
#define KEYCTL_ASSUME_AUTHORITY 16
#define KEYCTL_REJECT 19

#define EACCES 13
#define ENOKEY 126

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
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
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static int text_equal(const char *left, const char *right) {
    unsigned long index = 0;
    if (!left || !right) return 0;
    while (left[index] && left[index] == right[index]) ++index;
    return left[index] == right[index];
}

static long parse_number(const char *text) {
    long value = 0;
    if (!text || !*text) return -1;
    while (*text >= '0' && *text <= '9') {
        value = value * 10 + (*text - '0');
        ++text;
    }
    return *text ? -1 : value;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static __attribute__((noreturn)) void exit_now(long status) {
    (void)raw_syscall6(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) { }
}

static int run_helper(char **arguments) {
    static const char payload[] = "constructed-by-request-key";
    char callout[64] = {0};
    long target = parse_number(arguments[2]);
    long authorization;
    long length;

    if (target <= 0) return 10;
    authorization = raw_syscall6(
        SYS_keyctl, KEYCTL_ASSUME_AUTHORITY, target, 0, 0, 0, 0);
    if (authorization <= 0) return 11;
    length = raw_syscall6(
        SYS_keyctl, KEYCTL_READ, KEY_SPEC_REQKEY_AUTH_KEY,
        (long)callout, sizeof(callout), 0, 0);
    if (length <= 0) return 12;
    if (text_equal(callout, "instantiate"))
        return raw_syscall6(
            SYS_keyctl, KEYCTL_INSTANTIATE, target, (long)payload,
            sizeof(payload) - 1u, 0, 0) == 0 ? 0 : 13;
    if (text_equal(callout, "negate"))
        return raw_syscall6(
            SYS_keyctl, KEYCTL_NEGATE, target, 30, 0, 0, 0) == 0 ?
            0 : 14;
    if (text_equal(callout, "reject"))
        return raw_syscall6(
            SYS_keyctl, KEYCTL_REJECT, target, 30, EACCES, 0, 0) == 0 ?
            0 : 15;
    return 16;
}

static int run_parent(void) {
    static const char expected[] = "constructed-by-request-key";
    char payload[64] = {0};
    long session;
    long key;
    long result;

    session = raw_syscall6(
        SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING,
        1, 0, 0, 0);
    if (session <= 0) return 20;
    key = raw_syscall6(
        SYS_request_key, (long)"user", (long)"request-positive",
        (long)"instantiate", KEY_SPEC_SESSION_KEYRING, 0, 0);
    if (key <= 0) return 21;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_READ, key, (long)payload, sizeof(payload), 0, 0);
    if (result != (long)(sizeof(expected) - 1u) ||
        !text_equal(payload, expected))
        return 22;

    result = raw_syscall6(
        SYS_request_key, (long)"user", (long)"request-negative",
        (long)"negate", KEY_SPEC_SESSION_KEYRING, 0, 0);
    if (result != -ENOKEY) return 23;
    result = raw_syscall6(
        SYS_request_key, (long)"user", (long)"request-negative",
        (long)"negate", KEY_SPEC_SESSION_KEYRING, 0, 0);
    if (result != -ENOKEY) return 24;

    result = raw_syscall6(
        SYS_request_key, (long)"user", (long)"request-rejected",
        (long)"reject", KEY_SPEC_SESSION_KEYRING, 0, 0);
    if (result != -EACCES) return 25;
    result = raw_syscall6(
        SYS_request_key, (long)"user", (long)"request-rejected",
        (long)"reject", KEY_SPEC_SESSION_KEYRING, 0, 0);
    if (result != -EACCES) return 26;
    return 0;
}

static __attribute__((noreturn, noinline, used))
void probe_entry(uintptr_t *initial_stack) {
    long count = initial_stack ? (long)initial_stack[0] : 0;
    char **arguments = initial_stack ?
        (char **)&initial_stack[1] : (char **)0;
    int result;

    if (count >= 3 && arguments && text_equal(arguments[1], "create"))
        exit_now(run_helper(arguments));
    result = run_parent();
    print_text(result ? "KEYRING_REQUEST_ABI_PROBE_FAIL\n" :
                        "KEYRING_REQUEST_ABI_PROBE_PASS\n");
    exit_now(result);
}

#if defined(__x86_64__)
__asm__(
    ".global _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "movq %rsp, %rdi\n"
    "andq $-16, %rsp\n"
    "call probe_entry\n");
#else
__asm__(
    ".global _start\n"
    ".type _start, %function\n"
    "_start:\n"
    "mov x0, sp\n"
    "bl probe_entry\n");
#endif
