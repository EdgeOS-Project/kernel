/* SPDX-License-Identifier: MPL-2.0 */
/* Linux key retention service ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_add_key 248
#define SYS_request_key 249
#define SYS_keyctl 250
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_add_key 217
#define SYS_request_key 218
#define SYS_keyctl 219
#else
#error "keyring_abi_probe requires a Linux 64-bit architecture"
#endif

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_UPDATE 2
#define KEYCTL_REVOKE 3
#define KEYCTL_DESCRIBE 6
#define KEYCTL_LINK 8
#define KEYCTL_UNLINK 9
#define KEYCTL_SEARCH 10
#define KEYCTL_READ 11
#define KEYCTL_CAPABILITIES 31

#define EKEYREVOKED 128
#define ENOKEY 126
#define ENODEV 19

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
                     : "memory", "cc");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(
        SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected=");
    print_number(expected);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static int bytes_equal(const void *left, const void *right,
                       unsigned long length) {
    const unsigned char *a = left;
    const unsigned char *b = right;
    for (unsigned long index = 0; index < length; ++index)
        if (a[index] != b[index]) return 0;
    return 1;
}

void _start(void) {
    static const char payload[] = "edge-key-payload";
    static const char replacement[] = "updated";
    char output[128] = {0};
    unsigned char capabilities[8] = {0};
    long session;
    long key;
    long ring;
    long found;
    int failures = 0;

    session = raw_syscall6(
        SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING,
        1, 0, 0, 0);
    if (session <= 0) failures += expect_result("session", session, 1);

    key = raw_syscall6(
        SYS_add_key, (long)"user", (long)"edge-probe",
        (long)payload, sizeof(payload) - 1u,
        KEY_SPEC_SESSION_KEYRING, 0);
    if (key <= 0) failures += expect_result("add_key", key, 1);

    if (key > 0) {
        failures += expect_result(
            "read-size",
            raw_syscall6(SYS_keyctl, KEYCTL_READ, key, 0, 0, 0, 0),
            sizeof(payload) - 1u);
        failures += expect_result(
            "read",
            raw_syscall6(SYS_keyctl, KEYCTL_READ, key, (long)output,
                         sizeof(output), 0, 0),
            sizeof(payload) - 1u);
        if (!bytes_equal(output, payload, sizeof(payload) - 1u)) {
            print_text("FAIL read-payload\n");
            ++failures;
        }
        if (raw_syscall6(SYS_keyctl, KEYCTL_DESCRIBE, key,
                         (long)output, sizeof(output), 0, 0) <= 0) {
            print_text("FAIL describe\n");
            ++failures;
        }
        found = raw_syscall6(
            SYS_request_key, (long)"user", (long)"edge-probe",
            0, 0, 0, 0);
        failures += expect_result("request_key", found, key);
        found = raw_syscall6(
            SYS_keyctl, KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING,
            (long)"user", (long)"edge-probe", 0, 0);
        failures += expect_result("search", found, key);
        failures += expect_result(
            "update",
            raw_syscall6(SYS_keyctl, KEYCTL_UPDATE, key,
                         (long)replacement, sizeof(replacement) - 1u, 0, 0),
            0);
    }

    ring = raw_syscall6(
        SYS_add_key, (long)"keyring", (long)"edge-destination",
        0, 0, KEY_SPEC_SESSION_KEYRING, 0);
    if (ring <= 0) failures += expect_result("add-ring", ring, 1);
    if (key > 0 && ring > 0) {
        failures += expect_result(
            "link",
            raw_syscall6(SYS_keyctl, KEYCTL_LINK, key, ring, 0, 0, 0), 0);
        failures += expect_result(
            "unlink",
            raw_syscall6(SYS_keyctl, KEYCTL_UNLINK, key, ring, 0, 0, 0), 0);
    }

    failures += expect_result(
        "capabilities",
        raw_syscall6(SYS_keyctl, KEYCTL_CAPABILITIES,
                     (long)capabilities, sizeof(capabilities), 0, 0, 0),
        2);
    if (!(capabilities[0] & 0x01u)) {
        print_text("FAIL capabilities-bit\n");
        ++failures;
    }
    failures += expect_result(
        "unknown-type",
        raw_syscall6(SYS_add_key, (long)"edge-unknown",
                     (long)"missing", 0, 0,
                     KEY_SPEC_SESSION_KEYRING, 0),
        -ENODEV);
    failures += expect_result(
        "missing-request",
        raw_syscall6(SYS_request_key, (long)"user",
                     (long)"edge-missing", 0, 0, 0, 0),
        -ENOKEY);
    if (key > 0) {
        failures += expect_result(
            "revoke",
            raw_syscall6(SYS_keyctl, KEYCTL_REVOKE, key, 0, 0, 0, 0), 0);
        failures += expect_result(
            "revoked-read",
            raw_syscall6(SYS_keyctl, KEYCTL_READ, key,
                         (long)output, sizeof(output), 0, 0),
            -EKEYREVOKED);
    }

    if (!failures) print_text("KEYRING_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
