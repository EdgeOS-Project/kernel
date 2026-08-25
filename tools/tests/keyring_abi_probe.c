/* SPDX-License-Identifier: MPL-2.0 */
/* Linux key retention service ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_ioctl 16
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_add_key 248
#define SYS_request_key 249
#define SYS_keyctl 250
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_ioctl 29
#define SYS_clone 220
#define SYS_exit 93
#define SYS_wait4 260
#define SYS_add_key 217
#define SYS_request_key 218
#define SYS_keyctl 219
#define SYS_pipe2 59
#else
#error "keyring_abi_probe requires a Linux 64-bit architecture"
#endif

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_UPDATE 2
#define KEYCTL_REVOKE 3
#define KEYCTL_DESCRIBE 6
#define KEYCTL_LINK 8
#define KEYCTL_UNLINK 9
#define KEYCTL_SEARCH 10
#define KEYCTL_READ 11
#define KEYCTL_INSTANTIATE 12
#define KEYCTL_NEGATE 13
#define KEYCTL_ASSUME_AUTHORITY 16
#define KEYCTL_GET_SECURITY 17
#define KEYCTL_SESSION_TO_PARENT 18
#define KEYCTL_REJECT 19
#define KEYCTL_INSTANTIATE_IOV 20
#define KEYCTL_DH_COMPUTE 23
#define KEYCTL_PKEY_QUERY 24
#define KEYCTL_CAPABILITIES 31
#define KEYCTL_WATCH_KEY 32

#define O_NOTIFICATION_PIPE 0x80
#define IOC_WATCH_QUEUE_SET_SIZE 0x5760

#define EKEYREVOKED 128
#define ENOKEY 126
#define ENODEV 19
#define EBUSY 16
#define EPERM 1
#define EFAULT 14
#define EINVAL 22
#define EOPNOTSUPP 95
#define EXDEV 18
#define SIGCHLD 17

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

struct key_notification {
    uint32_t type_subtype;
    uint32_t info;
    uint32_t key_id;
    uint32_t auxiliary;
};

struct removal_notification {
    uint32_t type_subtype;
    uint32_t info;
    uint64_t key_id;
};

struct keyctl_dh_params {
    int32_t private_key;
    int32_t prime;
    int32_t base;
};

struct keyctl_kdf_params {
    uint64_t hash_name;
    uint64_t other_info;
    uint32_t other_info_length;
    uint32_t spare[8];
};

START_ATTRIBUTES void _start(void) {
    static const char payload[] = "edge-key-payload";
    static const char replacement[] = "updated";
    char output[128] = {0};
    unsigned char capabilities[8] = {0};
    long session;
    long key;
    long ring;
    long found;
    long dh_private;
    long dh_prime;
    long dh_base;
    int notification_pipe[2] = {-1, -1};
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

    {
        static const unsigned char private_value[] = {1u};
        static const unsigned char prime_value[] =
            "\xff\xff\xff\xff\xff\xff\xff\xff\xad\xf8\x54\x58\xa2\xbb\x4a\x9a"
            "\xaf\xdc\x56\x20\x27\x3d\x3c\xf1\xd8\xb9\xc5\x83\xce\x2d\x36\x95"
            "\xa9\xe1\x36\x41\x14\x64\x33\xfb\xcc\x93\x9d\xce\x24\x9b\x3e\xf9"
            "\x7d\x2f\xe3\x63\x63\x0c\x75\xd8\xf6\x81\xb2\x02\xae\xc4\x61\x7a"
            "\xd3\xdf\x1e\xd5\xd5\xfd\x65\x61\x24\x33\xf5\x1f\x5f\x06\x6e\xd0"
            "\x85\x63\x65\x55\x3d\xed\x1a\xf3\xb5\x57\x13\x5e\x7f\x57\xc9\x35"
            "\x98\x4f\x0c\x70\xe0\xe6\x8b\x77\xe2\xa6\x89\xda\xf3\xef\xe8\x72"
            "\x1d\xf1\x58\xa1\x36\xad\xe7\x35\x30\xac\xca\x4f\x48\x3a\x79\x7a"
            "\xbc\x0a\xb1\x82\xb3\x24\xfb\x61\xd1\x08\xa9\x4b\xb2\xc8\xe3\xfb"
            "\xb9\x6a\xda\xb7\x60\xd7\xf4\x68\x1d\x4f\x42\xa3\xde\x39\x4d\xf4"
            "\xae\x56\xed\xe7\x63\x72\xbb\x19\x0b\x07\xa7\xc8\xee\x0a\x6d\x70"
            "\x9e\x02\xfc\xe1\xcd\xf7\xe2\xec\xc0\x34\x04\xcd\x28\x34\x2f\x61"
            "\x91\x72\xfe\x9c\xe9\x85\x83\xff\x8e\x4f\x12\x32\xee\xf2\x81\x83"
            "\xc3\xfe\x3b\x1b\x4c\x6f\xad\x73\x3b\xb5\xfc\xbc\x2e\xc2\x20\x05"
            "\xc5\x8e\xf1\x83\x7d\x16\x83\xb2\xc6\xf3\x4a\x26\xc1\xb2\xef\xfa"
            "\x88\x6b\x42\x38\x61\x28\x5c\x97\xff\xff\xff\xff\xff\xff\xff\xff";
        static const unsigned char base_value[] = {2u};
        static const unsigned char kdf_sha1_expected[48] = {
            0x3a, 0x26, 0xe3, 0x07, 0xb3, 0x0a, 0xb3, 0xef,
            0x18, 0x5d, 0x98, 0xf9, 0x56, 0xf9, 0x1e, 0x0d,
            0x2c, 0x79, 0x76, 0x52, 0x8c, 0x54, 0xff, 0xb6,
            0x00, 0xa2, 0xe9, 0x2f, 0x58, 0xb7, 0x35, 0xf4,
            0xb8, 0x24, 0x2c, 0x4e, 0x33, 0x77, 0x2d, 0x85,
            0xf6, 0x60, 0x0b, 0xf4, 0xf4, 0xc9, 0x15, 0x78,
        };
        static const unsigned char kdf_sha384_expected[48] = {
            0x0c, 0xb6, 0xab, 0x22, 0xb8, 0xc9, 0xc3, 0x10,
            0x83, 0x83, 0x2d, 0xe8, 0x10, 0x68, 0x43, 0x2d,
            0x52, 0x28, 0x71, 0x08, 0x3e, 0x7b, 0x0f, 0xe5,
            0x2d, 0xd7, 0x86, 0x68, 0x88, 0x2d, 0xf2, 0x92,
            0x38, 0x44, 0x9c, 0x24, 0xe3, 0x3e, 0x2e, 0x5c,
            0xaf, 0x16, 0xaf, 0x6f, 0x5d, 0x10, 0x18, 0x85,
        };
        static const unsigned char kdf_sha512_expected[48] = {
            0x9a, 0x81, 0x10, 0x88, 0x73, 0x6b, 0xa1, 0x6d,
            0x9e, 0xc6, 0x5b, 0xd6, 0x97, 0x69, 0xf3, 0x7f,
            0x4d, 0xa2, 0xcb, 0xa8, 0x60, 0xee, 0x1d, 0x76,
            0xea, 0xee, 0x9d, 0x92, 0xfd, 0x2a, 0x07, 0x03,
            0x59, 0xf9, 0x0d, 0xb8, 0x7c, 0x1e, 0x84, 0x3f,
            0xb3, 0xed, 0x1d, 0x7c, 0xe5, 0xc3, 0x1e, 0x5c,
        };
        static const char kdf_other_info[] = "edge-kdf";
        struct keyctl_dh_params parameters;
        struct keyctl_kdf_params kdf = {0};
        unsigned char shared_value[sizeof(prime_value) - 1u];
        unsigned char derived_value[48];

        dh_private = raw_syscall6(
            SYS_add_key, (long)"user", (long)"edge-dh-private",
            (long)private_value, sizeof(private_value),
            KEY_SPEC_SESSION_KEYRING, 0);
        dh_prime = raw_syscall6(
            SYS_add_key, (long)"user", (long)"edge-dh-prime",
            (long)prime_value, sizeof(prime_value) - 1u,
            KEY_SPEC_SESSION_KEYRING, 0);
        dh_base = raw_syscall6(
            SYS_add_key, (long)"user", (long)"edge-dh-base",
            (long)base_value, sizeof(base_value),
            KEY_SPEC_SESSION_KEYRING, 0);
        if (dh_private <= 0 || dh_prime <= 0 || dh_base <= 0) {
            print_text("FAIL dh-add-keys\n");
            ++failures;
        } else {
            parameters.private_key = (int32_t)dh_private;
            parameters.prime = (int32_t)dh_prime;
            parameters.base = (int32_t)dh_base;
            failures += expect_result(
                "dh-size",
                raw_syscall6(
                    SYS_keyctl, KEYCTL_DH_COMPUTE,
                    (long)&parameters, 0, 0, 0, 0),
                sizeof(shared_value));
            for (unsigned long index = 0; index < sizeof(shared_value);
                 ++index)
                shared_value[index] = 0xffu;
            failures += expect_result(
                "dh-compute",
                raw_syscall6(
                    SYS_keyctl, KEYCTL_DH_COMPUTE,
                    (long)&parameters, (long)&shared_value,
                    sizeof(shared_value), 0, 0),
                sizeof(shared_value));
            for (unsigned long index = 0;
                 index + 1u < sizeof(shared_value); ++index) {
                if (shared_value[index] == 0u) continue;
                print_text("FAIL dh-leading-zero\n");
                ++failures;
                break;
            }
            if (shared_value[sizeof(shared_value) - 1u] != 2u) {
                print_text("FAIL dh-value\n");
                ++failures;
            }
            kdf.other_info = (uint64_t)(uintptr_t)kdf_other_info;
            kdf.other_info_length = sizeof(kdf_other_info) - 1u;
            kdf.hash_name = (uint64_t)(uintptr_t)"sha1";
            failures += expect_result(
                "dh-kdf-sha1",
                raw_syscall6(
                    SYS_keyctl, KEYCTL_DH_COMPUTE,
                    (long)&parameters, (long)derived_value,
                    sizeof(derived_value), (long)&kdf, 0),
                sizeof(derived_value));
            if (!bytes_equal(derived_value, kdf_sha1_expected,
                             sizeof(derived_value))) {
                print_text("FAIL dh-kdf-sha1-value\n");
                ++failures;
            }
            kdf.hash_name = (uint64_t)(uintptr_t)"sha384";
            failures += expect_result(
                "dh-kdf-sha384",
                raw_syscall6(
                    SYS_keyctl, KEYCTL_DH_COMPUTE,
                    (long)&parameters, (long)derived_value,
                    sizeof(derived_value), (long)&kdf, 0),
                sizeof(derived_value));
            if (!bytes_equal(derived_value, kdf_sha384_expected,
                             sizeof(derived_value))) {
                print_text("FAIL dh-kdf-sha384-value\n");
                ++failures;
            }
            kdf.hash_name = (uint64_t)(uintptr_t)"sha512";
            failures += expect_result(
                "dh-kdf-sha512",
                raw_syscall6(
                    SYS_keyctl, KEYCTL_DH_COMPUTE,
                    (long)&parameters, (long)derived_value,
                    sizeof(derived_value), (long)&kdf, 0),
                sizeof(derived_value));
            if (!bytes_equal(derived_value, kdf_sha512_expected,
                             sizeof(derived_value))) {
                print_text("FAIL dh-kdf-sha512-value\n");
                ++failures;
            }
            {
                unsigned char large_prime[384];
                unsigned char large_shared[384];
                long large_prime_key;

                for (unsigned long index = 0;
                     index < sizeof(large_prime); ++index)
                    large_prime[index] = 0xffu;
                large_prime_key = raw_syscall6(
                    SYS_add_key, (long)"user",
                    (long)"edge-dh-prime-3072", (long)large_prime,
                    sizeof(large_prime), KEY_SPEC_SESSION_KEYRING, 0);
                if (large_prime_key <= 0) {
                    print_text("FAIL dh-large-add-prime\n");
                    ++failures;
                } else {
                    parameters.prime = (int32_t)large_prime_key;
                    failures += expect_result(
                        "dh-large-size",
                        raw_syscall6(
                            SYS_keyctl, KEYCTL_DH_COMPUTE,
                            (long)&parameters, 0, 0, 0, 0),
                        sizeof(large_shared));
                    failures += expect_result(
                        "dh-large-compute",
                        raw_syscall6(
                            SYS_keyctl, KEYCTL_DH_COMPUTE,
                            (long)&parameters, (long)large_shared,
                            sizeof(large_shared), 0, 0),
                        sizeof(large_shared));
                    for (unsigned long index = 0;
                         index + 1u < sizeof(large_shared); ++index) {
                        if (large_shared[index] == 0u) continue;
                        print_text("FAIL dh-large-leading-zero\n");
                        ++failures;
                        break;
                    }
                    if (large_shared[sizeof(large_shared) - 1u] != 2u) {
                        print_text("FAIL dh-large-value\n");
                        ++failures;
                    }
                }
            }
        }
    }

#ifdef KEYRING_KDF_ONLY
    if (!failures) print_text("KEYRING_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
#endif

    failures += expect_result(
        "notification-pipe",
        raw_syscall6(
            SYS_pipe2, (long)notification_pipe,
            O_NOTIFICATION_PIPE, 0, 0, 0, 0),
        0);
    if (notification_pipe[0] >= 0 && notification_pipe[1] >= 0) {
        failures += expect_result(
            "notification-write",
            raw_syscall6(
                SYS_write, notification_pipe[1], (long)payload,
                sizeof(payload) - 1u, 0, 0, 0),
            -EXDEV);
        failures += expect_result(
            "notification-size",
            raw_syscall6(
                SYS_ioctl, notification_pipe[0],
                IOC_WATCH_QUEUE_SET_SIZE, 1, 0, 0, 0),
            0);
        failures += expect_result(
            "notification-size-repeat",
            raw_syscall6(
                SYS_ioctl, notification_pipe[0],
                IOC_WATCH_QUEUE_SET_SIZE, 1, 0, 0, 0),
            -EBUSY);
        failures += expect_result(
            "notification-size-write-end",
            raw_syscall6(
                SYS_ioctl, notification_pipe[1],
                IOC_WATCH_QUEUE_SET_SIZE, 1, 0, 0, 0),
            -EBUSY);
    }
    if (key > 0 && notification_pipe[0] >= 0) {
        failures += expect_result(
            "watch-key",
            raw_syscall6(
                SYS_keyctl, KEYCTL_WATCH_KEY, key,
                notification_pipe[0], 7, 0, 0),
            0);
        failures += expect_result(
            "watch-key-duplicate",
            raw_syscall6(
                SYS_keyctl, KEYCTL_WATCH_KEY, key,
                notification_pipe[0], 8, 0, 0),
            -EBUSY);
        failures += expect_result(
            "watch-key-id-range",
            raw_syscall6(
                SYS_keyctl, KEYCTL_WATCH_KEY, key,
                notification_pipe[0], 256, 0, 0),
            -EINVAL);
    }

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
        failures += expect_result(
            "security-size",
            raw_syscall6(SYS_keyctl, KEYCTL_GET_SECURITY, key,
                         0, sizeof(output), 0, 0),
            1);
        output[0] = (char)0xff;
        failures += expect_result(
            "security",
            raw_syscall6(SYS_keyctl, KEYCTL_GET_SECURITY, key,
                         (long)output, sizeof(output), 0, 0),
            1);
        if (output[0] != 0) {
            print_text("FAIL security-label\n");
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
        if (notification_pipe[0] >= 0) {
            struct key_notification notification;

            failures += expect_result(
                "watch-update-read",
                raw_syscall6(
                    SYS_read, notification_pipe[0],
                    (long)&notification, sizeof(notification), 0, 0, 0),
                sizeof(notification));
            if ((notification.type_subtype & 0x00ffffffu) != 1u ||
                (notification.type_subtype >> 24u) != 1u ||
                (notification.info & 0x7fu) != sizeof(notification) ||
                ((notification.info >> 8u) & 0xffu) != 7u ||
                notification.key_id != (uint32_t)key) {
                print_text("FAIL watch-update-record\n");
                ++failures;
            }
            failures += expect_result(
                "watch-key-remove",
                raw_syscall6(
                    SYS_keyctl, KEYCTL_WATCH_KEY, key,
                    notification_pipe[0], -1, 0, 0),
                0);
            {
                struct removal_notification removal;

                failures += expect_result(
                    "watch-removal-read",
                    raw_syscall6(
                        SYS_read, notification_pipe[0], (long)&removal,
                        sizeof(removal), 0, 0, 0),
                    sizeof(removal));
                if (removal.type_subtype != 0u ||
                    (removal.info & 0x7fu) != sizeof(removal) ||
                    ((removal.info >> 8u) & 0xffu) != 7u ||
                    removal.key_id != (uint64_t)(uint32_t)key) {
                    print_text("FAIL watch-removal-record\n");
                    ++failures;
                }
            }
        }
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
    if (!(capabilities[1] & 0x04u)) {
        print_text("FAIL notification-capability-bit\n");
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
        struct {
            uint64_t base;
            uint64_t length;
        } vector = {
            .base = (uint64_t)(uintptr_t)payload,
            .length = sizeof(payload) - 1u,
        };

        failures += expect_result(
            "drop-authority",
            raw_syscall6(
                SYS_keyctl, KEYCTL_ASSUME_AUTHORITY, 0, 0, 0, 0, 0),
            0);
        failures += expect_result(
            "negative-authority",
            raw_syscall6(
                SYS_keyctl, KEYCTL_ASSUME_AUTHORITY, -1, 0, 0, 0, 0),
            -EINVAL);
        failures += expect_result(
            "missing-authority",
            raw_syscall6(
                SYS_keyctl, KEYCTL_ASSUME_AUTHORITY, key, 0, 0, 0, 0),
            -ENOKEY);
        failures += expect_result(
            "instantiate-without-authority",
            raw_syscall6(
                SYS_keyctl, KEYCTL_INSTANTIATE, key,
                (long)payload, sizeof(payload) - 1u, 0, 0),
            -EPERM);
        failures += expect_result(
            "instantiate-length",
            raw_syscall6(
                SYS_keyctl, KEYCTL_INSTANTIATE, key,
                (long)payload, 1024u * 1024u, 0, 0),
            -EINVAL);
        failures += expect_result(
            "instantiate-iov-without-authority",
            raw_syscall6(
                SYS_keyctl, KEYCTL_INSTANTIATE_IOV, key,
                (long)&vector, 1, 0, 0),
            -EPERM);
        failures += expect_result(
            "instantiate-iov-fault",
            raw_syscall6(
                SYS_keyctl, KEYCTL_INSTANTIATE_IOV, key,
                1, 1, 0, 0),
            -EFAULT);
        failures += expect_result(
            "negate-without-authority",
            raw_syscall6(
                SYS_keyctl, KEYCTL_NEGATE, key, 0, 0, 0, 0),
            -EPERM);
        failures += expect_result(
            "reject-error",
            raw_syscall6(
                SYS_keyctl, KEYCTL_REJECT, key, 0, 0, 0, 0),
            -EINVAL);
        failures += expect_result(
            "reject-without-authority",
            raw_syscall6(
                SYS_keyctl, KEYCTL_REJECT, key, 0, ENOKEY, 0, 0),
            -EPERM);
        failures += expect_result(
            "dh-parameter-fault",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE, 1, 1, 1, 0, 0),
            -EFAULT);
        failures += expect_result(
            "pkey-disabled",
            raw_syscall6(
                SYS_keyctl, KEYCTL_PKEY_QUERY, 1, 1, 1, 0, 0),
            -EOPNOTSUPP);
        failures += expect_result(
            "revoke",
            raw_syscall6(SYS_keyctl, KEYCTL_REVOKE, key, 0, 0, 0, 0), 0);
        failures += expect_result(
            "revoked-read",
            raw_syscall6(SYS_keyctl, KEYCTL_READ, key,
                         (long)output, sizeof(output), 0, 0),
            -EKEYREVOKED);
    }
    if (notification_pipe[0] >= 0)
        (void)raw_syscall6(
            SYS_close, notification_pipe[0], 0, 0, 0, 0, 0);
    if (notification_pipe[1] >= 0)
        (void)raw_syscall6(
            SYS_close, notification_pipe[1], 0, 0, 0, 0, 0);

    {
        static const char child_name[] = "edge-probe-child-session";
        static long child_result[2];
        static int descriptors[2];
        long child;

        child_result[0] = -1;
        child_result[1] = -1;
        descriptors[0] = -1;
        descriptors[1] = -1;

        failures += expect_result(
            "session-parent-pipe",
            raw_syscall6(
                SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0),
            0);
        child = raw_syscall6(
            SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (child == 0) {
            (void)raw_syscall6(
                SYS_close, descriptors[0], 0, 0, 0, 0, 0);
            child_result[0] = raw_syscall6(
                SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING,
                (long)child_name, 0, 0, 0, 0);
            child_result[1] = raw_syscall6(
                SYS_keyctl, KEYCTL_SESSION_TO_PARENT,
                0, 0, 0, 0, 0);
            (void)raw_syscall6(
                SYS_write, descriptors[1], (long)child_result,
                sizeof(child_result), 0, 0, 0);
            (void)raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
            for (;;) { }
        }
        if (child < 0) {
            failures += expect_result("session-parent-clone", child, 0);
        } else {
            long parent_session;
            (void)raw_syscall6(
                SYS_close, descriptors[1], 0, 0, 0, 0, 0);
            failures += expect_result(
                "session-parent-result-read",
                raw_syscall6(
                    SYS_read, descriptors[0], (long)child_result,
                    sizeof(child_result), 0, 0, 0),
                sizeof(child_result));
            (void)raw_syscall6(
                SYS_wait4, child, 0, 0, 0, 0, 0);
            parent_session = raw_syscall6(
                SYS_keyctl, KEYCTL_GET_KEYRING_ID,
                KEY_SPEC_SESSION_KEYRING, 0, 0, 0, 0);
            if (child_result[0] <= 0 || child_result[1] != 0 ||
                parent_session != child_result[0]) {
                print_text("FAIL session-to-parent child_session=");
                print_number(child_result[0]);
                print_text(" child_result=");
                print_number(child_result[1]);
                print_text(" parent_session=");
                print_number(parent_session);
                print_text("\n");
                ++failures;
            }
            (void)raw_syscall6(
                SYS_close, descriptors[0], 0, 0, 0, 0, 0);
        }
    }

    if (!failures) print_text("KEYRING_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
