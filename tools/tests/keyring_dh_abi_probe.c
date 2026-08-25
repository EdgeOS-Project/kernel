/* SPDX-License-Identifier: MPL-2.0 */
/* Linux KEYCTL_DH_COMPUTE ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_exit 60
#define SYS_add_key 248
#define SYS_keyctl 250
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_write 64
#define SYS_exit 93
#define SYS_add_key 217
#define SYS_keyctl 219
#else
#error "keyring_dh_abi_probe requires a Linux 64-bit architecture"
#endif

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_DH_COMPUTE 23
#define KEYCTL_CAPABILITIES 31
#define EFAULT 14
#define EINVAL 22
#define EMSGSIZE 90
#define EOVERFLOW 75

struct keyctl_dh_params {
    int32_t private_key;
    int32_t prime;
    int32_t base;
};

struct keyctl_kdf_params {
    const char *hashname;
    const void *otherinfo;
    uint32_t otherinfolen;
    uint32_t spare[8];
};

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

START_ATTRIBUTES void _start(void) {
    static const unsigned char private_value[] = {1u};
    static const unsigned char base_value[] = {2u};
    static const unsigned char kdf_expected[48] = {
        0xdau, 0x8eu, 0xc1u, 0x67u, 0x48u, 0x77u, 0x1eu, 0x2eu,
        0x90u, 0x3du, 0x58u, 0x15u, 0xc9u, 0xf7u, 0x86u, 0x73u,
        0x37u, 0x8du, 0x6du, 0x96u, 0xb0u, 0x62u, 0x46u, 0xacu,
        0x57u, 0xfbu, 0xfau, 0xc0u, 0x28u, 0xcfu, 0xb5u, 0x63u,
        0x49u, 0x36u, 0x21u, 0xdeu, 0x31u, 0x31u, 0x7eu, 0x43u,
        0xecu, 0xd1u, 0xcdu, 0x70u, 0xffu, 0x78u, 0x6cu, 0x1bu,
    };
    static const unsigned char kdf_sha224_expected[44] = {
        0xcfu, 0xa4u, 0xf2u, 0x23u, 0x6bu, 0xe1u, 0x85u, 0x11u,
        0x34u, 0x66u, 0x72u, 0xbfu, 0x46u, 0x8fu, 0xa6u, 0x03u,
        0xc4u, 0xe2u, 0x99u, 0xabu, 0x3eu, 0xd0u, 0x4au, 0x73u,
        0x5eu, 0xc5u, 0x08u, 0x25u, 0xccu, 0x76u, 0xb1u, 0x68u,
        0xe8u, 0x12u, 0x59u, 0xe5u, 0xa7u, 0xf5u, 0xd8u, 0x62u,
        0x46u, 0xbdu, 0x5bu, 0xb7u,
    };
    static const char kdf_otherinfo[] = "edge-kdf";
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
    struct keyctl_dh_params parameters;
    struct keyctl_kdf_params kdf = {0};
    unsigned char output[sizeof(prime_value) - 1u];
    unsigned char derived[sizeof(kdf_expected)];
    unsigned char capabilities[2] = {0};
    long session;
    int failures = 0;

    session = raw_syscall6(
        SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING,
        1, 0, 0, 0);
    if (session <= 0) {
        print_text("FAIL session\n");
        ++failures;
    }
    parameters.private_key = (int32_t)raw_syscall6(
        SYS_add_key, (long)"user", (long)"edge-dh-private",
        (long)private_value, sizeof(private_value),
        KEY_SPEC_SESSION_KEYRING, 0);
    parameters.prime = (int32_t)raw_syscall6(
        SYS_add_key, (long)"user", (long)"edge-dh-prime",
        (long)prime_value, sizeof(prime_value) - 1u,
        KEY_SPEC_SESSION_KEYRING, 0);
    parameters.base = (int32_t)raw_syscall6(
        SYS_add_key, (long)"user", (long)"edge-dh-base",
        (long)base_value, sizeof(base_value),
        KEY_SPEC_SESSION_KEYRING, 0);
    if (parameters.private_key <= 0 || parameters.prime <= 0 ||
        parameters.base <= 0) {
        print_text("FAIL add-keys\n");
        ++failures;
    } else {
        failures += expect_result(
            "null-params",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE, 0, 0, 0, 0, 0),
            -EINVAL);
        failures += expect_result(
            "parameter-fault",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE, 1, 0, 0, 0, 0),
            -EFAULT);
        failures += expect_result(
            "size",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE,
                (long)&parameters, 0, 0, 0, 0),
            sizeof(output));
        failures += expect_result(
            "short-output",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE,
                (long)&parameters, (long)output,
                sizeof(output) - 1u, 0, 0),
            -EOVERFLOW);
        for (unsigned long index = 0; index < sizeof(output); ++index)
            output[index] = 0xffu;
        failures += expect_result(
            "compute",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE,
                (long)&parameters, (long)output,
                sizeof(output), 0, 0),
            sizeof(output));
        for (unsigned long index = 0; index + 1u < sizeof(output);
             ++index) {
            if (output[index] == 0u) continue;
            print_text("FAIL leading-zero\n");
            ++failures;
            break;
        }
        if (output[sizeof(output) - 1u] != 2u) {
            print_text("FAIL value\n");
            ++failures;
        }
        kdf.hashname = "sha256";
        kdf.otherinfo = kdf_otherinfo;
        kdf.otherinfolen = sizeof(kdf_otherinfo) - 1u;
        failures += expect_result(
            "kdf-compute",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE,
                (long)&parameters, (long)derived,
                sizeof(derived), (long)&kdf, 0),
            sizeof(derived));
        for (unsigned long index = 0; index < sizeof(derived); ++index) {
            if (derived[index] == kdf_expected[index]) continue;
            print_text("FAIL kdf-value\n");
            ++failures;
            break;
        }
        kdf.hashname = "sha224";
        failures += expect_result(
            "kdf-sha224-compute",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE,
                (long)&parameters, (long)derived,
                sizeof(kdf_sha224_expected), (long)&kdf, 0),
            sizeof(kdf_sha224_expected));
        for (unsigned long index = 0;
             index < sizeof(kdf_sha224_expected); ++index) {
            if (derived[index] == kdf_sha224_expected[index]) continue;
            print_text("FAIL kdf-sha224-value\n");
            ++failures;
            break;
        }
        kdf.spare[0] = 1u;
        failures += expect_result(
            "kdf-spare",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE,
                (long)&parameters, (long)derived,
                sizeof(derived), (long)&kdf, 0),
            -EINVAL);
        kdf.spare[0] = 0u;
        failures += expect_result(
            "kdf-output-limit",
            raw_syscall6(
                SYS_keyctl, KEYCTL_DH_COMPUTE,
                (long)&parameters, (long)derived,
                1025, (long)&kdf, 0),
            -EMSGSIZE);
    }
    failures += expect_result(
        "capabilities",
        raw_syscall6(
            SYS_keyctl, KEYCTL_CAPABILITIES, (long)capabilities,
            sizeof(capabilities), 0, 0, 0),
        sizeof(capabilities));
    if (!(capabilities[0] & 0x04u)) {
        print_text("FAIL capability-bit\n");
        ++failures;
    }

    print_text(failures ? "KEYRING_DH_ABI_PROBE_FAIL\n" :
                          "KEYRING_DH_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
