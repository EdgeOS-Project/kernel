/* SPDX-License-Identifier: MPL-2.0 */
/* X.509 RSA public-key keyctl ABI probe for x86_64 and AArch64. */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long uintptr_t;

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_add_key 248
#define SYS_keyctl 250
#define SYS_openat 257
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_exit 93
#define SYS_add_key 217
#define SYS_keyctl 219
#define SYS_openat 56
#else
#error "keyring_asymmetric_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_DESCRIBE 6
#define KEYCTL_PKEY_QUERY 24
#define KEYCTL_PKEY_ENCRYPT 25
#define KEYCTL_PKEY_DECRYPT 26
#define KEYCTL_PKEY_SIGN 27
#define KEYCTL_PKEY_VERIFY 28
#define KEYCTL_CAPABILITIES 31

#define EINVAL 22

typedef struct keyctl_pkey_query {
    uint32_t supported_operations;
    uint32_t key_size;
    uint16_t maximum_data_size;
    uint16_t maximum_signature_size;
    uint16_t maximum_encrypted_size;
    uint16_t maximum_decrypted_size;
    uint32_t spare[10];
} keyctl_pkey_query_t;

typedef struct keyctl_pkey_parameters {
    int32_t key_id;
    uint32_t input_length;
    uint32_t output_length;
    uint32_t spare[7];
} keyctl_pkey_parameters_t;

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

    while (left[index] && right[index]) {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(int value) {
    char output[16];
    unsigned int count = 0u;
    unsigned int magnitude;

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned int)(-value);
    } else {
        magnitude = (unsigned int)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    while (count)
        (void)raw_syscall6(
            SYS_write, 1, (long)&output[--count], 1, 0, 0, 0);
}

static __attribute__((noreturn)) void exit_now(long status) {
    (void)raw_syscall6(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) { }
}

static long load_file(const char *path, void *buffer,
                      unsigned long capacity) {
    long descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    long result;

    if (descriptor < 0) return descriptor;
    result = raw_syscall6(
        SYS_read, descriptor, (long)buffer, (long)capacity, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return result;
}

static unsigned char certificate[2048];
static unsigned char digest[64];
static unsigned char signature[512];
static unsigned char encrypted[512];
static char description[512];

static int run_probe(void) {
    static const char empty[] = "";
    static const char pkcs1[] = "enc=pkcs1 hash=sha256";
    static const char raw[] = "enc=raw";
    static const char invalid[] = "enc=oaep hash=sha256";
    long certificate_length =
        load_file("/cert.der", certificate, sizeof(certificate));
    long digest_length =
        load_file("/message.sha256", digest, sizeof(digest));
    long signature_length =
        load_file("/signature.bin", signature, sizeof(signature));
    unsigned char capabilities[8] = {0};
    keyctl_pkey_query_t query;
    keyctl_pkey_parameters_t parameters;
    long ring;
    long key;
    long automatic_key;
    long result;

    if (certificate_length <= 0 || digest_length != 32 ||
        signature_length != 128)
        return 10;
    ring = raw_syscall6(
        SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING,
        1, 0, 0, 0);
    if (ring <= 0) return 11;
    key = raw_syscall6(
        SYS_add_key, (long)"asymmetric", (long)"edgeos-rsa-test",
        (long)certificate, certificate_length,
        KEY_SPEC_SESSION_KEYRING, 0);
    if (key <= 0) return 12;
    automatic_key = raw_syscall6(
        SYS_add_key, (long)"asymmetric", 0,
        (long)certificate, certificate_length,
        KEY_SPEC_SESSION_KEYRING, 0);
    if (automatic_key <= 0) return 25;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_DESCRIBE, automatic_key,
        (long)description, sizeof(description), 0, 0);
    if (result != 83 || !text_equal(
            description,
            "asymmetric;0;0;39010000;EdgeOS UAPI Test: "
            "c85450cd460b481dfc02bbfd570aa9c7905d9623"))
        return 26;

    for (unsigned long index = 0; index < sizeof(query); ++index)
        ((unsigned char *)&query)[index] = 0xffu;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_QUERY, key, 0,
        (long)pkcs1, (long)&query, 0);
    if (result != 0 || query.supported_operations != 9u ||
        query.key_size != 1024u || query.maximum_data_size != 128u ||
        query.maximum_signature_size != 128u ||
        query.maximum_encrypted_size != 128u ||
        query.maximum_decrypted_size != 128u)
        return 13;
    for (unsigned int index = 0; index < 10u; ++index)
        if (query.spare[index]) return 14;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_QUERY, key, 0,
        (long)raw, (long)&query, 0);
    if (result != 0 || query.supported_operations != 1u)
        return 15;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_QUERY, key, 0,
        (long)empty, (long)&query, 0);
    if (result != 0 || query.supported_operations != 1u)
        return 16;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_QUERY, key, 0,
        (long)invalid, (long)&query, 0);
    if (result != -EINVAL) return 17;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_QUERY, key, 1,
        (long)pkcs1, (long)&query, 0);
    if (result != -EINVAL) return 18;

    for (unsigned long index = 0; index < sizeof(parameters); ++index)
        ((unsigned char *)&parameters)[index] = 0u;
    parameters.key_id = (int32_t)key;
    parameters.input_length = 8u;
    parameters.output_length = 128u;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_ENCRYPT, (long)&parameters,
        (long)"enc=pkcs1", (long)"plaintext", (long)encrypted, 0);
    if (result != 128) return 19;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_DECRYPT, (long)&parameters,
        (long)"enc=pkcs1", (long)encrypted, (long)digest, 0);
    if (result != -EINVAL) return 20;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_SIGN, (long)&parameters,
        (long)pkcs1, (long)digest, (long)encrypted, 0);
    if (result != -EINVAL) return 21;

    parameters.input_length = (uint32_t)digest_length;
    parameters.output_length = (uint32_t)signature_length;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_VERIFY, (long)&parameters,
        (long)pkcs1, (long)digest, (long)signature, 0);
    if (result != 0) return 22;
    signature[0] ^= 1u;
    result = raw_syscall6(
        SYS_keyctl, KEYCTL_PKEY_VERIFY, (long)&parameters,
        (long)pkcs1, (long)digest, (long)signature, 0);
    if (result != -EINVAL) return 23;

    result = raw_syscall6(
        SYS_keyctl, KEYCTL_CAPABILITIES, (long)capabilities,
        sizeof(capabilities), 0, 0, 0);
    if (result < 1 || !(capabilities[0] & 0x08u)) return 24;
    return 0;
}

static __attribute__((noreturn, noinline, used))
void probe_entry(uintptr_t *initial_stack) {
    int result;

    (void)initial_stack;
    result = run_probe();
    if (result) {
        print_text("KEYRING_ASYMMETRIC_ABI_PROBE_FAIL code=");
        print_number(result);
        print_text("\n");
    } else {
        print_text("KEYRING_ASYMMETRIC_ABI_PROBE_PASS\n");
    }
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
