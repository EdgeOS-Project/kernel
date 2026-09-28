/* SPDX-License-Identifier: MPL-2.0 */
/* Linux ia32 and x32 BPF compatibility ABI probe. */

#include <stdint.h>

#if defined(__i386__)
#define PROBE_NAME "IA32_BPF_UAPI_PROBE"
#define SYS_exit 1
#define SYS_write 4
#define SYS_close 6
#define SYS_mprotect 125
#define SYS_mmap 192
#define SYS_bpf 357
#elif defined(__x86_64__) && defined(__ILP32__)
#define PROBE_NAME "X32_BPF_UAPI_PROBE"
#define X32_SYSCALL_BIT UINT32_C(0x40000000)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_exit 60
#define SYS_bpf 321
#else
#error "compat_bpf_uapi_probe requires ia32 or x32"
#endif

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_ANY 0

union bpf_attr {
    struct {
        uint32_t map_type;
        uint32_t key_size;
        uint32_t value_size;
        uint32_t max_entries;
        uint32_t map_flags;
        uint32_t inner_map_fd;
        uint32_t numa_node;
        char map_name[16];
        uint32_t map_ifindex;
        uint32_t btf_fd;
        uint32_t btf_key_type_id;
        uint32_t btf_value_type_id;
        uint32_t btf_vmlinux_value_type_id;
        uint64_t map_extra;
    } map_create;
    struct {
        uint32_t map_fd;
        uint32_t padding;
        uint64_t key;
        uint64_t value;
        uint64_t flags;
    } map_element;
    unsigned char bytes[144];
};

_Static_assert(sizeof(union bpf_attr) == 144u,
               "bpf_attr must match Linux UAPI");

#if defined(__i386__)
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
#else
static long raw_call6(long number, long a0, long a1, long a2,
                      long a3, long a4, long a5) {
    register uint64_t r10 __asm__("r10") = (uint32_t)a3;
    register uint64_t r8 __asm__("r8") = (uint32_t)a4;
    register uint64_t r9 __asm__("r9") = (uint32_t)a5;
    int64_t result;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"((uint64_t)X32_SYSCALL_BIT +
                           (uint32_t)number),
                       "D"((uint64_t)(uint32_t)a0),
                       "S"((uint64_t)(uint32_t)a1),
                       "d"((uint64_t)(uint32_t)a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (long)result;
}
#endif

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

static void fail(const char *reason) {
    print_text(PROBE_NAME "_FAIL ");
    print_text(reason);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
}

static int syscall_failed(long result) {
    return (uint32_t)result >= UINT32_C(0xfffff001);
}

static void clear_attribute(union bpf_attr *attribute) {
    for (uint32_t index = 0; index < sizeof(*attribute); ++index)
        attribute->bytes[index] = 0;
}

static long bpf_call(uint32_t command, union bpf_attr *attribute) {
    return call6(SYS_bpf, command, attribute,
                 sizeof(*attribute), 0, 0, 0);
}

__attribute__((noreturn)) void _start(void) {
    const uint32_t page_size = 4096u;
    unsigned char *mapping;
    union bpf_attr *attribute;
    uint32_t key = 0;
    uint32_t value = UINT32_C(0x1234abcd);
    uint32_t output = 0;
    long descriptor;
    long result;

    result = call6(SYS_mmap, 0, page_size * 2u,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_failed(result)) fail("mmap");
    mapping = (unsigned char *)(uintptr_t)(uint32_t)result;
    result = call6(SYS_mprotect, mapping + page_size, page_size,
                   PROT_NONE, 0, 0, 0);
    if (result != 0) fail("mprotect");
    attribute = (union bpf_attr *)(
        mapping + page_size - sizeof(*attribute));

    clear_attribute(attribute);
    attribute->map_create.map_type = BPF_MAP_TYPE_ARRAY;
    attribute->map_create.key_size = sizeof(key);
    attribute->map_create.value_size = sizeof(value);
    attribute->map_create.max_entries = 1;
    descriptor = bpf_call(BPF_MAP_CREATE, attribute);
    if (descriptor < 0) fail("map-create-layout");

    clear_attribute(attribute);
    attribute->map_element.map_fd = (uint32_t)descriptor;
    attribute->map_element.key = (uint32_t)(uintptr_t)&key;
    attribute->map_element.value = (uint32_t)(uintptr_t)&value;
    attribute->map_element.flags = BPF_ANY;
    if (bpf_call(BPF_MAP_UPDATE_ELEM, attribute) != 0)
        fail("map-update-layout");

    clear_attribute(attribute);
    attribute->map_element.map_fd = (uint32_t)descriptor;
    attribute->map_element.key = (uint32_t)(uintptr_t)&key;
    attribute->map_element.value = (uint32_t)(uintptr_t)&output;
    if (bpf_call(BPF_MAP_LOOKUP_ELEM, attribute) != 0 || output != value)
        fail("map-lookup-layout");
    if (call6(SYS_close, descriptor, 0, 0, 0, 0, 0) != 0)
        fail("close");

    print_text(PROBE_NAME "_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
