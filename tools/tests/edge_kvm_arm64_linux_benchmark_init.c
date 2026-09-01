/* Minimal Linux PID 1 for EdgeOS nested-KVM boot and performance acceptance. */

#include <stdint.h>

#define LINUX_SYS_WRITE 64
#define LINUX_SYS_CLOCK_GETTIME 113
#define LINUX_SYS_REBOOT 142
#define LINUX_SYS_UNAME 160
#define LINUX_SYS_GETPID 172
#define LINUX_SYS_MMAP 222

#define LINUX_CLOCK_MONOTONIC 1
#define LINUX_PROT_READ 1
#define LINUX_PROT_WRITE 2
#define LINUX_MAP_PRIVATE 2
#define LINUX_MAP_ANONYMOUS 0x20
#define LINUX_REBOOT_MAGIC1 0xfee1dead
#define LINUX_REBOOT_MAGIC2 672274793
#define LINUX_REBOOT_CMD_POWER_OFF 0x4321fedc

#define CPU_ITERATIONS 50000000ULL
#define MEMORY_SIZE (64ULL * 1024ULL * 1024ULL)
#define MEMORY_PASSES 8ULL
#define GETPID_ITERATIONS 1000000ULL

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_utsname {
    char system_name[65];
    char node_name[65];
    char release[65];
    char version[65];
    char machine[65];
    char domain_name[65];
};

static long linux_syscall6(long number, long a0, long a1, long a2, long a3,
                           long a4, long a5)
{
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = number;

    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                       "r"(x8)
                     : "memory", "cc");
    return x0;
}

static uint64_t text_length(const char *text)
{
    uint64_t length = 0;

    while (text[length] != '\0')
        length++;
    return length;
}

static void print_text(const char *text)
{
    (void)linux_syscall6(
        LINUX_SYS_WRITE, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_u64(uint64_t value)
{
    char buffer[32];
    uint64_t index = sizeof(buffer);

    if (value == 0) {
        print_text("0");
        return;
    }
    while (value != 0) {
        buffer[--index] = (char)('0' + value % 10ULL);
        value /= 10ULL;
    }
    (void)linux_syscall6(
        LINUX_SYS_WRITE, 1, (long)&buffer[index],
        (long)(sizeof(buffer) - index), 0, 0, 0);
}

static void print_metric(const char *name, uint64_t value)
{
    print_text(name);
    print_u64(value);
    print_text("\n");
}

static uint64_t monotonic_nanoseconds(void)
{
    struct linux_timespec time = {0, 0};

    if (linux_syscall6(
            LINUX_SYS_CLOCK_GETTIME, LINUX_CLOCK_MONOTONIC,
            (long)&time, 0, 0, 0, 0) < 0)
        return 0;
    return (uint64_t)time.seconds * 1000000000ULL +
           (uint64_t)time.nanoseconds;
}

static void power_off(void)
{
    (void)linux_syscall6(
        LINUX_SYS_REBOOT, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
        LINUX_REBOOT_CMD_POWER_OFF, 0, 0, 0);
    for (;;)
        __asm__ volatile("wfe");
}

void _start(void)
{
    struct linux_utsname identity;
    volatile uint64_t *memory;
    volatile uint64_t state = 0x9e3779b97f4a7c15ULL;
    volatile uint64_t checksum = 0;
    uint64_t start;
    uint64_t end;
    uint64_t index;
    uint64_t pass;
    uint64_t bytes;
    uint64_t memory_rate;

    print_text("EDGE_LINUX_BOOT_PASS\n");
    if (linux_syscall6(LINUX_SYS_UNAME, (long)&identity, 0, 0, 0, 0, 0) == 0) {
        print_text("EDGE_LINUX_RELEASE=");
        print_text(identity.release);
        print_text("\nEDGE_LINUX_MACHINE=");
        print_text(identity.machine);
        print_text("\n");
    }

    start = monotonic_nanoseconds();
    for (index = 0; index < CPU_ITERATIONS; index++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
    }
    end = monotonic_nanoseconds();
    print_metric("EDGE_LINUX_CPU_ITERATIONS=", CPU_ITERATIONS);
    print_metric("EDGE_LINUX_CPU_NS=", end - start);
    print_metric("EDGE_LINUX_CPU_CHECKSUM=", state);

    memory = (volatile uint64_t *)(uintptr_t)linux_syscall6(
        LINUX_SYS_MMAP, 0, MEMORY_SIZE,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
    if ((long)(uintptr_t)memory < 0) {
        print_text("EDGE_LINUX_MEMORY_MAP_FAIL\n");
        power_off();
    }
    start = monotonic_nanoseconds();
    for (pass = 0; pass < MEMORY_PASSES; pass++) {
        for (index = 0; index < MEMORY_SIZE / sizeof(uint64_t); index++)
            memory[index] = index + pass;
    }
    for (index = 0; index < MEMORY_SIZE / sizeof(uint64_t); index += 512)
        checksum ^= memory[index];
    end = monotonic_nanoseconds();
    bytes = MEMORY_SIZE * MEMORY_PASSES;
    memory_rate = end > start ?
        (bytes * 1000000000ULL) / (end - start) / (1024ULL * 1024ULL) : 0;
    print_metric("EDGE_LINUX_MEMORY_BYTES=", bytes);
    print_metric("EDGE_LINUX_MEMORY_NS=", end - start);
    print_metric("EDGE_LINUX_MEMORY_MIB_PER_SEC=", memory_rate);
    print_metric("EDGE_LINUX_MEMORY_CHECKSUM=", checksum);

    start = monotonic_nanoseconds();
    for (index = 0; index < GETPID_ITERATIONS; index++)
        checksum ^= (uint64_t)linux_syscall6(LINUX_SYS_GETPID, 0, 0, 0, 0, 0, 0);
    end = monotonic_nanoseconds();
    print_metric("EDGE_LINUX_GETPID_CALLS=", GETPID_ITERATIONS);
    print_metric("EDGE_LINUX_GETPID_NS=", end - start);
    print_metric("EDGE_LINUX_FINAL_CHECKSUM=", checksum);
    print_text("EDGE_LINUX_BENCHMARK_PASS\n");
    power_off();
}
