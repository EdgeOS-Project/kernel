/* SPDX-License-Identifier: MPL-2.0 */
/* Validate cgroup v2 reclaim of resident shared-memory object pages. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mincore 27
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_ftruncate 77
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_unlinkat 263
#define SYS_memfd_create 319
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mincore 232
#define SYS_ftruncate 46
#define SYS_openat 56
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_memfd_create 279
#else
#error "memory_reclaim_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD -100
#define AT_REMOVEDIR 0x200
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CLOEXEC 02000000
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define OBJECT_PAGES 64u
#define OBJECT_BYTES ((uint64_t)OBJECT_PAGES * PAGE_SIZE)

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

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(unsigned long value) {
    char digits[24];
    unsigned long position = sizeof(digits);

    do {
        digits[--position] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    (void)raw_syscall6(SYS_write, 1, (long)&digits[position],
                       (long)(sizeof(digits) - position), 0, 0, 0);
}

static char *append_text(char *destination, const char *source) {
    while (*source) *destination++ = *source++;
    return destination;
}

static char *append_number(char *destination, unsigned long value) {
    char digits[24];
    unsigned long position = sizeof(digits);

    do {
        digits[--position] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    while (position < sizeof(digits))
        *destination++ = digits[position++];
    return destination;
}

static int write_file(const char *path, const char *value) {
    unsigned long length = string_length(value);
    long fd = raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
                           O_WRONLY | O_CLOEXEC, 0, 0, 0);
    long written;

    if (fd < 0) return -1;
    written = raw_syscall6(SYS_write, fd, (long)value,
                           (long)length, 0, 0, 0);
    (void)raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    return written == (long)length ? 0 : -1;
}

static int text_contains(const char *text, const char *needle) {
    if (!text || !needle || !*needle) return 0;
    for (; *text; ++text) {
        unsigned long index = 0;

        while (needle[index] && text[index] == needle[index]) ++index;
        if (!needle[index]) return 1;
    }
    return 0;
}

static int pressure_file_valid(const char *path) {
    char buffer[256];
    long fd = raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
                           O_RDONLY | O_CLOEXEC, 0, 0, 0);
    long length;

    if (fd < 0) return 0;
    length = raw_syscall6(SYS_read, fd, (long)buffer,
                          sizeof(buffer) - 1u, 0, 0, 0);
    (void)raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    if (length <= 0 || length >= (long)sizeof(buffer)) return 0;
    buffer[length] = 0;
    return text_contains(buffer, "some avg10=") &&
           text_contains(buffer, "full avg10=") &&
           text_contains(buffer, " avg60=") &&
           text_contains(buffer, " avg300=") &&
           text_contains(buffer, " total=");
}

static long file_counter_value(const char *path, const char *label) {
    char buffer[512];
    long fd = raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
                           O_RDONLY | O_CLOEXEC, 0, 0, 0);
    long length;

    if (fd < 0) return -1;
    length = raw_syscall6(SYS_read, fd, (long)buffer,
                          sizeof(buffer) - 1u, 0, 0, 0);
    (void)raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    if (length <= 0 || length >= (long)sizeof(buffer)) return -1;
    buffer[length] = 0;
    for (char *cursor = buffer; *cursor; ++cursor) {
        unsigned long index = 0;
        unsigned long value = 0;
        int digits = 0;

        if (cursor != buffer && cursor[-1] != '\n') continue;
        while (label[index] && cursor[index] == label[index]) ++index;
        if (label[index]) continue;
        cursor += index;
        while (*cursor >= '0' && *cursor <= '9') {
            value = value * 10u + (unsigned long)(*cursor - '0');
            ++cursor;
            digits = 1;
        }
        return digits ? (long)value : -1;
    }
    return -1;
}

static long file_u64_value(const char *path) {
    char buffer[64];
    unsigned long value = 0;
    int digits = 0;
    long fd = raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
                           O_RDONLY | O_CLOEXEC, 0, 0, 0);
    long length;

    if (fd < 0) return -1;
    length = raw_syscall6(SYS_read, fd, (long)buffer,
                          sizeof(buffer) - 1u, 0, 0, 0);
    (void)raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    if (length <= 0 || length >= (long)sizeof(buffer)) return -1;
    buffer[length] = 0;
    for (long index = 0; index < length; ++index) {
        if (buffer[index] < '0' || buffer[index] > '9') break;
        value = value * 10u + (unsigned long)(buffer[index] - '0');
        digits = 1;
    }
    return digits ? (long)value : -1;
}

static int resident_pages(long mapping, uint8_t *vector) {
    int resident = 0;

    for (uint32_t index = 0; index < OBJECT_PAGES; ++index)
        vector[index] = 0;
    if (raw_syscall6(SYS_mincore, mapping, OBJECT_BYTES,
                     (long)vector, 0, 0, 0) < 0)
        return -1;
    for (uint32_t index = 0; index < OBJECT_PAGES; ++index)
        if (vector[index] & 1u) ++resident;
    return resident;
}

static int run_probe(void) {
    static uint8_t residency[OBJECT_PAGES];
    static const char directory_prefix[] =
        "/sys/fs/cgroup/edgeos-shmem-reclaim-";
    static const char root_procs[] = "/sys/fs/cgroup/cgroup.procs";
    static const char global_pressure[] = "/proc/pressure/memory";
    static const char reclaim_value[] = "262144\n";
    static const char high_value[] = "262144\n";
    static const char unlimited_value[] = "max\n";
    static const char memfd_name[] = "edgeos-pressure-reclaim";
    char directory[96];
    char procs_path[128];
    char reclaim_path[128];
    char pressure_path[128];
    char high_path[128];
    char events_path[128];
    char current_path[128];
    char max_path[128];
    char max_value[32];
    char pid_text[32];
    char *cursor;
    long pid;
    long fd;
    long mapping;
    long high_fd = -1;
    long high_mapping = 0;
    int before;
    int after;
    long current_bytes;
    int result = 1;

    pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    cursor = append_text(directory, directory_prefix);
    cursor = append_number(cursor, (unsigned long)pid);
    *cursor = 0;
    cursor = append_text(procs_path, directory);
    cursor = append_text(cursor, "/cgroup.procs");
    *cursor = 0;
    cursor = append_text(reclaim_path, directory);
    cursor = append_text(cursor, "/memory.reclaim");
    *cursor = 0;
    cursor = append_text(pressure_path, directory);
    cursor = append_text(cursor, "/memory.pressure");
    *cursor = 0;
    cursor = append_text(high_path, directory);
    cursor = append_text(cursor, "/memory.high");
    *cursor = 0;
    cursor = append_text(events_path, directory);
    cursor = append_text(cursor, "/memory.events");
    *cursor = 0;
    cursor = append_text(current_path, directory);
    cursor = append_text(cursor, "/memory.current");
    *cursor = 0;
    cursor = append_text(max_path, directory);
    cursor = append_text(cursor, "/memory.max");
    *cursor = 0;
    cursor = append_number(pid_text, (unsigned long)pid);
    *cursor++ = '\n';
    *cursor = 0;

    if (raw_syscall6(SYS_mkdirat, AT_FDCWD, (long)directory,
                     0755, 0, 0, 0) < 0) {
        print_text("MEMORY_RECLAIM_ABI_PROBE_FAIL mkdir\n");
        return 1;
    }
    print_text("MEMORY_RECLAIM_PHASE directory\n");
    if (write_file(procs_path, pid_text) < 0) {
        print_text("MEMORY_RECLAIM_ABI_PROBE_FAIL join\n");
        goto cleanup_directory;
    }
    print_text("MEMORY_RECLAIM_PHASE joined\n");
    fd = raw_syscall6(SYS_memfd_create, (long)memfd_name, 1, 0, 0, 0, 0);
    if (fd < 0 || raw_syscall6(
            SYS_ftruncate, fd, OBJECT_BYTES, 0, 0, 0, 0) < 0) {
        print_text("MEMORY_RECLAIM_ABI_PROBE_FAIL memfd\n");
        goto cleanup_membership;
    }
    mapping = raw_syscall6(SYS_mmap, 0, OBJECT_BYTES,
                           PROT_READ | PROT_WRITE, MAP_SHARED,
                           fd, 0);
    if (mapping <= 0) {
        print_text("MEMORY_RECLAIM_ABI_PROBE_FAIL mmap\n");
        goto cleanup_fd;
    }
    print_text("MEMORY_RECLAIM_PHASE mapped\n");
    for (uint32_t index = 0; index < OBJECT_PAGES; ++index)
        ((volatile uint8_t *)(uintptr_t)mapping)[index * PAGE_SIZE] =
            (uint8_t)(index * 17u + 3u);
    before = resident_pages(mapping, residency);
    if (before != (int)OBJECT_PAGES) {
        print_text("MEMORY_RECLAIM_ABI_PROBE_FAIL initial-residency\n");
        goto cleanup_mapping;
    }
    print_text("MEMORY_RECLAIM_PHASE resident\n");
    if (write_file(reclaim_path, reclaim_value) < 0) {
        print_text("MEMORY_RECLAIM_ABI_PROBE_FAIL reclaim\n");
        goto cleanup_mapping;
    }
    print_text("MEMORY_RECLAIM_PHASE reclaimed\n");
    after = resident_pages(mapping, residency);
    if (after < 0 || after >= before) {
        print_text("MEMORY_RECLAIM_ABI_PROBE_FAIL residency before=");
        print_number((unsigned long)before);
        print_text(" after=");
        print_number((unsigned long)(after < 0 ? 0 : after));
        print_text("\n");
        goto cleanup_mapping;
    }
    for (uint32_t index = 0; index < OBJECT_PAGES; ++index) {
        uint8_t expected = (uint8_t)(index * 17u + 3u);
        if (((volatile uint8_t *)(uintptr_t)mapping)[index * PAGE_SIZE] !=
                expected) {
            print_text("MEMORY_RECLAIM_ABI_PROBE_FAIL restore\n");
            goto cleanup_mapping;
        }
    }
    if (!pressure_file_valid(global_pressure) ||
        !pressure_file_valid(pressure_path)) {
        print_text("MEMORY_PRESSURE_ABI_FAIL\n");
        goto cleanup_mapping;
    }
    print_text("MEMORY_PRESSURE_ABI_PASS\n");
    if (write_file(high_path, high_value) < 0) {
        print_text("MEMORY_HIGH_ABI_FAIL configure\n");
        goto cleanup_mapping;
    }
    high_fd = raw_syscall6(
        SYS_memfd_create, (long)"edgeos-high-reclaim", 1, 0, 0, 0, 0);
    if (high_fd < 0 || raw_syscall6(
            SYS_ftruncate, high_fd, PAGE_SIZE, 0, 0, 0, 0) < 0) {
        print_text("MEMORY_HIGH_ABI_FAIL memfd\n");
        goto cleanup_high;
    }
    high_mapping = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, high_fd, 0);
    if (high_mapping <= 0) {
        print_text("MEMORY_HIGH_ABI_FAIL mmap\n");
        goto cleanup_high;
    }
    *(volatile uint8_t *)(uintptr_t)high_mapping = 0x5au;
    if (file_counter_value(events_path, "high ") <= 0) {
        print_text("MEMORY_HIGH_ABI_FAIL event\n");
        goto cleanup_high;
    }
    print_text("MEMORY_HIGH_ABI_PASS\n");
    (void)raw_syscall6(SYS_munmap, high_mapping, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, high_fd, 0, 0, 0, 0, 0);
    high_mapping = 0;
    high_fd = -1;
    if (write_file(high_path, unlimited_value) < 0) {
        print_text("MEMORY_MAX_ABI_FAIL reset-high\n");
        goto cleanup_high;
    }
    current_bytes = file_u64_value(current_path);
    if (current_bytes <= 0) {
        print_text("MEMORY_MAX_ABI_FAIL current\n");
        goto cleanup_high;
    }
    cursor = append_number(max_value, (unsigned long)current_bytes);
    *cursor++ = '\n';
    *cursor = 0;
    if (write_file(max_path, max_value) < 0) {
        print_text("MEMORY_MAX_ABI_FAIL configure\n");
        goto cleanup_limits;
    }
    high_fd = raw_syscall6(
        SYS_memfd_create, (long)"edgeos-max-reclaim", 1, 0, 0, 0, 0);
    if (high_fd < 0 || raw_syscall6(
            SYS_ftruncate, high_fd, PAGE_SIZE, 0, 0, 0, 0) < 0) {
        print_text("MEMORY_MAX_ABI_FAIL memfd\n");
        goto cleanup_limits;
    }
    high_mapping = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, high_fd, 0);
    if (high_mapping <= 0) {
        print_text("MEMORY_MAX_ABI_FAIL mmap\n");
        goto cleanup_limits;
    }
    *(volatile uint8_t *)(uintptr_t)high_mapping = 0xa5u;
    if (file_counter_value(events_path, "max ") <= 0 ||
        file_counter_value(events_path, "oom ") != 0) {
        print_text("MEMORY_MAX_ABI_FAIL event\n");
        goto cleanup_limits;
    }
    print_text("MEMORY_MAX_RECLAIM_ABI_PASS\n");
    print_text("MEMORY_RECLAIM_SHARED_RECLAIMED before=");
    print_number((unsigned long)before);
    print_text(" after=");
    print_number((unsigned long)after);
    print_text("\nMEMORY_RECLAIM_ABI_PROBE_PASS\n");
    result = 0;

cleanup_limits:
    (void)write_file(max_path, unlimited_value);
cleanup_high:
    (void)write_file(high_path, unlimited_value);
    if (high_mapping > 0)
        (void)raw_syscall6(SYS_munmap, high_mapping, PAGE_SIZE, 0, 0, 0, 0);
    if (high_fd >= 0)
        (void)raw_syscall6(SYS_close, high_fd, 0, 0, 0, 0, 0);
cleanup_mapping:
    (void)raw_syscall6(SYS_munmap, mapping, OBJECT_BYTES, 0, 0, 0, 0);
cleanup_fd:
    (void)raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
cleanup_membership:
    (void)write_file(root_procs, pid_text);
cleanup_directory:
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)directory,
                       AT_REMOVEDIR, 0, 0, 0);
    return result;
}

void _start(void) {
    int result = run_probe();
    raw_syscall6(SYS_exit, result, 0, 0, 0, 0, 0);
    for (;;) { }
}
