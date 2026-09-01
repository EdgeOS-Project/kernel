/* PID 1 for unmodified QEMU AArch64 KVM migration acceptance on EdgeOS. */

#define EDGE_SYS_MOUNT 40
#define EDGE_SYS_OPENAT 56
#define EDGE_SYS_CLOSE 57
#define EDGE_SYS_READ 63
#define EDGE_SYS_WRITE 64
#define EDGE_SYS_EXIT 93
#define EDGE_SYS_NANOSLEEP 101
#define EDGE_SYS_KILL 129
#define EDGE_SYS_SOCKET 198
#define EDGE_SYS_CONNECT 203
#define EDGE_SYS_CLONE 220
#define EDGE_SYS_EXECVE 221
#define EDGE_SYS_WAIT4 260

#define EDGE_AT_FDCWD -100
#define EDGE_AF_UNIX 1
#define EDGE_SOCK_STREAM 1
#define EDGE_SOCK_NONBLOCK 0x800
#define EDGE_SIGCHLD 17
#define EDGE_SIGKILL 9
#define EDGE_EISCONN 106
#define EDGE_EALREADY 114
#define EDGE_EINPROGRESS 115

struct edge_timespec { long seconds; long nanoseconds; };
struct edge_sockaddr_un { unsigned short family; char path[108]; };

static long edge_syscall6(long number, long a0, long a1, long a2, long a3,
                          long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = number;

    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                     "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
    return x0;
}

static unsigned long edge_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static int edge_contains(const char *buffer, long size, const char *needle) {
    unsigned long needle_size = edge_length(needle);
    if (size < 0 || (unsigned long)size < needle_size) return 0;
    for (long offset = 0; offset + (long)needle_size <= size; ++offset) {
        unsigned long index = 0;
        while (index < needle_size &&
               buffer[offset + (long)index] == needle[index]) ++index;
        if (index == needle_size) return 1;
    }
    return 0;
}

static void edge_print(const char *text) {
    (void)edge_syscall6(EDGE_SYS_WRITE, 1, (long)text,
                        (long)edge_length(text), 0, 0, 0);
}

static void edge_delay(void) {
    struct edge_timespec delay = {0, 100000000};
    (void)edge_syscall6(EDGE_SYS_NANOSLEEP, (long)&delay, 0, 0, 0, 0, 0);
}

static _Noreturn void edge_exit(long status) {
    (void)edge_syscall6(EDGE_SYS_EXIT, status, 0, 0, 0, 0, 0);
    for (;;) __asm__ volatile("wfe");
}

static long edge_read_retry(long fd, char *buffer, unsigned long size,
                            int attempts) {
    for (int attempt = 0; attempt < attempts; ++attempt) {
        long count = edge_syscall6(
            EDGE_SYS_READ, fd, (long)buffer, (long)size, 0, 0, 0);
        if (count >= 0) return count;
        edge_delay();
    }
    return -1;
}

static long edge_start_qemu(char *const arguments[]) {
    static char *const environment[] = {
        "PATH=/usr/bin:/bin", "QEMU_AUDIO_DRV=none", 0,
    };
    long child = edge_syscall6(
        EDGE_SYS_CLONE, EDGE_SIGCHLD, 0, 0, 0, 0, 0);
    if (child == 0) {
        edge_print("EDGE_ARM64_MIGRATION_QEMU_EXEC_BEGIN\n");
        (void)edge_syscall6(EDGE_SYS_EXECVE, (long)arguments[0],
                            (long)arguments, (long)environment, 0, 0, 0);
        edge_print("EDGE_ARM64_MIGRATION_QEMU_EXEC_FAIL\n");
        edge_exit(126);
    }
    if (child > 0)
        edge_print("EDGE_ARM64_MIGRATION_QEMU_CHILD_READY\n");
    return child;
}

static long edge_qmp_connect(const char *path) {
    struct edge_sockaddr_un address;

    edge_print("EDGE_ARM64_MIGRATION_QMP_CONNECT_BEGIN\n");
    for (unsigned long index = 0; index < sizeof(address.path); ++index)
        address.path[index] = 0;
    address.family = EDGE_AF_UNIX;
    for (unsigned long index = 0;
         path[index] && index + 1 < sizeof(address.path); ++index)
        address.path[index] = path[index];
    for (int attempt = 0; attempt < 300; ++attempt) {
        long fd = edge_syscall6(
            EDGE_SYS_SOCKET, EDGE_AF_UNIX,
            EDGE_SOCK_STREAM | EDGE_SOCK_NONBLOCK, 0, 0, 0, 0);
        if (fd >= 0) {
            for (int connect_attempt = 0; connect_attempt < 300;
                 ++connect_attempt) {
                long result = edge_syscall6(
                    EDGE_SYS_CONNECT, fd, (long)&address,
                    sizeof(address), 0, 0, 0);
                if (result == 0 || result == -EDGE_EISCONN) {
                    edge_print("EDGE_ARM64_MIGRATION_QMP_CONNECTED\n");
                    return fd;
                }
                if (result != -EDGE_EINPROGRESS &&
                    result != -EDGE_EALREADY)
                    break;
                edge_delay();
            }
        }
        if (fd >= 0) (void)edge_syscall6(EDGE_SYS_CLOSE, fd, 0, 0, 0, 0, 0);
        edge_delay();
    }
    return -1;
}

static int edge_qmp_enable(long fd) {
    static const char command[] = "{\"execute\":\"qmp_capabilities\"}\n";
    char response[4096];
    edge_print("EDGE_ARM64_MIGRATION_QMP_ENABLE_BEGIN\n");
    if (edge_read_retry(fd, response, sizeof(response), 100) <= 0) return -1;
    edge_print("EDGE_ARM64_MIGRATION_QMP_GREETING_READY\n");
    for (int attempt = 0; attempt < 10; ++attempt)
        edge_delay();
    if (edge_syscall6(EDGE_SYS_WRITE, fd, (long)command,
                      sizeof(command) - 1, 0, 0, 0) < 0) return -1;
    if (edge_read_retry(fd, response, sizeof(response), 100) <= 0) return -1;
    edge_print("EDGE_ARM64_MIGRATION_QMP_CAPABILITIES_READY\n");
    return 0;
}

static int edge_qmp_command(long fd, const char *command) {
    return edge_syscall6(EDGE_SYS_WRITE, fd, (long)command,
                         (long)edge_length(command), 0, 0, 0) < 0 ? -1 : 0;
}

static int edge_qmp_execute(long fd, const char *command) {
    char response[16384];

    if (edge_qmp_command(fd, command) < 0) return -1;
    for (int attempt = 0; attempt < 20; ++attempt) {
        long count = edge_read_retry(fd, response, sizeof(response), 100);
        if (count <= 0) return -1;
        edge_print("EDGE_ARM64_MIGRATION_QMP_COMMAND ");
        (void)edge_syscall6(EDGE_SYS_WRITE, 1, (long)response,
                            count, 0, 0, 0);
        edge_print("\n");
        if (edge_contains(response, count, "\"return\"")) return 0;
        if (edge_contains(response, count, "\"error\"")) return -1;
    }
    return -1;
}

static int edge_qmp_wait_completed(long fd) {
    static const char query[] = "{\"execute\":\"query-migrate\"}\n";
    char response[16384];
    for (int attempt = 0; attempt < 600; ++attempt) {
        long count;
        if (edge_qmp_command(fd, query) < 0) return -1;
        count = edge_read_retry(fd, response, sizeof(response), 100);
        if (count > 0 && (attempt < 10 || attempt % 50 == 0)) {
            edge_print("EDGE_ARM64_MIGRATION_QMP_STATUS ");
            (void)edge_syscall6(EDGE_SYS_WRITE, 1, (long)response,
                                count, 0, 0, 0);
            edge_print("\n");
        }
        if (count > 0 && edge_contains(response, count, "completed")) return 0;
        if (count > 0 && edge_contains(response, count, "failed")) return -1;
        edge_delay();
    }
    return -1;
}

void _start(void) {
    static char *const source_arguments[] = {
        "/usr/bin/qemu-system-aarch64", "-machine",
        "virt,accel=kvm,gic-version=3,its=off", "-cpu", "host", "-smp", "1",
        "-m", "64M", "-S", "-display", "none", "-nodefaults", "-monitor", "none",
        "-qmp", "unix:/tmp/edge-arm64-qmp-source.sock,server=on,wait=on",
        "-serial", "stdio", "-kernel",
        "/edge-kvm-arm64-migration-guest.elf", 0,
    };
    static char *const destination_arguments[] = {
        "/usr/bin/qemu-system-aarch64", "-machine",
        "virt,accel=kvm,gic-version=3,its=off", "-cpu", "host", "-smp", "1",
        "-m", "64M", "-display", "none", "-nodefaults", "-monitor", "none",
        "-qmp", "unix:/tmp/edge-arm64-qmp-destination.sock,server=on,wait=on",
        "-serial", "stdio", "-kernel",
        "/edge-kvm-arm64-migration-guest.elf", "-incoming",
        "unix:/tmp/edge-arm64-migration.sock", 0,
    };
    static const char migrate[] =
        "{\"execute\":\"migrate\",\"arguments\":{\"uri\":\"unix:/tmp/edge-arm64-migration.sock\"}}\n";
    static const char stop[] = "{\"execute\":\"stop\"}\n";
    static const char resume[] = "{\"execute\":\"cont\"}\n";
    long source, destination, source_qmp, destination_qmp;
    int status = 0;

    (void)edge_syscall6(EDGE_SYS_MOUNT, (long)"devtmpfs", (long)"/dev",
                        (long)"devtmpfs", 0, 0, 0);
    edge_print("EDGE_ARM64_MIGRATION_STARTUP_BEGIN\n");
    source = edge_start_qemu(source_arguments);
    if (source < 0 ||
        (source_qmp = edge_qmp_connect(
            "/tmp/edge-arm64-qmp-source.sock")) < 0 ||
        edge_qmp_enable(source_qmp) < 0) {
        edge_print("EDGE_ARM64_MIGRATION_SOURCE_FAIL\n"); edge_exit(1);
    }
    destination = edge_start_qemu(destination_arguments);
    if (destination < 0 ||
        (destination_qmp = edge_qmp_connect(
            "/tmp/edge-arm64-qmp-destination.sock")) < 0 ||
        edge_qmp_enable(destination_qmp) < 0) {
        edge_print("EDGE_ARM64_MIGRATION_DESTINATION_FAIL\n"); edge_exit(1);
    }
    if (edge_qmp_execute(source_qmp, resume) < 0) {
        edge_print("EDGE_ARM64_MIGRATION_SOURCE_FAIL\n"); edge_exit(1);
    }
    edge_print("EDGE_ARM64_MIGRATION_SOURCE_QUIESCE\n");
    if (edge_qmp_execute(source_qmp, stop) < 0 ||
        edge_qmp_execute(source_qmp, migrate) < 0 ||
        edge_qmp_wait_completed(source_qmp) < 0) {
        edge_print("EDGE_ARM64_MIGRATION_SOURCE_FAIL\n"); edge_exit(1);
    }
    edge_print("EDGE_ARM64_MIGRATION_SOURCE_COMPLETE\n");
    (void)edge_syscall6(EDGE_SYS_CLOSE, source_qmp, 0, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_KILL, source, EDGE_SIGKILL, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_WAIT4, source, (long)&status, 0, 0, 0, 0);

    if (edge_qmp_wait_completed(destination_qmp) < 0 ||
        edge_qmp_execute(destination_qmp, resume) < 0) {
        edge_print("EDGE_ARM64_MIGRATION_DESTINATION_FAIL\n"); edge_exit(1);
    }
    for (int attempt = 0; attempt < 10; ++attempt)
        edge_delay();
    if (edge_qmp_execute(destination_qmp, stop) < 0) {
        edge_print("EDGE_ARM64_MIGRATION_DESTINATION_FAIL\n"); edge_exit(1);
    }
    edge_print("EDGE_ARM64_MIGRATION_DESTINATION_COMPLETE\n");
    edge_print("EDGE_ARM64_QEMU_KVM_MIGRATION_PASS\n");
    if (edge_qmp_execute(destination_qmp, resume) < 0) {
        edge_print("EDGE_ARM64_MIGRATION_DESTINATION_FAIL\n"); edge_exit(1);
    }
    for (int attempt = 0; attempt < 50; ++attempt)
        edge_delay();
    (void)edge_syscall6(EDGE_SYS_CLOSE, destination_qmp, 0, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_KILL, destination, EDGE_SIGKILL, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_WAIT4, destination, (long)&status, 0, 0, 0, 0);
    edge_exit(0);
}
