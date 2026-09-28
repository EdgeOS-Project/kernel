/* PID 1 for unmodified QEMU x86 KVM migration acceptance on EdgeOS. */

#define EDGE_SYS_READ 0
#define EDGE_SYS_WRITE 1
#define EDGE_SYS_OPEN 2
#define EDGE_SYS_CLOSE 3
#define EDGE_SYS_NANOSLEEP 35
#define EDGE_SYS_SOCKET 41
#define EDGE_SYS_CONNECT 42
#define EDGE_SYS_CLONE 56
#define EDGE_SYS_EXECVE 59
#define EDGE_SYS_EXIT 60
#define EDGE_SYS_WAIT4 61
#define EDGE_SYS_KILL 62
#define EDGE_SYS_MOUNT 165

#define EDGE_AF_UNIX 1
#define EDGE_SOCK_STREAM 1
#define EDGE_SIGCHLD 17
#define EDGE_SIGKILL 9

struct edge_timespec {
    long seconds;
    long nanoseconds;
};

struct edge_sockaddr_un {
    unsigned short family;
    char path[108];
};

static long edge_syscall6(long number, long a0, long a1, long a2, long a3,
                          long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory", "cc");
    return result;
}

static unsigned long edge_length(const char *text) {
    unsigned long length = 0;

    while (text[length] != '\0')
        ++length;
    return length;
}

static int edge_contains(const char *buffer, long size, const char *needle) {
    unsigned long needle_size = edge_length(needle);

    if (size < 0 || (unsigned long)size < needle_size)
        return 0;
    for (long offset = 0;
         offset + (long)needle_size <= size; ++offset) {
        unsigned long index = 0;

        while (index < needle_size &&
               buffer[offset + (long)index] == needle[index])
            ++index;
        if (index == needle_size)
            return 1;
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
    for (;;)
        __asm__ volatile("pause");
}

static long edge_start_qemu(char *const arguments[]) {
    static char *const environment[] = {
        "PATH=/usr/bin:/bin",
        "QEMU_AUDIO_DRV=none",
        0,
    };
    long child = edge_syscall6(
        EDGE_SYS_CLONE, EDGE_SIGCHLD, 0, 0, 0, 0, 0);

    if (child == 0) {
        (void)edge_syscall6(EDGE_SYS_EXECVE, (long)arguments[0],
                            (long)arguments, (long)environment, 0, 0, 0);
        edge_print("EDGE_X86_MIGRATION_QEMU_EXEC_FAIL\n");
        edge_exit(126);
    }
    return child;
}

static long edge_qmp_connect(const char *path) {
    struct edge_sockaddr_un address;

    address.family = EDGE_AF_UNIX;
    for (unsigned long index = 0; index < sizeof(address.path); ++index)
        address.path[index] = 0;
    for (unsigned long index = 0;
         path[index] && index + 1 < sizeof(address.path); ++index)
        address.path[index] = path[index];

    for (int attempt = 0; attempt < 200; ++attempt) {
        long descriptor = edge_syscall6(
            EDGE_SYS_SOCKET, EDGE_AF_UNIX, EDGE_SOCK_STREAM, 0, 0, 0, 0);

        if (descriptor >= 0 &&
            edge_syscall6(EDGE_SYS_CONNECT, descriptor, (long)&address,
                          sizeof(address), 0, 0, 0) == 0)
            return descriptor;
        if (descriptor >= 0)
            (void)edge_syscall6(
                EDGE_SYS_CLOSE, descriptor, 0, 0, 0, 0, 0);
        edge_delay();
    }
    return -1;
}

static int edge_qmp_enable(long descriptor) {
    static const char command[] =
        "{\"execute\":\"qmp_capabilities\"}\n";
    char response[4096];

    if (edge_syscall6(EDGE_SYS_READ, descriptor, (long)response,
                      sizeof(response), 0, 0, 0) <= 0)
        return -1;
    if (edge_syscall6(EDGE_SYS_WRITE, descriptor, (long)command,
                      sizeof(command) - 1, 0, 0, 0) < 0)
        return -1;
    return edge_syscall6(EDGE_SYS_READ, descriptor, (long)response,
                         sizeof(response), 0, 0, 0) > 0 ? 0 : -1;
}

static int edge_qmp_command(long descriptor, const char *command) {
    return edge_syscall6(EDGE_SYS_WRITE, descriptor, (long)command,
                         (long)edge_length(command), 0, 0, 0) < 0 ? -1 : 0;
}

static int edge_qmp_wait_completed(long descriptor) {
    static const char query[] = "{\"execute\":\"query-migrate\"}\n";
    char response[16384];

    for (int attempt = 0; attempt < 600; ++attempt) {
        long count;

        if (edge_qmp_command(descriptor, query) < 0)
            return -1;
        count = edge_syscall6(EDGE_SYS_READ, descriptor, (long)response,
                              sizeof(response), 0, 0, 0);
        if (count > 0 && edge_contains(response, count, "completed"))
            return 0;
        if (count > 0 && edge_contains(response, count, "failed"))
            return -1;
        edge_delay();
    }
    return -1;
}

static int edge_file_wait_marker(const char *path, const char *marker,
                                 int attempts) {
    char response[4096];

    for (int attempt = 0; attempt < attempts; ++attempt) {
        long descriptor = edge_syscall6(
            EDGE_SYS_OPEN, (long)path, 0, 0, 0, 0, 0);

        if (descriptor >= 0) {
            long count = edge_syscall6(
                EDGE_SYS_READ, descriptor, (long)response,
                sizeof(response), 0, 0, 0);
            (void)edge_syscall6(
                EDGE_SYS_CLOSE, descriptor, 0, 0, 0, 0, 0);
            if (count > 0 && edge_contains(response, count, marker)) {
                edge_print(marker);
                edge_print("\n");
                return 0;
            }
        }
        edge_delay();
    }
    return -1;
}

void _start(void) {
    static char *const source_arguments[] = {
        "/usr/bin/qemu-system-x86_64",
        "-machine", "pc,accel=kvm",
        "-cpu", "host",
        "-smp", "1",
        "-m", "128M",
        "-display", "none",
        "-vga", "none",
        "-monitor", "none",
        "-bios", "/usr/share/seabios/bios-256k.bin",
        "-qmp", "unix:/tmp/edge-kvm-qmp-source.sock,server=on,wait=off",
        "-chardev", "file,id=debug,path=/tmp/edge-kvm-debug-source.log",
        "-device", "isa-debugcon,iobase=0xe9,chardev=debug",
        "-drive", "file=/tmp/edge-kvm-migration-guest.img,format=raw,if=ide,index=0,media=disk",
        "-boot", "order=c",
        0,
    };
    static char *const destination_arguments[] = {
        "/usr/bin/qemu-system-x86_64",
        "-machine", "pc,accel=kvm",
        "-cpu", "host",
        "-smp", "1",
        "-m", "128M",
        "-display", "none",
        "-vga", "none",
        "-monitor", "none",
        "-bios", "/usr/share/seabios/bios-256k.bin",
        "-qmp", "unix:/tmp/edge-kvm-qmp-destination.sock,server=on,wait=off",
        "-chardev", "file,id=debug,path=/tmp/edge-kvm-debug-destination.log",
        "-device", "isa-debugcon,iobase=0xe9,chardev=debug",
        "-drive", "file=/tmp/edge-kvm-migration-guest.img,format=raw,if=ide,index=0,media=disk",
        "-boot", "order=c",
        "-incoming", "defer",
        0,
    };
    static const char migrate[] =
        "{\"execute\":\"migrate\",\"arguments\":{\"uri\":\"file:/tmp/edge-kvm-migration.state\"}}\n";
    static const char incoming[] =
        "{\"execute\":\"migrate-incoming\",\"arguments\":{\"uri\":\"file:/tmp/edge-kvm-migration.state\"}}\n";
    long source;
    long destination;
    long qmp;
    int status = 0;

    (void)edge_syscall6(EDGE_SYS_MOUNT, (long)"devtmpfs", (long)"/dev",
                        (long)"devtmpfs", 0, 0, 0);
    edge_print("EDGE_X86_MIGRATION_STARTUP_BEGIN\n");
    source = edge_start_qemu(source_arguments);
    if (source < 0 ||
        (qmp = edge_qmp_connect("/tmp/edge-kvm-qmp-source.sock")) < 0 ||
        edge_qmp_enable(qmp) < 0 ||
        edge_file_wait_marker(
            "/tmp/edge-kvm-debug-source.log",
            "EDGE_X86_MIGRATION_SOURCE_RUNNING", 300) < 0 ||
        edge_qmp_command(qmp, migrate) < 0 ||
        edge_qmp_wait_completed(qmp) < 0) {
        edge_print("EDGE_X86_MIGRATION_SOURCE_FAIL\n");
        edge_exit(1);
    }
    edge_print("EDGE_X86_MIGRATION_SOURCE_COMPLETE\n");
    (void)edge_syscall6(EDGE_SYS_CLOSE, qmp, 0, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_KILL, source, EDGE_SIGKILL, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_WAIT4, source, (long)&status, 0, 0, 0, 0);

    destination = edge_start_qemu(destination_arguments);
    if (destination < 0 ||
        (qmp = edge_qmp_connect("/tmp/edge-kvm-qmp-destination.sock")) < 0 ||
        edge_qmp_enable(qmp) < 0 ||
        edge_qmp_command(qmp, incoming) < 0 ||
        edge_qmp_wait_completed(qmp) < 0) {
        edge_print("EDGE_X86_MIGRATION_DESTINATION_FAIL\n");
        edge_exit(1);
    }
    edge_print("EDGE_X86_MIGRATION_DESTINATION_COMPLETE\n");
    if (edge_file_wait_marker(
            "/tmp/edge-kvm-debug-destination.log",
            "EDGE_X86_MIGRATION_RESUME_HEARTBEAT", 600) < 0) {
        edge_print("EDGE_X86_MIGRATION_RESUME_FAIL\n");
        edge_exit(1);
    }
    edge_print("EDGE_X86_QEMU_KVM_MIGRATION_PASS\n");
    (void)edge_syscall6(EDGE_SYS_CLOSE, qmp, 0, 0, 0, 0, 0);
    (void)edge_syscall6(
        EDGE_SYS_KILL, destination, EDGE_SIGKILL, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_WAIT4, destination, (long)&status,
                        0, 0, 0, 0);
    edge_exit(0);
}
