/* EdgeOS PID 1 for the nested ARM64 Linux boot and performance test. */

#include <stdint.h>

#define EDGE_SYS_MOUNT 40
#define EDGE_SYS_WRITE 64
#define EDGE_SYS_EXIT 93
#define EDGE_SYS_CLONE 220
#define EDGE_SYS_EXECVE 221
#define EDGE_SYS_WAIT4 260

#define EDGE_SIGCHLD 17

static long edge_syscall6(long number, long a0, long a1, long a2, long a3,
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

static unsigned long edge_length(const char *text)
{
    unsigned long length = 0;

    while (text[length] != '\0')
        length++;
    return length;
}

static void edge_print(const char *text)
{
    (void)edge_syscall6(
        EDGE_SYS_WRITE, 1, (long)text, (long)edge_length(text), 0, 0, 0);
}

static void edge_exit(long status)
{
    (void)edge_syscall6(EDGE_SYS_EXIT, status, 0, 0, 0, 0, 0);
    for (;;)
        __asm__ volatile("wfe");
}

void _start(void)
{
    static char *const arguments[] = {
        "/usr/bin/qemu-system-aarch64",
        "-machine", "virt,accel=kvm,gic-version=3,its=off",
        "-cpu", "host",
        "-smp", "1",
        "-m", "128M",
        "-display", "none",
        "-nodefaults",
        "-monitor", "none",
        "-serial", "stdio",
        "-no-reboot",
        "-kernel", "/edge-linux-arm64",
        "-initrd", "/edge-linux-benchmark-initramfs.cpio.gz",
        "-append", "console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init panic=-1 ignore_loglevel cpuidle.off=1 nohz=off",
        0,
    };
    static char *const environment[] = {
        "PATH=/usr/bin:/bin",
        "QEMU_AUDIO_DRV=none",
        0,
    };
    int status = 0;
    long child;
    long waited;

    (void)edge_syscall6(
        EDGE_SYS_MOUNT, (long)"devtmpfs", (long)"/dev",
        (long)"devtmpfs", 0, 0, 0);
    edge_print("EDGE_ARM64_LINUX_QEMU_STARTUP_BEGIN\n");

    child = edge_syscall6(EDGE_SYS_CLONE, EDGE_SIGCHLD, 0, 0, 0, 0, 0);
    if (child == 0) {
        (void)edge_syscall6(
            EDGE_SYS_EXECVE, (long)arguments[0],
            (long)arguments, (long)environment, 0, 0, 0);
        edge_print("EDGE_ARM64_LINUX_QEMU_EXEC_FAIL\n");
        edge_exit(126);
    }
    if (child < 0) {
        edge_print("EDGE_ARM64_LINUX_QEMU_CLONE_FAIL\n");
        edge_exit(1);
    }

    waited = edge_syscall6(EDGE_SYS_WAIT4, child, (long)&status, 0, 0, 0, 0);
    if (waited == child && status == 0) {
        edge_print("EDGE_ARM64_LINUX_QEMU_EXECUTION_PASS\n");
        edge_exit(0);
    }

    edge_print("EDGE_ARM64_LINUX_QEMU_EXECUTION_FAIL\n");
    edge_exit(1);
}
