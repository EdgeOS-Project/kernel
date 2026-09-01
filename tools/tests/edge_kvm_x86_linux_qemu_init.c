/* EdgeOS PID 1 for the nested x86_64 Linux boot and performance test. */

#define EDGE_SYS_WRITE 1
#define EDGE_SYS_CLONE 56
#define EDGE_SYS_EXECVE 59
#define EDGE_SYS_EXIT 60
#define EDGE_SYS_WAIT4 61
#define EDGE_SYS_MOUNT 165
#define EDGE_SYS_REBOOT 169

#define EDGE_SIGCHLD 17
#define EDGE_REBOOT_MAGIC1 0xfee1dead
#define EDGE_REBOOT_MAGIC2 672274793
#define EDGE_REBOOT_CMD_POWER_OFF 0x4321fedc

static long edge_syscall6(long number, long a0, long a1, long a2, long a3,
                          long a4, long a5)
{
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
        __asm__ volatile("pause");
}

static void edge_poweroff(long fallback_status)
{
    (void)edge_syscall6(
        EDGE_SYS_REBOOT, EDGE_REBOOT_MAGIC1, EDGE_REBOOT_MAGIC2,
        EDGE_REBOOT_CMD_POWER_OFF, 0, 0, 0);
    edge_exit(fallback_status);
}

static int edge_is_intel(void)
{
    unsigned int eax = 0;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;

    __asm__ volatile("cpuid"
                     : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    return ebx == 0x756e6547u && edx == 0x49656e69u &&
           ecx == 0x6c65746eu;
}

void _start(void)
{
    static char normal_command_line[] =
        "console=ttyS0 earlyprintk=serial rdinit=/init panic=-1 "
        "ignore_loglevel nohz=off tsc=reliable lpj=2890000";
    static char intel_command_line[] =
        "console=ttyS0 earlyprintk=serial rdinit=/init panic=-1 "
        "ignore_loglevel nohz=off tsc=reliable lpj=2890000";
    static char *arguments[] = {
        "/usr/bin/qemu-system-x86_64",
        "-machine", "pc,accel=kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", "512M",
        "-display", "none",
        "-nodefaults",
        "-monitor", "none",
        "-serial", "stdio",
        "-no-reboot",
        "-kernel", "/edge-linux-x86_64",
        "-initrd", "/edge-linux-x86-benchmark-initramfs.cpio.gz",
        "-append", normal_command_line,
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

    if (edge_is_intel())
        arguments[(sizeof(arguments) / sizeof(arguments[0])) - 2] =
            intel_command_line;

    (void)edge_syscall6(
        EDGE_SYS_MOUNT, (long)"devtmpfs", (long)"/dev",
        (long)"devtmpfs", 0, 0, 0);
    edge_print("EDGE_X86_LINUX_QEMU_STARTUP_BEGIN\n");

    child = edge_syscall6(EDGE_SYS_CLONE, EDGE_SIGCHLD, 0, 0, 0, 0, 0);
    if (child == 0) {
        (void)edge_syscall6(
            EDGE_SYS_EXECVE, (long)arguments[0],
            (long)arguments, (long)environment, 0, 0, 0);
        edge_print("EDGE_X86_LINUX_QEMU_EXEC_FAIL\n");
        edge_exit(126);
    }
    if (child < 0) {
        edge_print("EDGE_X86_LINUX_QEMU_CLONE_FAIL\n");
        edge_exit(1);
    }

    waited = edge_syscall6(EDGE_SYS_WAIT4, child, (long)&status, 0, 0, 0, 0);
    if (waited == child && status == 0) {
        edge_print("EDGE_X86_LINUX_QEMU_EXECUTION_PASS\n");
        edge_poweroff(0);
    }

    edge_print("EDGE_X86_LINUX_QEMU_EXECUTION_FAIL\n");
    edge_poweroff(1);
}
