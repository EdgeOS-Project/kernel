/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise concurrent file-backed faults, mapped writes, and sync. */

#if !defined(__aarch64__)
#error "This probe targets AArch64"
#endif

#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_ftruncate 46
#define SYS_openat 56
#define SYS_close 57
#define SYS_pread64 67
#define SYS_write 64
#define SYS_fsync 82
#define SYS_exit 93
#define SYS_sched_yield 124
#define SYS_munmap 215
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_msync 227
#define SYS_wait4 260

#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 64
#define O_TRUNC 512
#define SIGCHLD 17
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MS_SYNC 4
#define PAGE_SIZE 4096
#define WORKERS 4
#define ROUNDS 24

static long call(long number, long a0, long a1, long a2,
                 long a3, long a4, long a5) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}

static void say(const char *message) {
    unsigned long length = 0;
    while (message[length]) ++length;
    (void)call(SYS_write, 1, (long)message, length, 0, 0, 0);
}

static void say_number(long value) {
    char digits[24];
    unsigned long magnitude;
    int count = 0;
    if (value < 0) {
        say("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    while (count--) {
        (void)call(SYS_write, 1, (long)&digits[count], 1, 0, 0, 0);
    }
    say("\n");
}

static __attribute__((noreturn)) void leave(int status) {
    (void)call(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) {}
}

static int worker(int fd, int index) {
    long offset = (long)index * PAGE_SIZE;
    for (int round = 0; round < ROUNDS; ++round) {
        long mapped = call(SYS_mmap, 0, PAGE_SIZE,
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
        unsigned char expected = (unsigned char)(index * ROUNDS + round + 1);
        unsigned char observed = 0;
        volatile unsigned char *page;
        if (mapped < 0) return 1;
        page = (volatile unsigned char *)mapped;
        page[0] = expected;
        page[PAGE_SIZE - 1] = expected;
        if (call(SYS_msync, mapped, PAGE_SIZE, MS_SYNC, 0, 0, 0) != 0 ||
            call(SYS_fsync, fd, 0, 0, 0, 0, 0) != 0 ||
            call(SYS_pread64, fd, (long)&observed, 1,
                 offset, 0, 0) != 1 ||
            observed != expected || page[PAGE_SIZE - 1] != expected ||
            call(SYS_munmap, mapped, PAGE_SIZE, 0, 0, 0, 0) != 0)
            return 2;
        (void)call(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    return 0;
}

void _start(void) {
    static const char path[] = "/mnt/tmp/edgeos-file-page-stress.bin";
    long children[WORKERS];
    int launched = 0;
    int failed = 0;
    long fd;
    long mount_vdb;
    long mount_vda = 0;
    long probe_fd;
    long mount_dev;

    say("FILE_PAGE_START\n");
    (void)call(SYS_mkdirat, AT_FDCWD, (long)"/dev", 0755, 0, 0, 0);
    mount_dev = call(SYS_mount, (long)"devtmpfs", (long)"/dev",
                     (long)"devtmpfs", 0, 0, 0);
    if (mount_dev != 0) {
        say("MOUNT_DEV=");
        say_number(mount_dev);
        say("FILE_PAGE_DEV_FAIL\n");
        leave(1);
    }
    say("MKDIR_MNT=");
    say_number(call(SYS_mkdirat, AT_FDCWD, (long)"/mnt", 0755, 0, 0, 0));
    probe_fd = call(SYS_openat, AT_FDCWD, (long)"/mnt", 0, 0, 0, 0);
    say("OPEN_MNT=");
    say_number(probe_fd);
    if (probe_fd >= 0) (void)call(SYS_close, probe_fd, 0, 0, 0, 0, 0);
    probe_fd = call(SYS_openat, AT_FDCWD, (long)"/dev/vdb", 0, 0, 0, 0);
    say("OPEN_VDB=");
    say_number(probe_fd);
    if (probe_fd >= 0) (void)call(SYS_close, probe_fd, 0, 0, 0, 0, 0);
    probe_fd = call(SYS_openat, AT_FDCWD, (long)"/dev/vda", 0, 0, 0, 0);
    say("OPEN_VDA=");
    say_number(probe_fd);
    if (probe_fd >= 0) (void)call(SYS_close, probe_fd, 0, 0, 0, 0, 0);
    mount_vdb = call(SYS_mount, (long)"/dev/vdb", (long)"/mnt",
                     (long)"ext4", 0, 0, 0);
    if (mount_vdb != 0)
        mount_vda = call(SYS_mount, (long)"/dev/vda", (long)"/mnt",
                         (long)"ext4", 0, 0, 0);
    if (mount_vdb != 0 && mount_vda != 0) {
        say("MOUNT_VDB=");
        say_number(mount_vdb);
        say("MOUNT_VDA=");
        say_number(mount_vda);
        say("FILE_PAGE_MOUNT_FAIL\n");
        leave(1);
    }
    fd = call(SYS_openat, AT_FDCWD, (long)path,
              O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
    if (fd < 0 || call(SYS_ftruncate, fd, WORKERS * PAGE_SIZE,
                       0, 0, 0, 0) != 0) {
        say("FILE_PAGE_OPEN_FAIL\n");
        leave(2);
    }
    for (int index = 0; index < WORKERS; ++index) {
        long child = call(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (child < 0) {
            failed = 1;
            break;
        }
        if (child == 0) leave(worker((int)fd, index));
        children[launched++] = child;
    }
    for (int index = 0; index < launched; ++index) {
        int status = -1;
        if (call(SYS_wait4, children[index], (long)&status,
                 0, 0, 0, 0) != children[index] || status != 0)
            failed = 1;
    }
    if (call(SYS_close, fd, 0, 0, 0, 0, 0) != 0) failed = 1;
    say(failed ? "FILE_PAGE_FAIL\n" : "FILE_PAGE_PASS\n");
    for (;;) (void)call(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
}
