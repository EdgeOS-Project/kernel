/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 legacy identity, stat, and directory UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_open 5
#define SYS_close 6
#define SYS_unlink 10
#define SYS_lchown16 16
#define SYS_setuid16 23
#define SYS_getuid16 24
#define SYS_setgid16 46
#define SYS_getgid16 47
#define SYS_geteuid16 49
#define SYS_getegid16 50
#define SYS_setreuid16 70
#define SYS_setregid16 71
#define SYS_getgroups16 80
#define SYS_setgroups16 81
#define SYS_fchown16 95
#define SYS_stat 106
#define SYS_lstat 107
#define SYS_fstat 108
#define SYS_setfsuid16 138
#define SYS_setfsgid16 139
#define SYS_getdents 141
#define SYS_setresuid16 164
#define SYS_getresuid16 165
#define SYS_setresgid16 170
#define SYS_getresgid16 171
#define SYS_chown16 182

#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 0200000

struct ia32_stat {
    uint32_t device;
    uint32_t inode;
    uint16_t mode;
    uint16_t links;
    uint16_t uid;
    uint16_t gid;
    uint32_t special_device;
    uint32_t size;
    uint32_t block_size;
    uint32_t blocks;
    uint32_t access_time;
    uint32_t access_time_nsec;
    uint32_t modification_time;
    uint32_t modification_time_nsec;
    uint32_t change_time;
    uint32_t change_time_nsec;
    uint32_t unused4;
    uint32_t unused5;
};

struct ia32_dirent {
    uint32_t inode;
    uint32_t offset;
    uint16_t record_length;
    char name[];
};

_Static_assert(sizeof(struct ia32_stat) == 64,
               "i386 stat layout mismatch");

void *memset(void *destination, int value, uint32_t length) {
    volatile uint8_t *bytes = (volatile uint8_t *)destination;
    for (uint32_t index = 0; index < length; ++index)
        bytes[index] = (uint8_t)value;
    return destination;
}

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

static void fail(const char *name) {
    static const char prefix[] = "IA32_LEGACY_ID_STAT_UAPI_PROBE_FAIL ";
    static const char newline[] = "\n";
    call6(4, 1, prefix, sizeof(prefix) - 1u, 0, 0, 0);
    call6(4, 1, name, text_length(name), 0, 0, 0);
    call6(4, 1, newline, 1, 0, 0, 0);
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static int text_equal(const char *left, const char *right) {
    uint32_t index = 0;
    while (left[index] && right[index] && left[index] == right[index])
        ++index;
    return left[index] == right[index];
}

__attribute__((noreturn)) void _start(void) {
    static const char path[] = "/ia32-legacy-id-stat";
    static const char root_path[] = "/";
    static const char init_path[] = "/init";
    static const char pass[] = "IA32_LEGACY_ID_STAT_UAPI_PROBE_PASS\n";
    struct ia32_stat path_status = {0};
    struct ia32_stat descriptor_status = {0};
    uint8_t directory_buffer[512] = {0};
    uint16_t groups[2] = {0, 0};
    uint16_t real_id = UINT16_MAX;
    uint16_t effective_id = UINT16_MAX;
    uint16_t saved_id = UINT16_MAX;
    long descriptor;
    long directory;
    long count;
    uint32_t position;
    int saw_init = 0;

    if (call6(SYS_getuid16, 0, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_geteuid16, 0, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_getgid16, 0, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_getegid16, 0, 0, 0, 0, 0, 0) != 0)
        fail("get-id16");
    if (call6(SYS_setuid16, 0, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_setgid16, 0, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_setreuid16, UINT16_MAX, UINT16_MAX, 0, 0, 0, 0) != 0 ||
        call6(SYS_setregid16, UINT16_MAX, UINT16_MAX, 0, 0, 0, 0) != 0 ||
        call6(SYS_setresuid16, UINT16_MAX, UINT16_MAX, UINT16_MAX,
              0, 0, 0) != 0 ||
        call6(SYS_setresgid16, UINT16_MAX, UINT16_MAX, UINT16_MAX,
              0, 0, 0) != 0)
        fail("set-id16");
    if (call6(SYS_setfsuid16, UINT16_MAX, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_setfsgid16, UINT16_MAX, 0, 0, 0, 0, 0) != 0)
        fail("set-fsid16");
    if (call6(SYS_getresuid16, &real_id, &effective_id, &saved_id,
              0, 0, 0) != 0 || real_id != 0 || effective_id != 0 ||
        saved_id != 0)
        fail("getresuid16");
    real_id = effective_id = saved_id = UINT16_MAX;
    if (call6(SYS_getresgid16, &real_id, &effective_id, &saved_id,
              0, 0, 0) != 0 || real_id != 0 || effective_id != 0 ||
        saved_id != 0)
        fail("getresgid16");

    groups[0] = 0;
    if (call6(SYS_setgroups16, 1, groups, 0, 0, 0, 0) != 0 ||
        call6(SYS_getgroups16, 0, 0, 0, 0, 0, 0) != 1 ||
        call6(SYS_getgroups16, 1, groups, 0, 0, 0, 0) != 1 ||
        groups[0] != 0)
        fail("groups16");

    descriptor = call6(SYS_open, path, O_CREAT | O_TRUNC | O_RDWR,
                       0600, 0, 0, 0);
    if (descriptor < 0) fail("open");
    if (call6(SYS_chown16, path, UINT16_MAX, UINT16_MAX, 0, 0, 0) != 0 ||
        call6(SYS_lchown16, path, UINT16_MAX, UINT16_MAX, 0, 0, 0) != 0 ||
        call6(SYS_fchown16, descriptor, UINT16_MAX, UINT16_MAX,
              0, 0, 0) != 0)
        fail("chown16");
    if (call6(SYS_stat, path, &path_status, 0, 0, 0, 0) != 0 ||
        call6(SYS_lstat, path, &path_status, 0, 0, 0, 0) != 0 ||
        call6(SYS_fstat, descriptor, &descriptor_status, 0, 0, 0, 0) != 0)
        fail("stat");
    if (path_status.inode == 0 || path_status.mode != descriptor_status.mode ||
        path_status.uid != 0 || path_status.gid != 0 ||
        path_status.block_size == 0)
        fail("stat-layout");

    directory = call6(SYS_open, root_path, O_RDONLY | O_DIRECTORY,
                      0, 0, 0, 0);
    if (directory < 0) fail("open-directory");
    count = call6(SYS_getdents, directory, directory_buffer,
                  sizeof(directory_buffer), 0, 0, 0);
    if (count <= 0) fail("getdents");
    position = 0;
    while (position < (uint32_t)count) {
        const struct ia32_dirent *entry =
            (const struct ia32_dirent *)(const void *)(directory_buffer +
                                                       position);
        if (entry->record_length < 12u ||
            (entry->record_length & 3u) != 0 ||
            entry->record_length > (uint32_t)count - position)
            fail("getdents-layout");
        if (text_equal(entry->name, init_path + 1)) saw_init = 1;
        position += entry->record_length;
    }
    if (!saw_init) fail("getdents-entry");

    if (call6(SYS_close, directory, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_close, descriptor, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_unlink, path, 0, 0, 0, 0, 0) != 0)
        fail("cleanup");
    call6(4, 1, pass, sizeof(pass) - 1u, 0, 0, 0);
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
