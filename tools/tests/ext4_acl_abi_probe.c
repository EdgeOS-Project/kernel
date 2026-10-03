/* SPDX-License-Identifier: MPL-2.0 */
/* Run as root on EdgeOS and matched Linux. Mutations stay in one mkdtemp tree. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define ACCESS_ACL "system.posix_acl_access"
#define DEFAULT_ACL "system.posix_acl_default"
#define TEST_UID 65534u
#define TEST_GID 65533u
static int failures;
static char tree[4096], file_path[4096], dir_path[4096];
static int file_created, dir_created;

static void check(int ok, const char *label) {
    int saved = errno;
    printf("ACL_CHECK %s %s", label, ok ? "PASS" : "FAIL");
    if (!ok) { printf(" errno=%d (%s)", saved, strerror(saved)); ++failures; }
    putchar('\n'); fflush(stdout);
}
static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void entry(uint8_t *p, uint16_t tag, uint16_t perm, uint32_t id) {
    p[0] = tag; p[1] = tag >> 8; p[2] = perm; p[3] = perm >> 8;
    for (unsigned i = 0; i < 4; ++i) p[4 + i] = id >> (8 * i);
}
static void make_acl(uint8_t acl[52]) {
    memset(acl, 0, 52); acl[0] = 2;
    entry(acl + 4, 1, 6, UINT32_MAX);
    entry(acl + 12, 2, 6, TEST_UID);
    entry(acl + 20, 4, 0, UINT32_MAX);
    entry(acl + 28, 8, 4, TEST_GID);
    entry(acl + 36, 16, 6, UINT32_MAX);
    entry(acl + 44, 32, 0, UINT32_MAX);
}
static void verify_mode(const char *path, mode_t expected, const char *label) {
    struct stat st;
    int rc = stat(path, &st);
    if (rc == 0) printf("ACL_MODE %s actual=%04o expected=%04o\n",
                        label, st.st_mode & 07777, expected);
    check(rc == 0 && (st.st_mode & 07777) == expected, label);
}
static void verify_acl(const char *path, const char *key,
                       const uint8_t expected[52], const char *label) {
    uint8_t bytes[64];
    ssize_t size = getxattr(path, key, bytes, sizeof(bytes));
    check(size == 52 && !memcmp(bytes, expected, 52), label);
}
static int open_result(int flags, int allowed) {
    errno = 0;
    int fd = open(file_path, flags | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    if (fd >= 0) close(fd);
    return allowed ? fd >= 0 : fd < 0 && saved == EACCES;
}
static void child_access(int read_allowed, int write_allowed, const char *label) {
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
        struct __user_cap_data_struct caps[2] = {{0}};
        uid_t real, effective, saved;
        if (setgroups(0, NULL) || setresgid(TEST_UID, TEST_UID, TEST_UID) ||
            setresuid(TEST_UID, TEST_UID, TEST_UID) ||
            getresuid(&real, &effective, &saved) ||
            real != TEST_UID || effective != TEST_UID || saved != TEST_UID ||
            (uid_t)setfsuid((uid_t)-1) != TEST_UID || getgroups(0, NULL) != 0 ||
            syscall(SYS_capget, &header, caps) || caps[0].effective ||
            caps[1].effective || caps[0].permitted || caps[1].permitted)
            _exit(90);
        if (!open_result(O_RDONLY, read_allowed)) _exit(91);
        if (!open_result(O_WRONLY, write_allowed)) _exit(92);
        _exit(0);
    }
    int status = 0;
    pid_t waited;
    if (pid < 0) { check(0, label); return; }
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    printf("ACL_CHILD %s status=%d uid=%u capabilities=zero-required\n", label, status, TEST_UID);
    check(waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, label);
}
static void journal_check(const char *path) {
    /* Expected Linux ABI for the independently inspected 28-byte disk-v1 ACL. */
    static const uint8_t expected[] = {
        2,0,0,0, 1,0,7,0,255,255,255,255, 4,0,5,0,255,255,255,255,
        8,0,5,0,4,0,0,0, 16,0,5,0,255,255,255,255, 32,0,5,0,255,255,255,255
    };
    uint8_t bytes[4096];
    ssize_t size = getxattr(path, ACCESS_ACL, bytes, sizeof(bytes));
    int valid = size >= 28 && (size - 4) % 8 == 0 && read32(bytes) == 2;
    printf("ACL_JOURNAL path=%s bytes=%ld version=%u\n", path, (long)size,
           size >= 4 ? read32(bytes) : 0);
    check(valid, "journal_linux_xattr_v2");
    check(size == (ssize_t)sizeof(expected) && !memcmp(bytes, expected, sizeof(expected)),
          "journal_known_disk_fixture_28_to_44");
    if (valid) {
        check(getxattr(path, ACCESS_ACL, NULL, 0) == size, "journal_size_query");
        errno = 0;
        check(getxattr(path, ACCESS_ACL, bytes, (size_t)size - 1) == -1 && errno == ERANGE,
              "journal_short_buffer_erange");
    }
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    check(fd >= 0, "root_original_journal_open");
    if (fd >= 0) close(fd);
}
int main(int argc, char **argv) {
    const char *base = "/var/tmp", *journal = "/var/log/journal";
    if (argc > 3 || (argc > 1 && !strcmp(argv[1], "--help"))) {
        printf("Usage: %s [ext4-temp-parent [journal-directory]]\nRun as root; default: /var/tmp /var/log/journal\n", argv[0]);
        return argc > 3 ? 2 : 0;
    }
    if (argc > 1) base = argv[1];
    if (argc > 2) journal = argv[2];
    if (geteuid() != 0 || getuid() != 0) {
        fprintf(stderr, "ACL_SETUP FAIL: real/effective root required\n"); return 2;
    }
    journal_check(journal);
    if (snprintf(tree, sizeof(tree), "%s/edgeos-acl-XXXXXX", base) >= (int)sizeof(tree)) return 2;
    if (!mkdtemp(tree)) { perror("mkdtemp"); return 2; }
    printf("ACL_TEMP %s\n", tree); fflush(stdout);
    int fd = -1;
    struct statfs filesystem;
    int on_ext4 = statfs(tree, &filesystem) == 0 && filesystem.f_type == 0xef53;
    check(on_ext4, "private_fixture_on_ext4");
    if (!on_ext4) goto cleanup;
    if (chmod(tree, 0755) ||
        snprintf(file_path, sizeof(file_path), "%s/access", tree) >= (int)sizeof(file_path) ||
        snprintf(dir_path, sizeof(dir_path), "%s/default", tree) >= (int)sizeof(dir_path)) {
        check(0, "private_fixture_setup"); goto cleanup;
    }
    fd = open(file_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    check(fd >= 0, "create_private_file");
    if (fd < 0) goto cleanup;
    file_created = 1;
    uint8_t acl[52], changed[52]; make_acl(acl);
    check(fsetxattr(fd, ACCESS_ACL, acl, 52, 0) == 0, "set_named_access_acl");
    check(fsync(fd) == 0, "fsync_access_acl");
    close(fd); fd = -1;
    verify_acl(file_path, ACCESS_ACL, acl, "closed_reopened_named_acl");
    verify_mode(file_path, 0660, "access_acl_updates_mode");
    child_access(1, 1, "named_uid_initial_read_write");
    check(chmod(file_path, 0000) == 0, "chmod_000");
    verify_mode(file_path, 0000, "mode_000");
    memcpy(changed, acl, 52); changed[6] = changed[38] = changed[46] = 0;
    verify_acl(file_path, ACCESS_ACL, changed, "chmod_000_preserves_named_entries_ids");
    child_access(0, 0, "named_uid_000_denies_read_write");
    check(chmod(file_path, 0640) == 0, "chmod_0640");
    verify_mode(file_path, 0640, "mode_0640");
    changed[6] = 6; changed[38] = 4;
    verify_acl(file_path, ACCESS_ACL, changed, "chmod_0640_preserves_named_entries_ids");
    child_access(1, 0, "named_uid_0640_read_only");
    fd = open(file_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    check(fd >= 0 && fsync(fd) == 0, "fsync_chmod_acl");
    if (fd >= 0) { close(fd); fd = -1; }
    verify_acl(file_path, ACCESS_ACL, changed, "persisted_chmod_acl_readback");
    if (mkdir(dir_path, 0700)) { check(0, "create_default_acl_directory"); goto cleanup; }
    dir_created = 1;
    check(chmod(dir_path, 0710) == 0, "default_directory_initial_mode");
    check(setxattr(dir_path, DEFAULT_ACL, acl, 52, 0) == 0, "set_default_acl");
    verify_mode(dir_path, 0710, "default_acl_leaves_mode");
    check(chmod(dir_path, 0750) == 0, "chmod_default_directory");
    verify_acl(dir_path, DEFAULT_ACL, acl, "chmod_leaves_default_acl_unchanged");
    verify_mode(dir_path, 0750, "default_directory_final_mode");
cleanup:
    if (fd >= 0) close(fd);
    if (file_created) check(unlink(file_path) == 0, "cleanup_private_file");
    if (dir_created) check(rmdir(dir_path) == 0, "cleanup_private_directory");
    check(rmdir(tree) == 0, "cleanup_private_tree");
    printf("EXT4_ACL_ABI %s failures=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
