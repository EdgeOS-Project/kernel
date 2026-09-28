#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static int join_path(char *destination, size_t capacity,
                     const char *directory, const char *name) {
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    if (directory_length + name_length + 2u > capacity) return -1;
    memcpy(destination, directory, directory_length);
    destination[directory_length] = '/';
    memcpy(destination + directory_length + 1u, name, name_length + 1u);
    return 0;
}

static void check_value(const char *name, long actual, long expected) {
    if (actual == expected) {
        printf("%s:ok\n", name);
        return;
    }
    printf("%s:fail actual:%ld expected:%ld\n", name, actual, expected);
    ++failures;
}

static void check_text(const char *name, const char *actual,
                       const char *expected) {
    if (actual && expected && strcmp(actual, expected) == 0) {
        printf("%s:ok\n", name);
        return;
    }
    printf("%s:fail actual:%s expected:%s\n", name,
           actual ? actual : "(null)", expected ? expected : "(null)");
    ++failures;
}

static void check_errno(const char *name, long result, int actual_errno,
                        int expected_errno) {
    if (result == -1 && actual_errno == expected_errno) {
        printf("%s:ok\n", name);
        return;
    }
    printf("%s:fail result:%ld errno:%d expected_errno:%d\n",
           name, result, actual_errno, expected_errno);
    ++failures;
}

static long raw_getcwd(char *buffer, size_t size) {
    errno = 0;
    return syscall(SYS_getcwd, buffer, size);
}

static long raw_chdir(const char *path) {
    errno = 0;
    return syscall(SYS_chdir, path);
}

static long raw_fchdir(int descriptor) {
    errno = 0;
    return syscall(SYS_fchdir, descriptor);
}

struct thread_change {
    const char *path;
    int start_fd;
    long result;
    int error;
};

static void *thread_chdir(void *opaque) {
    struct thread_change *change = opaque;
    char command;
    if (change->start_fd >= 0 && read(change->start_fd, &command, 1) != 1) {
        change->result = -1;
        change->error = EIO;
        return 0;
    }
    errno = 0;
    change->result = syscall(SYS_chdir, change->path);
    change->error = errno;
    return 0;
}

struct chroot_result {
    int chroot_ok;
    int unreachable_ok;
    int root_cwd_ok;
    int inside_visible;
    int escape_blocked;
    int dotdot_clamped;
};

static void run_chroot_child(const char *base, const char *root,
                             int result_fd) {
    struct chroot_result result = {0};
    char cwd[PATH_MAX];
    char expected[PATH_MAX + 32];
    struct stat status;
    long length;

    if (chdir(base) == 0 && syscall(SYS_chroot, root) == 0)
        result.chroot_ok = 1;
    snprintf(expected, sizeof(expected), "(unreachable)%s", base);
    length = raw_getcwd(cwd, sizeof(cwd));
    if (length > 0 && strcmp(cwd, expected) == 0)
        result.unreachable_ok = 1;
    if (raw_chdir("/") == 0) {
        length = raw_getcwd(cwd, sizeof(cwd));
        if (length > 0 && strcmp(cwd, "/") == 0)
            result.root_cwd_ok = 1;
    }
    if (stat("/inside", &status) == 0 && S_ISDIR(status.st_mode))
        result.inside_visible = 1;
    errno = 0;
    if (stat("/../outside-sentinel", &status) == -1 && errno == ENOENT)
        result.escape_blocked = 1;
    if (raw_chdir("/../inside") == 0) {
        length = raw_getcwd(cwd, sizeof(cwd));
        if (length > 0 && strcmp(cwd, "/inside") == 0)
            result.dotdot_clamped = 1;
    }
    (void)write(result_fd, &result, sizeof(result));
    _exit(0);
}

struct privilege_result {
    long inaccessible_chroot_result;
    int inaccessible_chroot_errno;
    long existing_chroot_result;
    int existing_chroot_errno;
    long chdir_result;
    int chdir_errno;
};

struct capability_header {
    uint32_t version;
    int32_t pid;
};

struct capability_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

struct capability_result {
    long capset_result;
    int capset_errno;
    long chroot_result;
    int chroot_errno;
};

static void run_unprivileged_child(const char *missing,
                                   const char *locked, int result_fd) {
    struct privilege_result result;
    memset(&result, 0, sizeof(result));
    if (setgid(65534) != 0 || setuid(65534) != 0) {
        result.inaccessible_chroot_result = -2;
        result.existing_chroot_result = -2;
        result.chdir_result = -2;
    } else {
        errno = 0;
        result.inaccessible_chroot_result = syscall(SYS_chroot, missing);
        result.inaccessible_chroot_errno = errno;
        errno = 0;
        result.existing_chroot_result = syscall(SYS_chroot, "/");
        result.existing_chroot_errno = errno;
        errno = 0;
        result.chdir_result = syscall(SYS_chdir, locked);
        result.chdir_errno = errno;
    }
    (void)write(result_fd, &result, sizeof(result));
    _exit(0);
}

static void run_capability_child(int result_fd) {
    struct capability_header header = {0x20080522u, 0};
    struct capability_data data[2];
    struct capability_result result;
    memset(data, 0, sizeof(data));
    memset(&result, 0, sizeof(result));
    errno = 0;
    result.capset_result = syscall(SYS_capset, &header, data);
    result.capset_errno = errno;
    errno = 0;
    result.chroot_result = syscall(SYS_chroot, "/");
    result.chroot_errno = errno;
    (void)write(result_fd, &result, sizeof(result));
    _exit(0);
}

int main(void) {
    char base_template[] = "/tmp/edge-fsctx-XXXXXX";
    char *base;
    char directory_a[PATH_MAX];
    char directory_b[PATH_MAX];
    char locked[PATH_MAX];
    char root[PATH_MAX];
    char inside[PATH_MAX];
    char regular[PATH_MAX];
    char outside[PATH_MAX];
    char missing[PATH_MAX];
    char mode_directory[PATH_MAX];
    char absolute_directory[PATH_MAX];
    char at_directory[PATH_MAX];
    char cwd[PATH_MAX];
    int original_cwd = -1;
    int directory_fd = -1;
    int regular_fd = -1;
    long result;
    int saved_errno;
    mode_t previous_mask;
    struct stat status;
    pthread_t thread;
    struct thread_change change;
    int start_pipe[2] = {-1, -1};
    int child_pipe[2] = {-1, -1};
    pid_t child;
    int wait_status;

    original_cwd = open(".", O_RDONLY | O_DIRECTORY);
    base = mkdtemp(base_template);
    if (!base) {
        perror("mkdtemp");
        return 1;
    }
    if (join_path(directory_a, sizeof(directory_a), base, "a") < 0 ||
        join_path(directory_b, sizeof(directory_b), base, "b") < 0 ||
        join_path(locked, sizeof(locked), base, "locked") < 0 ||
        join_path(root, sizeof(root), base, "root") < 0 ||
        join_path(inside, sizeof(inside), root, "inside") < 0 ||
        join_path(regular, sizeof(regular), base, "regular") < 0 ||
        join_path(outside, sizeof(outside), base, "outside-sentinel") < 0 ||
        join_path(missing, sizeof(missing), base, "missing") < 0 ||
        join_path(mode_directory, sizeof(mode_directory), base,
                  "mode-directory") < 0 ||
        join_path(absolute_directory, sizeof(absolute_directory), base,
                  "absolute-directory") < 0 ||
        join_path(at_directory, sizeof(at_directory), directory_a,
                  "at-directory") < 0) {
        fprintf(stderr, "test path exceeds PATH_MAX\n");
        return 1;
    }
    if (mkdir(directory_a, 0755) != 0 || mkdir(directory_b, 0755) != 0 ||
        mkdir(locked, 0700) != 0 || mkdir(root, 0755) != 0 ||
        mkdir(inside, 0755) != 0) {
        perror("mkdir");
        return 1;
    }
    regular_fd = open(regular, O_CREAT | O_RDWR, 0644);
    if (regular_fd < 0 || close(regular_fd) != 0) {
        perror("regular file");
        return 1;
    }
    regular_fd = open(outside, O_CREAT | O_RDWR, 0644);
    if (regular_fd < 0 || close(regular_fd) != 0) {
        perror("outside file");
        return 1;
    }

    previous_mask = umask(0027);
    errno = 0;
    result = syscall(SYS_mkdirat, AT_FDCWD, mode_directory, 0777);
    umask(previous_mask);
    check_value("mkdirat_mode_create", result, 0);
    check_value("mkdirat_mode_stat", stat(mode_directory, &status), 0);
    if (result == 0 && stat(mode_directory, &status) == 0)
        check_value("mkdirat_mode_umask", status.st_mode & 07777, 0750);
    errno = 0;
    result = syscall(SYS_mkdirat, AT_FDCWD, mode_directory, 0700);
    saved_errno = errno;
    check_errno("mkdirat_existing", result, saved_errno, EEXIST);

    errno = 0;
    result = syscall(SYS_mkdirat, -1, absolute_directory, 0701);
    check_value("mkdirat_absolute_ignores_dirfd", result, 0);
    errno = 0;
    result = syscall(SYS_mkdirat, -1, "relative-directory", 0700);
    saved_errno = errno;
    check_errno("mkdirat_bad_dirfd", result, saved_errno, EBADF);
    regular_fd = open(regular, O_RDONLY);
    errno = 0;
    result = syscall(SYS_mkdirat, regular_fd, "relative-directory", 0700);
    saved_errno = errno;
    check_errno("mkdirat_nondirectory_dirfd", result, saved_errno, ENOTDIR);
    close(regular_fd);
    directory_fd = open(directory_a, O_RDONLY | O_DIRECTORY);
    previous_mask = umask(0);
    errno = 0;
    result = syscall(SYS_mkdirat, directory_fd, "at-directory", 0711);
    saved_errno = errno;
    umask(previous_mask);
    check_value("mkdirat_directory_fd", result, 0);
    check_value("mkdirat_directory_fd_stat", stat(at_directory, &status), 0);
    if (result == 0 && stat(at_directory, &status) == 0)
        check_value("mkdirat_directory_fd_mode", status.st_mode & 07777,
                    0711);
    close(directory_fd);

    check_value("chdir_base", raw_chdir(base), 0);
    result = raw_getcwd(cwd, sizeof(cwd));
    check_value("getcwd_length", result, (long)strlen(base) + 1);
    check_text("getcwd_text", cwd, base);
    result = raw_getcwd(cwd, 0);
    saved_errno = errno;
    check_errno("getcwd_zero_size", result, saved_errno, ERANGE);
    result = raw_getcwd(cwd, 1);
    saved_errno = errno;
    check_errno("getcwd_small_buffer", result, saved_errno, ERANGE);
    result = raw_getcwd(0, sizeof(cwd));
    saved_errno = errno;
    check_errno("getcwd_null_buffer", result, saved_errno, EFAULT);

    result = raw_chdir(0);
    saved_errno = errno;
    check_errno("chdir_null", result, saved_errno, EFAULT);
    result = raw_chdir("");
    saved_errno = errno;
    check_errno("chdir_empty", result, saved_errno, ENOENT);
    result = raw_chdir(missing);
    saved_errno = errno;
    check_errno("chdir_missing", result, saved_errno, ENOENT);
    result = raw_chdir(regular);
    saved_errno = errno;
    check_errno("chdir_regular", result, saved_errno, ENOTDIR);
    check_value("chdir_directory", raw_chdir(directory_a), 0);
    result = raw_getcwd(cwd, sizeof(cwd));
    check_text("chdir_getcwd", result > 0 ? cwd : 0, directory_a);

    result = raw_fchdir(-1);
    saved_errno = errno;
    check_errno("fchdir_bad_fd", result, saved_errno, EBADF);
    regular_fd = open(regular, O_RDONLY);
    result = raw_fchdir(regular_fd);
    saved_errno = errno;
    check_errno("fchdir_regular", result, saved_errno, ENOTDIR);
    close(regular_fd);
    directory_fd = open(directory_b, O_RDONLY | O_DIRECTORY);
    check_value("fchdir_directory", raw_fchdir(directory_fd), 0);
    result = raw_getcwd(cwd, sizeof(cwd));
    check_text("fchdir_getcwd", result > 0 ? cwd : 0, directory_b);
    close(directory_fd);

    if (geteuid() == 0) {
        chmod(locked, 0000);
        check_value("chdir_root_capability", raw_chdir(locked), 0);
        chmod(locked, 0700);
    }

    check_value("thread_share_setup", raw_chdir(directory_a), 0);
    memset(&change, 0, sizeof(change));
    change.path = directory_b;
    change.start_fd = -1;
    check_value("thread_share_create",
                pthread_create(&thread, 0, thread_chdir, &change), 0);
    check_value("thread_share_join", pthread_join(thread, 0), 0);
    check_value("thread_share_chdir", change.result, 0);
    result = raw_getcwd(cwd, sizeof(cwd));
    check_text("thread_share_visible", result > 0 ? cwd : 0, directory_b);

    check_value("unshare_setup", raw_chdir(directory_a), 0);
    check_value("unshare_pipe", pipe(start_pipe), 0);
    memset(&change, 0, sizeof(change));
    change.path = directory_b;
    change.start_fd = start_pipe[0];
    check_value("unshare_thread_create",
                pthread_create(&thread, 0, thread_chdir, &change), 0);
    errno = 0;
    result = syscall(SYS_unshare, CLONE_FS);
    saved_errno = errno;
    check_value("unshare_clone_fs", result, 0);
    if (result != 0)
        printf("unshare_clone_fs_errno:%d\n", saved_errno);
    check_value("unshare_release_thread", write(start_pipe[1], "x", 1), 1);
    check_value("unshare_thread_join", pthread_join(thread, 0), 0);
    check_value("unshare_peer_chdir", change.result, 0);
    result = raw_getcwd(cwd, sizeof(cwd));
    check_text("unshare_isolated_cwd", result > 0 ? cwd : 0, directory_a);
    close(start_pipe[0]);
    close(start_pipe[1]);

    check_value("chroot_pipe", pipe(child_pipe), 0);
    child = fork();
    if (child == 0) {
        close(child_pipe[0]);
        run_chroot_child(base, root, child_pipe[1]);
    }
    close(child_pipe[1]);
    if (child > 0) {
        struct chroot_result chroot_result;
        ssize_t count = read(child_pipe[0], &chroot_result,
                             sizeof(chroot_result));
        check_value("chroot_result_read", count, sizeof(chroot_result));
        if (count == sizeof(chroot_result)) {
            check_value("chroot_call", chroot_result.chroot_ok, 1);
            check_value("chroot_unreachable_cwd",
                        chroot_result.unreachable_ok, 1);
            check_value("chroot_root_cwd", chroot_result.root_cwd_ok, 1);
            check_value("chroot_inside_visible",
                        chroot_result.inside_visible, 1);
            check_value("chroot_escape_blocked",
                        chroot_result.escape_blocked, 1);
            check_value("chroot_dotdot_clamped",
                        chroot_result.dotdot_clamped, 1);
        }
        waitpid(child, &wait_status, 0);
        check_value("chroot_child_exit", WIFEXITED(wait_status), 1);
    } else {
        perror("fork chroot");
        ++failures;
    }
    close(child_pipe[0]);

    chmod(locked, 0000);
    check_value("privilege_pipe", pipe(child_pipe), 0);
    child = fork();
    if (child == 0) {
        close(child_pipe[0]);
        run_unprivileged_child(missing, locked, child_pipe[1]);
    }
    close(child_pipe[1]);
    if (child > 0) {
        struct privilege_result privilege;
        ssize_t count = read(child_pipe[0], &privilege, sizeof(privilege));
        check_value("privilege_result_read", count, sizeof(privilege));
        if (count == sizeof(privilege)) {
            check_errno("chroot_path_permission_order",
                        privilege.inaccessible_chroot_result,
                        privilege.inaccessible_chroot_errno, EACCES);
            check_errno("chroot_capability",
                        privilege.existing_chroot_result,
                        privilege.existing_chroot_errno, EPERM);
            check_errno("chdir_search_permission", privilege.chdir_result,
                        privilege.chdir_errno, EACCES);
        }
        waitpid(child, &wait_status, 0);
        check_value("privilege_child_exit", WIFEXITED(wait_status), 1);
    } else {
        perror("fork privilege");
        ++failures;
    }
    close(child_pipe[0]);
    chmod(locked, 0700);

    check_value("capability_pipe", pipe(child_pipe), 0);
    child = fork();
    if (child == 0) {
        close(child_pipe[0]);
        run_capability_child(child_pipe[1]);
    }
    close(child_pipe[1]);
    if (child > 0) {
        struct capability_result capability;
        ssize_t count = read(child_pipe[0], &capability,
                             sizeof(capability));
        check_value("capability_result_read", count, sizeof(capability));
        if (count == sizeof(capability)) {
            check_value("capability_drop", capability.capset_result, 0);
            check_errno("chroot_requires_effective_capability",
                        capability.chroot_result,
                        capability.chroot_errno, EPERM);
        }
        waitpid(child, &wait_status, 0);
        check_value("capability_child_exit", WIFEXITED(wait_status), 1);
    } else {
        perror("fork capability");
        ++failures;
    }
    close(child_pipe[0]);

    if (original_cwd >= 0) {
        (void)raw_fchdir(original_cwd);
        close(original_cwd);
    }
    unlink(outside);
    unlink(regular);
    rmdir(at_directory);
    rmdir(absolute_directory);
    rmdir(mode_directory);
    rmdir(inside);
    rmdir(root);
    rmdir(locked);
    rmdir(directory_b);
    rmdir(directory_a);
    rmdir(base);

    if (failures) {
        printf("FS_CONTEXT_ABI_PROBE_FAIL failures:%d\n", failures);
        return 1;
    }
    printf("FS_CONTEXT_ABI_PROBE_PASS failures:0\n");
    return 0;
}
