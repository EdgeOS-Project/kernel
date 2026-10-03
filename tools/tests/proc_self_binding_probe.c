/* SPDX-License-Identifier: MPL-2.0 */
/* Read task bindings through an inherited procfd; write maps only in new userns. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct child_args {
    int procfd, input, done;
    unsigned long flags;
    uid_t outer_uid;
    int prime;
    const char *kind;
};
static const char *proc_path = "/proc";
static int failures;
static void fd_link(int fd, const char *label) {
    char path[128], target[4096];
    snprintf(path, sizeof(path), "%s/self/fd/%d", proc_path, fd);
    errno = 0;
    ssize_t n = readlink(path, target, sizeof(target) - 1);
    int saved = errno;
    if (n >= 0) target[n] = 0;
    printf("SELF_FD label=%s fd=%d target=%s result=%ld errno=%d\n",
           label, fd, n >= 0 ? target : "<error>", (long)n, saved);
}
static void read_at(int dir, const char *name, const char *label) {
    char bytes[4096];
    errno = 0;
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC);
    int saved = errno;
    printf("SELF_OPEN label=%s name=%s fd=%d errno=%d\n", label, name, fd, saved);
    if (fd < 0) return;
    fd_link(fd, label);
    errno = 0;
    ssize_t n = read(fd, bytes, sizeof(bytes) - 1);
    saved = errno;
    if (n >= 0) {
        bytes[n] = 0;
        /* One output record per read; preserve text using escaped newlines. */
        printf("SELF_READ label=%s count=%ld text=", label, (long)n);
        for (ssize_t i = 0; i < n; ++i) {
            if (bytes[i] == '\n') fputs("\\n", stdout);
            else if (bytes[i] == '\r') fputs("\\r", stdout);
            else if (bytes[i] == '\\') fputs("\\\\", stdout);
            else if ((unsigned char)bytes[i] >= 32) putchar(bytes[i]);
        }
        putchar('\n');
    } else printf("SELF_READ label=%s count=-1 errno=%d\n", label, saved);
    close(fd);
}
static int child_main(void *opaque) {
    struct child_args *a = opaque;
    pid_t outer_pid;
    if (read(a->input, &outer_pid, sizeof(outer_pid)) != sizeof(outer_pid)) _exit(80);
    close(a->input);
    char marker[16], numeric[24], link[128];
    snprintf(marker, sizeof(marker), "sp-child-%d", outer_pid);
    prctl(PR_SET_NAME, marker, 0, 0, 0);
    snprintf(numeric, sizeof(numeric), "%d", outer_pid);
    printf("SELF_CHILD kind=%s prime=%d outer_pid=%d pid=%ld tid=%ld ppid=%ld uid=%ld expected_comm=%s\n",
           a->kind, a->prime, outer_pid, (long)getpid(), syscall(SYS_gettid),
           (long)getppid(), (long)getuid(), marker);
    fd_link(a->procfd, "inherited_procfd");
    errno = 0;
    ssize_t n = readlinkat(a->procfd, "self", link, sizeof(link) - 1);
    int saved = errno;
    if (n >= 0) link[n] = 0;
    int domain_ok = n >= 0 && !strcmp(link, numeric);
    printf("SELF_LINK target=%s expected_mount_visible=%s result=%ld errno=%d domain_match=%d\n",
           n >= 0 ? link : "<error>", numeric, (long)n, saved, domain_ok);
    errno = 0;
    int self = openat(a->procfd, "self", O_PATH | O_CLOEXEC);
    saved = errno;
    printf("SELF_OPEN_SELF fd=%d errno=%d\n", self, saved);
    int numeric_fd = openat(a->procfd, numeric, O_PATH | O_CLOEXEC);
    printf("SELF_OPEN_NUMERIC name=%s fd=%d errno=%d\n", numeric, numeric_fd, errno);
    if (self >= 0) {
        fd_link(self, "fresh_self_dir");
        read_at(self, "comm", "self_comm");
        read_at(self, "status", "self_status");
        read_at(self, "uid_map", "self_uid_map_before");
    }
    if (numeric_fd >= 0) {
        fd_link(numeric_fd, "numeric_dir");
        read_at(numeric_fd, "comm", "numeric_comm");
        read_at(numeric_fd, "status", "numeric_status");
    }
    int map_ok = 1;
    if ((a->flags & CLONE_NEWUSER) && self >= 0) {
        /* Match bubblewrap: fresh O_RDWR|CLOEXEC open followed by one write. */
        errno = 0;
        int map = openat(self, "uid_map", O_RDWR | O_CLOEXEC);
        saved = errno;
        printf("SELF_MAP_OPEN fd=%d errno=%d\n", map, saved);
        map_ok = 0;
        if (map >= 0) {
            fd_link(map, "fresh_uid_map");
            char content[64];
            int length = snprintf(content, sizeof(content), "0 %u 1\n", a->outer_uid);
            errno = 0;
            ssize_t written = write(map, content, length);
            saved = errno;
            printf("SELF_MAP_WRITE expected=%d actual=%ld errno=%d uid_after=%ld\n",
                   length, (long)written, saved, (long)getuid());
            map_ok = written == length;
            close(map);
            read_at(self, "uid_map", "self_uid_map_after");
        }
    }
    if (numeric_fd >= 0) close(numeric_fd);
    if (self >= 0) close(self);
    printf("SELF_CASE_END kind=%s prime=%d domain_match=%d self_open=%d map_ok=%d\n",
           a->kind, a->prime, domain_ok, self >= 0, map_ok);
    fflush(stdout);
    char done = 1;
    (void)write(a->done, &done, 1);
    close(a->done);
    return !domain_ok || self < 0 || !map_ok;
}
static void run_case(const char *kind, unsigned long flags, int prime) {
    struct child_args a = {.flags = flags, .outer_uid = getuid(), .prime = prime, .kind = kind};
    a.procfd = open(proc_path, O_PATH | O_CLOEXEC);
    if (a.procfd < 0) { perror("open proc"); ++failures; return; }
    char parent_marker[16]; snprintf(parent_marker, sizeof(parent_marker), "sp-parent-%d", getpid());
    prctl(PR_SET_NAME, parent_marker, 0, 0, 0);
    printf("SELF_CASE_BEGIN kind=%s prime=%d parent=%ld proc=%s\n", kind, prime, (long)getpid(), proc_path);
    if (prime) {
        struct stat st;
        errno = 0;
        int rc = fstatat(a.procfd, "self/ns/cgroup", &st, 0);
        printf("SELF_PARENT_PRIME rc=%d errno=%d inode=%llu\n", rc, errno,
               rc == 0 ? (unsigned long long)st.st_ino : 0);
    }
    int input[2], done[2];
    if (pipe2(input, O_CLOEXEC) || pipe2(done, O_CLOEXEC)) { perror("pipe"); exit(2); }
    a.input = input[0]; a.done = done[1];
    void *stack = malloc(1024 * 1024);
    if (!stack) exit(2);
    fflush(NULL);
    pid_t child = clone(child_main, (char *)stack + 1024 * 1024, (int)flags | SIGCHLD, &a);
    int saved = errno;
    close(input[0]); close(done[1]);
    if (child < 0) {
        printf("SELF_CLONE_FAIL kind=%s prime=%d errno=%d\n", kind, prime, saved);
        ++failures;
    } else {
        (void)write(input[1], &child, sizeof(child));
        struct pollfd ready = {.fd = done[0], .events = POLLIN};
        int polled = poll(&ready, 1, 12000);
        if (polled <= 0) {
            printf("SELF_CASE_TIMEOUT child=%d\n", child);
            kill(child, SIGKILL);
        }
        int status = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        printf("SELF_WAIT child=%d waited=%d status=%d\n", child, waited, status);
        if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status)) ++failures;
    }
    close(input[1]); close(done[0]); close(a.procfd); free(stack);
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 2) return 2;
    if (argc == 2) proc_path = argv[1];
    printf("SELF_PROBE_BEGIN pid=%ld uid=%ld\n", (long)getpid(), (long)getuid());
    /* Unprimed cases precede primed cases; no cache invalidation is attempted. */
    for (int prime = 0; prime < 2; ++prime) {
        run_case("fork", 0, prime);
        run_case("user", CLONE_NEWUSER, prime);
        run_case("user-pid", CLONE_NEWUSER | CLONE_NEWPID, prime);
    }
    printf("SELF_PROBE_END failed_cases=%d\n", failures);
    return failures ? 1 : 0;
}
