/* SPDX-License-Identifier: MPL-2.0 */
/* No child proc lookup or identity diagnostic precedes the two target opens. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
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
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
static int failures;
static double now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
static void link_fd(int fd, const char *label) {
    char path[64], value[1024];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    errno = 0;
    ssize_t n = readlink(path, value, sizeof(value)-1);
    int error = errno;
    if (n >= 0) value[n] = 0;
    printf("FIRST_LINK label=%s fd=%d result=%ld errno=%d target=%s\n",
           label, fd, (long)n, error, n >= 0 ? value : "<error>");
}
static void read_fd(int fd, const char *label) {
    char value[2048]; errno = 0;
    ssize_t n = pread(fd, value, sizeof(value)-1, 0);
    int error = errno;
    printf("FIRST_READ label=%s result=%ld errno=%d text=", label, (long)n, error);
    for (ssize_t i = 0; i < n; ++i) {
        if (value[i] == '\n') fputs("\\n", stdout);
        else if ((unsigned char)value[i] >= 32) putchar(value[i]);
    }
    putchar('\n');
}
static void run(unsigned long flags, int prime) {
    int procfd = open("/proc", O_PATH);
    if (procfd < 0) { perror("procfd"); ++failures; return; }
    uid_t outer_uid = getuid();
    printf("FIRST_BEGIN flags=0x%lx prime=%d parent=%ld uid=%u\n", flags, prime, (long)getpid(), outer_uid);
    if (prime) {
        struct stat st; errno = 0;
        int rc = stat("/proc/self/ns/cgroup", &st);
        printf("FIRST_PRIME rc=%d errno=%d\n", rc, errno);
    }
    fflush(NULL);
    /* Match bubblewrap's raw clone form: separate address space, no new stack. */
    long child = syscall(SYS_clone, flags | SIGCHLD, NULL, NULL, NULL, 0);
    if (child == 0) {
        /* Keep these as the first child operations after clone returns. */
        long self = syscall(SYS_openat, procfd, "self", O_PATH, 0);
        int self_error = self < 0 ? errno : 0;
        long map = syscall(SYS_openat, self, "uid_map", O_RDWR | O_CLOEXEC, 0);
        int map_error = map < 0 ? errno : 0;
        /* Diagnostics start only after both descriptors have been selected. */
        long pid = syscall(SYS_getpid), tid = syscall(SYS_gettid);
        char marker[16]; snprintf(marker, sizeof(marker), "first-%ld", pid);
        prctl(PR_SET_NAME, marker, 0, 0, 0);
        printf("FIRST_CHILD flags=0x%lx prime=%d pid=%ld tid=%ld self_fd=%ld self_errno=%d map_fd=%ld map_errno=%d\n",
               flags, prime, pid, tid, self, self_error, map, map_error);
        link_fd(procfd, "inherited_procfd");
        if (self >= 0) link_fd((int)self, "first_self");
        if (map >= 0) { link_fd((int)map, "first_uid_map"); read_fd((int)map, "map_before"); }
        char target[64]; errno = 0;
        ssize_t n = readlinkat(procfd, "self", target, sizeof(target)-1);
        if (n >= 0) target[n] = 0;
        printf("FIRST_SELF_TEXT result=%ld errno=%d target=%s\n", (long)n, errno, n >= 0 ? target : "<error>");
        int comm = self >= 0 ? openat((int)self, "comm", O_RDONLY | O_CLOEXEC) : -1;
        if (comm >= 0) { read_fd(comm, "comm_after_opens"); close(comm); }
        int ok = 0;
        if (map >= 0) {
            char value[64]; int length = snprintf(value, sizeof(value), "0 %u 1\n", outer_uid);
            errno = 0;
            ssize_t written = write((int)map, value, length);
            int error = errno;
            printf("FIRST_MAP_WRITE expected=%d actual=%ld errno=%d uid_after=%ld\n", length, (long)written, error, (long)getuid());
            ok = written == length;
            read_fd((int)map, "map_after"); close((int)map);
        }
        if (self >= 0) close((int)self);
        close(procfd);
        printf("FIRST_CHILD_END flags=0x%lx prime=%d map_ok=%d\n", flags, prime, ok);
        fflush(stdout); _exit(ok ? 0 : 1);
    }
    if (child < 0) {
        printf("FIRST_CLONE_FAIL errno=%d\n", errno); ++failures; close(procfd); return;
    }
    printf("FIRST_PARENT_CHILD outer_pid=%ld flags=0x%lx prime=%d\n", child, flags, prime);
    double deadline = now()+10;
    int status = 0; pid_t result;
    while ((result = waitpid((pid_t)child, &status, WNOHANG)) == 0 && now() < deadline) {
        struct timespec delay = {0, 10000000}; nanosleep(&delay, NULL);
    }
    if (!result) {
        printf("FIRST_TIMEOUT outer_pid=%ld\n", child); kill((pid_t)child, SIGKILL);
        result = waitpid((pid_t)child, &status, 0);
    }
    printf("FIRST_WAIT child=%ld result=%ld status=%d\n", child, (long)result, status);
    if (result != child || !WIFEXITED(status) || WEXITSTATUS(status)) ++failures;
    close(procfd);
}
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    unsigned long variants[] = {
        CLONE_NEWUSER | CLONE_NEWNS,
        CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID,
        CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET |
            CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP
    };
    for (unsigned i = 0; i < sizeof(variants)/sizeof(variants[0]); ++i)
        for (int prime = 0; prime < 2; ++prime) run(variants[i], prime);
    printf("FIRST_PROBE_END failures=%d\n", failures);
    return failures ? 1 : 0;
}
