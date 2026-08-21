/* SPDX-License-Identifier: MPL-2.0 */
/* Runtime probe for Linux restart_syscall and nanosleep restart blocks. */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__)
#define EDGE_SYS_RESTART_SYSCALL 219
#elif defined(__aarch64__)
#define EDGE_SYS_RESTART_SYSCALL 128
#else
#error "restart_syscall_abi_probe requires a supported 64-bit architecture"
#endif

static volatile sig_atomic_t g_signal_seen;

static void signal_handler(int signal_number) {
    (void)signal_number;
    g_signal_seen = 1;
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000u +
           (uint64_t)value.tv_nsec / 1000000u;
}

int main(void) {
    struct sigaction action = {0};
    struct timespec child_delay = {0, 30000000};
    struct timespec stop_delay = {0, 60000000};
    struct timespec request = {0, 150000000};
    struct timespec remaining = {0, 0};
    uint64_t started;
    uint64_t elapsed;
    pid_t child;
    long result;

    errno = 0;
    result = syscall(EDGE_SYS_RESTART_SYSCALL);
    if (result != -1 || errno != EINTR) {
        fprintf(stderr, "restart without block: result=%ld errno=%d\n",
                result, errno);
        return 1;
    }

    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0) != 0) return 2;
    child = fork();
    if (child < 0) return 3;
    if (child == 0) {
        (void)nanosleep(&child_delay, 0);
        (void)kill(getppid(), SIGUSR1);
        _exit(0);
    }

    started = monotonic_milliseconds();
    errno = 0;
    result = nanosleep(&request, &remaining);
    if (result != -1 || errno != EINTR || !g_signal_seen) {
        fprintf(stderr, "interrupted nanosleep: result=%ld errno=%d signal=%d\n",
                result, errno, (int)g_signal_seen);
        return 4;
    }
    if (waitpid(child, 0, 0) != child) return 5;
    errno = 0;
    result = syscall(EDGE_SYS_RESTART_SYSCALL);
    if (result != -1 || errno != EINTR) {
        fprintf(stderr, "restart after handler: result=%ld errno=%d\n",
                result, errno);
        return 6;
    }

    child = fork();
    if (child < 0) return 7;
    if (child == 0) {
        pid_t parent = getppid();
        (void)nanosleep(&child_delay, 0);
        (void)kill(parent, SIGSTOP);
        (void)nanosleep(&stop_delay, 0);
        (void)kill(parent, SIGCONT);
        _exit(0);
    }
    remaining.tv_sec = 0;
    remaining.tv_nsec = 0;
    started = monotonic_milliseconds();
    errno = 0;
    result = nanosleep(&request, &remaining);
    elapsed = monotonic_milliseconds() - started;
    if (result != 0 || errno != 0 || elapsed < 120u || elapsed > 400u) {
        fprintf(stderr,
                "stop restart: result=%ld errno=%d elapsed=%llu remaining=%ld.%09ld\n",
                result, errno, (unsigned long long)elapsed,
                remaining.tv_sec, remaining.tv_nsec);
        return 8;
    }
    if (waitpid(child, 0, 0) != child) return 9;
    puts("RESTART_SYSCALL_ABI_PROBE_PASS");
    return 0;
}
