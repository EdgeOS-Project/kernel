/* SPDX-License-Identifier: MPL-2.0 */
/* Verify AArch64 FPSIMD state across Linux task and signal transitions. */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "This probe requires AArch64"
#endif

struct vector_value {
    uint64_t low;
    uint64_t high;
};

extern void vector_set(uint64_t low, uint64_t high);
extern void vector_get(struct vector_value *value);

__asm__(
    ".text\n"
    ".align 2\n"
    ".type vector_set, %function\n"
    "vector_set:\n"
    "mov v8.d[0], x0\n"
    "mov v8.d[1], x1\n"
    "ret\n"
    ".size vector_set, .-vector_set\n"
    ".align 2\n"
    ".type vector_get, %function\n"
    "vector_get:\n"
    "str q8, [x0]\n"
    "ret\n"
    ".size vector_get, .-vector_get\n");

static int vector_matches(uint64_t low, uint64_t high) {
    struct vector_value value;
    vector_get(&value);
    return value.low == low && value.high == high;
}

static long raw_syscall0(long number) {
    register long x0 __asm__("x0");
    register long x8 __asm__("x8") = number;
    __asm__ __volatile__("svc #0" : "=r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
}

struct thread_context {
    uint64_t low;
    uint64_t high;
    int failed;
};

static void *switch_thread(void *opaque) {
    struct thread_context *context = opaque;
    vector_set(context->low, context->high);
    for (int iteration = 0; iteration < 2000; ++iteration) {
        if (raw_syscall0(SYS_sched_yield) < 0 ||
            !vector_matches(context->low, context->high)) {
            context->failed = 1;
            break;
        }
    }
    return NULL;
}

static void signal_handler(int signal_number) {
    (void)signal_number;
    vector_set(0xfeedfacecafebeefULL, 0x0123456789abcdefULL);
}

int main(void) {
    const uint64_t syscall_low = 0x1122334455667788ULL;
    const uint64_t syscall_high = 0x8877665544332211ULL;
    const uint64_t signal_low = 0xa5a5a5a55a5a5a5aULL;
    const uint64_t signal_high = 0x13579bdf2468ace0ULL;
    struct thread_context contexts[2] = {
        {0x1111111122222222ULL, 0x3333333344444444ULL, 0},
        {0xaaaabbbbccccddddULL, 0xeeeeffff00001111ULL, 0},
    };
    struct sigaction action;
    pthread_t threads[2];
    pid_t child;
    int status;

    vector_set(syscall_low, syscall_high);
    if (raw_syscall0(SYS_getpid) <= 0 ||
        !vector_matches(syscall_low, syscall_high)) {
        fprintf(stderr, "FPSIMD changed across getpid\n");
        return 1;
    }

    for (int index = 0; index < 2; ++index)
        if (pthread_create(&threads[index], NULL, switch_thread,
                           &contexts[index]) != 0) {
            perror("pthread_create");
            return 1;
        }
    for (int index = 0; index < 2; ++index)
        pthread_join(threads[index], NULL);
    if (contexts[0].failed || contexts[1].failed) {
        fprintf(stderr, "FPSIMD changed across thread scheduling\n");
        return 1;
    }

    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) < 0) {
        perror("sigaction");
        return 1;
    }
    vector_set(signal_low, signal_high);
    if (kill(getpid(), SIGUSR1) < 0 ||
        !vector_matches(signal_low, signal_high)) {
        fprintf(stderr, "FPSIMD changed across signal return\n");
        return 1;
    }

    vector_set(syscall_low, syscall_high);
    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0)
        _exit(vector_matches(syscall_low, syscall_high) ? 0 : 1);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 ||
        !vector_matches(syscall_low, syscall_high)) {
        fprintf(stderr, "FPSIMD fork inheritance failed status=%d\n", status);
        return 1;
    }

    puts("arm64_fpsimd_context: PASS");
    return 0;
}
