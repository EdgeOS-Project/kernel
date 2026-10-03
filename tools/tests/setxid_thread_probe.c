/* Exercise glibc's process-wide credential synchronization across threads. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

static atomic_int done;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

static void *worker(void *unused) {
    (void)unused;
    pthread_mutex_lock(&mutex);
    while (!atomic_load_explicit(&done, memory_order_relaxed))
        pthread_cond_wait(&condition, &mutex);
    pthread_mutex_unlock(&mutex);
    return 0;
}

int main(void) {
    pthread_t threads[4];
    if (geteuid() != 0) return 77;
    for (unsigned i = 0; i < 4; ++i)
        if (pthread_create(&threads[i], 0, worker, 0) != 0) return 1;
    for (unsigned i = 0; i < 1000; ++i) {
        if (setuid(0) != 0) return 2;
        if ((i + 1) % 100 == 0) {
            printf("setxid iteration %u\n", i + 1);
            fflush(stdout);
        }
    }
    atomic_store_explicit(&done, 1, memory_order_relaxed);
    pthread_cond_broadcast(&condition);
    for (unsigned i = 0; i < 4; ++i)
        if (pthread_join(threads[i], 0) != 0) return 3;
    return 0;
}
