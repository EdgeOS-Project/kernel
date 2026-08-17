/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD counting semaphore compatibility using EdgeOS mutexes and waits. */

#ifndef _SYS_SEMA_H_
#define _SYS_SEMA_H_

#include <sys/condvar.h>
#include <sys/mutex.h>

struct sema {
    struct mtx sema_mtx;
    struct cv sema_cv;
    int sema_waiters;
    int sema_value;
};

static inline void
sema_init(struct sema *semaphore, int value, const char *description)
{
    mtx_init(&semaphore->sema_mtx, description, "semaphore", MTX_DEF);
    cv_init(&semaphore->sema_cv, description);
    semaphore->sema_waiters = 0;
    semaphore->sema_value = value;
}

static inline void
sema_destroy(struct sema *semaphore)
{
    cv_destroy(&semaphore->sema_cv);
    mtx_destroy(&semaphore->sema_mtx);
}

static inline void
_sema_post(struct sema *semaphore, const char *file, int line)
{
    (void)file;
    (void)line;
    mtx_lock(&semaphore->sema_mtx);
    semaphore->sema_value++;
    if (semaphore->sema_waiters && semaphore->sema_value > 0)
        cv_signal(&semaphore->sema_cv);
    mtx_unlock(&semaphore->sema_mtx);
}

static inline void
_sema_wait(struct sema *semaphore, const char *file, int line)
{
    (void)file;
    (void)line;
    mtx_lock(&semaphore->sema_mtx);
    while (semaphore->sema_value == 0) {
        semaphore->sema_waiters++;
        cv_wait(&semaphore->sema_cv, &semaphore->sema_mtx);
        semaphore->sema_waiters--;
    }
    semaphore->sema_value--;
    mtx_unlock(&semaphore->sema_mtx);
}

static inline int
_sema_timedwait(struct sema *semaphore, int timeout_ticks,
    const char *file, int line)
{
    int error = 0;

    (void)file;
    (void)line;
    mtx_lock(&semaphore->sema_mtx);
    while (semaphore->sema_value == 0 && error == 0) {
        semaphore->sema_waiters++;
        error = cv_timedwait(&semaphore->sema_cv, &semaphore->sema_mtx,
            timeout_ticks);
        semaphore->sema_waiters--;
    }
    if (semaphore->sema_value > 0) {
        semaphore->sema_value--;
        error = 0;
    }
    mtx_unlock(&semaphore->sema_mtx);
    return error;
}

static inline int
_sema_trywait(struct sema *semaphore, const char *file, int line)
{
    int acquired = 0;

    (void)file;
    (void)line;
    mtx_lock(&semaphore->sema_mtx);
    if (semaphore->sema_value > 0) {
        semaphore->sema_value--;
        acquired = 1;
    }
    mtx_unlock(&semaphore->sema_mtx);
    return acquired;
}

static inline int
sema_value(struct sema *semaphore)
{
    int value;

    mtx_lock(&semaphore->sema_mtx);
    value = semaphore->sema_value;
    mtx_unlock(&semaphore->sema_mtx);
    return value;
}

#define sema_post(semaphore) \
    _sema_post((semaphore), __FILE__, __LINE__)
#define sema_wait(semaphore) \
    _sema_wait((semaphore), __FILE__, __LINE__)
#define sema_timedwait(semaphore, timeout_ticks) \
    _sema_timedwait((semaphore), (timeout_ticks), __FILE__, __LINE__)
#define sema_trywait(semaphore) \
    _sema_trywait((semaphore), __FILE__, __LINE__)

#endif
