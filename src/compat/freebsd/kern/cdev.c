/* SPDX-License-Identifier: MPL-2.0 */
/* Per-open character-device context for imported BSD drivers. */

#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/sys/conf.h"
#include "compat/freebsd/sys/kthread.h"

#define BSD_CDEV_EBUSY 16
#define BSD_CDEV_EBADF 9
#define BSD_CDEV_EINVAL 22
#define BSD_CDEV_ENOENT 2

static void
cdevpriv_lock(struct thread *thread)
{
    while (__atomic_test_and_set(&thread->td_lock, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
cdevpriv_unlock(struct thread *thread)
{
    __atomic_clear(&thread->td_lock, __ATOMIC_RELEASE);
}

int
devfs_set_cdevpriv(void *data, d_priv_dtor_t *destructor)
{
    struct thread *thread = bsd_kthread_current_public();
    int error = 0;

    if (!thread)
        return BSD_CDEV_EBADF;
    if (!destructor)
        return BSD_CDEV_EINVAL;
    cdevpriv_lock(thread);
    if (thread->td_cdevpriv)
        error = BSD_CDEV_EBUSY;
    else {
        thread->td_cdevpriv = data;
        thread->td_cdevpriv_dtr = destructor;
    }
    cdevpriv_unlock(thread);
    return error;
}

int
devfs_get_cdevpriv(void **data)
{
    struct thread *thread = bsd_kthread_current_public();
    int error = 0;

    if (data)
        *data = 0;
    if (!thread)
        return BSD_CDEV_EBADF;
    cdevpriv_lock(thread);
    if (!thread->td_cdevpriv)
        error = BSD_CDEV_ENOENT;
    if (data)
        *data = thread->td_cdevpriv;
    cdevpriv_unlock(thread);
    return error;
}

void
devfs_clear_cdevpriv(void)
{
    struct thread *thread = bsd_kthread_current_public();
    void (*destructor)(void *) = 0;
    void *data = 0;

    if (!thread)
        return;
    cdevpriv_lock(thread);
    data = thread->td_cdevpriv;
    destructor = thread->td_cdevpriv_dtr;
    thread->td_cdevpriv = 0;
    thread->td_cdevpriv_dtr = 0;
    cdevpriv_unlock(thread);
    if (destructor)
        destructor(data);
}
