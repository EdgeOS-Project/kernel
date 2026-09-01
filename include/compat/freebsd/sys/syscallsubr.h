/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD syscall helper declaration surface for imported drivers. */

#ifndef _SYS_SYSCALLSUBR_H_
#define _SYS_SYSCALLSUBR_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>

struct thread;

int kern_clock_gettime(struct thread *thread, clockid_t clock_id,
    struct timespec *value);
int kern_clock_settime(struct thread *thread, clockid_t clock_id,
    const struct timespec *value);

static inline int
kern_kldload(struct thread *thread, const char *filename, int *file_id)
{
    (void)thread;
    (void)filename;
    if (file_id)
        *file_id = -1;
    return ENOSYS;
}

static inline int
kern_kldunload(struct thread *thread, int file_id, int flags)
{
    (void)thread;
    (void)file_id;
    (void)flags;
    return ENOSYS;
}

#endif
