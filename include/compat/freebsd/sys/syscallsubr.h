/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD syscall helper declaration surface for imported drivers. */

#ifndef _SYS_SYSCALLSUBR_H_
#define _SYS_SYSCALLSUBR_H_

#include <sys/types.h>
#include <sys/time.h>

struct thread;

int kern_clock_gettime(struct thread *thread, clockid_t clock_id,
    struct timespec *value);
int kern_clock_settime(struct thread *thread, clockid_t clock_id,
    const struct timespec *value);

#endif
