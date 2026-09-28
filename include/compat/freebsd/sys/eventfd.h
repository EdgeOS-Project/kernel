/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD eventfd kernel interface consumed by LinuxKPI. */

#ifndef _SYS_EVENTFD_H_
#define _SYS_EVENTFD_H_

#include <stdint.h>

struct eventfd;
struct file;
struct thread;

int eventfd_create_file(struct thread *thread, struct file *file,
    uint32_t initial_value, int flags);
struct eventfd *eventfd_get(struct file *file);
void eventfd_put(struct eventfd *eventfd);
void eventfd_signal(struct eventfd *eventfd);

#endif
