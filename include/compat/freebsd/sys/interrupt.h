/* SPDX-License-Identifier: MPL-2.0 */
/* Interrupt-thread priority classes used by imported BSD drivers. */

#ifndef _SYS_INTERRUPT_H_
#define _SYS_INTERRUPT_H_

#include "cpuset.h"

#define CPU_WHICH_IRQ 4

#define SWI_TTY 0
#define SWI_NET 1
#define SWI_CAMBIO 2
#define SWI_BUSDMA 3
#define SWI_CLOCK 4
#define SWI_TQ_FAST 5
#define SWI_TQ 6
#define SWI_TQ_GIANT SWI_TQ

#define SWI_FROMNMI 0x01
#define SWI_DELAY 0x02

struct intr_event;
extern struct intr_event *clk_intr_event;

int swi_add(struct intr_event **event, const char *name,
    void (*handler)(void *), void *argument, int priority, int flags,
    void **cookie);
void swi_sched(void *cookie, int flags);
int swi_remove(void *cookie);
int intr_setaffinity(int id, int which, const cpuset_t *mask);
void _intr_drain(int irq);

#endif
