/* SPDX-License-Identifier: MPL-2.0 */
/* Select and kqueue notification state for imported character devices. */

#ifndef _SYS_SELINFO_H_
#define _SYS_SELINFO_H_

#include <stdint.h>
#include "compat/freebsd/sys/event.h"

struct thread;

struct selinfo {
    struct knlist si_note;
    volatile uint64_t edgeos_sequence;
};

void bsd_knote_notify(struct knlist *list, long hint);
uint64_t bsd_selinfo_change_sequence(void);

void selrecord(struct thread *thread, struct selinfo *info);
void selwakeup(struct selinfo *info);
void selwakeuppri(struct selinfo *info, int priority);
void seldrain(struct selinfo *info);

#endif
