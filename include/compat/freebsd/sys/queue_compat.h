/* SPDX-License-Identifier: BSD-2-Clause */
/* Queue entry layouts shared by host tests and imported BSD sources. */

#ifndef _EDGEOS_SYS_QUEUE_COMPAT_H_
#define _EDGEOS_SYS_QUEUE_COMPAT_H_

#ifndef STAILQ_ENTRY
#define STAILQ_ENTRY(type)                                               \
struct {                                                                \
    struct type *stqe_next;                                              \
}
#endif

#ifndef LIST_ENTRY
#define LIST_ENTRY(type)                                                 \
struct {                                                                \
    struct type *le_next;                                                \
    struct type **le_prev;                                               \
}
#endif

#endif
