/* SPDX-License-Identifier: BSD-2-Clause */
/* Event-handler base declarations for the EdgeOS BSD Driver Bridge. */

#ifndef _SYS__EVENTHANDLER_H_
#define _SYS__EVENTHANDLER_H_

#ifndef BSD_BRIDGE_HOST_TEST
#include <sys/queue.h>
#endif

struct eventhandler_entry;
struct eventhandler_list;
typedef struct eventhandler_entry *eventhandler_tag;

#define EVENTHANDLER_DECLARE(name, type) \
    struct bsd_eventhandler_declaration_##name
#define EVENTHANDLER_LIST_DECLARE(name) \
    extern struct eventhandler_list *_eventhandler_list_##name

#endif
