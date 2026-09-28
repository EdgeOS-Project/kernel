/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD-compatible event registry for imported drivers. */

#ifndef _SYS_EVENTHANDLER_H_
#define _SYS_EVENTHANDLER_H_

#include <stddef.h>
#include <stdint.h>

#include "_eventhandler.h"
#include "mutex.h"
#ifdef BSD_BRIDGE_HOST_TEST
#ifndef _SYS_POWER_H_
#define _SYS_POWER_H_
enum power_stype {
    POWER_STYPE_AWAKE,
    POWER_STYPE_STANDBY,
    POWER_STYPE_FW_SUSPEND,
    POWER_STYPE_SUSPEND_TO_IDLE,
    POWER_STYPE_FW_HIBERNATE,
    POWER_STYPE_POWEROFF,
    POWER_STYPE_UNKNOWN,
    POWER_STYPE_COUNT = POWER_STYPE_UNKNOWN
};
#endif
#else
#include <sys/power.h>
#endif

#define EVENTHANDLER_PRI_FIRST 0
#define EVENTHANDLER_PRI_ANY 10000
#define EVENTHANDLER_PRI_LAST 20000

#define SHUTDOWN_PRI_FIRST EVENTHANDLER_PRI_FIRST
#define SHUTDOWN_PRI_DEFAULT EVENTHANDLER_PRI_ANY
#define SHUTDOWN_PRI_LAST EVENTHANDLER_PRI_LAST

typedef void (*shutdown_fn)(void *, int);
typedef void (*power_change_fn)(void *, enum power_stype);

#define EVENTHANDLER_LIST_DEFINE(name) \
    struct eventhandler_list *_eventhandler_list_##name

#define EVENTHANDLER_REGISTER(name, function, argument, priority) \
    eventhandler_register(0, #name, (void *)(function), (argument), \
        (priority))
#define EVENTHANDLER_DEREGISTER(name, tag) \
    eventhandler_deregister(eventhandler_find_list(#name), (tag))
#define EVENTHANDLER_DEREGISTER_NOWAIT(name, tag) \
    eventhandler_deregister_nowait(eventhandler_find_list(#name), (tag))

eventhandler_tag eventhandler_register(struct eventhandler_list *list,
    const char *name, void *function, void *argument, int priority);
void eventhandler_deregister(struct eventhandler_list *list,
    eventhandler_tag tag);
void eventhandler_deregister_nowait(struct eventhandler_list *list,
    eventhandler_tag tag);
struct eventhandler_list *eventhandler_find_list(const char *name);
struct eventhandler_list *eventhandler_create_list(const char *name);
void eventhandler_prune_list(struct eventhandler_list *list);
size_t bsd_eventhandler_count(const char *name);

void bsd_eventhandler_invoke_0(const char *name);
void bsd_eventhandler_invoke_1(const char *name, uintptr_t argument0);
void bsd_eventhandler_invoke_2(const char *name, uintptr_t argument0,
    uintptr_t argument1);
void bsd_eventhandler_invoke_3(const char *name, uintptr_t argument0,
    uintptr_t argument1, uintptr_t argument2);

#define BSD_EVENTHANDLER_JOIN_INNER(left, right) left##right
#define BSD_EVENTHANDLER_JOIN(left, right) \
    BSD_EVENTHANDLER_JOIN_INNER(left, right)
#define BSD_EVENTHANDLER_ARGUMENT_COUNT(_0, _1, _2, _3, count, ...) count
#define BSD_EVENTHANDLER_COUNT(...) \
    BSD_EVENTHANDLER_ARGUMENT_COUNT(_, ##__VA_ARGS__, 3, 2, 1, 0)
#define BSD_EVENTHANDLER_INVOKE_0(name) \
    bsd_eventhandler_invoke_0(#name)
#define BSD_EVENTHANDLER_INVOKE_1(name, argument0) \
    bsd_eventhandler_invoke_1(#name, (uintptr_t)(argument0))
#define BSD_EVENTHANDLER_INVOKE_2(name, argument0, argument1) \
    bsd_eventhandler_invoke_2(#name, (uintptr_t)(argument0), \
        (uintptr_t)(argument1))
#define BSD_EVENTHANDLER_INVOKE_3(name, argument0, argument1, argument2) \
    bsd_eventhandler_invoke_3(#name, (uintptr_t)(argument0), \
        (uintptr_t)(argument1), (uintptr_t)(argument2))
#define EVENTHANDLER_INVOKE(name, ...) \
    BSD_EVENTHANDLER_JOIN(BSD_EVENTHANDLER_INVOKE_, \
        BSD_EVENTHANDLER_COUNT(__VA_ARGS__))(name, ##__VA_ARGS__)
#define EVENTHANDLER_DIRECT_INVOKE(name, ...) \
    EVENTHANDLER_INVOKE(name, ##__VA_ARGS__)

#endif
