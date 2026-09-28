/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD-compatible static startup ordering for the BSD Driver Bridge. */

#ifndef _SYS_KERNEL_H_
#define _SYS_KERNEL_H_

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "_task.h"
#include "queue_compat.h"
#include "linker_set.h"
#include "../edgeos/module.h"

int getenv_uint64(const char *name, uint64_t *data);
int getenv_int(const char *name, int *data);
int bsd_tunable_str_fetch(const char *path, char *value, size_t capacity);
int bsd_tunable_long_fetch(const char *path, long *value);

enum sysinit_sub_id {
    SI_SUB_DUMMY = 0x0000000,
    SI_SUB_TUNABLES = 0x0700000,
    SI_SUB_COPYRIGHT = 0x0800001,
    SI_SUB_VM = 0x1000000,
    SI_SUB_COUNTER = 0x1100000,
    SI_SUB_KMEM = 0x1800000,
    SI_SUB_HYPERVISOR = 0x1a40000,
    SI_SUB_WITNESS = 0x1a80000,
    SI_SUB_MTX_POOL_DYNAMIC = 0x1ac0000,
    SI_SUB_LOCK = 0x1b00000,
    SI_SUB_EVENTHANDLER = 0x1c00000,
    SI_SUB_VNET_PRELINK = 0x1e00000,
    SI_SUB_KLD = 0x2000000,
    SI_SUB_KHELP = 0x2080000,
    SI_SUB_CPU = 0x2100000,
    SI_SUB_RACCT = 0x2110000,
    SI_SUB_KDTRACE = 0x2140000,
    SI_SUB_RANDOM = 0x2160000,
    SI_SUB_MAC = 0x2180000,
    SI_SUB_MAC_POLICY = 0x21c0000,
    SI_SUB_MAC_LATE = 0x21d0000,
    SI_SUB_VNET = 0x21e0000,
    SI_SUB_INTRINSIC = 0x2200000,
    SI_SUB_VM_CONF = 0x2300000,
    SI_SUB_DDB_SERVICES = 0x2380000,
    SI_SUB_RUN_QUEUE = 0x2400000,
    SI_SUB_KTRACE = 0x2480000,
    SI_SUB_OPENSOLARIS = 0x2490000,
    SI_SUB_AUDIT = 0x24c0000,
    SI_SUB_CREATE_INIT = 0x2500000,
    SI_SUB_SCHED_IDLE = 0x2600000,
    SI_SUB_MBUF = 0x2700000,
    SI_SUB_INTR = 0x2800000,
    SI_SUB_TASKQ = 0x2880000,
    SI_SUB_EPOCH = 0x2888000,
    SI_SUB_SOFTINTR = 0x2a00000,
    SI_SUB_DEVFS = 0x2f00000,
    SI_SUB_INIT_IF = 0x3000000,
    SI_SUB_NETGRAPH = 0x3010000,
    SI_SUB_DTRACE = 0x3020000,
    SI_SUB_DTRACE_PROVIDER = 0x3048000,
    SI_SUB_DTRACE_ANON = 0x308c000,
    SI_SUB_DRIVERS = 0x3100000,
    SI_SUB_CONFIGURE = 0x3800000,
    SI_SUB_VFS = 0x4000000,
    SI_SUB_CLOCKS = 0x4800000,
    SI_SUB_SYSV_SHM = 0x6400000,
    SI_SUB_SYSV_SEM = 0x6800000,
    SI_SUB_SYSV_MSG = 0x6c00000,
    SI_SUB_P1003_1B = 0x6e00000,
    SI_SUB_PSEUDO = 0x7000000,
    SI_SUB_EXEC = 0x7400000,
    SI_SUB_PROTO_BEGIN = 0x8000000,
    SI_SUB_PROTO_PFIL = 0x8100000,
    SI_SUB_PROTO_MC = 0x8300000,
    SI_SUB_PROTO_IF = 0x8400000,
    SI_SUB_PROTO_DOMAININIT = 0x8600000,
    SI_SUB_PROTO_DOMAIN = 0x8800000,
    SI_SUB_PROTO_FIREWALL = 0x8806000,
    SI_SUB_PROTO_IFATTACHDOMAIN = 0x8808000,
    SI_SUB_PROTO_END = 0x8ffffff,
    SI_SUB_KPROF = 0x9000000,
    SI_SUB_KICK_SCHEDULER = 0xa000000,
    SI_SUB_INT_CONFIG_HOOKS = 0xa800000,
    SI_SUB_ROOT_CONF = 0xb000000,
    SI_SUB_INTRINSIC_POST = 0xd000000,
    SI_SUB_SYSCALLS = 0xd800000,
    SI_SUB_VNET_DONE = 0xdc00000,
    SI_SUB_KTHREAD_INIT = 0xe000000,
    SI_SUB_KTHREAD_PAGE = 0xe400000,
    SI_SUB_KTHREAD_VM = 0xe800000,
    SI_SUB_KTHREAD_BUF = 0xea00000,
    SI_SUB_KTHREAD_UPDATE = 0xec00000,
    SI_SUB_KTHREAD_IDLE = 0xee00000,
    SI_SUB_SMP = 0xf000000,
    SI_SUB_RACCTD = 0xf100000,
    SI_SUB_LAST = 0xfffffff,
};

#define SI_SUB_FIREWALL SI_SUB_PROTO_FIREWALL
#define SI_SUB_OFED_PREINIT (SI_SUB_ROOT_CONF - 2)
#define SI_SUB_OFED_MODINIT (SI_SUB_ROOT_CONF - 1)

enum sysinit_elem_order {
    SI_ORDER_FIRST = 0x0000000,
    SI_ORDER_SECOND = 0x0000001,
    SI_ORDER_THIRD = 0x0000002,
    SI_ORDER_FOURTH = 0x0000003,
    SI_ORDER_FIFTH = 0x0000004,
    SI_ORDER_SIXTH = 0x0000005,
    SI_ORDER_SEVENTH = 0x0000006,
    SI_ORDER_EIGHTH = 0x0000007,
    SI_ORDER_MIDDLE = 0x1000000,
    SI_ORDER_ANY = 0xfffffff,
};

#define SI_ORDER_LAST SI_ORDER_ANY

struct tunable_int {
    const char *path;
    int *var;
};

void tunable_int_init(const void *data);

#define EDGEOS_TUNABLE_CONCAT_INNER(left, right) left##right
#define EDGEOS_TUNABLE_CONCAT(left, right) \
    EDGEOS_TUNABLE_CONCAT_INNER(left, right)
#define TUNABLE_INT(path, value) \
    static struct tunable_int \
        EDGEOS_TUNABLE_CONCAT(edgeos_tunable_int_, __LINE__) = { \
            (path), (value), \
        }; \
    SYSINIT(EDGEOS_TUNABLE_CONCAT(edgeos_tunable_int_init_, __LINE__), \
        SI_SUB_TUNABLES, SI_ORDER_MIDDLE, tunable_int_init, \
        &EDGEOS_TUNABLE_CONCAT(edgeos_tunable_int_, __LINE__))
#define TUNABLE_INT_FETCH(path, value) \
    getenv_int((path), (value))
#define TUNABLE_BOOL(path, value)
#define TUNABLE_BOOL_FETCH(path, value) getenv_bool((path), (value))
#define TUNABLE_STR(path, value, size)
#define TUNABLE_STR_FETCH(path, value, size) \
    bsd_tunable_str_fetch((path), (value), (size))
#define TUNABLE_UINT64(path, value)
#define TUNABLE_UINT64_FETCH(path, value) getenv_uint64((path), (value))
static inline int
bsd_tunable_ulong_fetch(const char *path, unsigned long *value)
{
    uint64_t parsed;

    if (!value || !getenv_uint64(path, &parsed) || parsed > ULONG_MAX)
        return 0;
    *value = (unsigned long)parsed;
    return 1;
}
#define TUNABLE_ULONG(path, value)
#define TUNABLE_ULONG_FETCH(path, value) \
    bsd_tunable_ulong_fetch((path), (value))
#define TUNABLE_LONG(path, value)
#define TUNABLE_LONG_FETCH(path, value) \
    bsd_tunable_long_fetch((path), (value))

typedef void (*sysinit_nfunc_t)(void *);
typedef void (*sysinit_cfunc_t)(const void *);

struct sysinit {
    enum sysinit_sub_id subsystem;
    enum sysinit_elem_order order;
    sysinit_cfunc_t func;
    const void *udata;
    const char *name;
};

#define C_SYSINIT(uniquifier, subsystem_value, order_value, callback, argument) \
    static const struct sysinit uniquifier##_sys_init = {              \
        (subsystem_value), (order_value), (callback), (argument),       \
        #uniquifier,                                                    \
    };                                                                  \
    BSD_BRIDGE_LINK_SYSINIT(uniquifier##_sys_init)

#define SYSINIT(uniquifier, subsystem_value, order_value, callback, argument) \
    C_SYSINIT(uniquifier, subsystem_value, order_value,                 \
        (sysinit_cfunc_t)(sysinit_nfunc_t)(callback), (void *)(argument))

#define C_SYSUNINIT(uniquifier, subsystem_value, order_value, callback, argument) \
    static const struct sysinit uniquifier##_sys_uninit = {             \
        (subsystem_value), (order_value), (callback), (argument),       \
        #uniquifier,                                                    \
    };                                                                  \
    BSD_BRIDGE_LINK_SYSUNINIT(uniquifier##_sys_uninit)

#define SYSUNINIT(uniquifier, subsystem_value, order_value, callback, argument) \
    C_SYSUNINIT(uniquifier, subsystem_value, order_value,               \
        (sysinit_cfunc_t)(sysinit_nfunc_t)(callback), (void *)(argument))

void sysinit_add(struct sysinit **set, struct sysinit **set_end);

typedef void (*ich_func_t)(void *argument);

struct intr_config_hook {
    STAILQ_ENTRY(intr_config_hook) ich_links;
    uintptr_t ich_state;
#define ICHS_QUEUED 1u
#define ICHS_RUNNING 2u
#define ICHS_DONE 3u
    ich_func_t ich_func;
    void *ich_arg;
};

int config_intrhook_establish(struct intr_config_hook *hook);
void config_intrhook_disestablish(struct intr_config_hook *hook);
int config_intrhook_drain(struct intr_config_hook *hook);
void config_intrhook_oneshot(ich_func_t function, void *argument);

extern int tick;
extern int hz;
extern int psratio;
extern int stathz;
extern int profhz;
extern int profprocs;
extern volatile int ticks;
extern volatile long ticksl;

#endif
