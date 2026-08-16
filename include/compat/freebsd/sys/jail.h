/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_COMPAT_FREEBSD_SYS_JAIL_H
#define EDGEOS_COMPAT_FREEBSD_SYS_JAIL_H

#include "mutex.h"

/*
 * Driver sources include this FreeBSD policy header through their platform
 * wrapper. EdgeOS publishes the host identity needed by controller
 * registration while keeping isolation policy outside the driver bridge.
 */
struct prison {
    struct mtx pr_mtx;
    char pr_hostname[256];
};

extern struct prison prison0;

#endif
