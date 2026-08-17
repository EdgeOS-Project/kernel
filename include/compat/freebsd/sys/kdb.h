/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * FreeBSD Driver Bridge debugger compatibility.
 *
 * EdgeOS does not configure the FreeBSD kernel debugger.  Drivers are allowed
 * to include <sys/kdb.h> unconditionally and keep their KDB-only code guarded
 * by the upstream KDB option.
 */

#ifndef _SYS_KDB_H_
#define _SYS_KDB_H_

extern int kdb_active;

#endif
