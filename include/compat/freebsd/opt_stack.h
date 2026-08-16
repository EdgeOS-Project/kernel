/* SPDX-License-Identifier: MPL-2.0 */
/* Build policy for FreeBSD stack-trace consumers. */

#ifndef EDGEOS_COMPAT_FREEBSD_OPT_STACK_H
#define EDGEOS_COMPAT_FREEBSD_OPT_STACK_H

/*
 * Stack snapshots are intentionally omitted until the shared unwinder is
 * exposed through the BSD bridge.  Core failpoint behavior remains enabled.
 */

#endif
