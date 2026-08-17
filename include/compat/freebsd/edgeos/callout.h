/* SPDX-License-Identifier: MPL-2.0 */
/* Shared timer-callout runtime for imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CALLOUT_H
#define EDGEOS_COMPAT_FREEBSD_CALLOUT_H

int bsd_callout_runtime_initialize(void);
int bsd_callout_runtime_is_initialized(void);
void bsd_callout_process_timer_tick(void);

#endif
