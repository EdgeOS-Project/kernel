/* SPDX-License-Identifier: MPL-2.0 */
/* Linux-facing adapter for watchdog providers imported through the BSD bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_WATCHDOG_H
#define EDGEOS_COMPAT_FREEBSD_WATCHDOG_H

#include <stdint.h>

int bsd_watchdog_available(void);
int bsd_watchdog_enable(void);
int bsd_watchdog_disable(void);
int bsd_watchdog_keepalive(void);
int bsd_watchdog_set_timeout_seconds(int seconds);
int bsd_watchdog_get_timeout_seconds(void);
int bsd_watchdog_get_timeleft_seconds(void);
int bsd_watchdog_is_running(void);
int bsd_watchdog_write(const char *buffer, uint32_t length);
const char *bsd_watchdog_identity(void);

#endif
