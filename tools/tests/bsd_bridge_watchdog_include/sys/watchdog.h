/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal FreeBSD watchdog contract for hosted BSD bridge tests. */

#ifndef EDGEOS_TEST_SYS_WATCHDOG_H
#define EDGEOS_TEST_SYS_WATCHDOG_H

#include <stdint.h>

typedef unsigned int u_int;
typedef int64_t sbintime_t;

#define WD_ACTIVE 0x8000000
#define WD_PASSIVE 0x0400000
#define WD_LASTVAL 0x0200000
#define WD_INTERVAL 0x00000ff

#define WD_TO_NEVER 0
#define WD_TO_1MS 20
#define WD_TO_1SEC 30
#define WD_TO_64SEC 36

#define SBT_1S (INT64_C(1) << 32)

#define WD_CTRL_DISABLE 0x00000000
#define WD_CTRL_ENABLE 0x00000001
#define WD_CTRL_RESET 0x00000002

u_int wdog_kern_last_timeout(void);
int wdog_kern_pat(u_int timeout);
sbintime_t wdog_kern_last_timeout_sbt(void);
int wdog_kern_pat_sbt(sbintime_t timeout);
int wdog_control(int control);

#endif
