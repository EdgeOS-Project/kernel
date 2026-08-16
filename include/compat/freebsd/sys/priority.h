/* SPDX-License-Identifier: MPL-2.0 */
/* Kernel priority values mapped onto the shared EdgeOS worker scheduler. */

#ifndef _SYS_PRIORITY_H_
#define _SYS_PRIORITY_H_

#define PI_REALTIME 0
#define PI_INTR 1
#define PI_AV PI_INTR
#define PI_NET PI_INTR
#define PI_DISK PI_INTR
#define PI_TTY PI_INTR
#define PI_DULL PI_INTR
#define PI_SOFT 2
#define PI_SOFTCLOCK PI_SOFT
#define PI_SWI(source) PI_SOFT

#define PZERO 45
#define PRIBIO 43
#define PSOCK 46
#define PWAIT 47
#define PLOCK 48
#define PPAUSE 49
#define PUSER 56
#define PCATCH 0x100
#define PRI_MAX 255

#endif
