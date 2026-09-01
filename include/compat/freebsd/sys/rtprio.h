/* SPDX-License-Identifier: MPL-2.0 */
/* Realtime-priority ABI used by FreeBSD LinuxKPI scheduler helpers. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_RTPRIO_H
#define EDGEOS_COMPAT_FREEBSD_SYS_RTPRIO_H

#define RTP_PRIO_REALTIME 2
#define RTP_PRIO_NORMAL 3
#define RTP_PRIO_IDLE 4
#define RTP_PRIO_FIFO_BIT 8
#define RTP_PRIO_FIFO (RTP_PRIO_FIFO_BIT | RTP_PRIO_REALTIME)
#define RTP_PRIO_BASE(priority) ((priority) & ~RTP_PRIO_FIFO_BIT)
#define RTP_PRIO_MIN 0
#define RTP_PRIO_MAX 31

struct thread;

struct rtprio {
    unsigned short type;
    unsigned short prio;
};

int rtp_to_pri(struct rtprio *priority, struct thread *thread);

#endif
