/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * EdgeOS adaptation: declarations map to the shared bridge callout runtime.
 */

#ifndef _SYS_CALLOUT_H_
#define _SYS_CALLOUT_H_

#include "_callout.h"

#ifndef SBT_1S
#define SBT_1S ((sbintime_t)1 << 32)
#define SBT_1M (SBT_1S * 60)
#define SBT_1MS (SBT_1S / 1000)
#define SBT_1US (SBT_1S / 1000000)
#define SBT_1NS (SBT_1S / 1000000000)
#define SBT_MAX 0x7fffffffffffffffLL
#endif

#define CALLOUT_TRYLOCK 0x0001
#define CALLOUT_ACTIVE 0x0002
#define CALLOUT_PENDING 0x0004
#define CALLOUT_MPSAFE 0x0008
#define CALLOUT_RETURNUNLOCKED 0x0010
#define CALLOUT_SHAREDLOCK 0x0020
#define CALLOUT_DFRMIGRATION 0x0040
#define CALLOUT_PROCESSED 0x0080
#define CALLOUT_DIRECT 0x0100

#define C_DIRECT_EXEC 0x0001
#define C_PRELBITS 7
#define C_PRELRANGE ((1 << C_PRELBITS) - 1)
#define C_PREL(x) (((x) + 1) << 1)
#define C_PRELGET(x) ((int)((((x) >> 1) & C_PRELRANGE) - 1))
#define C_HARDCLOCK 0x0100
#define C_ABSOLUTE 0x0200
#define C_PRECALC 0x0400
#define C_CATCH 0x0800

#define CS_DRAIN 0x0001

#define callout_active(c) ((c)->c_flags & CALLOUT_ACTIVE)
#define callout_deactivate(c) ((c)->c_flags &= ~CALLOUT_ACTIVE)
#define callout_pending(c) ((c)->c_iflags & CALLOUT_PENDING)
#define callout_drain(c) _callout_stop_safe((c), CS_DRAIN)

void callout_init(struct callout *callout, int mpsafe);
void _callout_init_lock(struct callout *callout,
    struct lock_object *lock, int flags);

#define callout_init_mtx(c, mtx, flags) \
    _callout_init_lock((c), &(mtx)->lock_object, (flags))
#define callout_init_rm(c, rm, flags) \
    _callout_init_lock((c), &(rm)->lock_object, (flags))
#define callout_init_rw(c, rw, flags) \
    _callout_init_lock((c), &(rw)->lock_object, (flags))

int callout_reset_sbt_on(struct callout *callout, sbintime_t sbt,
    sbintime_t precision, callout_func_t *function, void *argument,
    int cpu, int flags);

#define callout_reset_sbt(c, sbt, precision, function, argument, flags) \
    callout_reset_sbt_on((c), (sbt), (precision), (function), \
        (argument), -1, (flags))
#define callout_reset_sbt_curcpu(c, sbt, precision, function, argument, flags) \
    callout_reset_sbt((c), (sbt), (precision), (function), (argument), (flags))
#define callout_reset_on(c, ticks, function, argument, cpu) \
    callout_reset_sbt_on((c), tick_sbt * (ticks), 0, (function), \
        (argument), (cpu), C_HARDCLOCK)
#define callout_reset(c, ticks, function, argument) \
    callout_reset_on((c), (ticks), (function), (argument), -1)
#define callout_reset_curcpu(c, ticks, function, argument) \
    callout_reset((c), (ticks), (function), (argument))
#define callout_schedule_sbt_on(c, sbt, precision, cpu, flags) \
    callout_reset_sbt_on((c), (sbt), (precision), (c)->c_func, \
        (c)->c_arg, (cpu), (flags))
#define callout_schedule_sbt(c, sbt, precision, flags) \
    callout_schedule_sbt_on((c), (sbt), (precision), -1, (flags))
#define callout_schedule_sbt_curcpu(c, sbt, precision, flags) \
    callout_schedule_sbt((c), (sbt), (precision), (flags))

int callout_schedule(struct callout *callout, int ticks);
int callout_schedule_on(struct callout *callout, int ticks, int cpu);
#define callout_schedule_curcpu(c, ticks) callout_schedule((c), (ticks))
#define callout_stop(c) _callout_stop_safe((c), 0)
int _callout_stop_safe(struct callout *callout, int flags);
void callout_process(sbintime_t now);
void callout_when(sbintime_t sbt, sbintime_t precision, int flags,
    sbintime_t *result, sbintime_t *precision_result);

extern sbintime_t tick_sbt;

#endif
