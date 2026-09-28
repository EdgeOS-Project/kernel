/* SPDX-License-Identifier: BSD-2-Clause */
/* Timecounter declarations exposed to imported FreeBSD drivers. */

#ifndef _SYS_TIMETC_H_
#define _SYS_TIMETC_H_

#include <sys/types.h>
#include <sys/time.h>

struct timecounter;
struct vdso_timehands;
struct vdso_timehands32;

typedef u_int timecounter_get_t(struct timecounter *);
typedef void timecounter_pps_t(struct timecounter *);
typedef uint32_t timecounter_fill_vdso_timehands_t(
    struct vdso_timehands *, struct timecounter *);
typedef uint32_t timecounter_fill_vdso_timehands32_t(
    struct vdso_timehands32 *, struct timecounter *);

struct timecounter {
    timecounter_get_t *tc_get_timecount;
    timecounter_pps_t *tc_poll_pps;
    u_int tc_counter_mask;
    uint64_t tc_frequency;
    const char *tc_name;
    int tc_quality;
    u_int tc_flags;
    void *tc_priv;
    struct timecounter *tc_next;
    timecounter_fill_vdso_timehands_t *tc_fill_vdso_timehands;
    timecounter_fill_vdso_timehands32_t *tc_fill_vdso_timehands32;
};

#define TC_FLAGS_C2STOP 0x00000001u
#define TC_FLAGS_SUSPEND_SAFE 0x00000002u

extern struct timecounter *timecounter;
extern int tc_min_ticktock_freq;

uint64_t tc_getfrequency(void);
void tc_init(struct timecounter *counter);
void tc_setclock(struct timespec *value);
void tc_ticktock(long count);
void cpu_tick_calibration(void);
uint64_t clockcalib(uint64_t (*read_counter)(void), const char *name);

#endif
