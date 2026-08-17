/* SPDX-License-Identifier: MPL-2.0 */
/* Shared delay and sleep-channel services for imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_SLEEP_H
#define EDGEOS_COMPAT_FREEBSD_SLEEP_H

#include <stdint.h>

struct mtx;

void bsd_delay(unsigned int microseconds);
int bsd_pause(const char *wait_message, int timeout_ticks);
int bsd_pause_sig(const char *wait_message, int timeout_ticks);
int bsd_pause_sbt(const char *wait_message, int64_t sleep_time,
    int64_t precision, int flags);
int bsd_msleep(const void *channel, struct mtx *mutex, int priority,
    const char *wait_message, int timeout_ticks);
int bsd_msleep_sbt(const void *channel, struct mtx *mutex, int priority,
    const char *wait_message, int64_t sleep_time, int64_t precision,
    int flags);
int bsd_tsleep_sbt(const void *channel, int priority,
    const char *wait_message, int64_t sleep_time, int64_t precision,
    int flags);
int bsd_rw_sleep(const void *channel, void *lock, int priority,
    const char *wait_message, int timeout_ticks);
void bsd_wakeup(const void *channel);
void bsd_wakeup_one(const void *channel);

#endif
