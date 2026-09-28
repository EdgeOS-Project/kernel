/* SPDX-License-Identifier: BSD-2-Clause */
/* Paravirtual clock contract used by imported BSD hypervisor drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_PVCLOCK_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_PVCLOCK_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/bus.h>
#include <sys/time.h>

#define PVCLOCK_CDEVNAME "pvclock"
#define PVCLOCK_FLAG_TSC_STABLE 0x01u
#define PVCLOCK_FLAG_GUEST_PAUSED 0x02u

struct pvclock_vcpu_time_info {
    uint32_t version;
    uint32_t pad0;
    uint64_t tsc_timestamp;
    uint64_t system_time;
    uint32_t tsc_to_system_mul;
    int8_t tsc_shift;
    uint8_t flags;
    uint8_t pad[2];
};

struct pvclock_wall_clock {
    uint32_t version;
    uint32_t sec;
    uint32_t nsec;
};

typedef struct pvclock_wall_clock *pvclock_get_wallclock_t(void *argument);

struct pvclock {
    pvclock_get_wallclock_t *get_wallclock;
    void *get_wallclock_arg;
    struct pvclock_vcpu_time_info *timeinfos;
    bool stable_flag_supported;
    device_t bridge_device;
    const char *bridge_name;
    int bridge_quality;
    unsigned int bridge_flags;
};

uint64_t pvclock_scale_delta(uint64_t delta, uint32_t multiplier,
    int shift);
void pvclock_resume(void);
uint64_t pvclock_tsc_freq(struct pvclock_vcpu_time_info *time_info);
uint64_t pvclock_get_timecount(struct pvclock_vcpu_time_info *time_info);
void pvclock_get_wallclock(struct pvclock_wall_clock *wall_clock,
    struct timespec *time);
void pvclock_init(struct pvclock *clock, device_t device,
    const char *name, int quality, unsigned int flags);
void pvclock_gettime(struct pvclock *clock, struct timespec *time);
int pvclock_destroy(struct pvclock *clock);

#endif
