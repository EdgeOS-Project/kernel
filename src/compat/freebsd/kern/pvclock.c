/* SPDX-License-Identifier: MPL-2.0 */
/* Shared paravirtual clock runtime for imported BSD clock drivers. */

#include <limits.h>
#include <stdint.h>

#include <sys/types.h>
#include <machine/cpufunc.h>
#include <machine/pvclock.h>
#include <sys/pcpu.h>

static volatile uint64_t g_pvclock_last_system_time;

uint64_t
pvclock_scale_delta(uint64_t delta, uint32_t multiplier, int shift)
{
    __uint128_t product;

    if (shift < 0)
        delta >>= (unsigned int)-shift;
    else if (shift < 64)
        delta <<= (unsigned int)shift;
    else
        delta = 0;
    product = (__uint128_t)delta * multiplier;
    return (uint64_t)(product >> 32);
}

static uint64_t
pvclock_read_system_time(struct pvclock_vcpu_time_info *time_info)
{
    uint64_t system_time;
    uint64_t previous;
    uint32_t version;

    if (!time_info)
        return 0;
    do {
        version = __atomic_load_n(&time_info->version, __ATOMIC_ACQUIRE);
        if ((version & 1u) != 0)
            continue;
        system_time = time_info->system_time + pvclock_scale_delta(
            rdtsc() - time_info->tsc_timestamp,
            time_info->tsc_to_system_mul, time_info->tsc_shift);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    } while (version != __atomic_load_n(
        &time_info->version, __ATOMIC_RELAXED));

    previous = __atomic_load_n(
        &g_pvclock_last_system_time, __ATOMIC_ACQUIRE);
    while (system_time > previous &&
        !__atomic_compare_exchange_n(&g_pvclock_last_system_time,
            &previous, system_time, false,
            __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
    }
    return system_time < previous ? previous : system_time;
}

void
pvclock_resume(void)
{
    __atomic_store_n(&g_pvclock_last_system_time, 0, __ATOMIC_RELEASE);
}

uint64_t
pvclock_tsc_freq(struct pvclock_vcpu_time_info *time_info)
{
    uint64_t frequency;

    if (!time_info || time_info->tsc_to_system_mul == 0)
        return 0;
    frequency = (UINT64_C(1000000000) << 32) /
        time_info->tsc_to_system_mul;
    if (time_info->tsc_shift < 0)
        frequency <<= (unsigned int)-time_info->tsc_shift;
    else
        frequency >>= (unsigned int)time_info->tsc_shift;
    return frequency;
}

uint64_t
pvclock_get_timecount(struct pvclock_vcpu_time_info *time_info)
{
    return pvclock_read_system_time(time_info);
}

void
pvclock_get_wallclock(struct pvclock_wall_clock *wall_clock,
    struct timespec *time)
{
    uint32_t version;

    if (!wall_clock || !time)
        return;
    do {
        version = __atomic_load_n(&wall_clock->version, __ATOMIC_ACQUIRE);
        if ((version & 1u) != 0)
            continue;
        time->tv_sec = wall_clock->sec;
        time->tv_nsec = wall_clock->nsec;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    } while (version != __atomic_load_n(
        &wall_clock->version, __ATOMIC_RELAXED));
}

void
pvclock_init(struct pvclock *clock, device_t device,
    const char *name, int quality, unsigned int flags)
{
    if (!clock)
        return;
    clock->bridge_device = device;
    clock->bridge_name = name;
    clock->bridge_quality = quality;
    clock->bridge_flags = flags;
    pvclock_resume();
}

void
pvclock_gettime(struct pvclock *clock, struct timespec *time)
{
    struct pvclock_wall_clock *wall_clock;
    uint64_t nanoseconds;

    if (!clock || !clock->get_wallclock || !clock->timeinfos || !time)
        return;
    wall_clock = clock->get_wallclock(clock->get_wallclock_arg);
    pvclock_get_wallclock(wall_clock, time);
    nanoseconds = pvclock_read_system_time(
        &clock->timeinfos[curcpu]);
    time->tv_sec += (time_t)(nanoseconds / UINT64_C(1000000000));
    time->tv_nsec += (long)(nanoseconds % UINT64_C(1000000000));
    if (time->tv_nsec >= 1000000000l) {
        time->tv_sec++;
        time->tv_nsec -= 1000000000l;
    }
}

int
pvclock_destroy(struct pvclock *clock)
{
    if (!clock)
        return 22;
    clock->bridge_device = 0;
    clock->bridge_name = 0;
    return 0;
}
