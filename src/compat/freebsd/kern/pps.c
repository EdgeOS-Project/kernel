/* SPDX-License-Identifier: MPL-2.0 */
/* Pulse-per-second support used by imported FreeBSD serial drivers. */

#include <stdint.h>

#include <sys/errno.h>
#include <sys/priority.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/timepps.h>

#ifdef BSD_BRIDGE_HOST_TEST
void getnanotime(struct timespec *value);
#ifndef ENOIOCTL
#define ENOIOCTL ENOTTY
#endif
#endif

static int
pps_abi_aware(const struct pps_state *pps, int version)
{
    return (pps->kcmode & KCMODE_ABIFLAG) != 0 &&
        pps->driver_abi >= version;
}

static int
pps_timeout_to_ticks(const struct timespec *timeout, int *timeout_ticks,
    int *infinite)
{
    uint64_t ticks;
    uint64_t nanosecond_ticks;

    if (!timeout || !timeout_ticks || !infinite)
        return EINVAL;
    *infinite = timeout->tv_sec == -1;
    if (*infinite) {
        *timeout_ticks = 0x7fffffff;
        return 0;
    }
    if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
        timeout->tv_nsec >= 1000000000l)
        return EINVAL;
    if ((uint64_t)timeout->tv_sec >
        (uint64_t)0x7fffffff / (uint64_t)hz) {
        *timeout_ticks = 0x7fffffff;
        return 0;
    }
    ticks = (uint64_t)timeout->tv_sec * (uint64_t)hz;
    nanosecond_ticks =
        ((uint64_t)timeout->tv_nsec * (uint64_t)hz +
        UINT64_C(999999999)) / UINT64_C(1000000000);
    if (ticks > (uint64_t)0x7fffffff - nanosecond_ticks)
        ticks = 0x7fffffff;
    else
        ticks += nanosecond_ticks;
    if (ticks == 0 && (timeout->tv_sec != 0 || timeout->tv_nsec != 0))
        ticks = 1;
    *timeout_ticks = (int)ticks;
    return 0;
}

static int
pps_fetch(struct pps_fetch_args *fetch, struct pps_state *pps)
{
    pps_seq_t assert_sequence;
    pps_seq_t clear_sequence;
    struct mtx *driver_mutex;
    int infinite;
    int timeout_ticks;
    int error;

    if (fetch->tsformat != 0 && fetch->tsformat != PPS_TSFMT_TSPEC)
        return EINVAL;
    if (fetch->timeout.tv_sec != 0 || fetch->timeout.tv_nsec != 0) {
        error = pps_timeout_to_ticks(&fetch->timeout, &timeout_ticks,
            &infinite);
        if (error != 0)
            return error;
        assert_sequence =
            atomic_load_int(&pps->ppsinfo.assert_sequence);
        clear_sequence =
            atomic_load_int(&pps->ppsinfo.clear_sequence);
        driver_mutex = pps_abi_aware(pps, 1) ?
            pps->driver_mtx : NULL;
        while (assert_sequence ==
                atomic_load_int(&pps->ppsinfo.assert_sequence) &&
            clear_sequence ==
                atomic_load_int(&pps->ppsinfo.clear_sequence)) {
            error = msleep(pps, driver_mutex, PCATCH, "ppsfch",
                timeout_ticks);
            if (error == EWOULDBLOCK) {
                if (infinite)
                    continue;
                return ETIMEDOUT;
            }
            if (error != 0)
                return error;
        }
    }
    pps->ppsinfo.current_mode = pps->ppsparam.mode;
    fetch->pps_info_buf = pps->ppsinfo;
    return 0;
}

static void
pps_timespec_add(struct timespec *value, const struct timespec *offset)
{
    if (!value || !offset)
        return;
    value->tv_sec += offset->tv_sec;
    value->tv_nsec += offset->tv_nsec;
    while (value->tv_nsec >= 1000000000l) {
        ++value->tv_sec;
        value->tv_nsec -= 1000000000l;
    }
    while (value->tv_nsec < 0) {
        --value->tv_sec;
        value->tv_nsec += 1000000000l;
    }
}

void
pps_init(struct pps_state *pps)
{
    if (!pps)
        return;
    pps->ppscap |= PPS_TSFMT_TSPEC | PPS_CANWAIT;
    if (pps->ppscap & PPS_CAPTUREASSERT)
        pps->ppscap |= PPS_OFFSETASSERT;
    if (pps->ppscap & PPS_CAPTURECLEAR)
        pps->ppscap |= PPS_OFFSETCLEAR;
    pps->kcmode &= ~KCMODE_ABIFLAG;
}

void
pps_init_abi(struct pps_state *pps)
{
    if (!pps)
        return;
    pps_init(pps);
    if (pps->driver_abi != 0) {
        pps->kcmode |= KCMODE_ABIFLAG;
        pps->kernel_abi = PPS_ABI_VERSION;
    }
}

void
pps_capture(struct pps_state *pps)
{
    if (!pps)
        return;
    pps->capgen = 1;
}

void
pps_event(struct pps_state *pps, int event)
{
    struct timespec *timestamp;
    const struct timespec *offset;
    pps_seq_t *sequence;
    int offset_enabled;

    if (!pps || (event & pps->ppsparam.mode) == 0)
        return;
    if (event == PPS_CAPTUREASSERT) {
        timestamp = &pps->ppsinfo.assert_timestamp;
        offset = &pps->ppsparam.assert_offset;
        sequence = &pps->ppsinfo.assert_sequence;
        offset_enabled =
            (pps->ppsparam.mode & PPS_OFFSETASSERT) != 0;
    } else if (event == PPS_CAPTURECLEAR) {
        timestamp = &pps->ppsinfo.clear_timestamp;
        offset = &pps->ppsparam.clear_offset;
        sequence = &pps->ppsinfo.clear_sequence;
        offset_enabled =
            (pps->ppsparam.mode & PPS_OFFSETCLEAR) != 0;
    } else {
        return;
    }
    getnanotime(timestamp);
    if (offset_enabled)
        pps_timespec_add(timestamp, offset);
    ++*sequence;
    pps->ppsinfo.current_mode = pps->ppsparam.mode;
    wakeup(pps);
}

int
pps_ioctl(unsigned long command, caddr_t data, struct pps_state *pps)
{
    if (!pps)
        return EINVAL;
    switch (command) {
    case PPS_IOC_CREATE:
    case PPS_IOC_DESTROY:
        return 0;
    case PPS_IOC_SETPARAMS: {
        pps_params_t *parameters = (pps_params_t *)data;

        if (!parameters || (parameters->mode & ~pps->ppscap) != 0 ||
            (parameters->mode & PPS_TSFMT_NTPFP) != 0)
            return EINVAL;
        pps->ppsparam = *parameters;
        return 0;
    }
    case PPS_IOC_GETPARAMS: {
        pps_params_t *parameters = (pps_params_t *)data;

        if (!parameters)
            return EINVAL;
        *parameters = pps->ppsparam;
        parameters->api_version = PPS_API_VERS_1;
        return 0;
    }
    case PPS_IOC_GETCAP:
        if (!data)
            return EINVAL;
        *(int *)data = pps->ppscap;
        return 0;
    case PPS_IOC_FETCH: {
        struct pps_fetch_args *fetch =
            (struct pps_fetch_args *)data;

        if (!fetch)
            return EINVAL;
        return pps_fetch(fetch, pps);
    }
    case PPS_IOC_FETCH_FFCOUNTER:
    case PPS_IOC_KCBIND:
        return EOPNOTSUPP;
    default:
        return ENOIOCTL;
    }
}
