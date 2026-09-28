/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the FreeBSD pulse-per-second compatibility service. */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <sys/errno.h>
#include <sys/timepps.h>

int hz = 1000;

static struct pps_state *g_wait_pps;
static int g_sleep_result;
static int g_sleep_calls;
static int g_wakeup_calls;
static int g_increment_on_sleep;
static struct timespec g_now = {
    .tv_sec = 100,
    .tv_nsec = 500000000,
};

void
getnanotime(struct timespec *value)
{
    *value = g_now;
}

int
bsd_msleep(const void *channel, struct mtx *mutex, int priority,
    const char *wait_message, int timeout_ticks)
{
    (void)mutex;
    (void)priority;
    (void)wait_message;
    if (channel != g_wait_pps || timeout_ticks <= 0)
        abort();
    ++g_sleep_calls;
    if (g_increment_on_sleep) {
        ++g_wait_pps->ppsinfo.assert_sequence;
        g_increment_on_sleep = 0;
    }
    return g_sleep_result;
}

void
bsd_wakeup(const void *channel)
{
    if (channel != g_wait_pps)
        abort();
    ++g_wakeup_calls;
}

static void
expect(int condition, const char *message)
{
    if (!condition) {
        printf("FAIL: %s\n", message);
        abort();
    }
}

static void
reset_wait(struct pps_state *pps)
{
    g_wait_pps = pps;
    g_sleep_result = 0;
    g_sleep_calls = 0;
    g_wakeup_calls = 0;
    g_increment_on_sleep = 0;
}

static void
test_init_and_parameters(void)
{
    struct pps_state pps = {
        .ppscap = PPS_CAPTUREASSERT | PPS_CAPTURECLEAR,
    };
    pps_params_t parameters = {
        .mode = PPS_CAPTUREASSERT | PPS_OFFSETASSERT,
    };
    pps_params_t returned = {0};
    int capabilities = 0;

    pps_init(&pps);
    expect((pps.ppscap & PPS_CANWAIT) != 0,
        "initialization advertises wait support");
    expect((pps.ppscap & PPS_CANPOLL) == 0,
        "initialization does not advertise unsupported polling");
    expect((pps.ppscap & PPS_OFFSETASSERT) != 0 &&
        (pps.ppscap & PPS_OFFSETCLEAR) != 0,
        "initialization advertises supported timestamp offsets");
    expect(pps_ioctl(PPS_IOC_SETPARAMS, (caddr_t)&parameters, &pps) == 0,
        "valid parameters are accepted");
    expect(pps_ioctl(PPS_IOC_GETPARAMS, (caddr_t)&returned, &pps) == 0,
        "parameters can be read");
    expect(returned.api_version == PPS_API_VERS_1 &&
        returned.mode == parameters.mode,
        "returned parameters include the API version and active mode");
    expect(pps_ioctl(PPS_IOC_GETCAP, (caddr_t)&capabilities, &pps) == 0 &&
        capabilities == pps.ppscap,
        "capability query returns the initialized capabilities");
    parameters.mode = PPS_TSFMT_NTPFP;
    expect(pps_ioctl(PPS_IOC_SETPARAMS, (caddr_t)&parameters, &pps) ==
        EINVAL, "unsupported timestamp formats are rejected");
}

static void
test_event_capture(void)
{
    struct pps_state pps = {
        .ppscap = PPS_CAPTUREASSERT,
    };

    pps.ppsparam.mode = PPS_CAPTUREASSERT | PPS_OFFSETASSERT;
    pps.ppsparam.assert_offset.tv_sec = 2;
    pps.ppsparam.assert_offset.tv_nsec = 750000000;
    reset_wait(&pps);
    pps_event(&pps, PPS_CAPTUREASSERT);
    expect(pps.ppsinfo.assert_sequence == 1,
        "assert events increment the sequence");
    expect(pps.ppsinfo.assert_timestamp.tv_sec == 103 &&
        pps.ppsinfo.assert_timestamp.tv_nsec == 250000000,
        "assert events capture and normalize the configured offset");
    expect(g_wakeup_calls == 1,
        "assert events wake blocked fetch operations");
    pps_event(&pps, PPS_CAPTURECLEAR);
    expect(pps.ppsinfo.clear_sequence == 0 && g_wakeup_calls == 1,
        "disabled event edges are ignored");
}

static void
test_fetch_waits_for_event(void)
{
    struct pps_state pps = {
        .ppsparam.mode = PPS_CAPTUREASSERT,
    };
    struct pps_fetch_args fetch = {
        .tsformat = PPS_TSFMT_TSPEC,
        .timeout = {
            .tv_sec = 0,
            .tv_nsec = 1000000,
        },
    };

    reset_wait(&pps);
    g_increment_on_sleep = 1;
    expect(pps_ioctl(PPS_IOC_FETCH, (caddr_t)&fetch, &pps) == 0,
        "fetch succeeds after a new event");
    expect(g_sleep_calls == 1 &&
        fetch.pps_info_buf.assert_sequence == 1,
        "fetch waits and returns the new sequence");
}

static void
test_fetch_timeout_and_validation(void)
{
    struct pps_state pps = {0};
    struct pps_fetch_args fetch = {
        .timeout = {
            .tv_sec = 0,
            .tv_nsec = 1,
        },
    };

    reset_wait(&pps);
    g_sleep_result = EWOULDBLOCK;
    expect(pps_ioctl(PPS_IOC_FETCH, (caddr_t)&fetch, &pps) == ETIMEDOUT,
        "finite waits return the PPS timeout error");
    expect(g_sleep_calls == 1,
        "sub-tick finite waits are rounded up and attempted");
    fetch.timeout.tv_nsec = 1000000000l;
    expect(pps_ioctl(PPS_IOC_FETCH, (caddr_t)&fetch, &pps) == EINVAL,
        "invalid nanosecond values are rejected");
    fetch.timeout.tv_nsec = 0;
    fetch.timeout.tv_sec = -2;
    expect(pps_ioctl(PPS_IOC_FETCH, (caddr_t)&fetch, &pps) == EINVAL,
        "invalid negative finite timeouts are rejected");
    fetch.timeout.tv_sec = 0;
    fetch.tsformat = PPS_TSFMT_NTPFP;
    expect(pps_ioctl(PPS_IOC_FETCH, (caddr_t)&fetch, &pps) == EINVAL,
        "unsupported fetch timestamp formats are rejected");
}

static void
test_fetch_indefinite_wait_retries(void)
{
    struct pps_state pps = {0};
    struct pps_fetch_args fetch = {
        .timeout = {
            .tv_sec = -1,
            .tv_nsec = -1,
        },
    };

    reset_wait(&pps);
    g_sleep_result = EWOULDBLOCK;
    g_increment_on_sleep = 1;
    expect(pps_ioctl(PPS_IOC_FETCH, (caddr_t)&fetch, &pps) == 0,
        "indefinite waits retry long sleep intervals");
    expect(g_sleep_calls == 1 &&
        fetch.pps_info_buf.assert_sequence == 1,
        "indefinite waits return after the next event");
}

int
main(void)
{
    test_init_and_parameters();
    test_event_capture();
    test_fetch_waits_for_event();
    test_fetch_timeout_and_validation();
    test_fetch_indefinite_wait_retries();
    printf("FreeBSD bridge PPS unit tests passed\n");
    return 0;
}
