/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the Linux-facing BSD watchdog adapter. */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/watchdog.h"
#include "compat/freebsd/sys/eventhandler.h"
#include <sys/watchdog.h>

static unsigned int g_command;
static unsigned int g_invocations;
static u_int g_last_timeout;
static sbintime_t g_last_timeout_sbt;

static u_int
test_timeout_command(sbintime_t timeout)
{
    __uint128_t scaled;
    uint64_t nanoseconds;
    u_int command = 0;

    if (timeout <= 0)
        return WD_TO_NEVER;
    scaled = (__uint128_t)(uint64_t)timeout * UINT64_C(1000000000);
    nanoseconds = (uint64_t)(scaled >> 32);
    while (nanoseconds != 0) {
        command++;
        nanoseconds >>= 1;
    }
    return command;
}

/* Model the upstream watchdog-core contract for the adapter unit test. */
int
wdog_kern_pat_sbt(sbintime_t timeout)
{
    u_int command = test_timeout_command(timeout);
    int error = timeout == 0 ? 0 : EOPNOTSUPP;

    g_last_timeout = command;
    g_last_timeout_sbt = timeout;
    EVENTHANDLER_INVOKE(watchdog_list, command, &error);
    return error;
}

int
wdog_kern_pat(u_int timeout)
{
    __uint128_t nanoseconds;

    if ((timeout & WD_LASTVAL) != 0)
        return wdog_kern_pat_sbt(g_last_timeout_sbt);
    timeout &= WD_INTERVAL;
    if (timeout == WD_TO_NEVER)
        return wdog_kern_pat_sbt(0);
    nanoseconds = (__uint128_t)UINT64_C(1) << timeout;
    return wdog_kern_pat_sbt((sbintime_t)((nanoseconds << 32) /
        UINT64_C(1000000000)));
}

u_int
wdog_kern_last_timeout(void)
{
    return g_last_timeout;
}

sbintime_t
wdog_kern_last_timeout_sbt(void)
{
    return g_last_timeout_sbt;
}

int
wdog_control(int control)
{
    if (control == WD_CTRL_DISABLE)
        (void)wdog_kern_pat_sbt(0);
    else if ((control & (WD_CTRL_ENABLE | WD_CTRL_RESET)) != 0)
        (void)wdog_kern_pat_sbt(g_last_timeout_sbt);
    return 0;
}

static void
test_watchdog_handler(void *argument, uintptr_t command,
    uintptr_t error_address)
{
    int *error = (int *)error_address;

    (void)argument;
    g_command = (unsigned int)command;
    g_invocations++;
    *error = 0;
}

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U,
        (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    eventhandler_tag tag;
    const char ping[] = "ping";

    assert(bsd_allocator_initialize(&allocator_operations) == 0);
    assert(bsd_watchdog_available() == 0);
    assert(bsd_watchdog_set_timeout_seconds(1) == -ENXIO);

    tag = EVENTHANDLER_REGISTER(watchdog_list,
        test_watchdog_handler, 0, EVENTHANDLER_PRI_ANY);
    assert(tag != 0);
    assert(bsd_watchdog_available() == 1);
    assert(strcmp(bsd_watchdog_identity(),
        "FreeBSD watchdog bridge") == 0);

    assert(bsd_watchdog_set_timeout_seconds(1) == 0);
    assert(g_command == WD_TO_1SEC);
    assert(g_invocations == 1);
    assert(bsd_watchdog_get_timeout_seconds() == 1);
    assert(bsd_watchdog_is_running() == 1);
    assert(wdog_kern_last_timeout() == WD_TO_1SEC);
    assert(wdog_kern_last_timeout_sbt() > 0);

    assert(bsd_watchdog_keepalive() == 0);
    assert(g_command == WD_TO_1SEC);
    assert(g_invocations == 2);
    assert(bsd_watchdog_write(ping, sizeof(ping)) ==
        (int)sizeof(ping));
    assert(g_invocations == 3);
    assert(bsd_watchdog_get_timeleft_seconds() == -EOPNOTSUPP);

    assert(bsd_watchdog_disable() == 0);
    assert(g_command == WD_TO_NEVER);
    assert(bsd_watchdog_is_running() == 0);
    assert(wdog_control(WD_CTRL_ENABLE) == 0);
    assert(g_command == WD_TO_NEVER);
    assert(bsd_watchdog_is_running() == 0);
    assert(bsd_watchdog_enable() == 0);
    assert(g_command == WD_TO_64SEC);
    assert(bsd_watchdog_get_timeout_seconds() == 60);
    assert(bsd_watchdog_is_running() == 1);
    assert(wdog_control(4) == 0);

    EVENTHANDLER_DEREGISTER(watchdog_list, tag);
    assert(bsd_watchdog_available() == 0);
    assert(strcmp(bsd_watchdog_identity(), "no watchdog") == 0);
    return 0;
}
