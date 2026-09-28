/* SPDX-License-Identifier: MPL-2.0 */
/* Shared Linux-facing control plane for imported FreeBSD watchdog drivers. */

#include <stdint.h>

#include "compat/freebsd/edgeos/watchdog.h"
#include "compat/freebsd/sys/eventhandler.h"

#include <sys/errno.h>
#include <sys/time.h>
#include <sys/watchdog.h>

int
bsd_watchdog_available(void)
{
    return bsd_eventhandler_count("watchdog_list") != 0 ||
        bsd_eventhandler_count("watchdog_sbt_list") != 0;
}

int
bsd_watchdog_set_timeout_seconds(int seconds)
{
    int error;

    if (seconds <= 0)
        return -EINVAL;
    if (!bsd_watchdog_available())
        return -ENXIO;
    error = wdog_kern_pat_sbt((sbintime_t)seconds * SBT_1S);
    if (error != 0)
        return -error;
    return 0;
}

int
bsd_watchdog_enable(void)
{
    sbintime_t timeout = wdog_kern_last_timeout_sbt();

    return bsd_watchdog_set_timeout_seconds(
        timeout > 0 ? (int)(timeout / SBT_1S) : 60);
}

int
bsd_watchdog_disable(void)
{
    int error = wdog_control(WD_CTRL_DISABLE);

    return error == 0 ? 0 : -error;
}

int
bsd_watchdog_keepalive(void)
{
    int error = wdog_control(WD_CTRL_RESET);

    return error == 0 ? 0 : -error;
}

int
bsd_watchdog_get_timeout_seconds(void)
{
    sbintime_t timeout;

    if (!bsd_watchdog_available())
        return -ENODEV;
    timeout = wdog_kern_last_timeout_sbt();
    return timeout > 0 ? (int)(timeout / SBT_1S) : 0;
}

int
bsd_watchdog_get_timeleft_seconds(void)
{
    return bsd_watchdog_available() ? -EOPNOTSUPP : -ENODEV;
}

int
bsd_watchdog_is_running(void)
{
    return bsd_watchdog_available() &&
        wdog_kern_last_timeout_sbt() != 0;
}

int
bsd_watchdog_write(const char *buffer, uint32_t length)
{
    int error;

    if (!buffer && length != 0)
        return -EINVAL;
    if (length == 0)
        return 0;
    error = bsd_watchdog_keepalive();
    return error == 0 ? (int)length : error;
}

const char *
bsd_watchdog_identity(void)
{
    return bsd_watchdog_available() ?
        "FreeBSD watchdog bridge" : "no watchdog";
}
