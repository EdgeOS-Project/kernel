/* Public domain. */

#ifndef EDGEOS_LINUXKPI_LINUX_PM_RUNTIME_H
#define EDGEOS_LINUXKPI_LINUX_PM_RUNTIME_H

#include <linux/device.h>
#include <linux/pm.h>
#include <compat/freebsd/edgeos/linuxkpi_runtime_pm.h>

#define pm_runtime_mark_last_busy(device) \
    bsd_linux_pm_runtime_mark_last_busy((device))
#define pm_runtime_use_autosuspend(device) \
    bsd_linux_pm_runtime_use_autosuspend((device))
#define pm_runtime_dont_use_autosuspend(device) \
    bsd_linux_pm_runtime_dont_use_autosuspend((device))
#define pm_runtime_put_autosuspend(device) \
    bsd_linux_pm_runtime_put((device), true)
#define pm_runtime_set_autosuspend_delay(device, delay) \
    bsd_linux_pm_runtime_set_autosuspend_delay((device), (delay))
#define pm_runtime_set_active(device) \
    bsd_linux_pm_runtime_set_active((device))
#define pm_runtime_allow(device) bsd_linux_pm_runtime_allow((device))
#define pm_runtime_forbid(device) bsd_linux_pm_runtime_forbid((device))
#define pm_runtime_put_noidle(device) \
    bsd_linux_pm_runtime_put_noidle((device))
#define pm_runtime_get_noresume(device) \
    bsd_linux_pm_runtime_get_noresume((device))
#define pm_runtime_put(device) bsd_linux_pm_runtime_put((device), false)
#define pm_runtime_enable(device) bsd_linux_pm_runtime_enable((device))
#define pm_runtime_disable(device) bsd_linux_pm_runtime_disable((device))
#define pm_runtime_autosuspend(device) \
    bsd_linux_pm_runtime_autosuspend((device))
#define pm_runtime_resume(device) bsd_linux_pm_runtime_resume((device))

static inline int
pm_runtime_get_sync(struct device *device)
{
    return bsd_linux_pm_runtime_get_sync(device);
}

static inline int
pm_runtime_get_if_in_use(struct device *device)
{
    return bsd_linux_pm_runtime_get_if_in_use(device);
}

#if defined(LINUXKPI_VERSION) && LINUXKPI_VERSION < 60900
static inline int
pm_runtime_get_if_active(struct device *device, bool ignore_usage)
{
    (void)ignore_usage;
    return bsd_linux_pm_runtime_get_if_active(device);
}
#else
static inline int
pm_runtime_get_if_active(struct device *device)
{
    return bsd_linux_pm_runtime_get_if_active(device);
}
#endif

static inline int
pm_runtime_suspended(struct device *device)
{
    return bsd_linux_pm_runtime_suspended(device);
}

static inline int
pm_runtime_resume_and_get(struct device *device)
{
    return bsd_linux_pm_runtime_resume_and_get(device);
}

#endif
