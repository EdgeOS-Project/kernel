/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS LinuxKPI runtime power-management bridge. */

#include <stdbool.h>

#define BSD_LINUX_PM_RUNTIME_UNIT_TEST 1
#include "../../src/compat/freebsd/kern/linuxkpi_runtime_pm.c"

#define assert(condition) do {                                          \
    if (!(condition))                                                    \
        __builtin_trap();                                                \
} while (0)

static int idle_count;
static int suspend_count;
static int resume_count;
static int resume_result;

static int
test_runtime_idle(struct device *device)
{
    assert(device != 0);
    ++idle_count;
    return 0;
}

static int
test_runtime_suspend(struct device *device)
{
    assert(device != 0);
    ++suspend_count;
    return 0;
}

static int
test_runtime_resume(struct device *device)
{
    assert(device != 0);
    ++resume_count;
    return resume_result;
}

int
main(void)
{
    const struct dev_pm_ops operations = {
        .runtime_idle = test_runtime_idle,
        .runtime_suspend = test_runtime_suspend,
        .runtime_resume = test_runtime_resume,
    };
    struct device_driver driver = {
        .pm = &operations,
    };
    struct device device = {
        .driver = &driver,
    };

    bsd_linux_pm_runtime_init(&device);
    assert(!bsd_linux_pm_runtime_suspended(&device));

    bsd_linux_pm_runtime_enable(&device);
    bsd_linux_pm_runtime_get_noresume(&device);
    assert(bsd_linux_pm_runtime_put(&device, false) == 0);
    assert(bsd_linux_pm_runtime_suspended(&device));
    assert(idle_count == 1);
    assert(suspend_count == 1);

    assert(bsd_linux_pm_runtime_get_sync(&device) == 0);
    assert(!bsd_linux_pm_runtime_suspended(&device));
    assert(resume_count == 1);
    bsd_linux_pm_runtime_dont_use_autosuspend(&device);
    assert(bsd_linux_pm_runtime_put(&device, true) == 0);
    assert(!bsd_linux_pm_runtime_suspended(&device));

    bsd_linux_pm_runtime_get_noresume(&device);
    bsd_linux_pm_runtime_use_autosuspend(&device);
    bsd_linux_pm_runtime_set_autosuspend_delay(&device, 25);
    bsd_linux_pm_runtime_mark_last_busy(&device);
    assert(bsd_linux_pm_runtime_put(&device, true) == 0);
    assert(bsd_linux_pm_runtime_suspended(&device));
    assert(suspend_count == 2);

    resume_result = -5;
    assert(bsd_linux_pm_runtime_resume_and_get(&device) == -5);
    assert(bsd_linux_pm_runtime_suspended(&device));
    assert(bsd_linux_pm_runtime_get_if_in_use(&device) == 0);
    resume_result = 0;

    bsd_linux_pm_runtime_forbid(&device);
    assert(!bsd_linux_pm_runtime_suspended(&device));
    assert(resume_count == 3);
    assert(bsd_linux_pm_runtime_autosuspend(&device) == 0);
    assert(!bsd_linux_pm_runtime_suspended(&device));
    bsd_linux_pm_runtime_allow(&device);
    assert(bsd_linux_pm_runtime_autosuspend(&device) == 0);
    assert(bsd_linux_pm_runtime_suspended(&device));

    bsd_linux_pm_runtime_remove(&device);
    assert(!bsd_linux_pm_runtime_suspended(&device));
    return 0;
}
