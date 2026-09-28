#ifndef EDGEOS_FREEBSD_LINUXKPI_RUNTIME_PM_H
#define EDGEOS_FREEBSD_LINUXKPI_RUNTIME_PM_H

#include <stdbool.h>

struct device;

void bsd_linux_pm_runtime_init(struct device *device);
void bsd_linux_pm_runtime_remove(struct device *device);
void bsd_linux_pm_runtime_mark_last_busy(struct device *device);
void bsd_linux_pm_runtime_use_autosuspend(struct device *device);
void bsd_linux_pm_runtime_dont_use_autosuspend(struct device *device);
void bsd_linux_pm_runtime_set_autosuspend_delay(struct device *device,
    int delay_ms);
void bsd_linux_pm_runtime_set_active(struct device *device);
void bsd_linux_pm_runtime_allow(struct device *device);
void bsd_linux_pm_runtime_forbid(struct device *device);
void bsd_linux_pm_runtime_enable(struct device *device);
void bsd_linux_pm_runtime_disable(struct device *device);
void bsd_linux_pm_runtime_get_noresume(struct device *device);
void bsd_linux_pm_runtime_put_noidle(struct device *device);
int bsd_linux_pm_runtime_get_sync(struct device *device);
int bsd_linux_pm_runtime_resume_and_get(struct device *device);
int bsd_linux_pm_runtime_get_if_in_use(struct device *device);
int bsd_linux_pm_runtime_get_if_active(struct device *device);
int bsd_linux_pm_runtime_put(struct device *device, bool autosuspend);
int bsd_linux_pm_runtime_autosuspend(struct device *device);
int bsd_linux_pm_runtime_resume(struct device *device);
bool bsd_linux_pm_runtime_suspended(struct device *device);

#endif
