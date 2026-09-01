#include <compat/freebsd/edgeos/linuxkpi_runtime_pm.h>

#ifdef BSD_LINUX_PM_RUNTIME_UNIT_TEST
#include <errno.h>
#include <stddef.h>

struct device;

struct dev_pm_ops {
    int (*runtime_idle)(struct device *device);
    int (*runtime_suspend)(struct device *device);
    int (*runtime_resume)(struct device *device);
};

struct device_driver {
    const struct dev_pm_ops *pm;
};

struct class {
    const struct dev_pm_ops *pm;
};

struct device {
    struct device_driver *driver;
    struct class *class;
};
#else
#include <sys/systm.h>

#undef min
#undef max
#include <linux/device.h>
#include <linux/errno.h>
#endif

#include <stdint.h>

#define BSD_LINUX_PM_RUNTIME_DEVICE_LIMIT 2048U

enum bsd_linux_pm_runtime_state {
    BSD_LINUX_PM_ACTIVE = 0,
    BSD_LINUX_PM_SUSPENDING,
    BSD_LINUX_PM_SUSPENDED,
    BSD_LINUX_PM_RESUMING,
};

typedef struct bsd_linux_pm_runtime_entry {
    struct device *device;
    unsigned int usage_count;
    unsigned int disable_depth;
    enum bsd_linux_pm_runtime_state state;
    bool allowed;
    bool use_autosuspend;
    int autosuspend_delay_ms;
    uint64_t last_busy_sequence;
} bsd_linux_pm_runtime_entry_t;

static bsd_linux_pm_runtime_entry_t
    g_runtime_pm_entries[BSD_LINUX_PM_RUNTIME_DEVICE_LIMIT];
static unsigned int g_runtime_pm_lock;
static uint64_t g_runtime_pm_sequence;

static void
runtime_pm_lock(void)
{
    while (__atomic_exchange_n(&g_runtime_pm_lock, 1U,
        __ATOMIC_ACQUIRE) != 0U) {
    }
}

static void
runtime_pm_unlock(void)
{
    __atomic_store_n(&g_runtime_pm_lock, 0U, __ATOMIC_RELEASE);
}

static bsd_linux_pm_runtime_entry_t *
runtime_pm_find_locked(struct device *device, bool create)
{
    bsd_linux_pm_runtime_entry_t *empty = NULL;

    for (unsigned int index = 0;
         index < BSD_LINUX_PM_RUNTIME_DEVICE_LIMIT; ++index) {
        bsd_linux_pm_runtime_entry_t *entry = &g_runtime_pm_entries[index];

        if (entry->device == device)
            return entry;
        if (!entry->device && !empty)
            empty = entry;
    }
    if (!create || !empty)
        return NULL;
    empty->device = device;
    empty->disable_depth = 1;
    empty->state = BSD_LINUX_PM_ACTIVE;
    empty->allowed = true;
    return empty;
}

static const struct dev_pm_ops *
runtime_pm_ops(struct device *device)
{
    if (device->driver && device->driver->pm)
        return device->driver->pm;
    if (device->class)
        return device->class->pm;
    return NULL;
}

static int
runtime_pm_transition(struct device *device, bool suspend)
{
    bsd_linux_pm_runtime_entry_t *entry;
    const struct dev_pm_ops *ops;
    int result = 0;

    if (!device)
        return -EINVAL;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (!entry) {
        runtime_pm_unlock();
        return -ENOMEM;
    }
    if (entry->disable_depth != 0 || (suspend && !entry->allowed)) {
        runtime_pm_unlock();
        return 0;
    }
    if (suspend) {
        if (entry->usage_count != 0 ||
            entry->state == BSD_LINUX_PM_SUSPENDED) {
            runtime_pm_unlock();
            return 0;
        }
        if (entry->state != BSD_LINUX_PM_ACTIVE) {
            runtime_pm_unlock();
            return -EAGAIN;
        }
        entry->state = BSD_LINUX_PM_SUSPENDING;
    } else {
        if (entry->state == BSD_LINUX_PM_ACTIVE) {
            runtime_pm_unlock();
            return 0;
        }
        if (entry->state != BSD_LINUX_PM_SUSPENDED) {
            runtime_pm_unlock();
            return -EAGAIN;
        }
        entry->state = BSD_LINUX_PM_RESUMING;
    }
    runtime_pm_unlock();

    ops = runtime_pm_ops(device);
    if (ops) {
        if (suspend && ops->runtime_idle)
            result = ops->runtime_idle(device);
        if (result == 0 && suspend && ops->runtime_suspend)
            result = ops->runtime_suspend(device);
        if (!suspend && ops->runtime_resume)
            result = ops->runtime_resume(device);
    }

    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, false);
    if (entry) {
        if (result == 0)
            entry->state = suspend ? BSD_LINUX_PM_SUSPENDED :
                BSD_LINUX_PM_ACTIVE;
        else
            entry->state = suspend ? BSD_LINUX_PM_ACTIVE :
                BSD_LINUX_PM_SUSPENDED;
    }
    runtime_pm_unlock();
    return result;
}

void
bsd_linux_pm_runtime_init(struct device *device)
{
    if (!device)
        return;
    runtime_pm_lock();
    (void)runtime_pm_find_locked(device, true);
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_remove(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, false);
    if (entry)
        *entry = (bsd_linux_pm_runtime_entry_t){0};
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_mark_last_busy(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        entry->last_busy_sequence = ++g_runtime_pm_sequence;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_use_autosuspend(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        entry->use_autosuspend = true;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_dont_use_autosuspend(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        entry->use_autosuspend = false;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_set_autosuspend_delay(struct device *device, int delay_ms)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        entry->autosuspend_delay_ms = delay_ms;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_set_active(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        entry->state = BSD_LINUX_PM_ACTIVE;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_allow(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        entry->allowed = true;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_forbid(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        entry->allowed = false;
    runtime_pm_unlock();
    (void)runtime_pm_transition(device, false);
}

void
bsd_linux_pm_runtime_enable(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry && entry->disable_depth != 0)
        --entry->disable_depth;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_disable(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        ++entry->disable_depth;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_get_noresume(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        ++entry->usage_count;
    runtime_pm_unlock();
}

void
bsd_linux_pm_runtime_put_noidle(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;

    if (!device)
        return;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry && entry->usage_count != 0)
        --entry->usage_count;
    runtime_pm_unlock();
}

int
bsd_linux_pm_runtime_get_sync(struct device *device)
{
    bsd_linux_pm_runtime_get_noresume(device);
    return runtime_pm_transition(device, false);
}

int
bsd_linux_pm_runtime_resume_and_get(struct device *device)
{
    int result = bsd_linux_pm_runtime_get_sync(device);

    if (result < 0)
        bsd_linux_pm_runtime_put_noidle(device);
    return result;
}

int
bsd_linux_pm_runtime_get_if_in_use(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;
    int result = 0;

    if (!device)
        return 0;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry && entry->usage_count != 0 &&
        entry->state == BSD_LINUX_PM_ACTIVE) {
        ++entry->usage_count;
        result = 1;
    }
    runtime_pm_unlock();
    return result;
}

int
bsd_linux_pm_runtime_get_if_active(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;
    int result = 0;

    if (!device)
        return 0;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry && entry->state == BSD_LINUX_PM_ACTIVE) {
        ++entry->usage_count;
        result = 1;
    }
    runtime_pm_unlock();
    return result;
}

int
bsd_linux_pm_runtime_put(struct device *device, bool autosuspend)
{
    bsd_linux_pm_runtime_entry_t *entry;
    bool should_suspend = false;

    if (!device)
        return -EINVAL;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (!entry) {
        runtime_pm_unlock();
        return -ENOMEM;
    }
    if (entry->usage_count != 0)
        --entry->usage_count;
    if (entry->usage_count == 0 && entry->disable_depth == 0 &&
        entry->allowed && (!autosuspend || entry->use_autosuspend))
        should_suspend = true;
    runtime_pm_unlock();
    return should_suspend ? runtime_pm_transition(device, true) : 0;
}

int
bsd_linux_pm_runtime_autosuspend(struct device *device)
{
    return runtime_pm_transition(device, true);
}

int
bsd_linux_pm_runtime_resume(struct device *device)
{
    return runtime_pm_transition(device, false);
}

bool
bsd_linux_pm_runtime_suspended(struct device *device)
{
    bsd_linux_pm_runtime_entry_t *entry;
    bool suspended = false;

    if (!device)
        return false;
    runtime_pm_lock();
    entry = runtime_pm_find_locked(device, true);
    if (entry)
        suspended = entry->state == BSD_LINUX_PM_SUSPENDED;
    runtime_pm_unlock();
    return suspended;
}
