#ifndef EDGEOS_NOUVEAU_LEGACY_DRM_MST_COMPAT_H
#define EDGEOS_NOUVEAU_LEGACY_DRM_MST_COMPAT_H

#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/wait.h>

#ifndef EREMOTEIO
#define EREMOTEIO 121
#endif

#define DRM_INIT_WAITQUEUE(_queue, _name) \
	init_waitqueue_head((_queue))
#define DRM_DESTROY_WAITQUEUE(_queue) do { (void)(_queue); } while (0)
#define DRM_WAKEUP_ALL(_queue, _interlock) do { \
	(void)(_interlock); \
	wake_up_all((_queue)); \
} while (0)
#define DRM_TIMED_WAIT_UNTIL(_result, _queue, _interlock, _ticks, _condition) do { \
	mutex_unlock((_interlock)); \
	(_result) = wait_event_timeout(*(_queue), (_condition), (_ticks)); \
	mutex_lock((_interlock)); \
} while (0)

#define device_xname(_device) dev_name((_device))
#define of_node fwnode

#endif
