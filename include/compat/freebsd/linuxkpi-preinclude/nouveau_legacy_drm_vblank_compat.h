#ifndef EDGEOS_NOUVEAU_LEGACY_DRM_VBLANK_COMPAT_H
#define EDGEOS_NOUVEAU_LEGACY_DRM_VBLANK_COMPAT_H

#include "nouveau_legacy_drm_mst_compat.h"
#include <linux/seqlock.h>

#ifndef seqlock_destroy
#define seqlock_destroy(lock) do { (void)(lock); } while (0)
#endif

#define DRM_SPIN_WAKEUP_ONE(_queue, _interlock) do { \
	(void)(_interlock); \
	wake_up((_queue)); \
} while (0)

#define DRM_SPIN_TIMED_WAIT_UNTIL(_result, _queue, _interlock, _ticks, \
    _condition) do { \
	spin_unlock((_interlock)); \
	(_result) = wait_event_timeout(*(_queue), (_condition), (_ticks)); \
	spin_lock((_interlock)); \
} while (0)

#endif
