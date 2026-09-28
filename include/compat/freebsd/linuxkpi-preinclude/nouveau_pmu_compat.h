#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_PMU_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_PMU_COMPAT_H

#define DRM_WAIT_NOINTR_UNTIL(_result, _queue, _interlock, _condition) do { \
	mutex_unlock((_interlock)); \
	wait_event(*(_queue), (_condition)); \
	mutex_lock((_interlock)); \
	(_result) = 0; \
} while (0)

#define DRM_WAKEUP_ONE(_queue, _interlock) do { \
	(void)(_interlock); \
	wake_up((_queue)); \
} while (0)

#undef KASSERT
#define KASSERT(_expression, ...) BUG_ON(!(_expression))

#endif
