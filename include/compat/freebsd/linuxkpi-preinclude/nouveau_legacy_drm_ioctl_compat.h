#ifndef EDGEOS_NOUVEAU_LEGACY_DRM_IOCTL_COMPAT_H
#define EDGEOS_NOUVEAU_LEGACY_DRM_IOCTL_COMPAT_H

#ifndef overflowuid
#define overflowuid 65534
#endif

#define drm_ioctl_enter(dev) ((void)(dev))
#define drm_ioctl_exit(dev) ((void)(dev))

#endif
