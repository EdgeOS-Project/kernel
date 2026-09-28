#ifndef EDGEOS_NOUVEAU_LEGACY_DRM_EDID_COMPAT_H
#define EDGEOS_NOUVEAU_LEGACY_DRM_EDID_COMPAT_H

#include <linux/hdmi.h>

static inline int
edgeos_nouveau_hdmi_avi_infoframe_init(struct hdmi_avi_infoframe *frame)
{
	hdmi_avi_infoframe_init(frame);
	return 0;
}

#define hdmi_avi_infoframe_init edgeos_nouveau_hdmi_avi_infoframe_init

#endif
