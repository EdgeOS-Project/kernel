#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_AMDGPU_CONFIG_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_AMDGPU_CONFIG_H_

/* EdgeOS does not provide the Linux perf event API required by AMDGPU PMU. */
#undef CONFIG_PERF_EVENTS

#endif
