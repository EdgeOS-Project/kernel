/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 platform discovery for controlled BSD bridge device handoff. */

#ifndef EDGEOS_COMPAT_FREEBSD_ARM64_HANDOFF_H
#define EDGEOS_COMPAT_FREEBSD_ARM64_HANDOFF_H

#include "arch/arm64/bootinfo.h"
#include "handoff.h"

int bsd_bridge_arm64_handoff_start(const char *command_line,
    const edgeos_arm64_bootinfo_t *bootinfo,
    bsd_bridge_handoff_status_t *status);

#endif
