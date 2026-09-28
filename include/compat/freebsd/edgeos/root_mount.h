/* SPDX-License-Identifier: MPL-2.0 */
/* Root readiness hold contract for imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_ROOT_MOUNT_H
#define EDGEOS_COMPAT_FREEBSD_ROOT_MOUNT_H

#include <stdint.h>

struct root_hold_token;
struct root_hold_token *root_mount_hold(const char *identifier);
void root_mount_rel(struct root_hold_token *token);
uint32_t bsd_root_mount_hold_count(void);
uint64_t bsd_root_mount_hold_sequence(void);

#endif
