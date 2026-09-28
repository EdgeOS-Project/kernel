/* SPDX-License-Identifier: BSD-2-Clause */
/* Capability-rights subset used for descriptor lookup by LinuxKPI. */

#ifndef _SYS_CAPSICUM_H_
#define _SYS_CAPSICUM_H_

#include <stdint.h>

typedef struct cap_rights {
    uint64_t words[2];
} cap_rights_t;

#define CAP_ALL(rights) do { \
    (rights)->words[0] = UINT64_MAX; \
    (rights)->words[1] = UINT64_MAX; \
} while (0)

extern const cap_rights_t cap_no_rights;

#endif
