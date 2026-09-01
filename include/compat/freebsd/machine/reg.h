/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture selector for imported FreeBSD register definitions. */

#if defined(__x86_64__)
#include <amd64/include/reg.h>
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#include <arm64/include/reg.h>
#else
#error "FreeBSD register definitions are unsupported on this architecture"
#endif
