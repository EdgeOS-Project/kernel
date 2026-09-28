/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture selector for imported FreeBSD hypervisor definitions. */

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#include <machine/armreg.h>
#include <arm64/include/hypervisor.h>
#else
#error "FreeBSD hypervisor definitions are unsupported on this architecture"
#endif
