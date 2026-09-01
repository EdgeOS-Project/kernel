/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture selector for the imported FreeBSD VMM snapshot interface. */

#if defined(__x86_64__)
#include <amd64/include/vmm_snapshot.h>
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#include <arm64/include/vmm_snapshot.h>
#else
#error "The FreeBSD VMM is unsupported on this architecture"
#endif
