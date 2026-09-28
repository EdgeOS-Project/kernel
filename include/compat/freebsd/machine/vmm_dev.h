/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture selector for the imported FreeBSD VMM device interface. */

#if defined(__x86_64__)
#include <amd64/include/vmm_dev.h>
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#include <arm64/include/vmm_dev.h>
#else
#error "The FreeBSD VMM is unsupported on this architecture"
#endif
