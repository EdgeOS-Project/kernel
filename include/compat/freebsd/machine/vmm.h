/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture selector for the imported FreeBSD VMM interface. */

#if defined(__x86_64__)
#include <amd64/include/vmm.h>
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#include <machine/pte.h>
#include <machine/pmap.h>
#include <arm64/include/vmm.h>
#else
#error "The FreeBSD VMM is unsupported on this architecture"
#endif
