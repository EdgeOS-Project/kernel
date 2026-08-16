/* SPDX-License-Identifier: MPL-2.0 */
/* Fatal assertion contract for BSD drivers on EdgeOS. */

#ifndef _SYS_KASSERT_H_
#define _SYS_KASSERT_H_

#include <edgeos/systm.h>

#define KERNEL_PANICKED() 0

#define panic(...) bsd_panic(__VA_ARGS__)

#ifdef INVARIANTS
#define KASSERT(expression, message) do {                                \
    if (__builtin_expect(!(expression), 0)) {                            \
        bsd_printf("[bsd-bridge] assertion failed: %s: ", #expression);  \
        bsd_printf message;                                               \
        bsd_printf("\n");                                                 \
        bsd_bridge_panic_stop();                                          \
    }                                                                     \
} while (0)

#define MPASS(expression) \
    KASSERT((expression), ("%s", #expression))
#else
#define KASSERT(expression, message) do { (void)0; } while (0)
#define MPASS(expression) do { (void)0; } while (0)
#endif

#ifndef __assert_unreachable
#define __assert_unreachable() __builtin_unreachable()
#endif

#endif
