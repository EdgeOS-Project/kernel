/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD-compatible kernel trace macros for non-KTR bridge builds. */

#ifndef _SYS_KTR_H_
#define _SYS_KTR_H_

#define KTR_DEV 0x00000004u
#define KTR_SPARE3 0x20000000u

/*
 * Imported drivers use CTR calls for optional diagnostic tracing.  EdgeOS
 * does not define KTR for production builds, matching FreeBSD's default
 * compile-out behavior while preserving all driver control flow.
 */
#define CTR0(mask, description) ((void)0)
#define CTR1(mask, description, argument1) ((void)0)
#define CTR2(mask, description, argument1, argument2) ((void)0)
#define CTR3(mask, description, argument1, argument2, argument3) ((void)0)
#define CTR4(mask, description, argument1, argument2, argument3, argument4) \
    ((void)0)
#define CTR5(mask, description, argument1, argument2, argument3, argument4, \
    argument5) ((void)0)
#define CTR6(mask, description, argument1, argument2, argument3, argument4, \
    argument5, argument6) ((void)0)

#endif
