/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture selector for imported FreeBSD assembly definitions. */

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#include <arm64/include/asm.h>

#if defined(EDGEOS_BSD_COFF_TARGET) && defined(LOCORE)
#undef LENTRY
#undef ENTRY
#undef EENTRY
#undef LEND
#undef END
#undef EEND
#define LENTRY(sym) .text; .p2align 2; sym:; BTI_C; DTRACE_NOP
#define ENTRY(sym) .globl sym; LENTRY(sym)
#define EENTRY(sym) .globl sym; .text; .p2align 2; sym:
#define LEND(sym) .ltorg
#define END(sym) LEND(sym)
#define EEND(sym)
#endif
#else
#error "FreeBSD assembly definitions are unsupported on this architecture"
#endif
