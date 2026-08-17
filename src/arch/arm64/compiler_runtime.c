/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 PE compiler runtime support. */

/*
 * lld's AArch64 PE target emits this helper for large stack frames.  EdgeOS
 * uses a preallocated EL1 stack without guard-page probing at this stage, so
 * the ABI entry only needs to return to the compiler-generated frame setup.
 */
void __chkstk(void) {}
