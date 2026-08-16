/* SPDX-License-Identifier: MPL-2.0 */
/* Offsets for the x86-64 trap frame exposed by the BSD driver bridge. */

#define TF_RDI 0
#define TF_RSI 8
#define TF_RDX 16
#define TF_RCX 24
#define TF_R8 32
#define TF_R9 40
#define TF_RAX 48
#define TF_RBX 56
#define TF_RBP 64
#define TF_R10 72
#define TF_R11 80
#define TF_R12 88
#define TF_R13 96
#define TF_R14 104
#define TF_R15 112
#define TF_TRAPNO 120
#define TF_ADDR 128
#define TF_FLAGS 136
#define TF_ERR 144
#define TF_RIP 152
#define TF_CS 160
#define TF_RFLAGS 168
#define TF_RSP 176
#define TF_SS 184
