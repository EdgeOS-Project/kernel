/* SPDX-License-Identifier: MPL-2.0 */
/* PE/COFF-callable ARM SMCCC entry points for the FreeBSD PSCI sources. */

#include <sys/types.h>
#include <dev/psci/smccc.h>

bool
__attribute__((weak))
has_hyp(void)
{
    register_t current_el;

    __asm __volatile("mrs %0, CurrentEL" : "=r"(current_el));
    return (current_el & 0xcul) == 0x8ul;
}

static int
arm_smccc_call(int use_hvc, register_t a0, register_t a1, register_t a2,
    register_t a3, register_t a4, register_t a5, register_t a6,
    register_t a7, struct arm_smccc_res *result)
{
    register register_t x0 __asm("x0") = a0;
    register register_t x1 __asm("x1") = a1;
    register register_t x2 __asm("x2") = a2;
    register register_t x3 __asm("x3") = a3;
    register register_t x4 __asm("x4") = a4;
    register register_t x5 __asm("x5") = a5;
    register register_t x6 __asm("x6") = a6;
    register register_t x7 __asm("x7") = a7;

    if (use_hvc) {
        __asm __volatile("hvc #0"
            : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3),
              "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7)
            : : "memory");
    } else {
        __asm __volatile("smc #0"
            : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3),
              "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7)
            : : "memory");
    }
    if (result) {
        result->a0 = x0;
        result->a1 = x1;
        result->a2 = x2;
        result->a3 = x3;
    }
    return (int)x0;
}

int
arm_smccc_smc(register_t a0, register_t a1, register_t a2,
    register_t a3, register_t a4, register_t a5, register_t a6,
    register_t a7, struct arm_smccc_res *result)
{
    return arm_smccc_call(0, a0, a1, a2, a3, a4, a5, a6, a7, result);
}

int
arm_smccc_hvc(register_t a0, register_t a1, register_t a2,
    register_t a3, register_t a4, register_t a5, register_t a6,
    register_t a7, struct arm_smccc_res *result)
{
    return arm_smccc_call(1, a0, a1, a2, a3, a4, a5, a6, a7, result);
}

#if defined(__clang__)
static int
arm_smccc_call_1_2(int use_hvc, const struct arm_smccc_1_2_regs *arguments,
    struct arm_smccc_1_2_regs *result)
{
    register register_t x0 __asm("x0") = arguments->a0;
    register register_t x1 __asm("x1") = arguments->a1;
    register register_t x2 __asm("x2") = arguments->a2;
    register register_t x3 __asm("x3") = arguments->a3;
    register register_t x4 __asm("x4") = arguments->a4;
    register register_t x5 __asm("x5") = arguments->a5;
    register register_t x6 __asm("x6") = arguments->a6;
    register register_t x7 __asm("x7") = arguments->a7;
    register register_t x8 __asm("x8") = arguments->a8;
    register register_t x9 __asm("x9") = arguments->a9;
    register register_t x10 __asm("x10") = arguments->a10;
    register register_t x11 __asm("x11") = arguments->a11;
    register register_t x12 __asm("x12") = arguments->a12;
    register register_t x13 __asm("x13") = arguments->a13;
    register register_t x14 __asm("x14") = arguments->a14;
    register register_t x15 __asm("x15") = arguments->a15;
    register register_t x16 __asm("x16") = arguments->a16;
    register register_t x17 __asm("x17") = arguments->a17;

#define EDGEOS_SMCCC_1_2_OPERANDS                                      \
    "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), \
    "+r"(x6), "+r"(x7), "+r"(x8), "+r"(x9), "+r"(x10),            \
    "+r"(x11), "+r"(x12), "+r"(x13), "+r"(x14), "+r"(x15),       \
    "+r"(x16), "+r"(x17)

    if (use_hvc) {
        __asm __volatile("hvc #0" : EDGEOS_SMCCC_1_2_OPERANDS
            : : "memory");
    } else {
        __asm __volatile("smc #0" : EDGEOS_SMCCC_1_2_OPERANDS
            : : "memory");
    }
    if (result) {
        result->a0 = x0;
        result->a1 = x1;
        result->a2 = x2;
        result->a3 = x3;
        result->a4 = x4;
        result->a5 = x5;
        result->a6 = x6;
        result->a7 = x7;
        result->a8 = x8;
        result->a9 = x9;
        result->a10 = x10;
        result->a11 = x11;
        result->a12 = x12;
        result->a13 = x13;
        result->a14 = x14;
        result->a15 = x15;
        result->a16 = x16;
        result->a17 = x17;
    }
#undef EDGEOS_SMCCC_1_2_OPERANDS
    return (int)x0;
}

int
arm_smccc_1_2_smc(const struct arm_smccc_1_2_regs *arguments,
    struct arm_smccc_1_2_regs *result)
{
    return arm_smccc_call_1_2(0, arguments, result);
}

int
arm_smccc_1_2_hvc(const struct arm_smccc_1_2_regs *arguments,
    struct arm_smccc_1_2_regs *result)
{
    return arm_smccc_call_1_2(1, arguments, result);
}
#else
/* GCC limits extended asm to 30 operands, below the SMCCC 1.2 register set. */
__asm__(
    ".text\n"
    ".macro edgeos_smccc_1_2 name, instruction\n"
    ".global \\name\n"
    ".type \\name, %function\n"
    "\\name:\n"
    "stp x19, x20, [sp, #-16]!\n"
    "mov x19, x0\n"
    "mov x20, x1\n"
    "ldp x0, x1, [x19, #0]\n"
    "ldp x2, x3, [x19, #16]\n"
    "ldp x4, x5, [x19, #32]\n"
    "ldp x6, x7, [x19, #48]\n"
    "ldp x8, x9, [x19, #64]\n"
    "ldp x10, x11, [x19, #80]\n"
    "ldp x12, x13, [x19, #96]\n"
    "ldp x14, x15, [x19, #112]\n"
    "ldp x16, x17, [x19, #128]\n"
    "\\instruction #0\n"
    "cbz x20, 1f\n"
    "stp x0, x1, [x20, #0]\n"
    "stp x2, x3, [x20, #16]\n"
    "stp x4, x5, [x20, #32]\n"
    "stp x6, x7, [x20, #48]\n"
    "stp x8, x9, [x20, #64]\n"
    "stp x10, x11, [x20, #80]\n"
    "stp x12, x13, [x20, #96]\n"
    "stp x14, x15, [x20, #112]\n"
    "stp x16, x17, [x20, #128]\n"
    "1:\n"
    "ldp x19, x20, [sp], #16\n"
    "ret\n"
    ".size \\name, .-\\name\n"
    ".endm\n"
    "edgeos_smccc_1_2 arm_smccc_1_2_smc, smc\n"
    "edgeos_smccc_1_2 arm_smccc_1_2_hvc, hvc\n");
#endif
