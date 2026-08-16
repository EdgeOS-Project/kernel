/* SPDX-License-Identifier: MPL-2.0 */
/* Verify every AArch64 SIMD register across sustained scheduler handoffs. */

        .text
        .align  2
        .global _start
        .type   _start, %function

_start:
        movi    v0.16b, #0
        movi    v1.16b, #1
        movi    v2.16b, #2
        movi    v3.16b, #3
        movi    v4.16b, #4
        movi    v5.16b, #5
        movi    v6.16b, #6
        movi    v7.16b, #7
        movi    v8.16b, #8
        movi    v9.16b, #9
        movi    v10.16b, #10
        movi    v11.16b, #11
        movi    v12.16b, #12
        movi    v13.16b, #13
        movi    v14.16b, #14
        movi    v15.16b, #15
        movi    v16.16b, #16
        movi    v17.16b, #17
        movi    v18.16b, #18
        movi    v19.16b, #19
        movi    v20.16b, #20
        movi    v21.16b, #21
        movi    v22.16b, #22
        movi    v23.16b, #23
        movi    v24.16b, #24
        movi    v25.16b, #25
        movi    v26.16b, #26
        movi    v27.16b, #27
        movi    v28.16b, #28
        movi    v29.16b, #29
        movi    v30.16b, #30
        movi    v31.16b, #31
        movz    x20, #0x2710

.Literation:
        mov     x8, #124
        svc     #0
        adrp    x9, register_snapshot
        add     x9, x9, :lo12:register_snapshot
        stp     q0, q1, [x9, #0]
        stp     q2, q3, [x9, #32]
        stp     q4, q5, [x9, #64]
        stp     q6, q7, [x9, #96]
        stp     q8, q9, [x9, #128]
        stp     q10, q11, [x9, #160]
        stp     q12, q13, [x9, #192]
        stp     q14, q15, [x9, #224]
        stp     q16, q17, [x9, #256]
        stp     q18, q19, [x9, #288]
        stp     q20, q21, [x9, #320]
        stp     q22, q23, [x9, #352]
        stp     q24, q25, [x9, #384]
        stp     q26, q27, [x9, #416]
        stp     q28, q29, [x9, #448]
        stp     q30, q31, [x9, #480]
        mov     x10, #0
.Lcheck:
        ldrb    w11, [x9, x10]
        lsr     x12, x10, #4
        cmp     w11, w12
        b.ne    .Lfailed
        add     x10, x10, #1
        cmp     x10, #512
        b.ne    .Lcheck
        subs    x20, x20, #1
        b.ne    .Literation

        mov     x0, #1
        adrp    x1, pass_message
        add     x1, x1, :lo12:pass_message
        mov     x2, #19
        mov     x8, #64
        svc     #0
        mov     x0, #0
        mov     x8, #93
        svc     #0

.Lfailed:
        adrp    x13, failure_record
        add     x13, x13, :lo12:failure_record
        stp     x10, x11, [x13]
        mov     x0, #2
        adrp    x1, fail_message
        add     x1, x1, :lo12:fail_message
        mov     x2, #19
        mov     x8, #64
        svc     #0
        mov     x0, #2
        mov     x1, x13
        mov     x2, #16
        mov     x8, #64
        svc     #0
        mov     x0, #1
        mov     x8, #93
        svc     #0

        .section .rodata
pass_message:
        .ascii  "arm64_fpsimd: PASS\n"
fail_message:
        .ascii  "arm64_fpsimd: FAIL\n"

        .bss
        .align  4
register_snapshot:
        .skip   512
failure_record:
        .skip   16
