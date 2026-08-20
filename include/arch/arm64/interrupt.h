/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 interrupt interface. */
#ifndef EDGEOS_ARCH_ARM64_INTERRUPT_H
#define EDGEOS_ARCH_ARM64_INTERRUPT_H

#include "arch/arm64/bootinfo.h"

typedef struct edgeos_arm64_exception_frame {
    uint64_t x[31];
    uint64_t esr;
    uint64_t far;
    uint64_t elr;
    uint64_t spsr;
    uint64_t sp_el0;
} edgeos_arm64_exception_frame_t;

typedef void (*edgeos_arm64_irq_callback_t)(uint32_t interrupt, void *context);

void edgeos_arm64_exceptions_init(void);
int edgeos_arm64_gic_discover(const edgeos_arm64_bootinfo_t *bootinfo,
                               uint64_t *dist_out, uint64_t *redist_out);
uint32_t edgeos_arm64_gic_version(void);
int edgeos_arm64_gic_send_sgi(uint64_t mpidr, uint32_t interrupt_id);
int edgeos_arm64_irq_init(const edgeos_arm64_bootinfo_t *bootinfo);
int edgeos_arm64_irq_init_secondary(void);
int edgeos_arm64_irq_register(uint32_t interrupt, uint32_t flags,
                              edgeos_arm64_irq_callback_t callback,
                              void *context);
int edgeos_arm64_irq_unregister(uint32_t interrupt,
                                edgeos_arm64_irq_callback_t callback,
                                void *context);
int edgeos_arm64_irq_mask(uint32_t interrupt);
int edgeos_arm64_irq_unmask(uint32_t interrupt);
void edgeos_arm64_timer_enter_idle(void);
void edgeos_arm64_timer_leave_idle(void);
int edgeos_arm64_timer_arm_rseq_slice(uint32_t microseconds);
void edgeos_arm64_timer_cancel_rseq_slice(void);
int edgeos_arm64_timer_consume_rseq_slice(void);
void edgeos_arm64_sync_handler(edgeos_arm64_exception_frame_t *frame);
void edgeos_arm64_irq_handler(edgeos_arm64_exception_frame_t *frame);
uint64_t edgeos_arm64_timer_ticks(void);
void edgeos_arm64_fiq_handler(edgeos_arm64_exception_frame_t *frame);
void edgeos_arm64_serror_handler(edgeos_arm64_exception_frame_t *frame);

#endif
