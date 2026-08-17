#ifndef ISR_H
#define ISR_H

#include "types.h"
#include "arch/x86_64/interrupt.h"

#define NO_INTERRUPT_HANDLERS 256

typedef edgeos_x86_64_interrupt_frame_t REGISTERS;

typedef void (*ISR)(REGISTERS *);
typedef void (*ISR_CONTEXT)(void *);

void isr_register_interrupt_handler(int num, ISR handler);
int isr_register_context_interrupt_handler(int num, ISR_CONTEXT handler,
                                            void *context, void **cookie);
int isr_unregister_context_interrupt_handler(void *cookie);
int isr_interrupt_has_handler(int num);
void isr_end_interrupt(int num);
void isr_exception_handler(REGISTERS *reg);
void isr_irq_handler(REGISTERS *reg);

extern void exception_0();
extern void exception_1();
extern void exception_2();
extern void exception_3();
extern void exception_4();
extern void exception_5();
extern void exception_6();
extern void exception_7();
extern void exception_8();
extern void exception_9();
extern void exception_10();
extern void exception_11();
extern void exception_12();
extern void exception_13();
extern void exception_14();
extern void exception_15();
extern void exception_16();
extern void exception_17();
extern void exception_18();
extern void exception_19();
extern void exception_20();
extern void exception_21();
extern void exception_22();
extern void exception_23();
extern void exception_24();
extern void exception_25();
extern void exception_26();
extern void exception_27();
extern void exception_28();
extern void exception_29();
extern void exception_30();
extern void exception_31();
extern void exception_128();

extern void irq_0();
extern void irq_1();
extern void irq_2();
extern void irq_3();
extern void irq_4();
extern void irq_5();
extern void irq_6();
extern void irq_7();
extern void irq_8();
extern void irq_9();
extern void irq_10();
extern void irq_11();
extern void irq_12();
extern void irq_13();
extern void irq_14();
extern void irq_15();
extern void irq_16();
extern void irq_17();
extern void irq_18();
extern void irq_19();
extern void irq_20();
extern void irq_21();
extern void irq_22();
extern void irq_23();
extern void irq_24();
extern void irq_25();
extern void irq_26();
extern void irq_27();
extern void irq_28();
extern void irq_29();
extern void irq_30();
extern void irq_31();
extern void irq_apic_reschedule();
extern void irq_apic_timer();
extern void irq_apic_tlb();

#define IRQ_BASE            0x20
#define IRQ0_TIMER          0x00
#define IRQ1_KEYBOARD       0x01
#define IRQ2_CASCADE        0x02
#define IRQ3_SERIAL_PORT2   0x03
#define IRQ4_SERIAL_PORT1   0x04
#define IRQ5_RESERVED       0x05
#define IRQ6_DISKETTE_DRIVE 0x06
#define IRQ7_PARALLEL_PORT  0x07
#define IRQ8_CMOS_CLOCK     0x08
#define IRQ9_CGA            0x09
#define IRQ10_RESERVED      0x0A
#define IRQ11_RESERVED      0x0B
#define IRQ12_AUXILIARY     0x0C
#define IRQ13_FPU           0x0D
#define IRQ14_HARD_DISK     0x0E
#define IRQ15_RESERVED      0x0F

#endif
