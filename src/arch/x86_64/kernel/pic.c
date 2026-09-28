/**
 * 8259 Programmable Interrupt Controller(8259 PIC) setup
 * for more, see https://wiki.osdev.org/8259_PIC
 */

#include "arch/x86_64/isr.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/io_ports.h"
#include "arch/x86_64/pic.h"

/**
 * initialize 8259 PIC with default IRQ's defined in isr.h
 */
void pic8259_init() {
    uint8 a1, a2;

    // save mask registers
    a1 = inportb(PIC1_DATA);
    a2 = inportb(PIC2_DATA);

    // send commands to pic to initialize both master & slave
    outportb(PIC1_COMMAND, ICW1);
    outportb(PIC2_COMMAND, ICW1);

    // map vector offset of all default IRQ's from 0x20 to 0x27 in master(ICW2)
    outportb(PIC1_DATA, 0x20);
    // map vector offset of all default IRQ's from 0x28 to 0x2F in slave(ICW2)
    outportb(PIC2_DATA, 0x28);

    // ICW3: tell master PIC that there is a slave PIC at IRQ2 (0000 0100)
    outportb(PIC1_DATA, 4);
    // ICW3: tell slave PIC its cascade identity (0000 0010)
    outportb(PIC2_DATA, 2);

    // ICW4, set x86 mode
    outportb(PIC1_DATA, ICW4_8086);
    outportb(PIC2_DATA, ICW4_8086);

    // restore the mask registers
    outportb(PIC1_DATA, a1);
    outportb(PIC2_DATA, a2);

    // Unmask IRQ0 (timer) and IRQ1 (keyboard)
    outportb(PIC1_DATA, 0xFC);
    outportb(PIC2_DATA, 0xFF);

}

/**
 * send end of interrupt command to PIC 8259
 */
void pic8259_eoi(uint8 irq) {
    /*
     * LAPIC and MSI/MSI-X vectors share the generic interrupt dispatcher but
     * are not owned by the legacy PIC.  Acknowledging those vectors here turns
     * every local timer or device interrupt into unnecessary port I/O and may
     * disturb a real 8259 interrupt that is still in service.
     */
    if (irq < 0x20 || irq > 0x2F)
        return;
    if(irq >= 0x28)
        outportb(PIC2, PIC_EOI);
    outportb(PIC1, PIC_EOI);
}

void pic8259_mask_irq(uint8 irq_line) {
    if (irq_line < 8) {
        uint8 mask = inportb(PIC1_DATA);
        mask = (uint8)(mask | (1u << irq_line));
        outportb(PIC1_DATA, mask);
    } else if (irq_line < 16) {
        uint8 slave = (uint8)(irq_line - 8u);
        uint8 mask = inportb(PIC2_DATA);
        mask = (uint8)(mask | (1u << slave));
        outportb(PIC2_DATA, mask);
    }
}

void pic8259_unmask_irq(uint8 irq_line) {
    if (irq_line < 8) {
        uint8 mask = inportb(PIC1_DATA);
        mask = (uint8)(mask & ~(1u << irq_line));
        outportb(PIC1_DATA, mask);
    } else if (irq_line < 16) {
        uint8 slave = (uint8)(irq_line - 8u);
        uint8 mask2 = inportb(PIC2_DATA);
        uint8 mask1 = inportb(PIC1_DATA);
        mask2 = (uint8)(mask2 & ~(1u << slave));
        mask1 = (uint8)(mask1 & ~(1u << 2)); /* ensure cascade enabled */
        outportb(PIC2_DATA, mask2);
        outportb(PIC1_DATA, mask1);
    }
}
