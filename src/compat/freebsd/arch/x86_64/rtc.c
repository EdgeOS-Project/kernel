/* SPDX-License-Identifier: MPL-2.0 */
/* MC146818 register access for imported FreeBSD x86 laptop drivers. */

#include <stdint.h>

static volatile uint32_t g_rtc_io_guard;

static uint64_t
rtc_interrupt_save_disable(void)
{
    uint64_t flags;

    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    return flags;
}

static void
rtc_interrupt_restore(uint64_t flags)
{
    if ((flags & (1ull << 9)) != 0)
        __asm__ __volatile__("sti" ::: "memory");
}

static void
rtc_guard_lock(void)
{
    while (__atomic_test_and_set(&g_rtc_io_guard, __ATOMIC_ACQUIRE))
        __asm__ __volatile__("pause");
}

static void
rtc_guard_unlock(void)
{
    __atomic_clear(&g_rtc_io_guard, __ATOMIC_RELEASE);
}

static uint8_t
rtc_port_read(uint16_t port)
{
    uint8_t value;

    __asm__ __volatile__("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void
rtc_port_write(uint16_t port, uint8_t value)
{
    __asm__ __volatile__("outb %0, %1" :: "a"(value), "Nd"(port));
}

int
rtcin(int reg)
{
    uint64_t flags;
    uint8_t value;

    flags = rtc_interrupt_save_disable();
    rtc_guard_lock();
    (void)rtc_port_read(0x84);
    rtc_port_write(0x70, (uint8_t)reg);
    (void)rtc_port_read(0x84);
    value = rtc_port_read(0x71);
    rtc_guard_unlock();
    rtc_interrupt_restore(flags);
    return value;
}

void
writertc(int reg, unsigned char value)
{
    uint64_t flags;

    flags = rtc_interrupt_save_disable();
    rtc_guard_lock();
    (void)rtc_port_read(0x84);
    rtc_port_write(0x70, (uint8_t)reg);
    (void)rtc_port_read(0x84);
    rtc_port_write(0x71, value);
    (void)rtc_port_read(0x84);
    rtc_guard_unlock();
    rtc_interrupt_restore(flags);
}
