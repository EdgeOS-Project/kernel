/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CPU helpers for the EdgeOS FreeBSD driver bridge. */

#ifndef _MACHINE_CPUFUNC_H_
#define _MACHINE_CPUFUNC_H_

#include <sys/stdint.h>

#define readb(location) (*(volatile uint8_t *)(location))
#define readw(location) (*(volatile uint16_t *)(location))
#define readl(location) (*(volatile uint32_t *)(location))
#define readq(location) (*(volatile uint64_t *)(location))

#define writeb(location, value) \
    (*(volatile uint8_t *)(location) = (uint8_t)(value))
#define writew(location, value) \
    (*(volatile uint16_t *)(location) = (uint16_t)(value))
#define writel(location, value) \
    (*(volatile uint32_t *)(location) = (uint32_t)(value))
#define writeq(location, value) \
    (*(volatile uint64_t *)(location) = (uint64_t)(value))

static __inline void
breakpoint(void)
{
#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
    __asm __volatile("brk #0");
#elif defined(__x86_64__)
    __asm __volatile("int $3");
#else
#error "Unsupported EdgeOS FreeBSD driver bridge architecture"
#endif
}

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
static __inline register_t
intr_disable(void)
{
    register_t flags;

    __asm__ __volatile__(
        "mrs %0, daif\n"
        "msr daifset, #3"
        : "=&r"(flags) : : "memory");
    return flags;
}

static __inline void
disable_intr(void)
{
    __asm__ __volatile__("msr daifset, #3" : : : "memory");
}

static __inline void
enable_intr(void)
{
    __asm__ __volatile__("msr daifclr, #3" : : : "memory");
}

static __inline void
intr_restore(register_t flags)
{
    __asm__ __volatile__("msr daif, %0" : : "r"(flags) : "memory");
}

static __inline uint64_t
arm64_address_translate_s1e1r(uint64_t address)
{
    uint64_t result;

    __asm__ __volatile__(
        "at s1e1r, %1\n"
        "isb\n"
        "mrs %0, par_el1"
        : "=r"(result) : "r"(address) : "memory");
    return result;
}
#elif defined(__x86_64__)
struct region_descriptor;

static __inline void
do_cpuid(unsigned int leaf, unsigned int *registers)
{
    __asm__ __volatile__("cpuid"
        : "=a"(registers[0]), "=b"(registers[1]),
          "=c"(registers[2]), "=d"(registers[3])
        : "a"(leaf), "c"(0));
}

static __inline void
cpuid_count(unsigned int leaf, unsigned int subleaf,
    unsigned int *registers)
{
    __asm__ __volatile__("cpuid"
        : "=a"(registers[0]), "=b"(registers[1]),
          "=c"(registers[2]), "=d"(registers[3])
        : "a"(leaf), "c"(subleaf));
}

static __inline void
clts(void)
{
    __asm__ __volatile__("clts");
}

static __inline void
load_cr0(unsigned long value)
{
    __asm__ __volatile__("movq %0, %%cr0" : : "r"(value) : "memory");
}

static __inline unsigned long
rcr0(void)
{
    unsigned long value;

    __asm__ __volatile__("movq %%cr0, %0" : "=r"(value));
    return value;
}

static __inline unsigned long
rcr3(void)
{
    unsigned long value;

    __asm__ __volatile__("movq %%cr3, %0" : "=r"(value));
    return value;
}

static __inline void
load_cr4(unsigned long value)
{
    __asm__ __volatile__("movq %0, %%cr4" : : "r"(value) : "memory");
}

static __inline unsigned long
rcr4(void)
{
    unsigned long value;

    __asm__ __volatile__("movq %%cr4, %0" : "=r"(value));
    return value;
}

static __inline unsigned long
rxcr(unsigned int register_id)
{
    uint32_t low;
    uint32_t high;

    __asm__ __volatile__("xgetbv" : "=a"(low), "=d"(high)
        : "c"(register_id));
    return (unsigned long)low | ((unsigned long)high << 32);
}

static __inline void
load_xcr(unsigned int register_id, unsigned long value)
{
    uint32_t low = (uint32_t)value;
    uint32_t high = (uint32_t)(value >> 32);

    __asm__ __volatile__("xsetbv" : : "c"(register_id), "a"(low),
        "d"(high) : "memory");
}

static __inline void
xrstors(uint8_t *save_area, uint64_t state_bitmap)
{
    uint32_t low = (uint32_t)state_bitmap;
    uint32_t high = (uint32_t)(state_bitmap >> 32);

    __asm__ __volatile__("xrstors %0" : : "m"(*save_area), "a"(low),
        "d"(high) : "memory");
}

static __inline void
xsaves(uint8_t *save_area, uint64_t state_bitmap)
{
    uint32_t low = (uint32_t)state_bitmap;
    uint32_t high = (uint32_t)(state_bitmap >> 32);

    __asm__ __volatile__("xsaves %0" : "=m"(*save_area) : "a"(low),
        "d"(high) : "memory");
}

static __inline uint64_t
rdmsr(unsigned int register_id)
{
    uint32_t low;
    uint32_t high;

    __asm__ __volatile__("rdmsr"
        : "=a"(low), "=d"(high) : "c"(register_id));
    return ((uint64_t)high << 32) | low;
}

static __inline void
wrmsr(unsigned int register_id, uint64_t value)
{
    __asm__ __volatile__("wrmsr"
        : : "c"(register_id), "a"((uint32_t)value),
            "d"((uint32_t)(value >> 32)) : "memory");
}

#define EDGEOS_X86_DEBUG_REGISTER_READER(name, reg) \
static __inline unsigned long name(void) \
{ \
    unsigned long value; \
    __asm__ __volatile__("movq %%" #reg ", %0" : "=r"(value)); \
    return value; \
}

#define EDGEOS_X86_DEBUG_REGISTER_WRITER(name, reg) \
static __inline void name(unsigned long value) \
{ \
    __asm__ __volatile__("movq %0, %%" #reg : : "r"(value) : "memory"); \
}

EDGEOS_X86_DEBUG_REGISTER_READER(rdr0, dr0)
EDGEOS_X86_DEBUG_REGISTER_READER(rdr1, dr1)
EDGEOS_X86_DEBUG_REGISTER_READER(rdr2, dr2)
EDGEOS_X86_DEBUG_REGISTER_READER(rdr3, dr3)
EDGEOS_X86_DEBUG_REGISTER_READER(rdr6, dr6)
EDGEOS_X86_DEBUG_REGISTER_READER(rdr7, dr7)
EDGEOS_X86_DEBUG_REGISTER_WRITER(load_dr0, dr0)
EDGEOS_X86_DEBUG_REGISTER_WRITER(load_dr1, dr1)
EDGEOS_X86_DEBUG_REGISTER_WRITER(load_dr2, dr2)
EDGEOS_X86_DEBUG_REGISTER_WRITER(load_dr3, dr3)
EDGEOS_X86_DEBUG_REGISTER_WRITER(load_dr6, dr6)
EDGEOS_X86_DEBUG_REGISTER_WRITER(load_dr7, dr7)

#undef EDGEOS_X86_DEBUG_REGISTER_READER
#undef EDGEOS_X86_DEBUG_REGISTER_WRITER

static __inline uint16_t
sldt(void)
{
    uint16_t selector;

    __asm__ __volatile__("sldt %0" : "=m"(selector));
    return selector;
}

static __inline void
lldt(uint16_t selector)
{
    __asm__ __volatile__("lldt %0" : : "m"(selector) : "memory");
}

static __inline void
ltr(uint16_t selector)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    extern void bsd_x86_ltr(uint16_t selector);

    bsd_x86_ltr(selector);
#else
    __asm__ __volatile__("ltr %0" : : "m"(selector) : "memory");
#endif
}

static __inline uint8_t
inb(uint16_t port)
{
    uint8_t value;

    __asm__ __volatile__("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static __inline uint16_t
inw(uint16_t port)
{
    uint16_t value;

    __asm__ __volatile__("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static __inline uint32_t
inl(uint16_t port)
{
    uint32_t value;

    __asm__ __volatile__("inl %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static __inline void
outb(uint16_t port, uint8_t value)
{
    __asm__ __volatile__("outb %0, %1" : : "a"(value), "Nd"(port));
}

static __inline void
outw(uint16_t port, uint16_t value)
{
    __asm__ __volatile__("outw %0, %1" : : "a"(value), "Nd"(port));
}

static __inline void
outl(uint16_t port, uint32_t value)
{
    __asm__ __volatile__("outl %0, %1" : : "a"(value), "Nd"(port));
}

static __inline uint64_t
rdtsc(void)
{
    uint32_t low;
    uint32_t high;

    __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
    return (uint64_t)low | ((uint64_t)high << 32);
}

static __inline void
lfence(void)
{
    __asm__ __volatile__("lfence" : : : "memory");
}

static __inline void
mfence(void)
{
    __asm__ __volatile__("mfence" : : : "memory");
}

static __inline void
sfence(void)
{
    __asm__ __volatile__("sfence" : : : "memory");
}

static __inline unsigned long
read_rflags(void)
{
    unsigned long flags;

    __asm__ __volatile__("pushfq; popq %0" : "=r"(flags));
    return flags;
}

static __inline void
write_rflags(unsigned long flags)
{
    __asm__ __volatile__("pushq %0; popfq" : : "r"(flags) : "memory", "cc");
}

static __inline void
bare_lgdt(struct region_descriptor *descriptor)
{
    __asm__ __volatile__("lgdt (%0)" : : "r"(descriptor) : "memory");
}

static __inline void
sgdt(struct region_descriptor *descriptor)
{
    __asm__ __volatile__("sgdt %0" : "=m"(*(char *)descriptor) : : "memory");
}

static __inline void
lidt(struct region_descriptor *descriptor)
{
    __asm__ __volatile__("lidt (%0)" : : "r"(descriptor) : "memory");
}

static __inline void
sidt(struct region_descriptor *descriptor)
{
    __asm__ __volatile__("sidt %0" : "=m"(*(char *)descriptor) : : "memory");
}

static __inline register_t
intr_disable(void)
{
    register_t flags;

    __asm__ __volatile__("pushfq; popq %0; cli"
        : "=r"(flags) : : "memory");
    return flags;
}

static __inline void
disable_intr(void)
{
    __asm__ __volatile__("cli" : : : "memory");
}

static __inline void
enable_intr(void)
{
    __asm__ __volatile__("sti" : : : "memory");
}

static __inline void
intr_restore(register_t flags)
{
    __asm__ __volatile__("pushq %0; popfq"
        : : "r"(flags) : "memory", "cc");
}
#endif

#endif
