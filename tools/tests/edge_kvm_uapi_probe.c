/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding EdgeOS acceptance probe for the clean-room KVM run mapping. */

#include <stdint.h>

#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_MMAP 9
#define SYS_MUNMAP 11
#define SYS_IOCTL 16
#define SYS_PREAD64 17
#define SYS_FTRUNCATE 77
#define SYS_EXIT 60
#define SYS_MOUNT 165
#define SYS_OPENAT 257
#define SYS_MKDIRAT 258
#define SYS_FALLOCATE 285

#define AT_FDCWD (-100)
#define O_RDWR 2
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

#define KVM_GET_API_VERSION 0xae00u
#define KVM_CREATE_VM 0xae01u
#define KVM_CHECK_EXTENSION 0xae03u
#define KVM_GET_VCPU_MMAP_SIZE 0xae04u
#define KVM_GET_SUPPORTED_CPUID 0xc008ae05u
#define KVM_GET_MSR_INDEX_LIST 0xc004ae02u
#define KVM_GET_MSR_FEATURE_INDEX_LIST 0xc004ae0au
#define KVM_GET_STATS_FD 0xaeceu
#define KVM_CREATE_VCPU 0xae41u
#define KVM_SET_USER_MEMORY_REGION 0x4020ae46u
#define KVM_SET_USER_MEMORY_REGION2 0x40a0ae49u
#define KVM_SET_MEMORY_ATTRIBUTES 0x4020aed2u
#define KVM_CREATE_GUEST_MEMFD 0xc040aed4u
#define KVM_PRE_FAULT_MEMORY 0xc040aed5u
#define KVM_GET_DIRTY_LOG 0x4010ae42u
#define KVM_CLEAR_DIRTY_LOG 0xc018aec0u
#define KVM_ENABLE_CAP 0x4068aea3u
#define KVM_SET_TSS_ADDR 0xae47u
#define KVM_SET_IDENTITY_MAP_ADDR 0x4008ae48u
#define KVM_CREATE_IRQCHIP 0xae60u
#define KVM_IRQ_LINE 0x4008ae61u
#define KVM_IRQ_LINE_STATUS 0xc008ae67u
#define KVM_GET_IRQCHIP 0xc208ae62u
#define KVM_SET_IRQCHIP 0x8208ae63u
#define KVM_SET_GSI_ROUTING 0x4008ae6au
#define KVM_CREATE_PIT2 0x4040ae77u
#define KVM_REGISTER_COALESCED_MMIO 0x4010ae67u
#define KVM_UNREGISTER_COALESCED_MMIO 0x4010ae68u
#define KVM_GET_PIT2 0x8070ae9fu
#define KVM_SET_PIT2 0x4070aea0u
#define KVM_SET_CLOCK 0x4030ae7bu
#define KVM_GET_CLOCK 0x8030ae7cu
#define KVM_RUN 0xae80u
#define KVM_GET_REGS 0x8090ae81u
#define KVM_SET_REGS 0x4090ae82u
#define KVM_GET_SREGS 0x8138ae83u
#define KVM_SET_SREGS 0x4138ae84u
#define KVM_TRANSLATE 0xc018ae85u
#define KVM_GET_SREGS2 0x8140aeccu
#define KVM_SET_SREGS2 0x4140aecdu
#define KVM_GET_FPU 0x81a0ae8cu
#define KVM_SET_FPU 0x41a0ae8du
#define KVM_GET_LAPIC 0x8400ae8eu
#define KVM_SET_LAPIC 0x4400ae8fu
#define KVM_GET_DEBUGREGS 0x8080aea1u
#define KVM_SET_DEBUGREGS 0x4080aea2u
#define KVM_GET_XCRS 0x8188aea6u
#define KVM_SET_XCRS 0x4188aea7u
#define KVM_GET_XSAVE 0x9000aea4u
#define KVM_SET_XSAVE 0x5000aea5u
#define KVM_GET_XSAVE2 0x9000aecfu
#define KVM_GET_MSRS 0xc008ae88u
#define KVM_SET_MSRS 0x4008ae89u
#define KVM_GET_MP_STATE 0x8004ae98u
#define KVM_SET_MP_STATE 0x4004ae99u
#define KVM_GET_VCPU_EVENTS 0x8040ae9fu
#define KVM_SET_VCPU_EVENTS 0x4040aea0u
#define KVM_X86_SETUP_MCE 0x4008ae9cu
#define KVM_X86_GET_MCE_CAP_SUPPORTED 0x8008ae9du
#define KVM_X86_SET_MCE 0x4040ae9eu
#define KVM_SET_TSC_KHZ 0xaea2u
#define KVM_GET_TSC_KHZ 0xaea3u
#define KVM_SMI 0xaeb7u
#define KVM_SET_GUEST_DEBUG 0x4048ae9bu
#define KVM_SET_CPUID2 0x4008ae90u

#define KVM_API_VERSION 12
#define KVM_RUN_PAGES 3
#define PAGE_SIZE 4096
#define EINTR 4
#define ENOENT 2
#define EIO 5
#define E2BIG 7
#define EINVAL 22
#define ENODEV 19
#define ENOTTY 25
#define ESPIPE 29
#define EOPNOTSUPP 95
#define KVM_CAP_XSAVE 55
#define KVM_CAP_SET_GUEST_DEBUG 23
#define KVM_CAP_COALESCED_MMIO 15
#define KVM_CAP_XSAVE2 208
#define KVM_CAP_USER_MEMORY2 231
#define KVM_CAP_PRE_FAULT_MEMORY 236
#define KVM_CAP_GET_MSR_FEATURES 153
#define KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 168
#define KVM_CAP_IRQ_ROUTING 25
#define KVM_CAP_IRQ_INJECT_STATUS 26
#define KVM_CAP_PIT2 33
#define KVM_CAP_PIT_STATE2 35
#define KVM_CAP_ADJUST_CLOCK 39
#define CPUID_CAPACITY 512
#define MSR_CAPACITY 1024
#define MCE_BANK_COUNT_MASK UINT64_C(0xff)
#define MCE_CTL_PRESENT (UINT64_C(1) << 8)
#define MCE_SER_PRESENT (UINT64_C(1) << 24)
#define MCE_STATUS_VALID (UINT64_C(1) << 63)
#define KVM_EXIT_DEBUG 4
#define KVM_EXIT_IO 2
#define KVM_EXIT_HLT 5
#define KVM_EXIT_MMIO 6
#define KVM_GUESTDBG_ENABLE UINT32_C(0x00000001)
#define KVM_GUESTDBG_SINGLESTEP UINT32_C(0x00000002)
#define KVM_GUESTDBG_USE_HW_BP UINT32_C(0x00020000)
#define DR6_B0 UINT64_C(0x00000001)
#define DR6_BS (UINT64_C(1) << 14)
#define KVM_MEM_GUEST_MEMFD UINT32_C(0x00000004)
#define KVM_MEM_LOG_DIRTY_PAGES UINT32_C(0x00000001)
#define KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE UINT64_C(1)
#define KVM_MEMORY_ATTRIBUTE_PRIVATE (UINT64_C(1) << 3)
#define FALLOC_FL_KEEP_SIZE 0x01
#define FALLOC_FL_PUNCH_HOLE 0x02
#define KVM_STATS_NAME_SIZE 48

typedef struct kvm_stats_header {
    uint32_t flags;
    uint32_t name_size;
    uint32_t num_desc;
    uint32_t id_offset;
    uint32_t desc_offset;
    uint32_t data_offset;
} kvm_stats_header_t;

typedef struct kvm_regs {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rsp, rbp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip, rflags;
} kvm_regs_t;

typedef struct kvm_segment {
    uint64_t base;
    uint32_t limit;
    uint16_t selector;
    uint8_t type, present, dpl, db, s, l, g, avl, unusable, padding;
} kvm_segment_t;

typedef struct kvm_dtable {
    uint64_t base;
    uint16_t limit;
    uint16_t padding[3];
} kvm_dtable_t;

typedef struct kvm_sregs {
    kvm_segment_t cs, ds, es, fs, gs, ss, tr, ldt;
    kvm_dtable_t gdt, idt;
    uint64_t cr0, cr2, cr3, cr4, cr8, efer, apic_base;
    uint64_t interrupt_bitmap[4];
} kvm_sregs_t;

typedef struct kvm_sregs2 {
    uint8_t common[280];
    uint64_t flags;
    uint64_t pdptrs[4];
} kvm_sregs2_t;

typedef struct kvm_translation {
    uint64_t linear_address;
    uint64_t physical_address;
    uint8_t valid;
    uint8_t writeable;
    uint8_t usermode;
    uint8_t padding[5];
} kvm_translation_t;

typedef struct kvm_fpu {
    uint8_t fpr[8][16];
    uint16_t fcw, fsw;
    uint8_t ftwx, padding1;
    uint16_t last_opcode;
    uint64_t last_ip, last_dp;
    uint8_t xmm[16][16];
    uint32_t mxcsr, padding2;
} kvm_fpu_t;

typedef struct kvm_lapic_state {
    uint8_t registers[1024];
} kvm_lapic_state_t;

typedef struct kvm_debugregs {
    uint64_t db[4];
    uint64_t dr6;
    uint64_t dr7;
    uint64_t flags;
    uint64_t reserved[9];
} kvm_debugregs_t;

typedef struct kvm_guest_debug {
    uint32_t control;
    uint32_t padding;
    uint64_t debug_registers[8];
} kvm_guest_debug_t;

typedef struct kvm_run_debug {
    uint32_t exception;
    uint32_t padding;
    uint64_t program_counter;
    uint64_t dr6;
    uint64_t dr7;
} kvm_run_debug_t;

typedef struct kvm_xcr {
    uint32_t xcr;
    uint32_t reserved;
    uint64_t value;
} kvm_xcr_t;

typedef struct kvm_xcrs {
    uint32_t nr_xcrs;
    uint32_t flags;
    kvm_xcr_t xcrs[16];
    uint64_t padding[16];
} kvm_xcrs_t;

typedef struct kvm_xsave {
    uint8_t region[4096];
} kvm_xsave_t;

typedef struct kvm_userspace_memory_region2 {
    uint32_t slot, flags;
    uint64_t guest_phys_addr, memory_size, userspace_addr;
    uint64_t guest_memfd_offset;
    uint32_t guest_memfd, pad1;
    uint64_t pad2[14];
} kvm_userspace_memory_region2_t;

typedef struct kvm_memory_attributes {
    uint64_t address, size, attributes, flags;
} kvm_memory_attributes_t;

typedef struct kvm_create_guest_memfd {
    uint64_t size, flags, reserved[6];
} kvm_create_guest_memfd_t;

typedef struct kvm_pre_fault_memory {
    uint64_t gpa, size, flags, padding[5];
} kvm_pre_fault_memory_t;

typedef struct kvm_enable_cap {
    uint32_t capability;
    uint32_t flags;
    uint64_t arguments[4];
    uint8_t padding[64];
} kvm_enable_cap_t;

typedef struct kvm_dirty_log {
    uint32_t slot;
    uint32_t padding;
    uint64_t dirty_bitmap;
} kvm_dirty_log_t;

typedef struct kvm_clear_dirty_log {
    uint32_t slot;
    uint32_t num_pages;
    uint64_t first_page;
    uint64_t dirty_bitmap;
} kvm_clear_dirty_log_t;

typedef struct kvm_coalesced_mmio_zone {
    uint64_t address;
    uint32_t size;
    uint32_t pio;
} kvm_coalesced_mmio_zone_t;

typedef struct kvm_coalesced_mmio {
    uint64_t physical_address;
    uint32_t length;
    uint32_t pio;
    uint8_t data[8];
} kvm_coalesced_mmio_t;

#define KVM_COALESCED_MMIO_MAX 170

typedef struct kvm_coalesced_mmio_ring {
    uint32_t first;
    uint32_t last;
    kvm_coalesced_mmio_t entries[KVM_COALESCED_MMIO_MAX];
} kvm_coalesced_mmio_ring_t;

typedef struct kvm_run_mmio {
    uint64_t physical_address;
    uint8_t data[8];
    uint32_t length;
    uint8_t is_write;
} kvm_run_mmio_t;

typedef struct kvm_pit_config {
    uint32_t flags;
    uint32_t padding[15];
} kvm_pit_config_t;

typedef struct kvm_irq_level {
    uint32_t irq;
    uint32_t level;
} kvm_irq_level_t;

typedef struct kvm_irq_routing_entry {
    uint32_t gsi, type, flags, padding;
    union {
        struct { uint32_t irqchip, pin; } irqchip;
        uint8_t padding[32];
    } u;
} kvm_irq_routing_entry_t;

typedef struct kvm_irq_routing_buffer {
    uint32_t nr, flags;
    kvm_irq_routing_entry_t entries[2];
} kvm_irq_routing_buffer_t;

typedef struct kvm_pic_state {
    uint8_t last_irr, irr, imr, isr, priority_add, irq_base;
    uint8_t read_reg_select, poll, special_mask, init_state;
    uint8_t auto_eoi, rotate_on_auto_eoi, special_fully_nested_mode;
    uint8_t init4, elcr, elcr_mask;
} kvm_pic_state_t;

typedef struct kvm_ioapic_state {
    uint64_t base_address;
    uint32_t ioregsel, id, irr, padding;
    uint64_t redirtbl[24];
} kvm_ioapic_state_t;

typedef struct kvm_irqchip {
    uint32_t chip_id, padding;
    union {
        kvm_pic_state_t pic;
        kvm_ioapic_state_t ioapic;
        uint8_t padding[512];
    } chip;
} kvm_irqchip_t;

typedef struct kvm_pit_channel_state {
    uint32_t count;
    uint16_t latched_count;
    uint8_t count_latched, status_latched, status;
    uint8_t read_state, write_state, write_latch, rw_mode, mode, bcd, gate;
    int64_t count_load_time;
} kvm_pit_channel_state_t;

typedef struct kvm_pit_state2 {
    kvm_pit_channel_state_t channels[3];
    uint32_t flags;
    uint32_t reserved[9];
} kvm_pit_state2_t;

typedef struct kvm_clock_data {
    uint64_t clock;
    uint32_t flags, padding0;
    uint64_t realtime, host_tsc;
    uint32_t padding[4];
} kvm_clock_data_t;

typedef struct kvm_cpuid_entry2 {
    uint32_t function, index, flags;
    uint32_t eax, ebx, ecx, edx;
    uint32_t padding[3];
} kvm_cpuid_entry2_t;

typedef struct kvm_cpuid_buffer {
    uint32_t nent, padding;
    kvm_cpuid_entry2_t entries[CPUID_CAPACITY];
} kvm_cpuid_buffer_t;

typedef struct kvm_msr_entry {
    uint32_t index, reserved;
    uint64_t data;
} kvm_msr_entry_t;

typedef struct kvm_msr_buffer {
    uint32_t nmsrs, padding;
    kvm_msr_entry_t entries[3];
} kvm_msr_buffer_t;

typedef struct kvm_msr_list_buffer {
    uint32_t nmsrs;
    uint32_t indices[MSR_CAPACITY];
} kvm_msr_list_buffer_t;

typedef struct kvm_x86_mce {
    uint64_t status;
    uint64_t address;
    uint64_t miscellaneous;
    uint64_t mcg_status;
    uint8_t bank;
    uint8_t padding1[7];
    uint64_t padding2[3];
} kvm_x86_mce_t;

typedef struct kvm_mp_state {
    uint32_t mp_state;
} kvm_mp_state_t;

typedef struct kvm_vcpu_events {
    struct {
        uint8_t injected, number, has_error_code, pending;
        uint32_t error_code;
    } exception;
    struct {
        uint8_t injected, number, soft, shadow;
    } interrupt;
    struct {
        uint8_t injected, pending, masked, padding;
    } nmi;
    uint32_t sipi_vector;
    uint32_t flags;
    struct {
        uint8_t smm, pending, smm_inside_nmi, latched_init;
    } smi;
    uint8_t triple_fault;
    uint8_t reserved[26];
    uint8_t exception_has_payload;
    uint64_t exception_payload;
} kvm_vcpu_events_t;

static kvm_cpuid_buffer_t cpuid_buffer;
static kvm_msr_list_buffer_t msr_list_buffer;
static kvm_msr_buffer_t msr_input;
static kvm_msr_buffer_t msr_output;
static kvm_xsave_t xsave_input __attribute__((aligned(64)));
static kvm_xsave_t xsave_output __attribute__((aligned(64)));

static long syscall1(long number, long a0) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall2(long number, long a0, long a1) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall3(long number, long a0, long a1, long a2) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall4(long number, long a0, long a1, long a2, long a3) {
    register long r10 __asm__("r10") = a3;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall5(long number, long a0, long a1, long a2, long a3,
                     long a4) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall6(long number, long a0, long a1, long a2, long a3,
                     long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

void *memset(void *destination, int value, unsigned long length) {
    uint8_t *bytes = destination;

    for (unsigned long index = 0; index < length; ++index)
        bytes[index] = (uint8_t)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned long length) {
    uint8_t *output = destination;
    const uint8_t *input = source;

    for (unsigned long index = 0; index < length; ++index)
        output[index] = input[index];
    return destination;
}

int memcmp(const void *left, const void *right, unsigned long length) {
    const uint8_t *left_bytes = left;
    const uint8_t *right_bytes = right;

    for (unsigned long index = 0; index < length; ++index) {
        if (left_bytes[index] != right_bytes[index])
            return (int)left_bytes[index] - (int)right_bytes[index];
    }
    return 0;
}

static void print(const char *text) {
    (void)syscall3(SYS_WRITE, 1, (long)text, (long)text_length(text));
}

static void print_hex64(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char output[19];

    output[0] = '0';
    output[1] = 'x';
    for (uint32_t index = 0; index < 16; ++index)
        output[2 + index] = digits[(value >> ((15 - index) * 4)) & 0xf];
    output[18] = '\n';
    (void)syscall3(SYS_WRITE, 1, (long)output, sizeof(output));
}

static void fail(const char *stage) {
    print("EDGE_KVM_UAPI_FAIL ");
    print(stage);
    print("\n");
    (void)syscall1(SYS_EXIT, 1);
    for (;;) { }
}

void _start(void) {
    long system_fd;
    long vm_fd;
    long vcpu_fd;
    long mmap_size;
    long mapping;
    long guest_memory;
    long paging_memory;
    long msr_feature_capability;
    kvm_regs_t input_registers = {0};
    kvm_regs_t output_registers = {0};
    kvm_sregs_t original_special_registers = {0};
    kvm_sregs_t output_special_registers = {0};
    kvm_sregs2_t input_special_registers2 = {0};
    kvm_sregs2_t output_special_registers2 = {0};
    kvm_fpu_t input_fpu = {0};
    kvm_fpu_t output_fpu = {0};
    kvm_lapic_state_t input_lapic = {0};
    kvm_lapic_state_t output_lapic = {0};
    kvm_debugregs_t input_debugregs = {0};
    kvm_debugregs_t output_debugregs = {0};
    kvm_xcrs_t input_xcrs = {0};
    kvm_xcrs_t output_xcrs = {0};
    kvm_userspace_memory_region2_t memory_region2 = {0};
    kvm_enable_cap_t enable_manual_dirty_log = {
        .capability = KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
        .arguments = {KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE},
    };
    kvm_pit_config_t pit_config = {0};
    kvm_irq_routing_buffer_t irq_routing = {0};
    kvm_irq_level_t irq_level = {0};
    kvm_irqchip_t irqchip = {0};
    kvm_pit_state2_t pit_state = {0};
    kvm_clock_data_t clock_data = {0};
    kvm_mp_state_t mp_state = {0};
    kvm_vcpu_events_t input_events = {0};
    kvm_vcpu_events_t output_events = {0};
    kvm_coalesced_mmio_zone_t coalesced_zone = {
        .address = UINT64_C(0x8000),
        .size = 1,
    };
    uint64_t identity_map_address = UINT64_C(0xfeffc000);
    uint64_t supported_mce_capability = 0;
    const uint64_t configured_mce_capability = UINT64_C(0x0100010a);
    const uint64_t injected_mce_status =
        MCE_STATUS_VALID | UINT64_C(0x12345678);
    kvm_x86_mce_t machine_check = {0};

    (void)syscall3(SYS_MKDIRAT, AT_FDCWD, (long)"/dev", 0755);
    (void)syscall5(SYS_MOUNT, (long)"devtmpfs", (long)"/dev",
                   (long)"devtmpfs", 0, 0);
    system_fd = syscall3(SYS_OPENAT, AT_FDCWD, (long)"/dev/kvm", O_RDWR);
    if (system_fd < 0) fail("open");
    if (syscall3(SYS_IOCTL, system_fd, KVM_GET_API_VERSION, 0) !=
        KVM_API_VERSION)
        fail("api-version");
    if (syscall3(SYS_IOCTL, system_fd, KVM_GET_STATS_FD, 0) != -EINVAL)
        fail("modern-system-boundary");
    msr_feature_capability = syscall3(
        SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
        KVM_CAP_GET_MSR_FEATURES);
    if (msr_feature_capability != 0 && msr_feature_capability != 1)
        fail("msr-feature-capability");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_XSAVE) != 1 ||
        syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_XSAVE2) != 4096)
        fail("xsave-capabilities");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_SET_GUEST_DEBUG) != 1)
        fail("guest-debug-capability");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_USER_MEMORY2) != 1)
        fail("user-memory2-capability");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_PRE_FAULT_MEMORY) != 1)
        fail("pre-fault-memory-capability");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2) != 1)
        fail("manual-dirty-log-capability");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_COALESCED_MMIO) != 2)
        fail("coalesced-mmio-capability");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_IRQ_ROUTING) < 256 ||
        syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_IRQ_INJECT_STATUS) != 1)
        fail("irq-routing-capabilities");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_PIT2) != 1 ||
        syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_PIT_STATE2) != 1)
        fail("pit-capabilities");
    if (syscall3(SYS_IOCTL, system_fd, KVM_CHECK_EXTENSION,
                 KVM_CAP_ADJUST_CLOCK) != 14)
        fail("clock-capability");
    if (syscall3(SYS_IOCTL, system_fd, KVM_X86_GET_MCE_CAP_SUPPORTED,
                 (long)&supported_mce_capability) != 0 ||
        (supported_mce_capability & (MCE_CTL_PRESENT | MCE_SER_PRESENT)) !=
            (MCE_CTL_PRESENT | MCE_SER_PRESENT))
        fail("mce-capability");
    msr_list_buffer.nmsrs = 0;
    if (syscall3(SYS_IOCTL, system_fd, KVM_GET_MSR_INDEX_LIST,
                 (long)&msr_list_buffer) != -E2BIG ||
        msr_list_buffer.nmsrs == 0 ||
        msr_list_buffer.nmsrs > MSR_CAPACITY)
        fail("msr-list-size");
    msr_list_buffer.nmsrs = MSR_CAPACITY;
    if (syscall3(SYS_IOCTL, system_fd, KVM_GET_MSR_INDEX_LIST,
                 (long)&msr_list_buffer) != 0 ||
        msr_list_buffer.nmsrs == 0)
        fail("msr-list-get");
    if (msr_feature_capability == 1) {
        msr_list_buffer.nmsrs = 0;
        if (syscall3(SYS_IOCTL, system_fd,
                     KVM_GET_MSR_FEATURE_INDEX_LIST,
                     (long)&msr_list_buffer) != -E2BIG ||
            msr_list_buffer.nmsrs != 1)
            fail("msr-feature-list-size");
        msr_list_buffer.nmsrs = MSR_CAPACITY;
        if (syscall3(SYS_IOCTL, system_fd,
                     KVM_GET_MSR_FEATURE_INDEX_LIST,
                     (long)&msr_list_buffer) != 0 ||
            msr_list_buffer.nmsrs != 1 ||
            msr_list_buffer.indices[0] != UINT32_C(0xc0011029))
            fail("msr-feature-list-get");
        memset(&msr_output, 0, sizeof(msr_output));
        msr_output.nmsrs = 1;
        msr_output.entries[0].index = msr_list_buffer.indices[0];
        msr_output.entries[0].data = UINT64_MAX;
        if (syscall3(SYS_IOCTL, system_fd, KVM_GET_MSRS,
                     (long)&msr_output) != 1 ||
            msr_output.entries[0].data != 0)
            fail("msr-feature-get");
    }
    cpuid_buffer.nent = 0;
    if (syscall3(SYS_IOCTL, system_fd, KVM_GET_SUPPORTED_CPUID,
                 (long)&cpuid_buffer) != -E2BIG)
        fail("cpuid-size");
    cpuid_buffer.nent = CPUID_CAPACITY;
    if (syscall3(SYS_IOCTL, system_fd, KVM_GET_SUPPORTED_CPUID,
                 (long)&cpuid_buffer) != 0 || cpuid_buffer.nent == 0)
        fail("cpuid-get");
    {
        int found_leaf1 = 0;
        for (uint32_t index = 0; index < cpuid_buffer.nent; ++index) {
            if (cpuid_buffer.entries[index].function == 1)
                found_leaf1 = 1;
        }
        if (!found_leaf1) fail("cpuid-leaf1");
    }
    mmap_size = syscall3(SYS_IOCTL, system_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size != KVM_RUN_PAGES * PAGE_SIZE) fail("mmap-size");
    vm_fd = syscall3(SYS_IOCTL, system_fd, KVM_CREATE_VM, 0);
    if (vm_fd < 0) fail("create-vm");
    {
        kvm_pre_fault_memory_t pre_fault = {.size = PAGE_SIZE};

        if (syscall3(SYS_IOCTL, vm_fd, KVM_PRE_FAULT_MEMORY,
                     (long)&pre_fault) != -ENOTTY)
            fail("pre-fault-memory-vm-boundary");
    }
    {
        kvm_translation_t translation = {0};

        if (syscall3(SYS_IOCTL, vm_fd, KVM_TRANSLATE,
                     (long)&translation) != -ENOTTY)
            fail("translate-vm-boundary");
    }
    {
        kvm_create_guest_memfd_t create_guest = {.size = PAGE_SIZE};
        kvm_memory_attributes_t attributes = {.size = PAGE_SIZE};
        long guest_fd;
        char byte;

        guest_fd = syscall3(SYS_IOCTL, vm_fd, KVM_CREATE_GUEST_MEMFD,
                            (long)&create_guest);
        if (guest_fd < 0) fail("create-guest-memfd");
        if (syscall4(SYS_PREAD64, guest_fd, (long)&byte, 1, 0) !=
            -ESPIPE)
            fail("guest-memfd-pread");
        if (syscall6(SYS_MMAP, 0, PAGE_SIZE, PROT_READ,
                     MAP_SHARED, guest_fd, 0) != -ENODEV)
            fail("guest-memfd-mmap");
        if (syscall2(SYS_FTRUNCATE, guest_fd, PAGE_SIZE * 2) != -EINVAL)
            fail("guest-memfd-ftruncate");
        if (syscall4(SYS_FALLOCATE, guest_fd,
                     FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
                     0, PAGE_SIZE) != 0)
            fail("guest-memfd-punch-hole");
        if (syscall1(SYS_CLOSE, guest_fd) != 0)
            fail("guest-memfd-close");
        create_guest.size = 0;
        if (syscall3(SYS_IOCTL, vm_fd, KVM_CREATE_GUEST_MEMFD,
                     (long)&create_guest) != -EINVAL)
            fail("guest-memfd-zero-size");
        if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_MEMORY_ATTRIBUTES,
                     (long)&attributes) != 0)
            fail("memory-attributes-shared");
        attributes.attributes = KVM_MEMORY_ATTRIBUTE_PRIVATE;
        if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_MEMORY_ATTRIBUTES,
                     (long)&attributes) != -EOPNOTSUPP)
            fail("memory-attributes-private-boundary");
    }
    if (syscall3(SYS_IOCTL, vm_fd, KVM_ENABLE_CAP,
                 (long)&enable_manual_dirty_log) != 0)
        fail("enable-manual-dirty-log");
    if (syscall3(SYS_IOCTL, vm_fd, KVM_REGISTER_COALESCED_MMIO,
                 (long)&coalesced_zone) != 0)
        fail("register-coalesced-mmio");
    if (syscall3(SYS_IOCTL, vm_fd, KVM_GET_CLOCK,
                 (long)&clock_data) != 0)
        fail("get-clock-initial");
    clock_data.clock = UINT64_C(123456789);
    if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_CLOCK,
                 (long)&clock_data) != 0)
        fail("set-clock");
    memset(&clock_data, 0, sizeof(clock_data));
    if (syscall3(SYS_IOCTL, vm_fd, KVM_GET_CLOCK,
                 (long)&clock_data) != 0 ||
        clock_data.clock < UINT64_C(123456789) ||
        clock_data.flags != 0)
        fail("clock-roundtrip");
    clock_data.flags = UINT32_C(0x80000000);
    if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_CLOCK,
                 (long)&clock_data) != -EINVAL)
        fail("clock-flags-validation");
    if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_TSS_ADDR,
                 UINT64_C(0xfeffd000)) != 0)
        fail("set-tss-address");
    if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_IDENTITY_MAP_ADDR,
                 (long)&identity_map_address) != 0)
        fail("set-identity-map-address");
    if (syscall3(SYS_IOCTL, vm_fd, KVM_CREATE_IRQCHIP, 0) != 0)
        fail("create-irqchip");
    irq_routing.nr = 2;
    irq_routing.entries[0].gsi = 5;
    irq_routing.entries[0].type = 1;
    irq_routing.entries[0].u.irqchip.irqchip = 0;
    irq_routing.entries[0].u.irqchip.pin = 5;
    irq_routing.entries[1].gsi = 5;
    irq_routing.entries[1].type = 1;
    irq_routing.entries[1].u.irqchip.irqchip = 2;
    irq_routing.entries[1].u.irqchip.pin = 5;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_GSI_ROUTING,
                 (long)&irq_routing) != 0)
        fail("set-gsi-routing");
    irq_level.irq = 5;
    irq_level.level = 1;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_IRQ_LINE_STATUS,
                 (long)&irq_level) != 0 || irq_level.level != 1 ||
        syscall3(SYS_IOCTL, vm_fd, KVM_IRQ_LINE,
                 (long)&irq_level) != 0)
        fail("assert-irq-line");
    irq_level.level = 0;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_IRQ_LINE_STATUS,
                 (long)&irq_level) != 0 || irq_level.level != 0)
        fail("deassert-irq-line");
    if (syscall3(SYS_IOCTL, vm_fd, KVM_CREATE_PIT2,
                 (long)&pit_config) != 0)
        fail("create-pit2");
    irqchip.chip_id = 0;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_GET_IRQCHIP,
                 (long)&irqchip) != 0)
        fail("get-pic-master");
    irqchip.chip.pic.imr = 0x5a;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_IRQCHIP,
                 (long)&irqchip) != 0) {
        fail("set-pic-master");
    }
    memset(&irqchip, 0, sizeof(irqchip));
    irqchip.chip_id = 0;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_GET_IRQCHIP,
                 (long)&irqchip) != 0 || irqchip.chip.pic.imr != 0x5a)
        fail("pic-master-roundtrip");
    memset(&irqchip, 0, sizeof(irqchip));
    irqchip.chip_id = 2;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_GET_IRQCHIP,
                 (long)&irqchip) != 0 ||
        irqchip.chip.ioapic.base_address != UINT64_C(0xfec00000) ||
        syscall3(SYS_IOCTL, vm_fd, KVM_SET_IRQCHIP,
                 (long)&irqchip) != 0)
        fail("ioapic-roundtrip");
    if (syscall3(SYS_IOCTL, vm_fd, KVM_GET_PIT2,
                 (long)&pit_state) != 0 ||
        pit_state.channels[0].count == 0 ||
        syscall3(SYS_IOCTL, vm_fd, KVM_SET_PIT2,
                 (long)&pit_state) != 0) {
        fail("pit2-roundtrip");
    }
    guest_memory = syscall6(SYS_MMAP, 0, PAGE_SIZE,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guest_memory < 0) fail("mmap-guest");
    memory_region2.memory_size = PAGE_SIZE;
    memory_region2.userspace_addr = (uint64_t)guest_memory;
    memory_region2.flags = KVM_MEM_LOG_DIRTY_PAGES;
    long set_memory2_result = syscall3(
        SYS_IOCTL, vm_fd, KVM_SET_USER_MEMORY_REGION2,
        (long)&memory_region2);
    if (set_memory2_result != 0) {
        print_hex64((uint64_t)set_memory2_result);
        fail("set-memory2");
    }
    memory_region2.pad1 = 1;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_USER_MEMORY_REGION2,
                 (long)&memory_region2) != -EINVAL)
        fail("set-memory2-padding");
    memory_region2.pad1 = 0;
    memory_region2.flags = KVM_MEM_GUEST_MEMFD;
    if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_USER_MEMORY_REGION2,
                 (long)&memory_region2) != -EOPNOTSUPP)
        fail("set-memory2-guest-memfd-boundary");
    memory_region2.flags = KVM_MEM_LOG_DIRTY_PAGES;
    vcpu_fd = syscall3(SYS_IOCTL, vm_fd, KVM_CREATE_VCPU, 0);
    if (vcpu_fd < 0) fail("create-vcpu");
    {
        kvm_translation_t translation = {
            .linear_address = UINT64_C(0x1234),
            .physical_address = UINT64_C(0xfeedface),
            .valid = 0xa5,
            .writeable = 0xa5,
            .usermode = 0xa5,
            .padding = {0x5a},
        };

        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_TRANSLATE,
                     (long)&translation) != 0 ||
            translation.physical_address != UINT64_C(0x1234) ||
            translation.valid != 1 || translation.writeable != 1 ||
            translation.usermode != 0 || translation.padding[0] != 0x5a)
            fail("translate-flat");
        translation.linear_address = UINT64_C(0x123456789);
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_TRANSLATE,
                     (long)&translation) != 0 ||
            translation.physical_address != UINT64_C(0x123456789) ||
            translation.valid != 1)
            fail("translate-flat-outside-slot");
    }
    paging_memory = syscall6(SYS_MMAP, 0, PAGE_SIZE * 3,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (paging_memory < 0) fail("mmap-translate-pages");
    {
        kvm_userspace_memory_region2_t paging_region = {
            .slot = 1,
            .guest_phys_addr = UINT64_C(0x10000),
            .memory_size = PAGE_SIZE * 3,
            .userspace_addr = (uint64_t)paging_memory,
        };
        kvm_sregs_t saved_sregs;
        kvm_sregs_t paging_sregs;
        kvm_translation_t translation = {
            .linear_address = UINT64_C(0x4567),
        };
        volatile uint32_t *page_directory =
            (volatile uint32_t *)(uintptr_t)paging_memory;
        volatile uint32_t *page_table =
            (volatile uint32_t *)(uintptr_t)(paging_memory + PAGE_SIZE);

        page_directory[0] = UINT32_C(0x11003);
        page_table[4] = UINT32_C(0x12003);
        if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_USER_MEMORY_REGION2,
                     (long)&paging_region) != 0)
            fail("set-translate-memory");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_SREGS,
                     (long)&saved_sregs) != 0)
            fail("get-translate-sregs");
        paging_sregs = saved_sregs;
        paging_sregs.cr0 |= UINT64_C(0x80000001);
        paging_sregs.cr3 = UINT64_C(0x10000);
        paging_sregs.cr4 &= ~UINT64_C(0x20);
        paging_sregs.efer &= ~UINT64_C(0x500);
        paging_sregs.cs.l = 0;
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_SREGS,
                     (long)&paging_sregs) != 0)
            fail("set-translate-sregs");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_TRANSLATE,
                     (long)&translation) != 0 ||
            translation.physical_address != UINT64_C(0x12567) ||
            translation.valid != 1 || translation.writeable != 1 ||
            translation.usermode != 0)
            fail("translate-page-walk");
        translation.linear_address = UINT64_C(0x8567);
        translation.physical_address = 0;
        translation.valid = 1;
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_TRANSLATE,
                     (long)&translation) != 0 ||
            translation.physical_address != UINT64_MAX ||
            translation.valid != 0 || translation.writeable != 1 ||
            translation.usermode != 0)
            fail("translate-invalid-pte");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_SREGS,
                     (long)&saved_sregs) != 0)
            fail("restore-translate-sregs");
        paging_region.memory_size = 0;
        paging_region.userspace_addr = 0;
        if (syscall3(SYS_IOCTL, vm_fd, KVM_SET_USER_MEMORY_REGION2,
                     (long)&paging_region) != 0)
            fail("remove-translate-memory");
    }
    {
        kvm_pre_fault_memory_t pre_fault = {
            .size = PAGE_SIZE * 2u,
            .padding = {1},
        };

        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_PRE_FAULT_MEMORY,
                     (long)&pre_fault) != 0 ||
            pre_fault.gpa != PAGE_SIZE || pre_fault.size != PAGE_SIZE ||
            pre_fault.padding[0] != 1)
            fail("pre-fault-memory-partial");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_PRE_FAULT_MEMORY,
                     (long)&pre_fault) != -ENOENT ||
            pre_fault.gpa != PAGE_SIZE || pre_fault.size != PAGE_SIZE)
            fail("pre-fault-memory-outside");
        pre_fault.gpa = 0;
        pre_fault.size = 0;
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_PRE_FAULT_MEMORY,
                     (long)&pre_fault) != -EINVAL)
            fail("pre-fault-memory-zero-size");
        pre_fault.size = PAGE_SIZE;
        pre_fault.flags = 1;
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_PRE_FAULT_MEMORY,
                     (long)&pre_fault) != -EINVAL)
            fail("pre-fault-memory-flags");
    }
    {
        uint8_t stats_blob[512] __attribute__((aligned(8)));
        kvm_stats_header_t *header =
            (kvm_stats_header_t *)(void *)stats_blob;
        uint64_t *values;
        long stats_fd = syscall3(SYS_IOCTL, vm_fd, KVM_GET_STATS_FD, 0);

        if (stats_fd < 0) fail("vm-stats-fd");
        if (syscall4(SYS_PREAD64, stats_fd, (long)stats_blob,
                     sizeof(stats_blob), 0) <= 0)
            fail("vm-stats-read");
        if (header->flags != 0 || header->name_size != KVM_STATS_NAME_SIZE ||
            header->num_desc != 3 || header->id_offset != sizeof(*header) ||
            header->desc_offset != sizeof(*header) + KVM_STATS_NAME_SIZE ||
            memcmp(stats_blob + header->id_offset,
                   "edgeos-kvm-vm-", 14) != 0)
            fail("vm-stats-layout");
        values = (uint64_t *)(void *)(stats_blob + header->data_offset);
        if (values[0] != 1 || values[1] != 0 || values[2] != 1)
            fail("vm-stats-values");
        if (syscall4(SYS_PREAD64, stats_fd, (long)stats_blob,
                     sizeof(stats_blob), 4096) != 0)
            fail("vm-stats-eof");
        (void)syscall1(SYS_CLOSE, stats_fd);
    }
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SMI, 0) != -EOPNOTSUPP)
        fail("modern-vcpu-boundary");
    {
        long frequency_khz = syscall3(
            SYS_IOCTL, vcpu_fd, KVM_GET_TSC_KHZ, 0);
        if (frequency_khz <= 0)
            fail("get-tsc-khz");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_TSC_KHZ,
                     frequency_khz) != 0 ||
            syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_TSC_KHZ, 0) != 0)
            fail("set-tsc-khz");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_X86_SETUP_MCE,
                     (long)&configured_mce_capability) != 0)
            fail("setup-mce");
    }
    machine_check.status = injected_mce_status;
    machine_check.address = UINT64_C(0x1122334455667788);
    machine_check.miscellaneous = UINT64_C(0x8877665544332211);
    machine_check.bank = 1;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_X86_SET_MCE,
                 (long)&machine_check) != 0)
        fail("set-mce");
    memset(&msr_output, 0, sizeof(msr_output));
    msr_output.nmsrs = 2;
    msr_output.entries[0].index = UINT32_C(0x00000179);
    msr_output.entries[1].index = UINT32_C(0x00000405);
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_MSRS,
                 (long)&msr_output) != 2 ||
        msr_output.entries[0].data != configured_mce_capability ||
        msr_output.entries[1].data != injected_mce_status)
        fail("get-mce-msrs");
    machine_check.status = 0;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_X86_SET_MCE,
                 (long)&machine_check) != -EINVAL)
        fail("set-mce-validation");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_LAPIC,
                 (long)&input_lapic) != 0)
        fail("get-lapic-initial");
    input_lapic.registers[0x80] = 0x50;
    input_lapic.registers[0x81] = 0;
    input_lapic.registers[0x82] = 0;
    input_lapic.registers[0x83] = 0;
    input_lapic.registers[0xf0] |= 0x00;
    input_lapic.registers[0xf1] |= 0x01;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_LAPIC,
                 (long)&input_lapic) != 0 ||
        syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_LAPIC,
                 (long)&output_lapic) != 0 ||
        output_lapic.registers[0x80] != 0x50 ||
        output_lapic.registers[0xa0] != 0x50 ||
        output_lapic.registers[0xf1] != input_lapic.registers[0xf1])
        fail("lapic-roundtrip");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_DEBUGREGS,
                 (long)&input_debugregs) != 0)
        fail("get-debugregs");
    input_debugregs.db[0] = UINT64_C(0x12345000);
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_DEBUGREGS,
                 (long)&input_debugregs) != 0 ||
        syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_DEBUGREGS,
                 (long)&output_debugregs) != 0 ||
        output_debugregs.db[0] != UINT64_C(0x12345000) ||
        output_debugregs.dr6 != input_debugregs.dr6 ||
        output_debugregs.dr7 != input_debugregs.dr7)
        fail("debugregs-roundtrip");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_XCRS,
                 (long)&input_xcrs) != 0 ||
        input_xcrs.nr_xcrs != 1 || input_xcrs.flags != 0 ||
        input_xcrs.xcrs[0].xcr != 0 ||
        input_xcrs.xcrs[0].value == 0 ||
        syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_XCRS,
                 (long)&input_xcrs) != 0 ||
        syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_XCRS,
                 (long)&output_xcrs) != 0 ||
        output_xcrs.nr_xcrs != 1 ||
        output_xcrs.xcrs[0].value != input_xcrs.xcrs[0].value)
        fail("xcrs-roundtrip");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_XSAVE,
                 (long)&xsave_input) != 0 ||
        syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_XSAVE2,
                 (long)&xsave_output) != 0 ||
        memcmp(&xsave_input, &xsave_output, sizeof(xsave_input)) != 0 ||
        xsave_input.region[464] == 0)
        fail("xsave-initial");
    xsave_input.region[0] = 0x7f;
    xsave_input.region[1] = 0x02;
    xsave_input.region[24] = 0x00;
    xsave_input.region[25] = 0x1f;
    xsave_input.region[26] = 0;
    xsave_input.region[27] = 0;
    xsave_input.region[512] = 3;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_XSAVE,
                 (long)&xsave_input) != 0) {
        fail("set-xsave");
    }
    memset(&xsave_output, 0, sizeof(xsave_output));
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_XSAVE,
                 (long)&xsave_output) != 0 ||
        xsave_output.region[0] != 0x7f ||
        xsave_output.region[1] != 0x02 ||
        xsave_output.region[24] != 0x00 ||
        xsave_output.region[25] != 0x1f ||
        xsave_output.region[512] != 3)
        fail("xsave-roundtrip");
    xsave_input.region[528] = 1;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_XSAVE,
                 (long)&xsave_input) != -EINVAL)
        fail("xsave-reserved-validation");
    xsave_input.region[528] = 0;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_MP_STATE,
                 (long)&mp_state) != 0 || mp_state.mp_state != 0)
        fail("get-mp-state-initial");
    mp_state.mp_state = 3;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_MP_STATE,
                 (long)&mp_state) != 0)
        fail("set-mp-state-halted");
    mp_state.mp_state = 0;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_MP_STATE,
                 (long)&mp_state) != 0 || mp_state.mp_state != 3)
        fail("get-mp-state-halted");
    mp_state.mp_state = 0;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_MP_STATE,
                 (long)&mp_state) != 0)
        fail("set-mp-state-runnable");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_SREGS2,
                 (long)&input_special_registers2) != 0 ||
        input_special_registers2.flags != 0 ||
        syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_SREGS2,
                 (long)&input_special_registers2) != 0 ||
        syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_SREGS2,
                 (long)&output_special_registers2) != 0 ||
        output_special_registers2.flags != 0 ||
        memcmp(input_special_registers2.common,
               output_special_registers2.common,
               sizeof(input_special_registers2.common)) != 0)
        fail("sregs2-roundtrip");
    input_events.exception.injected = 1;
    input_events.exception.number = 14;
    input_events.exception.has_error_code = 1;
    input_events.exception.error_code = 5;
    input_events.flags = UINT32_C(0x12);
    input_events.sipi_vector = UINT32_C(0x10);
    input_events.exception_has_payload = 1;
    input_events.exception_payload = UINT64_C(0x12345000);
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_VCPU_EVENTS,
                 (long)&input_events) != 0)
        fail("set-vcpu-events");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_VCPU_EVENTS,
                 (long)&output_events) != 0 ||
        output_events.exception.injected != 1 ||
        output_events.exception.pending != 1 ||
        output_events.exception.number != 14 ||
        output_events.exception.error_code != 5 ||
        output_events.exception_payload != UINT64_C(0x12345000))
        fail("get-vcpu-events");
    memset(&input_events, 0, sizeof(input_events));
    memset(&output_events, 0, sizeof(output_events));
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_VCPU_EVENTS,
                 (long)&input_events) != 0 ||
        syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_VCPU_EVENTS,
                 (long)&output_events) != 0 ||
        output_events.exception.injected != 0 ||
        output_events.exception.pending != 0)
        fail("clear-vcpu-events");
    msr_input.nmsrs = 3;
    msr_input.entries[0].index = UINT32_C(0xc0000081);
    msr_input.entries[0].data = UINT64_C(0x0013000800000000);
    msr_input.entries[1].index = UINT32_C(0xc0000082);
    msr_input.entries[1].data = UINT64_C(0x0000000000102000);
    msr_input.entries[2].index = UINT32_C(0x00000277);
    msr_input.entries[2].data = UINT64_C(0x0007040600070406);
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_MSRS,
                 (long)&msr_input) != 3)
        fail("set-msrs");
    msr_output.nmsrs = 3;
    for (uint32_t index = 0; index < 3; ++index)
        msr_output.entries[index].index = msr_input.entries[index].index;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_MSRS,
                 (long)&msr_output) != 3)
        fail("get-msrs");
    for (uint32_t index = 0; index < 3; ++index) {
        if (msr_output.entries[index].data != msr_input.entries[index].data)
            fail("msr-roundtrip");
    }
    input_fpu.fcw = UINT16_C(0x027f);
    input_fpu.ftwx = UINT8_C(0xff);
    input_fpu.last_opcode = UINT16_C(0x0321);
    input_fpu.last_ip = UINT64_C(0x1122334455667788);
    input_fpu.last_dp = UINT64_C(0x8877665544332211);
    input_fpu.fpr[0][0] = UINT8_C(0xa5);
    input_fpu.xmm[3][7] = UINT8_C(0x5a);
    input_fpu.mxcsr = UINT32_C(0x1f80);
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_FPU,
                 (long)&input_fpu) != 0)
        fail("set-fpu");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_FPU,
                 (long)&output_fpu) != 0 ||
        output_fpu.fcw != input_fpu.fcw ||
        output_fpu.ftwx != input_fpu.ftwx ||
        output_fpu.last_opcode != input_fpu.last_opcode ||
        output_fpu.last_ip != input_fpu.last_ip ||
        output_fpu.last_dp != input_fpu.last_dp ||
        output_fpu.fpr[0][0] != input_fpu.fpr[0][0] ||
        output_fpu.xmm[3][7] != input_fpu.xmm[3][7] ||
        output_fpu.mxcsr != input_fpu.mxcsr)
        fail("get-fpu");
    mapping = syscall6(SYS_MMAP, 0, mmap_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, vcpu_fd, 0);
    if (mapping < 0) fail("mmap-vcpu");
    input_registers.rax = UINT64_C(0x123456789abcdef0);
    input_registers.rip = UINT64_C(0x0000000000100000);
    input_registers.rflags = 2;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_REGS,
                 (long)&input_registers) != 0)
        fail("set-regs");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_REGS,
                 (long)&output_registers) != 0 ||
        output_registers.rax != input_registers.rax ||
        output_registers.rip != input_registers.rip ||
        output_registers.rflags != input_registers.rflags)
        fail("get-regs");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_SREGS,
                 (long)&original_special_registers) != 0)
        fail("get-sregs-initial");
    original_special_registers.cr2 = UINT64_C(0x12345000);
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_SREGS,
                 (long)&original_special_registers) != 0)
        fail("set-sregs");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_SREGS,
                 (long)&output_special_registers) != 0 ||
        output_special_registers.cr0 != original_special_registers.cr0 ||
        output_special_registers.cr2 != original_special_registers.cr2 ||
        output_special_registers.cr3 != original_special_registers.cr3 ||
        output_special_registers.cs.selector !=
            original_special_registers.cs.selector ||
        output_special_registers.gdt.base !=
            original_special_registers.gdt.base)
        fail("get-sregs-roundtrip");
    memset(&cpuid_buffer, 0, sizeof(cpuid_buffer));
    cpuid_buffer.nent = 1;
    cpuid_buffer.entries[0].function = UINT32_C(0x4fffffff);
    cpuid_buffer.entries[0].eax = UINT32_C(0x11223344);
    cpuid_buffer.entries[0].ebx = UINT32_C(0x55667788);
    cpuid_buffer.entries[0].ecx = UINT32_C(0x99aabbcc);
    cpuid_buffer.entries[0].edx = UINT32_C(0xddeeff00);
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_CPUID2,
                 (long)&cpuid_buffer) != 0)
        fail("set-cpuid2");
    *(volatile uint8_t *)(uintptr_t)(mapping + 1) = 1;
    print("EDGE_KVM_RUN_STAGE immediate-exit-enter\n");
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_RUN, 0) != -EINTR)
        fail("immediate-exit");
    print("EDGE_KVM_RUN_STAGE immediate-exit-return\n");
    *(volatile uint8_t *)(uintptr_t)(mapping + 1) = 0;
    {
        static const uint8_t guest_code[] = {
            0xc6, 0x06, 0x00, 0x01, 0xa5,
            0xa2, 0x00, 0x80, 0xe6, 0x80,
        };
        volatile uint32_t *exit_reason =
            (volatile uint32_t *)(uintptr_t)(mapping + 8);
        volatile kvm_coalesced_mmio_ring_t *ring =
            (volatile kvm_coalesced_mmio_ring_t *)(uintptr_t)(
                mapping + 2 * PAGE_SIZE);
        volatile kvm_run_mmio_t *mmio_exit =
            (volatile kvm_run_mmio_t *)(uintptr_t)(mapping + 32);

        for (uint32_t index = 0; index < sizeof(guest_code); ++index)
            ((volatile uint8_t *)(uintptr_t)guest_memory)[index] =
                guest_code[index];
        memset(&input_registers, 0, sizeof(input_registers));
        input_registers.rax = UINT64_C(0x5a);
        input_registers.rflags = 2;
        input_registers.rip = 0;
        original_special_registers.cs.base = 0;
        original_special_registers.cs.selector = 0;
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_SREGS,
                     (long)&original_special_registers) != 0)
            fail("set-coalesced-mmio-sregs");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_REGS,
                     (long)&input_registers) != 0)
            fail("set-coalesced-mmio-regs");
        {
            print("EDGE_KVM_RUN_STAGE coalesced-mmio-enter\n");
            long run_result = syscall3(SYS_IOCTL, vcpu_fd, KVM_RUN, 0);

            print("EDGE_KVM_RUN_STAGE coalesced-mmio-return\n");

            if (run_result == -EIO)
                fail("run-coalesced-mmio-eio");
            if (run_result == -EINVAL)
                fail("run-coalesced-mmio-einval");
            if (run_result != 0)
                fail("run-coalesced-mmio-ioctl");
        }
        if (ring->first != 0 || ring->last != 1)
            fail("coalesced-mmio-ring-index");
        if (ring->entries[0].physical_address != UINT64_C(0x8000)) {
            print("EDGE_KVM_COALESCED_ACTUAL_GPA ");
            print_hex64(ring->entries[0].physical_address);
            fail("coalesced-mmio-ring-address");
        }
        if (ring->entries[0].length != 1 || ring->entries[0].pio != 0)
            fail("coalesced-mmio-ring-shape");
        if (ring->entries[0].data[0] != UINT8_C(0x5a))
            fail("coalesced-mmio-ring-data");
        if (*exit_reason == KVM_EXIT_MMIO)
            fail("run-coalesced-mmio-returned-mmio");
        if (*exit_reason == KVM_EXIT_HLT)
            fail("run-coalesced-mmio-returned-hlt");
        if (*exit_reason != KVM_EXIT_IO)
            fail("run-coalesced-mmio-reason");
        {
            uint64_t dirty_bitmap = 0;
            uint64_t clear_bitmap = 1;
            kvm_dirty_log_t dirty_log = {
                .slot = 0,
                .dirty_bitmap = (uint64_t)(uintptr_t)&dirty_bitmap,
            };
            kvm_clear_dirty_log_t clear_dirty_log = {
                .slot = 0,
                .num_pages = 1,
                .first_page = 0,
                .dirty_bitmap = (uint64_t)(uintptr_t)&clear_bitmap,
            };

            if (*(volatile uint8_t *)(uintptr_t)(guest_memory + 0x100) !=
                    UINT8_C(0xa5) ||
                syscall3(SYS_IOCTL, vm_fd, KVM_GET_DIRTY_LOG,
                         (long)&dirty_log) != 0 ||
                (dirty_bitmap & 1u) == 0)
                fail("manual-dirty-log-first-read");
            dirty_bitmap = 0;
            if (syscall3(SYS_IOCTL, vm_fd, KVM_GET_DIRTY_LOG,
                         (long)&dirty_log) != 0 ||
                (dirty_bitmap & 1u) == 0)
                fail("manual-dirty-log-preserve");
            if (syscall3(SYS_IOCTL, vm_fd, KVM_CLEAR_DIRTY_LOG,
                         (long)&clear_dirty_log) != 0)
                fail("manual-dirty-log-clear");
            dirty_bitmap = UINT64_MAX;
            if (syscall3(SYS_IOCTL, vm_fd, KVM_GET_DIRTY_LOG,
                         (long)&dirty_log) != 0 || dirty_bitmap != 0)
                fail("manual-dirty-log-clean");
        }
        ring->first = ring->last;
        if (syscall3(SYS_IOCTL, vm_fd, KVM_UNREGISTER_COALESCED_MMIO,
                     (long)&coalesced_zone) != 0)
            fail("unregister-coalesced-mmio");
        input_registers.rip = 0;
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_REGS,
                     (long)&input_registers) != 0)
            fail("reset-unregistered-mmio-regs");
        print("EDGE_KVM_RUN_STAGE unregistered-mmio-enter\n");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_RUN, 0) != 0 ||
            *exit_reason != KVM_EXIT_MMIO ||
            mmio_exit->physical_address != UINT64_C(0x8000) ||
            mmio_exit->length != 1 || mmio_exit->is_write != 1 ||
            mmio_exit->data[0] != UINT8_C(0x5a))
            fail("unregistered-mmio-fallback");
        print("EDGE_KVM_RUN_STAGE unregistered-mmio-return\n");
    }
    {
        static const uint8_t guest_code[] = {
            0x90,
            0x66, 0xb9, 0x05, 0x04, 0x00, 0x00,
            0x0f, 0x32,
            0x66, 0x89, 0xc5,
            0x66, 0x89, 0xd4,
            0x66, 0xb8, 0xff, 0xff, 0xff, 0x4f,
            0x66, 0x31, 0xc9,
            0x0f, 0xa2,
            0xf4,
        };
        for (uint32_t index = 0; index < sizeof(guest_code); ++index)
            ((volatile uint8_t *)(uintptr_t)guest_memory)[index] =
                guest_code[index];
    }
    memset(&input_registers, 0, sizeof(input_registers));
    original_special_registers.cs.base = 0;
    original_special_registers.cs.selector = 0;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_SREGS,
                 (long)&original_special_registers) != 0)
        fail("set-cpuid-sregs");
    input_registers.rip = 0;
    input_registers.rflags = 2;
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_REGS,
                 (long)&input_registers) != 0)
        fail("set-cpuid-regs");
    {
        kvm_guest_debug_t guest_debug = {
            .control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
        };
        volatile uint32_t *exit_reason =
            (volatile uint32_t *)(uintptr_t)(mapping + 8);
        volatile kvm_run_debug_t *debug_exit =
            (volatile kvm_run_debug_t *)(uintptr_t)(mapping + 32);

        print("EDGE_KVM_DEBUG_STAGE single-step-set\n");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_GUEST_DEBUG,
                     (long)&guest_debug) != 0)
            fail("set-guest-debug");
        print("EDGE_KVM_DEBUG_STAGE single-step-run\n");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_RUN, 0) != 0)
            fail("run-single-step-ioctl");
        if (*exit_reason != KVM_EXIT_DEBUG)
            fail("run-single-step-reason");
        if (debug_exit->exception != 1)
            fail("run-single-step-exception");
        if (debug_exit->program_counter == 0 ||
            debug_exit->program_counter > 64)
            fail("run-single-step-pc");
        if ((debug_exit->dr6 & DR6_BS) == 0)
            fail("run-single-step-dr6");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_REGS,
                     (long)&input_registers) != 0)
            fail("get-hardware-breakpoint-regs");
        memset(&guest_debug, 0, sizeof(guest_debug));
        guest_debug.control =
            KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
        guest_debug.debug_registers[0] = input_registers.rip;
        guest_debug.debug_registers[6] = UINT64_C(0xffff0ff0);
        guest_debug.debug_registers[7] = UINT64_C(0x0601);
        print("EDGE_KVM_DEBUG_STAGE hardware-set\n");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_GUEST_DEBUG,
                     (long)&guest_debug) != 0)
            fail("set-hardware-breakpoint");
        print("EDGE_KVM_DEBUG_STAGE hardware-run\n");
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_RUN, 0) != 0)
            fail("run-hardware-breakpoint-ioctl");
        print("EDGE_KVM_DEBUG_STAGE hardware-exit\n");
        if (*exit_reason != KVM_EXIT_DEBUG)
            fail("run-hardware-breakpoint-reason");
        if (debug_exit->exception != 1 ||
            debug_exit->program_counter != input_registers.rip ||
            (debug_exit->dr6 & DR6_B0) == 0) {
            print("EDGE_KVM_DEBUG_ACTUAL exception=");
            print_hex64(debug_exit->exception);
            print("EDGE_KVM_DEBUG_ACTUAL pc=");
            print_hex64(debug_exit->program_counter);
            print("EDGE_KVM_DEBUG_EXPECTED pc=");
            print_hex64(input_registers.rip);
            print("EDGE_KVM_DEBUG_ACTUAL dr6=");
            print_hex64(debug_exit->dr6);
            fail("run-hardware-breakpoint-state");
        }
        memset(&guest_debug, 0, sizeof(guest_debug));
        if (syscall3(SYS_IOCTL, vcpu_fd, KVM_SET_GUEST_DEBUG,
                     (long)&guest_debug) != 0)
            fail("clear-guest-debug");
    }
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_RUN, 0) != 0)
        fail("run-cpuid");
    memset(&output_registers, 0, sizeof(output_registers));
    if (syscall3(SYS_IOCTL, vcpu_fd, KVM_GET_REGS,
                 (long)&output_registers) != 0)
        fail("get-cpuid-execute-regs");
    if (
        output_registers.rax != UINT32_C(0x11223344) ||
        output_registers.rbx != UINT32_C(0x55667788) ||
        output_registers.rcx != UINT32_C(0x99aabbcc) ||
        output_registers.rdx != UINT32_C(0xddeeff00) ||
        ((output_registers.rsp << 32) | output_registers.rbp) !=
            injected_mce_status) {
        print("EDGE_KVM_CPUID_ACTUAL rax="); print_hex64(output_registers.rax);
        print("EDGE_KVM_CPUID_ACTUAL rbx="); print_hex64(output_registers.rbx);
        print("EDGE_KVM_CPUID_ACTUAL rcx="); print_hex64(output_registers.rcx);
        print("EDGE_KVM_CPUID_ACTUAL rdx="); print_hex64(output_registers.rdx);
        print("EDGE_KVM_CPUID_ACTUAL rsi="); print_hex64(output_registers.rsi);
        print("EDGE_KVM_CPUID_ACTUAL rdi="); print_hex64(output_registers.rdi);
        print("EDGE_KVM_CPUID_ACTUAL rbp="); print_hex64(output_registers.rbp);
        print("EDGE_KVM_CPUID_ACTUAL rsp="); print_hex64(output_registers.rsp);
        fail("cpuid-execute");
    }
    {
        uint8_t stats_blob[512] __attribute__((aligned(8)));
        kvm_stats_header_t *header =
            (kvm_stats_header_t *)(void *)stats_blob;
        uint64_t *values;
        long stats_fd = syscall3(
            SYS_IOCTL, vcpu_fd, KVM_GET_STATS_FD, 0);

        if (stats_fd < 0) fail("vcpu-stats-fd");
        if (syscall4(SYS_PREAD64, stats_fd, (long)stats_blob,
                     sizeof(stats_blob), 0) <= 0)
            fail("vcpu-stats-read");
        if (header->flags != 0 || header->name_size != KVM_STATS_NAME_SIZE ||
            header->num_desc != 2 ||
            memcmp(stats_blob + header->id_offset,
                   "edgeos-kvm-vcpu-", 16) != 0)
            fail("vcpu-stats-layout");
        values = (uint64_t *)(void *)(stats_blob + header->data_offset);
        if (values[0] != 0 || values[1] == 0)
            fail("vcpu-stats-values");
        (void)syscall1(SYS_CLOSE, stats_fd);
    }
    print("EDGE_KVM_UAPI_PASS\n");
    (void)syscall2(SYS_MUNMAP, mapping, mmap_size);
    (void)syscall2(SYS_MUNMAP, guest_memory, PAGE_SIZE);
    (void)syscall1(SYS_CLOSE, vcpu_fd);
    (void)syscall1(SYS_CLOSE, vm_fd);
    (void)syscall1(SYS_CLOSE, system_fd);
    (void)syscall1(SYS_EXIT, 0);
    for (;;) { }
}
