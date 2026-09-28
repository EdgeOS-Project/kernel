/* PID 1 for the EdgeOS ARM64 QEMU/KVM physical-hardware acceptance image. */

#include <stdint.h>

#define EDGE_SYS_MOUNT 40
#define EDGE_SYS_FTRUNCATE 46
#define EDGE_SYS_FALLOCATE 47
#define EDGE_SYS_OPENAT 56
#define EDGE_SYS_CLOSE 57
#define EDGE_SYS_WRITE 64
#define EDGE_SYS_PREAD64 67
#define EDGE_SYS_IOCTL 29
#define EDGE_SYS_EXIT 93
#define EDGE_SYS_CLONE 220
#define EDGE_SYS_EXECVE 221
#define EDGE_SYS_WAIT4 260
#define EDGE_SYS_MMAP 222

#define EDGE_AT_FDCWD (-100)
#define EDGE_O_RDWR 2
#define EDGE_PROT_READ 1
#define EDGE_PROT_WRITE 2
#define EDGE_MAP_SHARED 1
#define EDGE_MAP_PRIVATE 2
#define EDGE_MAP_ANONYMOUS 0x20
#define EDGE_ENOENT 2
#define EDGE_EINVAL 22
#define EDGE_ENODEV 19
#define EDGE_ESPIPE 29
#define EDGE_EOPNOTSUPP 95
#define EDGE_PAGE_SIZE 4096
#define EDGE_FALLOC_FL_KEEP_SIZE 0x01
#define EDGE_FALLOC_FL_PUNCH_HOLE 0x02
#define EDGE_KVM_CREATE_VM 0xae01u
#define EDGE_KVM_CHECK_EXTENSION 0xae03u
#define EDGE_KVM_CREATE_VCPU 0xae41u
#define EDGE_KVM_SET_USER_MEMORY_REGION 0x4020ae46u
#define EDGE_KVM_SET_MEMORY_ATTRIBUTES 0x4020aed2u
#define EDGE_KVM_CREATE_GUEST_MEMFD 0xc040aed4u
#define EDGE_KVM_PRE_FAULT_MEMORY 0xc040aed5u
#define EDGE_KVM_CAP_PRE_FAULT_MEMORY 236
#define EDGE_KVM_MEMORY_ATTRIBUTE_PRIVATE (UINT64_C(1) << 3)

#define EDGE_SIGCHLD 17

static long edge_syscall6(long number, long a0, long a1, long a2, long a3,
                          long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = number;

    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                       "r"(x8)
                     : "memory", "cc");
    return x0;
}

static unsigned long edge_length(const char *text) {
    unsigned long length = 0;

    while (text[length] != '\0')
        ++length;
    return length;
}

static void edge_print(const char *text) {
    (void)edge_syscall6(EDGE_SYS_WRITE, 1, (long)text,
                        (long)edge_length(text), 0, 0, 0);
}

static void edge_exit(long status) {
    (void)edge_syscall6(EDGE_SYS_EXIT, status, 0, 0, 0, 0, 0);
    for (;;)
        __asm__ volatile("wfe");
}

static void edge_zero(void *buffer, unsigned long size) {
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;

    while (size-- != 0)
        *bytes++ = 0;
}

typedef struct edge_kvm_create_guest_memfd {
    uint64_t size;
    uint64_t flags;
    uint64_t reserved[6];
} edge_kvm_create_guest_memfd_t;

typedef struct edge_kvm_memory_attributes {
    uint64_t address;
    uint64_t size;
    uint64_t attributes;
    uint64_t flags;
} edge_kvm_memory_attributes_t;

typedef struct edge_kvm_userspace_memory_region {
    uint32_t slot;
    uint32_t flags;
    uint64_t guest_physical_address;
    uint64_t memory_size;
    uint64_t userspace_address;
} edge_kvm_userspace_memory_region_t;

typedef struct edge_kvm_pre_fault_memory {
    uint64_t guest_physical_address;
    uint64_t size;
    uint64_t flags;
    uint64_t padding[5];
} edge_kvm_pre_fault_memory_t;

static int edge_guest_memfd_probe(void) {
    edge_kvm_create_guest_memfd_t create;
    edge_kvm_memory_attributes_t attributes;
    edge_kvm_userspace_memory_region_t region;
    edge_kvm_pre_fault_memory_t pre_fault;
    char byte;
    long guest_memory;
    long system_fd;
    long vm_fd;
    long vcpu_fd;
    long guest_fd;

    edge_zero(&create, sizeof(create));
    edge_zero(&attributes, sizeof(attributes));
    edge_zero(&region, sizeof(region));
    edge_zero(&pre_fault, sizeof(pre_fault));
    create.size = EDGE_PAGE_SIZE;
    attributes.size = EDGE_PAGE_SIZE;
    system_fd = edge_syscall6(EDGE_SYS_OPENAT, EDGE_AT_FDCWD,
        (long)"/dev/kvm", EDGE_O_RDWR, 0, 0, 0);
    if (system_fd < 0) return -1;
    if (edge_syscall6(EDGE_SYS_IOCTL, system_fd,
            EDGE_KVM_CHECK_EXTENSION, EDGE_KVM_CAP_PRE_FAULT_MEMORY,
            0, 0, 0) != 1)
        return -10;
    vm_fd = edge_syscall6(EDGE_SYS_IOCTL, system_fd,
        EDGE_KVM_CREATE_VM, 0, 0, 0, 0);
    if (vm_fd < 0) return -2;
    guest_fd = edge_syscall6(EDGE_SYS_IOCTL, vm_fd,
        EDGE_KVM_CREATE_GUEST_MEMFD, (long)&create, 0, 0, 0);
    if (guest_fd < 0) return -3;
    if (edge_syscall6(EDGE_SYS_PREAD64, guest_fd, (long)&byte, 1,
            0, 0, 0) != -EDGE_ESPIPE)
        return -4;
    if (edge_syscall6(EDGE_SYS_MMAP, 0, EDGE_PAGE_SIZE, EDGE_PROT_READ,
            EDGE_MAP_SHARED, guest_fd, 0) != -EDGE_ENODEV)
        return -5;
    if (edge_syscall6(EDGE_SYS_FTRUNCATE, guest_fd,
            EDGE_PAGE_SIZE * 2, 0, 0, 0, 0) != -EDGE_EINVAL)
        return -6;
    if (edge_syscall6(EDGE_SYS_FALLOCATE, guest_fd,
            EDGE_FALLOC_FL_KEEP_SIZE | EDGE_FALLOC_FL_PUNCH_HOLE,
            0, EDGE_PAGE_SIZE, 0, 0) != 0)
        return -7;
    if (edge_syscall6(EDGE_SYS_IOCTL, vm_fd,
            EDGE_KVM_SET_MEMORY_ATTRIBUTES, (long)&attributes,
            0, 0, 0) != 0)
        return -8;
    attributes.attributes = EDGE_KVM_MEMORY_ATTRIBUTE_PRIVATE;
    if (edge_syscall6(EDGE_SYS_IOCTL, vm_fd,
            EDGE_KVM_SET_MEMORY_ATTRIBUTES, (long)&attributes,
            0, 0, 0) != -EDGE_EOPNOTSUPP)
        return -9;
    guest_memory = edge_syscall6(EDGE_SYS_MMAP, 0, EDGE_PAGE_SIZE,
        EDGE_PROT_READ | EDGE_PROT_WRITE,
        EDGE_MAP_PRIVATE | EDGE_MAP_ANONYMOUS, -1, 0);
    if (guest_memory < 0)
        return -11;
    region.memory_size = EDGE_PAGE_SIZE;
    region.userspace_address = (uint64_t)guest_memory;
    if (edge_syscall6(EDGE_SYS_IOCTL, vm_fd,
            EDGE_KVM_SET_USER_MEMORY_REGION, (long)&region,
            0, 0, 0) != 0)
        return -12;
    vcpu_fd = edge_syscall6(EDGE_SYS_IOCTL, vm_fd,
        EDGE_KVM_CREATE_VCPU, 0, 0, 0, 0);
    if (vcpu_fd < 0)
        return -13;
    pre_fault.size = EDGE_PAGE_SIZE * 2u;
    pre_fault.padding[0] = 1;
    if (edge_syscall6(EDGE_SYS_IOCTL, vcpu_fd,
            EDGE_KVM_PRE_FAULT_MEMORY, (long)&pre_fault,
            0, 0, 0) != 0 ||
        pre_fault.guest_physical_address != EDGE_PAGE_SIZE ||
        pre_fault.size != EDGE_PAGE_SIZE || pre_fault.padding[0] != 1)
        return -14;
    if (edge_syscall6(EDGE_SYS_IOCTL, vcpu_fd,
            EDGE_KVM_PRE_FAULT_MEMORY, (long)&pre_fault,
            0, 0, 0) != -EDGE_ENOENT)
        return -15;
    (void)edge_syscall6(EDGE_SYS_CLOSE, vcpu_fd, 0, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_CLOSE, guest_fd, 0, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_CLOSE, vm_fd, 0, 0, 0, 0, 0);
    (void)edge_syscall6(EDGE_SYS_CLOSE, system_fd, 0, 0, 0, 0, 0);
    return 0;
}

void _start(void) {
    static char *const arguments[] = {
        "/usr/bin/qemu-system-aarch64",
        "-machine", "virt,accel=kvm,gic-version=3,its=off",
        "-cpu", "host",
        "-smp", "1",
        "-m", "8M",
        "-display", "none",
        "-nodefaults",
        "-monitor", "none",
        "-serial", "stdio",
        "-no-reboot",
        "-kernel", "/edge-kvm-arm64-guest.elf",
        0,
    };
    static char *const environment[] = {
        "PATH=/usr/bin:/bin",
        "QEMU_AUDIO_DRV=none",
        0,
    };
    int status = 0;
    long child;
    long waited;

    (void)edge_syscall6(EDGE_SYS_MOUNT, (long)"devtmpfs", (long)"/dev",
                        (long)"devtmpfs", 0, 0, 0);
    if (edge_guest_memfd_probe() != 0) {
        edge_print("EDGE_ARM64_GUEST_MEMFD_UAPI_FAIL\n");
        edge_exit(1);
    }
    edge_print("EDGE_ARM64_GUEST_MEMFD_UAPI_PASS\n");
    edge_print("EDGE_ARM64_PRE_FAULT_MEMORY_UAPI_PASS\n");
    edge_print("EDGE_ARM64_QEMU_KVM_STARTUP_BEGIN\n");

    child = edge_syscall6(EDGE_SYS_CLONE, EDGE_SIGCHLD, 0, 0, 0, 0, 0);
    if (child == 0) {
        (void)edge_syscall6(EDGE_SYS_EXECVE, (long)arguments[0],
                            (long)arguments, (long)environment, 0, 0, 0);
        edge_print("EDGE_ARM64_QEMU_KVM_EXEC_FAIL\n");
        edge_exit(126);
    }
    if (child < 0) {
        edge_print("EDGE_ARM64_QEMU_KVM_CLONE_FAIL\n");
        edge_exit(1);
    }

    waited = edge_syscall6(EDGE_SYS_WAIT4, child, (long)&status, 0, 0, 0, 0);
    if (waited == child && status == 0) {
        edge_print("EDGE_ARM64_QEMU_KVM_GUEST_EXECUTION_PASS\n");
        edge_exit(0);
    }

    edge_print("EDGE_ARM64_QEMU_KVM_GUEST_EXECUTION_FAIL\n");
    edge_exit(1);
}
