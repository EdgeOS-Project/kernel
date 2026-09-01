/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding runtime probe for EdgeOS virtualization peripheral UAPIs. */

#include <stdint.h>

#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_MMAP 9
#define SYS_MUNMAP 11
#define SYS_IOCTL 16
#define SYS_EXIT 60
#define SYS_FTRUNCATE 77
#define SYS_OPENAT 257
#define SYS_MEMFD_CREATE 319
#define AT_FDCWD (-100)
#define O_RDWR 2
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1

#define IOMMU_IOAS_ALLOC 0x3b81u
#define IOMMU_IOAS_UNMAP 0x3b86u
#define IOMMU_VFIO_IOAS 0x3b88u
#define IOMMU_FAULT_QUEUE_ALLOC 0x3b8eu
#define IOMMU_IOAS_MAP_FILE 0x3b8fu
#define IOMMU_IOAS_CHANGE_PROCESS 0x3b92u
#define IOMMU_VEVENTQ_ALLOC 0x3b93u
#define IOMMU_HW_QUEUE_ALLOC 0x3b94u
#define IOMMU_VFIO_IOAS_GET 0u
#define IOMMU_VFIO_IOAS_SET 1u
#define IOMMU_VFIO_IOAS_CLEAR 2u

#define VHOST_SET_OWNER 0xaf01u
#define VHOST_NEW_WORKER 0x8004af08u
#define VHOST_FREE_WORKER 0x4004af09u
#define VHOST_ATTACH_VRING_WORKER 0x4008af15u
#define VHOST_GET_VRING_WORKER 0xc008af16u
#define VHOST_SCSI_SET_ENDPOINT 0x40e8af40u
#define VHOST_SCSI_CLEAR_ENDPOINT 0x40e8af41u
#define VHOST_SCSI_GET_ABI_VERSION 0x4004af42u
#define VHOST_SCSI_SET_EVENTS_MISSED 0x4004af43u
#define VHOST_SCSI_GET_EVENTS_MISSED 0x4004af44u
#define VHOST_VSOCK_SET_GUEST_CID 0x4008af60u
#define VHOST_VSOCK_SET_RUNNING 0x4004af61u
#define VHOST_GET_FEATURES_ARRAY 0x8008af83u
#define VHOST_SET_FEATURES_ARRAY 0x4008af83u
#define VHOST_SET_FORK_FROM_OWNER 0x4001af84u
#define VHOST_GET_FORK_FROM_OWNER 0x8001af85u
#define EOPNOTSUPP 95

typedef struct iommu_ioas_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t out_ioas_id;
} iommu_ioas_alloc_t;

typedef struct iommu_vfio_ioas {
    uint32_t size;
    uint32_t ioas_id;
    uint16_t op;
    uint16_t reserved;
} iommu_vfio_ioas_t;

typedef struct iommu_fault_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t out_fault_id;
    uint32_t out_fault_fd;
} iommu_fault_alloc_t;

typedef struct iommu_ioas_map_file {
    uint32_t size;
    uint32_t flags;
    uint32_t ioas_id;
    int32_t fd;
    uint64_t start;
    uint64_t length;
    uint64_t iova;
} iommu_ioas_map_file_t;

typedef struct iommu_ioas_change_process {
    uint32_t size;
    uint32_t reserved;
} iommu_ioas_change_process_t;

typedef struct iommu_ioas_unmap {
    uint32_t size;
    uint32_t ioas_id;
    uint64_t iova;
    uint64_t length;
} iommu_ioas_unmap_t;

typedef struct iommu_veventq_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t viommu_id;
    uint32_t type;
    uint32_t veventq_depth;
    uint32_t out_veventq_id;
    uint32_t out_veventq_fd;
    uint32_t reserved;
} iommu_veventq_alloc_t;

typedef struct iommu_hw_queue_alloc {
    uint32_t size;
    uint32_t flags;
    uint32_t viommu_id;
    uint32_t type;
    uint32_t index;
    uint32_t out_hw_queue_id;
    uint64_t nesting_parent_iova;
    uint64_t length;
} iommu_hw_queue_alloc_t;

typedef struct vhost_worker_state {
    uint32_t worker_id;
} vhost_worker_state_t;

typedef struct vhost_vring_worker {
    uint32_t index;
    uint32_t worker_id;
} vhost_vring_worker_t;

typedef struct vhost_scsi_target {
    int32_t abi_version;
    char vhost_wwpn[224];
    uint16_t vhost_tpgt;
    uint16_t reserved;
} vhost_scsi_target_t;

typedef struct vhost_features_array_one {
    uint64_t count;
    uint64_t features[1];
} vhost_features_array_one_t;

typedef struct vhost_iotlb_msg {
    uint64_t iova;
    uint64_t size;
    uint64_t uaddr;
    uint8_t perm;
    uint8_t type;
} vhost_iotlb_msg_t;

typedef struct vhost_msg_v2 {
    uint32_t type;
    uint32_t asid;
    union {
        vhost_iotlb_msg_t iotlb;
        uint8_t padding[64];
    } payload;
} vhost_msg_v2_t;

static long syscall1(long number, long a0) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a0)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall2(long number, long a0, long a1) {
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall3(long number, long a0, long a1, long a2) {
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall4(long number, long a0, long a1, long a2, long a3) {
    register long r10 __asm__("r10") = a3;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall6(long number, long a0, long a1, long a2, long a3,
                     long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
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

static void print(const char *text) {
    (void)syscall3(SYS_WRITE, 1, (long)text, (long)text_length(text));
}

static void fail(const char *stage) {
    print("EDGE_VIRTUALIZATION_PERIPHERAL_FAIL ");
    print(stage);
    print("\n");
    (void)syscall1(SYS_EXIT, 1);
    for (;;) { }
}

static long open_device(const char *path) {
    return syscall4(SYS_OPENAT, AT_FDCWD, (long)path, O_RDWR, 0);
}

static long issue(long descriptor, uint32_t command, void *argument) {
    return syscall3(SYS_IOCTL, descriptor, command, (long)argument);
}

void _start(void) {
    iommu_ioas_alloc_t allocation = {.size = sizeof(allocation)};
    iommu_vfio_ioas_t vfio_ioas = {.size = sizeof(vfio_ioas)};
    iommu_fault_alloc_t fault = {.size = sizeof(fault)};
    iommu_ioas_map_file_t map_file = {
        .size = sizeof(map_file),
        .flags = 0x1u | 0x4u,
        .fd = 0,
        .start = 0,
        .length = 0x1000,
        .iova = 0x1000,
    };
    iommu_ioas_change_process_t change_process = {
        .size = sizeof(change_process),
    };
    iommu_ioas_unmap_t unmap = {
        .size = sizeof(unmap),
        .iova = 0x1000,
        .length = 0x1000,
    };
    iommu_veventq_alloc_t veventq = {
        .size = sizeof(veventq),
        .type = 1,
        .viommu_id = 1,
        .veventq_depth = 8,
    };
    iommu_hw_queue_alloc_t hw_queue = {
        .size = sizeof(hw_queue),
        .type = 1,
        .viommu_id = 1,
        .nesting_parent_iova = 0x1000,
        .length = 0x1000,
    };
    vhost_worker_state_t worker = {0};
    vhost_vring_worker_t ring_worker = {0};
    vhost_scsi_target_t target = {
        .abi_version = 1,
        .vhost_wwpn = "naa.5001405ed5700001",
    };
    uint32_t abi_version = 0;
    uint32_t events_missed = 1;
    uint64_t guest_cid = 7;
    int32_t running = 1;
    uint8_t fork_owner = 0;
    vhost_features_array_one_t feature_array = {.count = 1};
    vhost_msg_v2_t iotlb = {
        .type = 2,
        .payload.iotlb = {
            .iova = 0x1000,
            .size = 0x1000,
            .uaddr = 0x100000,
            .perm = 3,
            .type = 2,
        },
    };
    long iommu_fd = open_device("/dev/iommu");
    long memfd;
    long shared_mapping;
    long net_fd;
    long scsi_fd;
    long vsock_fd;

    if (iommu_fd < 0) fail("open-iommu");
    if (issue(iommu_fd, IOMMU_IOAS_ALLOC, &allocation) < 0 ||
        allocation.out_ioas_id == 0)
        fail("ioas-alloc");
    vfio_ioas.op = IOMMU_VFIO_IOAS_SET;
    vfio_ioas.ioas_id = allocation.out_ioas_id;
    if (issue(iommu_fd, IOMMU_VFIO_IOAS, &vfio_ioas) < 0)
        fail("vfio-ioas-set");
    vfio_ioas.op = IOMMU_VFIO_IOAS_GET;
    vfio_ioas.ioas_id = 0;
    if (issue(iommu_fd, IOMMU_VFIO_IOAS, &vfio_ioas) < 0 ||
        vfio_ioas.ioas_id != allocation.out_ioas_id)
        fail("vfio-ioas-get");
    vfio_ioas.op = IOMMU_VFIO_IOAS_CLEAR;
    vfio_ioas.ioas_id = 0;
    if (issue(iommu_fd, IOMMU_VFIO_IOAS, &vfio_ioas) < 0)
        fail("vfio-ioas-clear");
    map_file.ioas_id = allocation.out_ioas_id;
    unmap.ioas_id = allocation.out_ioas_id;
    if (issue(iommu_fd, IOMMU_IOAS_CHANGE_PROCESS,
              &change_process) < 0)
        fail("iommufd-change-process-empty");
    memfd = syscall2(SYS_MEMFD_CREATE, (long)"edge-iommufd-probe", 0);
    if (memfd < 0 || syscall2(SYS_FTRUNCATE, memfd, 0x1000) < 0)
        fail("iommufd-map-file-memfd");
    shared_mapping = syscall6(SYS_MMAP, 0, 0x1000,
                              PROT_READ | PROT_WRITE, MAP_SHARED,
                              memfd, 0);
    if (shared_mapping < 0) fail("iommufd-map-file-mmap");
    map_file.fd = (int32_t)memfd;
    if (issue(iommu_fd, IOMMU_IOAS_MAP_FILE, &map_file) < 0)
        fail("iommufd-map-file");
    if (syscall2(SYS_MUNMAP, shared_mapping, 0x1000) < 0)
        fail("iommufd-map-file-munmap-before-transfer");
    if (issue(iommu_fd, IOMMU_IOAS_CHANGE_PROCESS,
              &change_process) < 0)
        fail("iommufd-change-process-file");
    if (issue(iommu_fd, IOMMU_IOAS_UNMAP, &unmap) < 0)
        fail("iommufd-map-file-release");
    (void)syscall1(SYS_CLOSE, memfd);
    if (issue(iommu_fd, IOMMU_FAULT_QUEUE_ALLOC, &fault) != -EOPNOTSUPP ||
        issue(iommu_fd, IOMMU_VEVENTQ_ALLOC, &veventq) != -EOPNOTSUPP ||
        issue(iommu_fd, IOMMU_HW_QUEUE_ALLOC, &hw_queue) != -EOPNOTSUPP)
        fail("iommufd-advanced-capability-boundary");

    net_fd = open_device("/dev/vhost-net");
    if (net_fd < 0 ||
        issue(net_fd, VHOST_GET_FEATURES_ARRAY, &feature_array) < 0 ||
        feature_array.count != 1 || feature_array.features[0] == 0 ||
        issue(net_fd, VHOST_SET_FORK_FROM_OWNER, &fork_owner) < 0 ||
        issue(net_fd, VHOST_GET_FORK_FROM_OWNER, &fork_owner) < 0 ||
        fork_owner != 0 || issue(net_fd, VHOST_SET_OWNER, 0) < 0 ||
        issue(net_fd, VHOST_SET_FEATURES_ARRAY, &feature_array) < 0)
        fail("vhost-net-owner");
    if (syscall3(SYS_WRITE, net_fd, (long)&iotlb,
                 sizeof(iotlb)) != -EOPNOTSUPP)
        fail("vhost-iotlb-capability-boundary");
    if (issue(net_fd, VHOST_NEW_WORKER, &worker) < 0 ||
        worker.worker_id == 0)
        fail("vhost-new-worker");
    ring_worker.worker_id = worker.worker_id;
    if (issue(net_fd, VHOST_ATTACH_VRING_WORKER, &ring_worker) < 0)
        fail("vhost-attach-worker");
    ring_worker.worker_id = 0;
    if (issue(net_fd, VHOST_GET_VRING_WORKER, &ring_worker) < 0 ||
        ring_worker.worker_id != worker.worker_id)
        fail("vhost-get-worker");
    ring_worker.worker_id = 0;
    if (issue(net_fd, VHOST_ATTACH_VRING_WORKER, &ring_worker) < 0 ||
        issue(net_fd, VHOST_FREE_WORKER, &worker) < 0)
        fail("vhost-free-worker");

    scsi_fd = open_device("/dev/vhost-scsi");
    if (scsi_fd < 0 ||
        issue(scsi_fd, VHOST_SCSI_GET_ABI_VERSION, &abi_version) < 0 ||
        abi_version != 1 || issue(scsi_fd, VHOST_SET_OWNER, 0) < 0)
        fail("vhost-scsi-open");
    if (issue(scsi_fd, VHOST_SCSI_SET_ENDPOINT, &target) < 0 ||
        issue(scsi_fd, VHOST_SCSI_SET_EVENTS_MISSED, &events_missed) < 0)
        fail("vhost-scsi-set");
    events_missed = 0;
    if (issue(scsi_fd, VHOST_SCSI_GET_EVENTS_MISSED, &events_missed) < 0 ||
        events_missed != 1 ||
        issue(scsi_fd, VHOST_SCSI_CLEAR_ENDPOINT, &target) < 0)
        fail("vhost-scsi-get");

    vsock_fd = open_device("/dev/vhost-vsock");
    if (vsock_fd < 0 || issue(vsock_fd, VHOST_SET_OWNER, 0) < 0 ||
        issue(vsock_fd, VHOST_VSOCK_SET_GUEST_CID, &guest_cid) < 0 ||
        issue(vsock_fd, VHOST_VSOCK_SET_RUNNING, &running) < 0)
        fail("vhost-vsock-start");
    running = 0;
    if (issue(vsock_fd, VHOST_VSOCK_SET_RUNNING, &running) < 0)
        fail("vhost-vsock-stop");

    (void)syscall1(SYS_CLOSE, vsock_fd);
    (void)syscall1(SYS_CLOSE, scsi_fd);
    (void)syscall1(SYS_CLOSE, net_fd);
    (void)syscall1(SYS_CLOSE, iommu_fd);
    print("EDGE_VIRTUALIZATION_PERIPHERAL_PASS\n");
    (void)syscall1(SYS_EXIT, 0);
    for (;;) { }
}
