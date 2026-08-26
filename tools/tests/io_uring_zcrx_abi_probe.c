/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring RECV_ZC, nodev and device-backed ZCRX ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define ENTRY_ALIGNMENT __attribute__((force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_ioctl 16
#define SYS_socket 41
#define SYS_connect 42
#define SYS_accept 43
#define SYS_bind 49
#define SYS_listen 50
#define SYS_getsockname 51
#define SYS_exit 60
#elif defined(__aarch64__)
#define ENTRY_ALIGNMENT
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_ioctl 29
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept 202
#define SYS_connect 203
#define SYS_getsockname 204
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_zcrx_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define MAP_PRIVATE 2u
#define MAP_ANONYMOUS 0x20u
#define PAGE_SIZE 4096u
#define AF_INET 2
#define SOCK_STREAM 1
#define SIOCGIFFLAGS 0x8913u
#define SIOCSIFFLAGS 0x8914u
#define IFF_UP 1u
#define EINVAL 22
#define ENODEV 19
#define EOPNOTSUPP 95

#define IORING_ENTER_GETEVENTS 1u
#define IORING_SETUP_SINGLE_ISSUER (1u << 12)
#define IORING_SETUP_DEFER_TASKRUN (1u << 13)
#define IORING_SETUP_CQE32 (1u << 11)
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_OFF_ZCRX_REGION 0x30000000ull
#define IORING_OFF_ZCRX_SHIFT 16u
#define IORING_REGISTER_ZCRX_IFQ 32u
#define IORING_REGISTER_ZCRX_CTRL 36u
#define IORING_OP_RECV_ZC 58u
#define IORING_RECV_MULTISHOT (1u << 1)
#define IORING_CQE_F_MORE (1u << 1)
#define ZCRX_REG_IMPORT 1u
#define ZCRX_REG_NODEV 2u
#define ZCRX_CTRL_FLUSH_RQ 0u
#define ZCRX_CTRL_EXPORT 1u
#define EBADF 9

struct probe_sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t zero[8];
};

struct probe_ifreq {
    char name[16];
    uint8_t value[24];
};

struct io_uring_sqe {
    uint8_t opcode;
    uint8_t flags;
    uint16_t ioprio;
    int32_t descriptor;
    uint64_t offset;
    uint64_t address;
    uint32_t length;
    uint32_t operation_flags;
    uint64_t user_data;
    uint16_t buffer_index;
    uint16_t personality;
    int32_t splice_descriptor;
    uint64_t address3;
    uint64_t reserved2;
};

struct io_uring_cqe32 {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
    uint64_t extra[2];
};

struct io_sqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t flags;
    uint32_t dropped;
    uint32_t array;
    uint32_t reserved1;
    uint64_t user_address;
};

struct io_cqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t overflow;
    uint32_t cqes;
    uint32_t flags;
    uint32_t reserved1;
    uint64_t user_address;
};

struct io_uring_params {
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t flags;
    uint32_t sq_thread_cpu;
    uint32_t sq_thread_idle;
    uint32_t features;
    uint32_t workqueue_descriptor;
    uint32_t reserved[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
};

struct io_uring_region_desc {
    uint64_t user_address;
    uint64_t size;
    uint32_t flags;
    uint32_t id;
    uint64_t mmap_offset;
    uint64_t reserved[4];
};

struct io_uring_zcrx_area_reg {
    uint64_t address;
    uint64_t length;
    uint64_t rq_area_token;
    uint32_t flags;
    uint32_t dmabuf_descriptor;
    uint64_t reserved[2];
};

struct io_uring_zcrx_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t rqes;
    uint32_t reserved2;
    uint64_t reserved[2];
};

struct io_uring_zcrx_ifq_reg {
    uint32_t interface_index;
    uint32_t receive_queue;
    uint32_t rq_entries;
    uint32_t flags;
    uint64_t area;
    uint64_t region;
    struct io_uring_zcrx_offsets offsets;
    uint32_t zcrx_id;
    uint32_t receive_buffer_length;
    uint64_t notification;
    uint64_t reserved[2];
};

struct io_uring_zcrx_rqe {
    uint64_t offset;
    uint32_t length;
    uint32_t padding;
};

struct io_uring_zcrx_ctrl {
    uint32_t zcrx_id;
    uint32_t operation;
    uint64_t reserved[2];
    uint64_t operation_data[6];
};

typedef struct probe_ring {
    long descriptor;
    struct io_uring_params parameters;
    void *sq_ring;
    void *cq_ring;
    struct io_uring_sqe *sqes;
} probe_ring_t;

static uint8_t g_receive_area[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
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
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

void *memset(void *destination, int value, unsigned long length) {
    uint8_t *bytes = destination;
    while (length) bytes[--length] = (uint8_t)value;
    return destination;
}

unsigned long strlen(const char *text) {
    unsigned long length = 0u;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)strlen(text), 0, 0, 0);
}

static void print_number(long value) {
    char digits[24];
    unsigned long magnitude;
    unsigned long count = 0u;

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    while (count)
        (void)raw_syscall6(
            SYS_write, 1, (long)&digits[--count], 1, 0, 0, 0);
}

static void print_error(const char *label, long result) {
    print_text(label);
    print_text(" result=");
    print_number(result);
    print_text("\n");
}

static int record_failure(int failed, const char *label) {
    if (failed) print_text(label);
    return failed;
}

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       uint32_t length) {
    for (uint32_t index = 0; index < length; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static void *map_memory(long descriptor, uint64_t offset,
                        uint32_t flags) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        flags, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 :
        (void *)(uintptr_t)result;
}

static void bring_loopback_up(void) {
    struct probe_ifreq request;
    int16_t *flags = (int16_t *)&request.value[0];
    long descriptor;

    memset(&request, 0, sizeof(request));
    request.name[0] = 'l';
    request.name[1] = 'o';
    descriptor = raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (descriptor < 0) return;
    if (raw_syscall6(
            SYS_ioctl, descriptor, SIOCGIFFLAGS,
            (long)&request, 0, 0, 0) == 0) {
        *flags = (int16_t)((uint16_t)*flags | IFF_UP);
        (void)raw_syscall6(
            SYS_ioctl, descriptor, SIOCSIFFLAGS,
            (long)&request, 0, 0, 0);
    }
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
}

static int create_tcp_pair(long descriptors[2]) {
    struct probe_sockaddr_in address;
    uint32_t address_length = sizeof(address);
    long listener = -1;
    long client = -1;
    long accepted = -1;

    bring_loopback_up();
    memset(&address, 0, sizeof(address));
    address.family = AF_INET;
    address.address = 0x0100007fu;
    listener = raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (listener < 0) {
        print_error("ZCRX_TCP_LISTENER_SOCKET_FAIL", listener);
        goto fail;
    }
    if (raw_syscall6(
            SYS_bind, listener, (long)&address,
            sizeof(address), 0, 0, 0) < 0) {
        print_text("ZCRX_TCP_BIND_FAIL\n");
        goto fail;
    }
    if (raw_syscall6(SYS_listen, listener, 1, 0, 0, 0, 0) < 0) {
        print_text("ZCRX_TCP_LISTEN_FAIL\n");
        goto fail;
    }
    if (raw_syscall6(
            SYS_getsockname, listener, (long)&address,
            (long)&address_length, 0, 0, 0) < 0) {
        print_text("ZCRX_TCP_GETSOCKNAME_FAIL\n");
        goto fail;
    }
    client = raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (client < 0) {
        print_text("ZCRX_TCP_CLIENT_SOCKET_FAIL\n");
        goto fail;
    }
    if (raw_syscall6(
            SYS_connect, client, (long)&address,
            sizeof(address), 0, 0, 0) < 0) {
        print_text("ZCRX_TCP_CONNECT_FAIL\n");
        goto fail;
    }
    accepted = raw_syscall6(
        SYS_accept, listener, 0, 0, 0, 0, 0);
    if (accepted < 0) {
        print_text("ZCRX_TCP_ACCEPT_FAIL\n");
        goto fail;
    }
    (void)raw_syscall6(SYS_close, listener, 0, 0, 0, 0, 0);
    descriptors[0] = client;
    descriptors[1] = accepted;
    return 0;

fail:
    if (accepted >= 0)
        (void)raw_syscall6(SYS_close, accepted, 0, 0, 0, 0, 0);
    if (client >= 0)
        (void)raw_syscall6(SYS_close, client, 0, 0, 0, 0, 0);
    if (listener >= 0)
        (void)raw_syscall6(SYS_close, listener, 0, 0, 0, 0, 0);
    return 1;
}

static int ring_open(probe_ring_t *ring, uint32_t flags) {
    memset(ring, 0, sizeof(*ring));
    ring->descriptor = -1;
    ring->parameters.flags = flags;
    ring->descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&ring->parameters, 0, 0, 0, 0);
    if (ring->descriptor < 0) return 1;
    ring->sq_ring = map_memory(
        ring->descriptor, IORING_OFF_SQ_RING, MAP_SHARED);
    ring->cq_ring = map_memory(
        ring->descriptor, IORING_OFF_CQ_RING, MAP_SHARED);
    ring->sqes = map_memory(
        ring->descriptor, IORING_OFF_SQES, MAP_SHARED);
    return !ring->sq_ring || !ring->cq_ring || !ring->sqes;
}

static void ring_close(probe_ring_t *ring) {
    if (ring->sqes)
        (void)raw_syscall6(
            SYS_munmap, (long)ring->sqes, PAGE_SIZE, 0, 0, 0, 0);
    if (ring->cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)ring->cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (ring->sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)ring->sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (ring->descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, ring->descriptor, 0, 0, 0, 0, 0);
}

static void ring_submit(probe_ring_t *ring,
                        const struct io_uring_sqe *request) {
    volatile uint32_t *tail = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.tail);
    volatile uint32_t *mask = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.ring_mask);
    volatile uint32_t *array = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.array);
    uint32_t value = *tail;
    uint32_t index = value & *mask;

    ring->sqes[index] = *request;
    array[index] = index;
    __atomic_store_n(tail, value + 1u, __ATOMIC_RELEASE);
}

static uint32_t ring_completion_count(probe_ring_t *ring) {
    volatile uint32_t *head = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.head);
    volatile uint32_t *tail = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.tail);
    return __atomic_load_n(tail, __ATOMIC_ACQUIRE) - *head;
}

static struct io_uring_cqe32 *ring_completion(
        probe_ring_t *ring, uint32_t relative_index) {
    volatile uint32_t *head = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.head);
    volatile uint32_t *mask = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.ring_mask);
    struct io_uring_cqe32 *entries = (struct io_uring_cqe32 *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.cqes);
    return &entries[(*head + relative_index) & *mask];
}

static void ring_consume(probe_ring_t *ring, uint32_t count) {
    volatile uint32_t *head = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.head);
    __atomic_store_n(head, *head + count, __ATOMIC_RELEASE);
}

static int test_required_setup_flags(void) {
    struct io_uring_zcrx_ifq_reg registration;
    struct io_uring_zcrx_area_reg area;
    struct io_uring_region_desc region;
    probe_ring_t ring;
    long result;

    if (ring_open(&ring, 0u)) return 1;
    memset(&registration, 0, sizeof(registration));
    memset(&area, 0, sizeof(area));
    memset(&region, 0, sizeof(region));
    area.address = (uint64_t)(uintptr_t)g_receive_area;
    area.length = PAGE_SIZE;
    region.size = PAGE_SIZE;
    registration.rq_entries = 8u;
    registration.flags = ZCRX_REG_NODEV;
    registration.area = (uint64_t)(uintptr_t)&area;
    registration.region = (uint64_t)(uintptr_t)&region;
    result = raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_ZCRX_IFQ, (long)&registration, 1, 0, 0);
    ring_close(&ring);
    return result != -EINVAL;
}

static int test_receive(uint32_t registration_flags,
                        uint32_t interface_index,
                        int allow_unsupported_device) {
    static const uint8_t payload[] = {
        'z', 'c', 'r', 'x', '-', 'o', 'r', 'a', 'c', 'l', 'e'
    };
    struct io_uring_zcrx_ifq_reg registration;
    struct io_uring_zcrx_area_reg area;
    struct io_uring_region_desc region;
    struct io_uring_zcrx_ctrl control;
    struct io_uring_zcrx_rqe *refill;
    struct io_uring_sqe request;
    struct io_uring_cqe32 *data_completion;
    struct io_uring_cqe32 *final_completion;
    probe_ring_t ring;
    long sockets[2] = {-1, -1};
    void *refill_region = 0;
    uint32_t *refill_head;
    uint32_t *refill_tail;
    uint64_t data_offset;
    long registration_result;
    int failures = 0;

    memset(g_receive_area, 0, sizeof(g_receive_area));
    if (ring_open(
            &ring, IORING_SETUP_SINGLE_ISSUER |
                   IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32)) {
        print_text("ZCRX_SETUP_FAIL\n");
        return 1;
    }
    memset(&registration, 0, sizeof(registration));
    memset(&area, 0, sizeof(area));
    memset(&region, 0, sizeof(region));
    area.address = (uint64_t)(uintptr_t)g_receive_area;
    area.length = PAGE_SIZE;
    region.size = PAGE_SIZE;
    registration.rq_entries = 8u;
    registration.flags = registration_flags;
    registration.interface_index = interface_index;
    registration.area = (uint64_t)(uintptr_t)&area;
    registration.region = (uint64_t)(uintptr_t)&region;
    registration_result = raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_ZCRX_IFQ, (long)&registration, 1, 0, 0);
    if (allow_unsupported_device &&
        registration_result == -EOPNOTSUPP) {
        print_text("ZCRX_DEVICE_BACKEND_UNAVAILABLE\n");
        ring_close(&ring);
        return 0;
    }
    failures += record_failure(
        registration_result != 0, "ZCRX_REGISTER_FAIL\n");
    failures += record_failure(
        registration.rq_entries != 8u ||
        registration.receive_buffer_length != PAGE_SIZE ||
        region.mmap_offset == 0u ||
        registration.offsets.tail != 4u ||
        registration.offsets.rqes < 8u,
        "ZCRX_REGISTER_OUTPUT_FAIL\n");
    if (failures) goto done;
    refill_region = map_memory(
        ring.descriptor, region.mmap_offset, MAP_SHARED);
    failures += record_failure(
        !refill_region, "ZCRX_REGION_MMAP_FAIL\n");
    if (failures) goto done;
    refill_head = (uint32_t *)((uint8_t *)refill_region +
        registration.offsets.head);
    refill_tail = (uint32_t *)((uint8_t *)refill_region +
        registration.offsets.tail);
    refill = (struct io_uring_zcrx_rqe *)((uint8_t *)refill_region +
        registration.offsets.rqes);

    failures += record_failure(
        create_tcp_pair(sockets), "ZCRX_TCP_PAIR_FAIL\n");
    if (failures) goto done;
    failures += record_failure(raw_syscall6(
        SYS_write, sockets[0], (long)payload, sizeof(payload),
        0, 0, 0) != (long)sizeof(payload), "ZCRX_TCP_WRITE_FAIL\n");
    if (failures) goto done;

    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_RECV_ZC;
    request.ioprio = IORING_RECV_MULTISHOT;
    request.descriptor = (int32_t)sockets[1];
    request.length = sizeof(payload);
    request.user_data = 0x5a435258u;
    request.splice_descriptor = (int32_t)registration.zcrx_id;
    ring_submit(&ring, &request);
    failures += record_failure(raw_syscall6(
        SYS_io_uring_enter, ring.descriptor, 1, 2,
        IORING_ENTER_GETEVENTS, 0, 0) < 1, "ZCRX_ENTER_FAIL\n");
    for (uint32_t attempt = 0;
         attempt < 8u && ring_completion_count(&ring) < 2u; ++attempt)
        (void)raw_syscall6(
            SYS_io_uring_enter, ring.descriptor, 0, 1,
            IORING_ENTER_GETEVENTS, 0, 0);
    failures += record_failure(
        ring_completion_count(&ring) < 2u,
        "ZCRX_COMPLETION_COUNT_FAIL\n");
    if (failures) goto done;
    data_completion = ring_completion(&ring, 0u);
    final_completion = ring_completion(&ring, 1u);
    data_offset = data_completion->extra[0] &
        ((UINT64_C(1) << 48u) - 1u);
    failures += record_failure(
        data_completion->user_data != request.user_data ||
        data_completion->result != (int32_t)sizeof(payload) ||
        data_completion->flags != IORING_CQE_F_MORE ||
        data_completion->extra[1] != 0u ||
        final_completion->user_data != request.user_data ||
        final_completion->result != 0 || final_completion->flags != 0u,
        "ZCRX_COMPLETION_VALUE_FAIL\n");
    failures += record_failure(
        data_offset + sizeof(payload) > PAGE_SIZE ||
        !bytes_equal(g_receive_area + data_offset,
                     payload, sizeof(payload)),
        "ZCRX_PAYLOAD_FAIL\n");
    if (failures) goto done;
    ring_consume(&ring, 2u);

    memset(&refill[0], 0, sizeof(refill[0]));
    refill[0].offset = data_completion->extra[0];
    refill[0].length = sizeof(payload);
    __atomic_store_n(refill_tail, 1u, __ATOMIC_RELEASE);
    memset(&control, 0, sizeof(control));
    control.zcrx_id = registration.zcrx_id;
    control.operation = ZCRX_CTRL_FLUSH_RQ;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_ZCRX_CTRL, (long)&control, 0, 0, 0) != 0,
        "ZCRX_FLUSH_FAIL\n");
    failures += record_failure(
        __atomic_load_n(refill_head, __ATOMIC_ACQUIRE) != 1u,
        "ZCRX_REFILL_HEAD_FAIL\n");

    request.ioprio = 0u;
    request.user_data = 0x5a435259u;
    ring_submit(&ring, &request);
    failures += record_failure(raw_syscall6(
        SYS_io_uring_enter, ring.descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0) != 1,
        "ZCRX_INVALID_ENTER_FAIL\n");
    failures += record_failure(
        ring_completion_count(&ring) != 1u ||
        ring_completion(&ring, 0u)->user_data != request.user_data ||
        ring_completion(&ring, 0u)->result != -EINVAL,
        "ZCRX_MULTISHOT_VALIDATION_FAIL\n");

done:
    if (refill_region)
        (void)raw_syscall6(
            SYS_munmap, (long)refill_region, PAGE_SIZE, 0, 0, 0, 0);
    if (sockets[1] >= 0)
        (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
    if (sockets[0] >= 0)
        (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
    ring_close(&ring);
    if (!failures && allow_unsupported_device)
        print_text("ZCRX_DEVICE_BACKEND_ACTIVE\n");
    return failures;
}

static int test_device_validation(void) {
    struct io_uring_zcrx_ifq_reg registration;
    struct io_uring_zcrx_area_reg area;
    struct io_uring_region_desc region;
    probe_ring_t ring;
    uint32_t flags = IORING_SETUP_SINGLE_ISSUER |
        IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32;
    int failures = 0;

    if (ring_open(&ring, flags)) return 1;
    memset(&registration, 0, sizeof(registration));
    memset(&area, 0, sizeof(area));
    memset(&region, 0, sizeof(region));
    area.address = (uint64_t)(uintptr_t)g_receive_area;
    area.length = PAGE_SIZE;
    region.size = PAGE_SIZE;
    registration.interface_index = UINT32_MAX;
    registration.rq_entries = 8u;
    registration.area = (uint64_t)(uintptr_t)&area;
    registration.region = (uint64_t)(uintptr_t)&region;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_ZCRX_IFQ, (long)&registration, 1, 0, 0) != -ENODEV,
        "ZCRX_DEVICE_IFINDEX_VALIDATION_FAIL\n");

    registration.interface_index = 2u;
    registration.receive_queue = UINT32_MAX;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_ZCRX_IFQ, (long)&registration, 1, 0, 0) != -EINVAL,
        "ZCRX_DEVICE_QUEUE_VALIDATION_FAIL\n");
    ring_close(&ring);
    return failures;
}

static int test_export_import(void) {
    struct io_uring_zcrx_ifq_reg registration;
    struct io_uring_zcrx_ifq_reg imported_registration;
    struct io_uring_zcrx_area_reg area;
    struct io_uring_region_desc region;
    struct io_uring_zcrx_ctrl control;
    probe_ring_t origin;
    probe_ring_t imported;
    void *origin_region = 0;
    void *imported_region = 0;
    long export_descriptor = -1;
    uint32_t setup_flags = IORING_SETUP_SINGLE_ISSUER |
        IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32;
    int failures = 0;

    memset(g_receive_area, 0, sizeof(g_receive_area));
    if (ring_open(&origin, setup_flags)) {
        print_text("ZCRX_EXPORT_ORIGIN_SETUP_FAIL\n");
        return 1;
    }
    if (ring_open(&imported, setup_flags)) {
        print_text("ZCRX_IMPORT_RING_SETUP_FAIL\n");
        ring_close(&origin);
        return 1;
    }

    memset(&registration, 0, sizeof(registration));
    memset(&area, 0, sizeof(area));
    memset(&region, 0, sizeof(region));
    area.address = (uint64_t)(uintptr_t)g_receive_area;
    area.length = PAGE_SIZE;
    region.size = PAGE_SIZE;
    registration.rq_entries = 8u;
    registration.flags = ZCRX_REG_NODEV;
    registration.area = (uint64_t)(uintptr_t)&area;
    registration.region = (uint64_t)(uintptr_t)&region;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, origin.descriptor,
        IORING_REGISTER_ZCRX_IFQ, (long)&registration, 1, 0, 0) != 0,
        "ZCRX_EXPORT_REGISTER_FAIL\n");
    if (failures) goto done;

    memset(&control, 0, sizeof(control));
    control.zcrx_id = registration.zcrx_id;
    control.operation = ZCRX_CTRL_EXPORT;
    control.operation_data[5] = 1u;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, origin.descriptor,
        IORING_REGISTER_ZCRX_CTRL, (long)&control, 0, 0, 0) != -EINVAL,
        "ZCRX_EXPORT_RESERVED_VALIDATION_FAIL\n");
    memset(control.operation_data, 0, sizeof(control.operation_data));
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, origin.descriptor,
        IORING_REGISTER_ZCRX_CTRL, (long)&control, 0, 0, 0) != 0,
        "ZCRX_EXPORT_FAIL\n");
    export_descriptor = (int32_t)(uint32_t)control.operation_data[0];
    failures += record_failure(
        export_descriptor < 0, "ZCRX_EXPORT_DESCRIPTOR_FAIL\n");
    if (failures) goto done;

    memset(&imported_registration, 0, sizeof(imported_registration));
    imported_registration.interface_index = UINT32_MAX;
    imported_registration.receive_queue = 1u;
    imported_registration.flags = ZCRX_REG_IMPORT;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, imported.descriptor,
        IORING_REGISTER_ZCRX_IFQ, (long)&imported_registration,
        1, 0, 0) != -EINVAL,
        "ZCRX_IMPORT_VALIDATION_ORDER_FAIL\n");
    imported_registration.receive_queue = 0u;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, imported.descriptor,
        IORING_REGISTER_ZCRX_IFQ, (long)&imported_registration,
        1, 0, 0) != -EBADF,
        "ZCRX_IMPORT_BAD_DESCRIPTOR_FAIL\n");

    imported_registration.interface_index = (uint32_t)export_descriptor;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, imported.descriptor,
        IORING_REGISTER_ZCRX_IFQ, (long)&imported_registration,
        1, 0, 0) != 0,
        "ZCRX_IMPORT_FAIL\n");
    failures += record_failure(
        imported_registration.offsets.head != registration.offsets.head ||
        imported_registration.offsets.tail != registration.offsets.tail ||
        imported_registration.offsets.rqes != registration.offsets.rqes,
        "ZCRX_IMPORT_OUTPUT_FAIL\n");
    if (failures) goto done;

    origin_region = map_memory(
        origin.descriptor, region.mmap_offset, MAP_SHARED);
    imported_region = map_memory(
        imported.descriptor,
        IORING_OFF_ZCRX_REGION +
            ((uint64_t)imported_registration.zcrx_id <<
             IORING_OFF_ZCRX_SHIFT),
        MAP_SHARED);
    failures += record_failure(
        !origin_region || !imported_region,
        "ZCRX_IMPORT_REGION_MMAP_FAIL\n");
    if (failures) goto done;

    *(volatile uint32_t *)((uint8_t *)origin_region +
        registration.offsets.tail) = 3u;
    failures += record_failure(
        *(volatile uint32_t *)((uint8_t *)imported_region +
            imported_registration.offsets.tail) != 3u,
        "ZCRX_IMPORT_REGION_SHARING_FAIL\n");
    *(volatile uint32_t *)((uint8_t *)imported_region +
        imported_registration.offsets.tail) = 0u;

    (void)raw_syscall6(
        SYS_munmap, (long)origin_region, PAGE_SIZE, 0, 0, 0, 0);
    origin_region = 0;
    ring_close(&origin);
    origin.descriptor = -1;
    (void)raw_syscall6(
        SYS_close, export_descriptor, 0, 0, 0, 0, 0);
    export_descriptor = -1;

    memset(&control, 0, sizeof(control));
    control.zcrx_id = imported_registration.zcrx_id;
    control.operation = ZCRX_CTRL_FLUSH_RQ;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, imported.descriptor,
        IORING_REGISTER_ZCRX_CTRL, (long)&control, 0, 0, 0) != 0,
        "ZCRX_IMPORT_LIFETIME_FAIL\n");

done:
    if (origin_region)
        (void)raw_syscall6(
            SYS_munmap, (long)origin_region, PAGE_SIZE, 0, 0, 0, 0);
    if (imported_region)
        (void)raw_syscall6(
            SYS_munmap, (long)imported_region, PAGE_SIZE, 0, 0, 0, 0);
    if (export_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, export_descriptor, 0, 0, 0, 0, 0);
    ring_close(&imported);
    ring_close(&origin);
    return failures;
}

ENTRY_ALIGNMENT void _start(void) {
    int failures = 0;

    failures += record_failure(
        test_required_setup_flags(), "ZCRX_SETUP_VALIDATION_FAIL\n");
    failures += test_receive(ZCRX_REG_NODEV, 0u, 0);
    failures += test_device_validation();
    failures += test_receive(0u, 2u, 1);
    failures += test_export_import();
    print_text(failures ? "io-uring-zcrx: FAIL\n" :
                          "io-uring-zcrx: PASS\n");
    (void)raw_syscall6(
        SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
