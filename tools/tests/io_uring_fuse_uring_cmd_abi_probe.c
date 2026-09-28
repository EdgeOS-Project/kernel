/* SPDX-License-Identifier: MPL-2.0 */
/* Linux FUSE io_uring transport ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_ioctl 16
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_newfstatat 262
#define SYS_openat 257
#define SYS_mkdir 83
#define SYS_mount 165
#define SYS_umount2 166
#define SYS_fork 57
#define SYS_wait4 61
#define SYS_exit 60
#define SYS_sched_yield 24
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_ioctl 29
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_wait4 260
#define SYS_clone 220
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_umount2 39
#define SYS_newfstatat 79
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_openat 56
#define SYS_sched_yield 124
#else
#error "io_uring_fuse_uring_cmd_abi_probe requires a 64-bit Linux ABI"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426

#define AT_FDCWD -100
#define O_RDWR 2u
#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define SIGCHLD 17
#define ENOENT 2
#define EINVAL 22
#define FUSE_INIT 26u
#define FUSE_LOOKUP 1u
#define FUSE_HEADER_LENGTH 288u
#define FUSE_PAYLOAD_LENGTH 65536u
#define FUSE_RING_HEADER_OFFSET 256u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_SETUP_SQE128 (1u << 10)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_URING_CMD 46u
#define FUSE_IO_URING_CMD_REGISTER 1u
#define FUSE_IO_URING_CMD_COMMIT_AND_FETCH 2u
#define FUSE_OVER_IO_URING (1ULL << 41)
#define FUSE_MAX_PAGES (1u << 22)
#define FUSE_INIT_EXT (1u << 30)
#define FUSE_DEV_IOC_SYNC_INIT 0x0000e503u

struct user_iovec {
    uint64_t base;
    uint64_t length;
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

struct fuse_uring_cmd_req {
    uint64_t flags;
    uint64_t commit_id;
    uint16_t qid;
    uint8_t padding[6];
};

struct fuse_uring_ent_in_out {
    uint64_t flags;
    uint64_t commit_id;
    uint32_t payload_size;
    uint32_t padding;
    uint64_t reserved;
};

struct io_uring_cqe {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
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

struct ring {
    long descriptor;
    struct io_uring_params parameters;
    void *sq_ring;
    void *cq_ring;
    void *sqes;
    uint32_t sqe_stride;
};

struct fuse_in_header {
    uint32_t length;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};

struct fuse_out_header {
    uint32_t length;
    int32_t error;
    uint64_t unique;
};

struct fuse_init_out {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint16_t max_background;
    uint16_t congestion_threshold;
    uint32_t max_write;
    uint32_t time_granularity;
    uint16_t max_pages;
    uint16_t map_alignment;
    uint32_t flags2;
    uint32_t unused[7];
};

static uint8_t headers[FUSE_HEADER_LENGTH] __attribute__((aligned(PAGE_SIZE)));
static uint8_t payload[FUSE_PAYLOAD_LENGTH] __attribute__((aligned(PAGE_SIZE)));
static uint8_t headers_qid1[FUSE_HEADER_LENGTH]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t payload_qid1[FUSE_PAYLOAD_LENGTH]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t init_request[8192] __attribute__((aligned(PAGE_SIZE)));

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
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned long length) {
    unsigned char *output = destination;
    const unsigned char *input = source;
    for (unsigned long index = 0; index < length; ++index)
        output[index] = input[index];
    return destination;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char buffer[32];
    unsigned long magnitude;
    unsigned long length = 0;

    if (value < 0) {
        buffer[length++] = '-';
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    {
        unsigned long start = length;
        do {
            buffer[length++] = (char)('0' + magnitude % 10u);
            magnitude /= 10u;
        } while (magnitude);
        for (unsigned long left = start, right = length - 1u;
             left < right; ++left, --right) {
            char temporary = buffer[left];
            buffer[left] = buffer[right];
            buffer[right] = temporary;
        }
    }
    buffer[length++] = '\n';
    (void)raw_syscall6(SYS_write, 1, (long)buffer, (long)length, 0, 0, 0);
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 :
        (void *)(uintptr_t)result;
}

static int ring_open(struct ring *ring, uint32_t flags) {
    memset(ring, 0, sizeof(*ring));
    ring->descriptor = -1;
    ring->parameters.flags = flags;
    ring->descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&ring->parameters, 0, 0, 0, 0);
    if (ring->descriptor < 0) return 1;
    ring->sq_ring = map_ring(ring->descriptor, IORING_OFF_SQ_RING);
    ring->cq_ring = map_ring(ring->descriptor, IORING_OFF_CQ_RING);
    ring->sqes = map_ring(ring->descriptor, IORING_OFF_SQES);
    ring->sqe_stride = flags & IORING_SETUP_SQE128 ? 128u : 64u;
    return !ring->sq_ring || !ring->cq_ring || !ring->sqes;
}

static void ring_close(struct ring *ring) {
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
        (void)raw_syscall6(SYS_close, ring->descriptor, 0, 0, 0, 0, 0);
}

static int ring_submit(struct ring *ring, long fuse_descriptor,
                       uint32_t operation, uint64_t commit_id,
                       uint16_t qid, uint64_t user_data,
                       uint32_t header_length, int wait,
                       int32_t *completion_result) {
    volatile uint32_t *sq_tail = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.tail);
    volatile uint32_t *sq_mask = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.ring_mask);
    volatile uint32_t *sq_array = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.array);
    volatile uint32_t *cq_head = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.head);
    volatile uint32_t *cq_tail = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.tail);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.cqes);
    struct user_iovec vectors[2];
    struct io_uring_sqe *submission;
    struct fuse_uring_cmd_req *command;
    uint8_t *command_headers = qid == 1u ? headers_qid1 : headers;
    uint8_t *command_payload = qid == 1u ? payload_qid1 : payload;
    uint32_t tail = *sq_tail;
    uint32_t index = tail & *sq_mask;
    long result;

    vectors[0].base = (uint64_t)(uintptr_t)command_headers;
    vectors[0].length = header_length;
    vectors[1].base = (uint64_t)(uintptr_t)command_payload;
    vectors[1].length = FUSE_PAYLOAD_LENGTH;
    memset((uint8_t *)ring->sqes +
           (uint64_t)index * ring->sqe_stride, 0, ring->sqe_stride);
    submission = (struct io_uring_sqe *)((uint8_t *)ring->sqes +
        (uint64_t)index * ring->sqe_stride);
    submission->opcode = IORING_OP_URING_CMD;
    submission->descriptor = (int32_t)fuse_descriptor;
    submission->offset = operation;
    submission->address = (uint64_t)(uintptr_t)vectors;
    submission->length = 2u;
    submission->user_data = user_data;
    command = (struct fuse_uring_cmd_req *)((uint8_t *)submission + 48u);
    command->commit_id = commit_id;
    command->qid = qid;
    sq_array[index] = index;
    __atomic_store_n(sq_tail, tail + 1u, __ATOMIC_RELEASE);
    result = raw_syscall6(
        SYS_io_uring_enter, ring->descriptor, 1, wait ? 1 : 0,
        wait ? IORING_ENTER_GETEVENTS : 0, 0, 0);
    if (result != 1) return 1;
    if (!wait) return 0;
    if (*cq_head == *cq_tail) return 1;
    index = *cq_head & (ring->parameters.cq_entries - 1u);
    if (cqes[index].user_data != user_data) return 1;
    *completion_result = cqes[index].result;
    __atomic_store_n(cq_head, *cq_head + 1u, __ATOMIC_RELEASE);
    return 0;
}

static int write_init_reply(long descriptor,
                            const struct fuse_in_header *request) {
    struct {
        struct fuse_out_header header;
        struct fuse_init_out payload;
    } reply;

    memset(&reply, 0, sizeof(reply));
    reply.header.length = sizeof(reply);
    reply.header.unique = request->unique;
    reply.payload.major = 7u;
    reply.payload.minor = 45u;
    reply.payload.flags = FUSE_MAX_PAGES | FUSE_INIT_EXT;
    reply.payload.max_write = FUSE_PAYLOAD_LENGTH;
    reply.payload.max_pages = FUSE_PAYLOAD_LENGTH / PAGE_SIZE;
    reply.payload.flags2 = (uint32_t)(FUSE_OVER_IO_URING >> 32);
    {
        long result = raw_syscall6(
            SYS_write, descriptor, (long)&reply,
            sizeof(reply), 0, 0, 0);
        if (result != (long)sizeof(reply)) {
            print_text("io-uring-fuse: init write failed: ");
            print_number(result);
            return 1;
        }
    }
    return 0;
}

static int daemon_main(long fuse_descriptor) {
    struct fuse_in_header *request;
    struct fuse_out_header *reply;
    struct fuse_uring_ent_in_out *ring_header;
    struct ring ring;
    uint8_t *request_headers = headers;
    uint16_t request_qid = 0u;
    long read_result;
    uint64_t request_unique;
    int32_t completion = 0;

    print_text("io-uring-fuse: daemon waiting init\n");
    for (;;) {
        read_result = raw_syscall6(
            SYS_read, fuse_descriptor, (long)init_request,
            sizeof(init_request), 0, 0, 0);
        if (read_result != -1) break;
        (void)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    if (read_result < (long)sizeof(*request)) {
        print_text("io-uring-fuse: init read failed: ");
        print_number(read_result);
        return 10;
    }
    request = (struct fuse_in_header *)init_request;
    if (request->opcode != FUSE_INIT ||
        request->length != (uint32_t)read_result) {
        print_text("io-uring-fuse: unexpected init length: ");
        print_number(read_result);
        print_text("io-uring-fuse: unexpected init opcode: ");
        print_number(request->opcode);
        return 11;
    }
    print_text("io-uring-fuse: init flags low: ");
    print_number(*(const uint32_t *)(init_request +
        sizeof(struct fuse_in_header) + 12u));
    print_text("io-uring-fuse: init flags high: ");
    print_number(*(const uint32_t *)(init_request +
        sizeof(struct fuse_in_header) + 16u));
    if (write_init_reply(fuse_descriptor, request)) return 12;
    print_text("io-uring-fuse: init replied\n");

    if (ring_open(&ring, 0u)) return 13;
    if (ring_submit(&ring, fuse_descriptor,
                    FUSE_IO_URING_CMD_REGISTER, 0u, 0u, 1u,
                    FUSE_HEADER_LENGTH, 1, &completion) ||
        completion != -EINVAL) {
        ring_close(&ring);
        return 14;
    }
    print_text("io-uring-fuse: non-sqe128 rejected\n");
    ring_close(&ring);

    if (ring_open(&ring, IORING_SETUP_SQE128)) return 15;
    if (ring_submit(&ring, fuse_descriptor,
                    FUSE_IO_URING_CMD_REGISTER, 0u, 0xffffu, 2u,
                    FUSE_HEADER_LENGTH, 1, &completion) ||
        completion != -EINVAL) {
        ring_close(&ring);
        return 16;
    }
    print_text("io-uring-fuse: invalid qid rejected\n");
    if (ring_submit(&ring, fuse_descriptor,
                    FUSE_IO_URING_CMD_REGISTER, 0u, 0u, 3u,
                    FUSE_HEADER_LENGTH - 1u, 1, &completion) ||
        completion != -EINVAL) {
        ring_close(&ring);
        return 17;
    }
    print_text("io-uring-fuse: short header rejected\n");
    if (ring_submit(&ring, fuse_descriptor,
                    FUSE_IO_URING_CMD_REGISTER, 0u, 1u, 4u,
                    FUSE_HEADER_LENGTH, 0, &completion)) {
        ring_close(&ring);
        return 18;
    }
    print_text("io-uring-fuse: waiting ring request\n");
    if (ring_submit(&ring, fuse_descriptor,
                    FUSE_IO_URING_CMD_REGISTER, 0u, 0u, 5u,
                    FUSE_HEADER_LENGTH, 0, &completion)) {
        ring_close(&ring);
        return 19;
    }
    if (raw_syscall6(
            SYS_io_uring_enter, ring.descriptor, 0, 1,
            IORING_ENTER_GETEVENTS, 0, 0) < 0) {
        ring_close(&ring);
        return 19;
    }
    {
        volatile uint32_t *cq_head = (volatile uint32_t *)(
            (uint8_t *)ring.cq_ring + ring.parameters.cq_off.head);
        volatile uint32_t *cq_tail = (volatile uint32_t *)(
            (uint8_t *)ring.cq_ring + ring.parameters.cq_off.tail);
        struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
            (uint8_t *)ring.cq_ring + ring.parameters.cq_off.cqes);
        uint32_t cqe_index;

        if (*cq_head == *cq_tail) {
            ring_close(&ring);
            return 19;
        }
        cqe_index = *cq_head & (ring.parameters.cq_entries - 1u);
        if (cqes[cqe_index].result != 0 ||
            (cqes[cqe_index].user_data != 4u &&
             cqes[cqe_index].user_data != 5u)) {
            ring_close(&ring);
            return 19;
        }
        if (cqes[cqe_index].user_data == 4u) {
            request_headers = headers_qid1;
            request_qid = 1u;
        }
        __atomic_store_n(cq_head, *cq_head + 1u, __ATOMIC_RELEASE);
    }
    print_text("io-uring-fuse: ring request received\n");
    request = (struct fuse_in_header *)request_headers;
    ring_header = (struct fuse_uring_ent_in_out *)(
        request_headers + FUSE_RING_HEADER_OFFSET);
    if (request->opcode != FUSE_LOOKUP || !request->unique ||
        ring_header->commit_id != request->unique ||
        ring_header->payload_size == 0u) {
        ring_close(&ring);
        return 20;
    }
    request_unique = request->unique;
    memset(request_headers, 0, FUSE_HEADER_LENGTH);
    reply = (struct fuse_out_header *)request_headers;
    reply->length = sizeof(*reply);
    reply->error = -ENOENT;
    reply->unique = request_unique;
    ring_header = (struct fuse_uring_ent_in_out *)(
        request_headers + FUSE_RING_HEADER_OFFSET);
    ring_header->commit_id = request_unique;
    if (ring_submit(&ring, fuse_descriptor,
                    FUSE_IO_URING_CMD_COMMIT_AND_FETCH,
                    request_unique, request_qid, 6u,
                    FUSE_HEADER_LENGTH, 0, &completion)) {
        ring_close(&ring);
        return 21;
    }
    print_text("io-uring-fuse: reply committed\n");
    ring_close(&ring);
    return 0;
}

static long spawn(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static int make_mount_options(char *buffer, unsigned long capacity,
                              long descriptor) {
    static const char prefix[] =
        "fd=,rootmode=40000,user_id=0,group_id=0";
    char digits[24];
    unsigned long prefix_length = text_length(prefix);
    unsigned long count = 0;
    unsigned long output = 3u;
    unsigned long value = (unsigned long)descriptor;

    if (prefix_length + 24u >= capacity) return 1;
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    buffer[0] = 'f';
    buffer[1] = 'd';
    buffer[2] = '=';
    while (count) buffer[output++] = digits[--count];
    for (unsigned long index = 3u; prefix[index]; ++index)
        buffer[output++] = prefix[index];
    buffer[output] = 0;
    return 0;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
int main(void) {
    static const char device[] = "/dev/fuse";
    static const char mount_root[] = "/mnt";
    static const char mountpoint[] = "/mnt/fuse-uring";
    static const char missing[] = "/mnt/fuse-uring/missing";
    static const char source[] = "edge-fuse-uring";
    static const char filesystem[] = "fuse.edge-fuse-uring";
    uint8_t status_buffer[256];
    char options[96];
    long descriptor;
    long child;
    int child_status = -1;
    int failures = 0;

#if defined(__x86_64__)
    (void)raw_syscall6(SYS_mkdir, (long)mount_root, 0755, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_mkdir, (long)mountpoint, 0755, 0, 0, 0, 0);
#else
    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)mount_root, 0755, 0, 0, 0);
    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)mountpoint, 0755, 0, 0, 0);
#endif
    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)device, O_RDWR, 0, 0, 0);
    if (descriptor < 0 || make_mount_options(
            options, sizeof(options), descriptor)) {
        print_text("io-uring-fuse: device setup failed\n");
        return 1;
    }
    if (raw_syscall6(
            SYS_ioctl, descriptor, FUSE_DEV_IOC_SYNC_INIT,
            0, 0, 0, 0) != 0) {
        print_text("io-uring-fuse: sync init ioctl failed\n");
        return 1;
    }
    child = spawn();
    if (child < 0) return 1;
    if (child == 0) {
        int result = 0;

        print_text("io-uring-fuse: mounter mounting\n");
        if (raw_syscall6(
                SYS_mount, (long)source, (long)mountpoint,
                (long)filesystem, 0, (long)options, 0) != 0) {
            result = 1;
        } else {
            long lookup_result;

            print_text("io-uring-fuse: mounter mounted\n");
            lookup_result = raw_syscall6(
                SYS_newfstatat, AT_FDCWD, (long)missing,
                (long)status_buffer, 0, 0, 0);
            if (lookup_result != -ENOENT) result = 1;
            print_text("io-uring-fuse: mounter lookup returned\n");
            (void)raw_syscall6(
                SYS_umount2, (long)mountpoint, 0, 0, 0, 0, 0);
        }
        (void)raw_syscall6(SYS_exit, result, 0, 0, 0, 0, 0);
        for (;;) { }
    }
    failures = daemon_main(descriptor);
    if (failures) {
        print_text("io-uring-fuse: daemon result: ");
        print_number(failures);
    }
    if (raw_syscall6(
            SYS_wait4, child, (long)&child_status, 0, 0, 0, 0) != child ||
        child_status != 0)
        failures = 1;
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    print_text(failures ? "io-uring-fuse: FAIL\n" :
                          "io-uring-fuse: PASS\n");
    return failures;
}

__attribute__((noreturn))
#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int result = main();
    (void)raw_syscall6(SYS_exit, result, 0, 0, 0, 0, 0);
    for (;;) { }
}
