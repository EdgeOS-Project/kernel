/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux packet-socket implementation.
 * Copyright (c) EdgeOS Contributors.
 *
 * This file owns the architecture-independent Linux AF_PACKET policy used by
 * every EdgeOS architecture.  Architecture code supplies only physical-page
 * allocation and user page-table mapping for PACKET_RX_RING mmap(2).
 */

#include "kernel/linux_packet.h"

#include "kernel/runtime_limits.h"
#include "net/network_core.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"

#define EDGE_PACKET_PAGE_SIZE 4096u
#define EDGE_PACKET_ALIGNMENT 16u
#define EDGE_PACKET_RING_TOTAL_PAGES 16384u
#define EDGE_PACKET_MEMBERSHIP_MAX 16u

#define EDGE_PACKET_EINVAL 22
#define EDGE_PACKET_ENOMEM 12
#define EDGE_PACKET_EBUSY 16
#define EDGE_PACKET_ENODEV 19
#define EDGE_PACKET_ENOSPC 28
#define EDGE_PACKET_EMSGSIZE 90
#define EDGE_PACKET_ENOPROTOOPT 92
#define EDGE_PACKET_EOPNOTSUPP 95
#define EDGE_PACKET_EADDRINUSE 98
#define EDGE_PACKET_ENETDOWN 100
#define EDGE_PACKET_ENOBUFS 105

#define EDGE_BPF_LD 0x00u
#define EDGE_BPF_LDX 0x01u
#define EDGE_BPF_ST 0x02u
#define EDGE_BPF_STX 0x03u
#define EDGE_BPF_ALU 0x04u
#define EDGE_BPF_JMP 0x05u
#define EDGE_BPF_RET 0x06u
#define EDGE_BPF_MISC 0x07u
#define EDGE_BPF_W 0x00u
#define EDGE_BPF_H 0x08u
#define EDGE_BPF_B 0x10u
#define EDGE_BPF_IMM 0x00u
#define EDGE_BPF_ABS 0x20u
#define EDGE_BPF_IND 0x40u
#define EDGE_BPF_MEM 0x60u
#define EDGE_BPF_LEN 0x80u
#define EDGE_BPF_MSH 0xa0u
#define EDGE_BPF_ADD 0x00u
#define EDGE_BPF_SUB 0x10u
#define EDGE_BPF_MUL 0x20u
#define EDGE_BPF_DIV 0x30u
#define EDGE_BPF_OR 0x40u
#define EDGE_BPF_AND 0x50u
#define EDGE_BPF_LSH 0x60u
#define EDGE_BPF_RSH 0x70u
#define EDGE_BPF_NEG 0x80u
#define EDGE_BPF_MOD 0x90u
#define EDGE_BPF_XOR 0xa0u
#define EDGE_BPF_JA 0x00u
#define EDGE_BPF_JEQ 0x10u
#define EDGE_BPF_JGT 0x20u
#define EDGE_BPF_JGE 0x30u
#define EDGE_BPF_JSET 0x40u
#define EDGE_BPF_K 0x00u
#define EDGE_BPF_X 0x08u
#define EDGE_BPF_A 0x10u
#define EDGE_BPF_TAX 0x00u
#define EDGE_BPF_TXA 0x80u
#define EDGE_BPF_CLASS(code) ((code) & 0x07u)
#define EDGE_BPF_SIZE(code) ((code) & 0x18u)
#define EDGE_BPF_MODE(code) ((code) & 0xe0u)
#define EDGE_BPF_OP(code) ((code) & 0xf0u)
#define EDGE_BPF_SRC(code) ((code) & 0x08u)
#define EDGE_BPF_RVAL(code) ((code) & 0x18u)

struct edge_packet_ring_page {
    void *kernel_address;
    uint64_t mapping_cookie;
    uint8_t used;
};

struct edge_packet_membership {
    uint8_t used;
    struct edge_linux_packet_mreq request;
};

struct edge_packet_ring {
    uint32_t page_base;
    uint32_t page_count;
    uint32_t block_size;
    uint32_t block_count;
    uint32_t frame_size;
    uint32_t frame_count;
    uint32_t producer;
    struct edge_linux_packet_page_allocator allocator;
};

struct edge_packet_socket {
    uint8_t used;
    uint8_t socket_type;
    uint8_t tpacket_version;
    uint8_t auxdata;
    uint8_t loss;
    uint8_t qdisc_bypass;
    uint8_t ignore_outgoing;
    uint16_t protocol;
    int32_t ifindex;
    uint32_t network_namespace;
    uint32_t reserve;
    uint32_t statistics_packets;
    uint32_t statistics_drops;
    uint64_t ring_readiness_sequence;
    uint16_t filter_length;
    struct edge_linux_sock_filter filter[EDGE_LINUX_PACKET_FILTER_MAX];
    struct edge_packet_membership memberships[EDGE_PACKET_MEMBERSHIP_MAX];
    struct edge_packet_ring ring;
};

static spinlock_t g_packet_lock;
static struct edge_packet_socket g_packet_sockets[EDGE_RUNTIME_MAX_SOCKETS];
static struct edge_packet_ring_page
    g_packet_ring_pages[EDGE_PACKET_RING_TOTAL_PAGES];
static uint32_t g_packet_capture_count;
static uint64_t g_packet_readiness_sequence = 1u;

/*
 * Zero is reserved for an invalid handle.  Capture generations therefore
 * start at one and wrap to one after the largest 64-bit value.
 */
static void packet_readiness_sequence_advance(uint64_t *sequence) {
    uint64_t current;

    current = __atomic_load_n(sequence, __ATOMIC_RELAXED);
    for (;;) {
        uint64_t next = current + 1u;

        if (!next) next = 1u;
        if (__atomic_compare_exchange_n(sequence, &current, next, 0,
                                        __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED))
            return;
    }
}

static uint32_t packet_align(uint32_t value) {
    return (value + EDGE_PACKET_ALIGNMENT - 1u) &
           ~(EDGE_PACKET_ALIGNMENT - 1u);
}

static uint16_t packet_bswap16(uint16_t value) {
    return (uint16_t)((value << 8) | (value >> 8));
}

static struct edge_packet_socket *packet_socket_locked(int handle) {
    if (handle < 0 || handle >= (int)EDGE_RUNTIME_MAX_SOCKETS ||
        !g_packet_sockets[handle].used)
        return 0;
    return &g_packet_sockets[handle];
}

static int packet_bpf_read_contiguous(void *context, uint32_t offset,
                                      uint32_t size, uint32_t *value) {
    const uint8_t *packet = (const uint8_t *)context;
    if (!packet || !value) return -1;
    if (size == 4u) {
        *value = ((uint32_t)packet[offset] << 24) |
                 ((uint32_t)packet[offset + 1u] << 16) |
                 ((uint32_t)packet[offset + 2u] << 8) |
                 (uint32_t)packet[offset + 3u];
        return 0;
    }
    if (size == 2u) {
        *value = ((uint32_t)packet[offset] << 8) |
                 (uint32_t)packet[offset + 1u];
        return 0;
    }
    if (size == 1u) {
        *value = packet[offset];
        return 0;
    }
    return -1;
}

static int packet_bpf_load(edge_linux_bpf_load_fn load, void *context,
                           uint32_t packet_length, uint32_t offset,
                           uint32_t size, uint32_t *value) {
    if (!load || !value || offset > packet_length ||
        size > packet_length - offset)
        return -1;
    return load(context, offset, size, value);
}

int edge_linux_bpf_validate(const struct edge_linux_sock_filter *program,
                            uint32_t program_length) {
    int has_return = 0;

    if (!program || program_length == 0u ||
        program_length > EDGE_LINUX_PACKET_FILTER_MAX)
        return 0;
    for (uint32_t pc = 0; pc < program_length; ++pc) {
        uint16_t code = program[pc].code;
        uint16_t class = EDGE_BPF_CLASS(code);
        uint16_t mode = EDGE_BPF_MODE(code);
        uint16_t operation = EDGE_BPF_OP(code);
        uint16_t source = EDGE_BPF_SRC(code);

        switch (class) {
            case EDGE_BPF_LD:
                if (!(mode == EDGE_BPF_IMM || mode == EDGE_BPF_ABS ||
                      mode == EDGE_BPF_IND || mode == EDGE_BPF_MEM ||
                      mode == EDGE_BPF_LEN))
                    return 0;
                if ((mode == EDGE_BPF_ABS || mode == EDGE_BPF_IND) &&
                    !(EDGE_BPF_SIZE(code) == EDGE_BPF_W ||
                      EDGE_BPF_SIZE(code) == EDGE_BPF_H ||
                      EDGE_BPF_SIZE(code) == EDGE_BPF_B))
                    return 0;
                if (mode == EDGE_BPF_MEM && program[pc].k >= 16u) return 0;
                break;
            case EDGE_BPF_LDX:
                if (!(mode == EDGE_BPF_IMM ||
                      (mode == EDGE_BPF_MEM && program[pc].k < 16u) ||
                      mode == EDGE_BPF_LEN ||
                      (mode == EDGE_BPF_MSH &&
                       EDGE_BPF_SIZE(code) == EDGE_BPF_B)))
                    return 0;
                break;
            case EDGE_BPF_ST:
            case EDGE_BPF_STX:
                if (program[pc].k >= 16u) return 0;
                break;
            case EDGE_BPF_ALU:
                if (!(source == EDGE_BPF_K || source == EDGE_BPF_X)) return 0;
                if (!(operation == EDGE_BPF_ADD || operation == EDGE_BPF_SUB ||
                      operation == EDGE_BPF_MUL || operation == EDGE_BPF_DIV ||
                      operation == EDGE_BPF_OR || operation == EDGE_BPF_AND ||
                      operation == EDGE_BPF_LSH || operation == EDGE_BPF_RSH ||
                      operation == EDGE_BPF_NEG || operation == EDGE_BPF_MOD ||
                      operation == EDGE_BPF_XOR))
                    return 0;
                if ((operation == EDGE_BPF_DIV || operation == EDGE_BPF_MOD) &&
                    source == EDGE_BPF_K && program[pc].k == 0u)
                    return 0;
                break;
            case EDGE_BPF_JMP:
                if (operation == EDGE_BPF_JA) {
                    if (pc + 1u >= program_length ||
                        program[pc].k >= program_length - pc - 1u)
                        return 0;
                } else if (operation == EDGE_BPF_JEQ ||
                           operation == EDGE_BPF_JGT ||
                           operation == EDGE_BPF_JGE ||
                           operation == EDGE_BPF_JSET) {
                    if (!(source == EDGE_BPF_K || source == EDGE_BPF_X)) return 0;
                    if (pc + 1u + program[pc].jt >= program_length ||
                        pc + 1u + program[pc].jf >= program_length)
                        return 0;
                } else {
                    return 0;
                }
                break;
            case EDGE_BPF_RET:
                if (!(EDGE_BPF_RVAL(code) == EDGE_BPF_K ||
                      EDGE_BPF_RVAL(code) == EDGE_BPF_A))
                    return 0;
                has_return = 1;
                break;
            case EDGE_BPF_MISC:
                if (!(operation == EDGE_BPF_TAX || operation == EDGE_BPF_TXA))
                    return 0;
                break;
            default:
                return 0;
        }
    }
    return has_return;
}

uint32_t edge_linux_bpf_run_reader(
    const struct edge_linux_sock_filter *program, uint32_t program_length,
    uint32_t packet_length, edge_linux_bpf_load_fn load, void *context) {
    uint32_t accumulator = 0;
    uint32_t index_register = 0;
    uint32_t memory[16];

    if (!program || program_length == 0u) return packet_length;
    memset(memory, 0, sizeof(memory));
    for (uint32_t pc = 0; pc < program_length; ++pc) {
        const struct edge_linux_sock_filter *instruction = &program[pc];
        uint16_t code = instruction->code;
        uint32_t constant = instruction->k;
        uint32_t value = 0;
        uint32_t source;

        switch (EDGE_BPF_CLASS(code)) {
            case EDGE_BPF_LD:
                switch (EDGE_BPF_MODE(code)) {
                    case EDGE_BPF_IMM:
                        accumulator = constant;
                        break;
                    case EDGE_BPF_ABS:
                        if (packet_bpf_load(
                                load, context, packet_length, constant,
                                EDGE_BPF_SIZE(code) == EDGE_BPF_W ? 4u :
                                EDGE_BPF_SIZE(code) == EDGE_BPF_H ? 2u : 1u,
                                &accumulator) < 0)
                            return 0;
                        break;
                    case EDGE_BPF_IND:
                        if (packet_bpf_load(
                                load, context, packet_length,
                                index_register + constant,
                                EDGE_BPF_SIZE(code) == EDGE_BPF_W ? 4u :
                                EDGE_BPF_SIZE(code) == EDGE_BPF_H ? 2u : 1u,
                                &accumulator) < 0)
                            return 0;
                        break;
                    case EDGE_BPF_MEM:
                        accumulator = memory[constant];
                        break;
                    case EDGE_BPF_LEN:
                        accumulator = packet_length;
                        break;
                    default:
                        return 0;
                }
                break;
            case EDGE_BPF_LDX:
                switch (EDGE_BPF_MODE(code)) {
                    case EDGE_BPF_IMM:
                        index_register = constant;
                        break;
                    case EDGE_BPF_MEM:
                        index_register = memory[constant];
                        break;
                    case EDGE_BPF_LEN:
                        index_register = packet_length;
                        break;
                    case EDGE_BPF_MSH:
                        if (packet_bpf_load(load, context, packet_length,
                                           constant, 1u, &value) < 0)
                            return 0;
                        index_register = (value & 0x0fu) << 2;
                        break;
                    default:
                        return 0;
                }
                break;
            case EDGE_BPF_ST:
                memory[constant] = accumulator;
                break;
            case EDGE_BPF_STX:
                memory[constant] = index_register;
                break;
            case EDGE_BPF_ALU:
                source = EDGE_BPF_SRC(code) == EDGE_BPF_X ?
                         index_register : constant;
                switch (EDGE_BPF_OP(code)) {
                    case EDGE_BPF_ADD: accumulator += source; break;
                    case EDGE_BPF_SUB: accumulator -= source; break;
                    case EDGE_BPF_MUL: accumulator *= source; break;
                    case EDGE_BPF_DIV:
                        if (!source) return 0;
                        accumulator /= source;
                        break;
                    case EDGE_BPF_OR: accumulator |= source; break;
                    case EDGE_BPF_AND: accumulator &= source; break;
                    case EDGE_BPF_LSH: accumulator <<= source & 31u; break;
                    case EDGE_BPF_RSH: accumulator >>= source & 31u; break;
                    case EDGE_BPF_NEG: accumulator = 0u - accumulator; break;
                    case EDGE_BPF_MOD:
                        if (!source) return 0;
                        accumulator %= source;
                        break;
                    case EDGE_BPF_XOR: accumulator ^= source; break;
                    default: return 0;
                }
                break;
            case EDGE_BPF_JMP:
                source = EDGE_BPF_SRC(code) == EDGE_BPF_X ?
                         index_register : constant;
                switch (EDGE_BPF_OP(code)) {
                    case EDGE_BPF_JA: pc += constant; break;
                    case EDGE_BPF_JEQ:
                        pc += accumulator == source ?
                              instruction->jt : instruction->jf;
                        break;
                    case EDGE_BPF_JGT:
                        pc += accumulator > source ?
                              instruction->jt : instruction->jf;
                        break;
                    case EDGE_BPF_JGE:
                        pc += accumulator >= source ?
                              instruction->jt : instruction->jf;
                        break;
                    case EDGE_BPF_JSET:
                        pc += (accumulator & source) ?
                              instruction->jt : instruction->jf;
                        break;
                    default: return 0;
                }
                break;
            case EDGE_BPF_RET:
                return EDGE_BPF_RVAL(code) == EDGE_BPF_A ?
                       accumulator : constant;
            case EDGE_BPF_MISC:
                if (EDGE_BPF_OP(code) == EDGE_BPF_TAX)
                    index_register = accumulator;
                else if (EDGE_BPF_OP(code) == EDGE_BPF_TXA)
                    accumulator = index_register;
                else
                    return 0;
                break;
            default:
                return 0;
        }
    }
    return 0;
}

uint32_t edge_linux_bpf_run(const struct edge_linux_sock_filter *program,
                            uint32_t program_length, const uint8_t *packet,
                            uint32_t packet_length) {
    return edge_linux_bpf_run_reader(
        program, program_length, packet_length,
        packet_bpf_read_contiguous, (void *)(uintptr_t)packet);
}

static void packet_ring_release_locked(struct edge_packet_socket *socket) {
    struct edge_packet_ring *ring;

    if (!socket) return;
    ring = &socket->ring;
    if (ring->page_count)
        __atomic_fetch_sub(&g_packet_capture_count, 1u, __ATOMIC_RELEASE);
    if (ring->page_count && ring->allocator.release) {
        for (uint32_t page = 0; page < ring->page_count; ++page) {
            struct edge_packet_ring_page *entry =
                &g_packet_ring_pages[ring->page_base + page];
            if (entry->used)
                ring->allocator.release(ring->allocator.context,
                                        entry->kernel_address,
                                        entry->mapping_cookie);
            memset(entry, 0, sizeof(*entry));
        }
    }
    memset(ring, 0, sizeof(*ring));
}

static int packet_ring_find_pages_locked(uint32_t page_count,
                                         uint32_t *base_out) {
    uint32_t run = 0;
    uint32_t start = 0;

    if (!page_count || page_count > EDGE_PACKET_RING_TOTAL_PAGES || !base_out)
        return -EDGE_PACKET_ENOMEM;
    for (uint32_t page = 0; page < EDGE_PACKET_RING_TOTAL_PAGES; ++page) {
        if (g_packet_ring_pages[page].used) {
            run = 0;
            continue;
        }
        if (!run) start = page;
        if (++run == page_count) {
            *base_out = start;
            return 0;
        }
    }
    return -EDGE_PACKET_ENOMEM;
}

static int packet_ring_configure_locked(
    struct edge_packet_socket *socket,
    const struct edge_linux_tpacket_req *request,
    const struct edge_linux_packet_page_allocator *allocator) {
    uint64_t bytes;
    uint64_t expected_frames;
    uint32_t page_count;
    uint32_t page_base;

    if (!socket || !request) return -EDGE_PACKET_EINVAL;
    if (!request->tp_block_size && !request->tp_block_nr &&
        !request->tp_frame_size && !request->tp_frame_nr) {
        packet_ring_release_locked(socket);
        return 0;
    }
    if (socket->ring.page_count) return -EDGE_PACKET_EBUSY;
    if (socket->tpacket_version != EDGE_LINUX_TPACKET_V2)
        return -EDGE_PACKET_EINVAL;
    if (!allocator || !allocator->allocate || !allocator->release)
        return -EDGE_PACKET_EINVAL;
    if (request->tp_block_size < EDGE_PACKET_PAGE_SIZE ||
        (request->tp_block_size & (EDGE_PACKET_PAGE_SIZE - 1u)) ||
        request->tp_frame_size < EDGE_PACKET_ALIGNMENT ||
        (request->tp_frame_size & (EDGE_PACKET_ALIGNMENT - 1u)) ||
        request->tp_frame_size > request->tp_block_size ||
        !request->tp_block_nr || !request->tp_frame_nr)
        return -EDGE_PACKET_EINVAL;
    expected_frames = (uint64_t)request->tp_block_nr *
                      (request->tp_block_size / request->tp_frame_size);
    if (expected_frames != request->tp_frame_nr)
        return -EDGE_PACKET_EINVAL;
    if ((uint64_t)packet_align(
            sizeof(struct edge_linux_tpacket2_hdr) +
            sizeof(struct edge_linux_sockaddr_ll)) + socket->reserve + 14u >=
        request->tp_frame_size)
        return -EDGE_PACKET_EINVAL;
    bytes = (uint64_t)request->tp_block_size * request->tp_block_nr;
    if (!bytes || bytes >
            (uint64_t)EDGE_PACKET_RING_TOTAL_PAGES * EDGE_PACKET_PAGE_SIZE ||
        (bytes & (EDGE_PACKET_PAGE_SIZE - 1u)))
        return -EDGE_PACKET_ENOMEM;
    page_count = (uint32_t)(bytes / EDGE_PACKET_PAGE_SIZE);
    if (packet_ring_find_pages_locked(page_count, &page_base) < 0)
        return -EDGE_PACKET_ENOMEM;

    for (uint32_t page = 0; page < page_count; ++page)
        g_packet_ring_pages[page_base + page].used = 1;
    for (uint32_t page = 0; page < page_count; ++page) {
        struct edge_packet_ring_page *entry =
            &g_packet_ring_pages[page_base + page];
        if (allocator->allocate(allocator->context, &entry->kernel_address,
                                &entry->mapping_cookie) < 0 ||
            !entry->kernel_address) {
            for (uint32_t release_page = 0; release_page <= page;
                 ++release_page) {
                struct edge_packet_ring_page *allocated =
                    &g_packet_ring_pages[page_base + release_page];
                if (allocated->kernel_address)
                    allocator->release(allocator->context,
                                       allocated->kernel_address,
                                       allocated->mapping_cookie);
                memset(allocated, 0, sizeof(*allocated));
            }
            for (uint32_t clear_page = page + 1u;
                 clear_page < page_count; ++clear_page)
                memset(&g_packet_ring_pages[page_base + clear_page], 0,
                       sizeof(g_packet_ring_pages[0]));
            return -EDGE_PACKET_ENOMEM;
        }
        memset(entry->kernel_address, 0, EDGE_PACKET_PAGE_SIZE);
    }

    socket->ring.page_base = page_base;
    socket->ring.page_count = page_count;
    socket->ring.block_size = request->tp_block_size;
    socket->ring.block_count = request->tp_block_nr;
    socket->ring.frame_size = request->tp_frame_size;
    socket->ring.frame_count = request->tp_frame_nr;
    socket->ring.producer = 0;
    socket->ring.allocator = *allocator;
    __atomic_fetch_add(&g_packet_capture_count, 1u, __ATOMIC_RELEASE);
    return 0;
}

static int packet_ring_copy_locked(struct edge_packet_socket *socket,
                                   uint64_t offset, const void *source,
                                   uint32_t length) {
    const uint8_t *input = (const uint8_t *)source;
    uint64_t ring_bytes;

    if (!socket || (!source && length)) return -1;
    ring_bytes = (uint64_t)socket->ring.page_count * EDGE_PACKET_PAGE_SIZE;
    if (offset > ring_bytes || length > ring_bytes - offset) return -1;
    while (length) {
        uint32_t page = (uint32_t)(offset / EDGE_PACKET_PAGE_SIZE);
        uint32_t in_page = (uint32_t)(offset & (EDGE_PACKET_PAGE_SIZE - 1u));
        uint32_t count = EDGE_PACKET_PAGE_SIZE - in_page;
        struct edge_packet_ring_page *entry =
            &g_packet_ring_pages[socket->ring.page_base + page];
        if (count > length) count = length;
        if (!entry->used || !entry->kernel_address) return -1;
        memcpy((uint8_t *)entry->kernel_address + in_page, input, count);
        input += count;
        offset += count;
        length -= count;
    }
    return 0;
}

static volatile uint32_t *packet_ring_status_locked(
    struct edge_packet_socket *socket, uint32_t frame) {
    uint64_t offset;
    uint32_t page;
    uint32_t in_page;
    struct edge_packet_ring_page *entry;

    if (!socket || frame >= socket->ring.frame_count) return 0;
    {
        uint32_t frames_per_block =
            socket->ring.block_size / socket->ring.frame_size;
        if (!frames_per_block) return 0;
        offset = (uint64_t)(frame / frames_per_block) *
                     socket->ring.block_size +
                 (uint64_t)(frame % frames_per_block) *
                     socket->ring.frame_size;
    }
    page = (uint32_t)(offset / EDGE_PACKET_PAGE_SIZE);
    in_page = (uint32_t)(offset & (EDGE_PACKET_PAGE_SIZE - 1u));
    if (page >= socket->ring.page_count ||
        in_page > EDGE_PACKET_PAGE_SIZE - sizeof(uint32_t))
        return 0;
    entry = &g_packet_ring_pages[socket->ring.page_base + page];
    if (!entry->used || !entry->kernel_address) return 0;
    return (volatile uint32_t *)((uint8_t *)entry->kernel_address + in_page);
}

static uint8_t packet_type(const uint8_t *frame, uint32_t length,
                           int outgoing) {
    if (outgoing) return EDGE_LINUX_PACKET_OUTGOING;
    if (!frame || length < 6u) return EDGE_LINUX_PACKET_HOST;
    if (frame[0] == 0xffu && frame[1] == 0xffu && frame[2] == 0xffu &&
        frame[3] == 0xffu && frame[4] == 0xffu && frame[5] == 0xffu)
        return EDGE_LINUX_PACKET_BROADCAST;
    if (frame[0] & 1u) return EDGE_LINUX_PACKET_MULTICAST;
    return EDGE_LINUX_PACKET_HOST;
}

static void packet_capture_locked(struct edge_packet_socket *socket,
                                  const uint8_t *frame, uint32_t length,
                                  int32_t ifindex, int outgoing) {
    struct edge_linux_tpacket2_hdr header;
    struct edge_linux_sockaddr_ll link;
    volatile uint32_t *status;
    uint64_t frame_offset;
    uint32_t data_offset;
    uint32_t data_capacity;
    uint32_t snapshot_length;
    uint32_t filter_result;
    uint16_t ethernet_protocol;
    uint16_t requested_protocol;
    uint64_t now;

    if (!socket || !socket->ring.page_count || !frame || length < 14u ||
        (socket->ifindex && socket->ifindex != ifindex) ||
        (outgoing && socket->ignore_outgoing))
        return;
    ethernet_protocol = (uint16_t)(((uint16_t)frame[12] << 8) | frame[13]);
    requested_protocol = packet_bswap16(socket->protocol);
    if (!requested_protocol ||
        (requested_protocol != EDGE_LINUX_ETH_P_ALL &&
         requested_protocol != ethernet_protocol))
        return;

    filter_result = socket->filter_length ?
        edge_linux_bpf_run(socket->filter, socket->filter_length,
                           frame, length) : UINT32_MAX;
    if (!filter_result) return;
    ++socket->statistics_packets;

    status = packet_ring_status_locked(socket, socket->ring.producer);
    if (!status || __atomic_load_n(status, __ATOMIC_ACQUIRE) !=
                       EDGE_LINUX_TP_STATUS_KERNEL) {
        ++socket->statistics_drops;
        return;
    }

    data_offset = packet_align(sizeof(header) + sizeof(link)) + socket->reserve;
    data_capacity = socket->ring.frame_size - data_offset;
    snapshot_length = length;
    if (snapshot_length > filter_result) snapshot_length = filter_result;
    if (snapshot_length > data_capacity) snapshot_length = data_capacity;
    {
        uint32_t frames_per_block =
            socket->ring.block_size / socket->ring.frame_size;
        frame_offset =
            (uint64_t)(socket->ring.producer / frames_per_block) *
                socket->ring.block_size +
            (uint64_t)(socket->ring.producer % frames_per_block) *
                socket->ring.frame_size;
    }
    now = boottime_realtime_us();

    memset(&header, 0, sizeof(header));
    header.tp_len = length;
    header.tp_snaplen = snapshot_length;
    header.tp_mac = (uint16_t)data_offset;
    header.tp_net = (uint16_t)(data_offset + 14u);
    header.tp_sec = (uint32_t)(now / 1000000ull);
    header.tp_nsec = (uint32_t)((now % 1000000ull) * 1000ull);

    memset(&link, 0, sizeof(link));
    link.sll_family = EDGE_LINUX_AF_PACKET;
    link.sll_protocol = packet_bswap16(ethernet_protocol);
    link.sll_ifindex = ifindex;
    link.sll_hatype = ifindex == 1 ? EDGE_LINUX_ARPHRD_LOOPBACK :
                                    EDGE_LINUX_ARPHRD_ETHER;
    link.sll_pkttype = packet_type(frame, length, outgoing);
    if (ifindex != 1) {
        link.sll_halen = 6u;
        memcpy(link.sll_addr, frame + 6u, 6u);
    }

    if (packet_ring_copy_locked(socket, frame_offset, &header,
                                sizeof(header)) < 0 ||
        packet_ring_copy_locked(socket,
                                frame_offset + packet_align(sizeof(header)),
                                &link, sizeof(link)) < 0 ||
        packet_ring_copy_locked(socket, frame_offset + data_offset, frame,
                                snapshot_length) < 0) {
        ++socket->statistics_drops;
        return;
    }
    __atomic_store_n(status,
                     EDGE_LINUX_TP_STATUS_USER |
                     (socket->statistics_drops ?
                          EDGE_LINUX_TP_STATUS_LOSING : 0u),
                     __ATOMIC_RELEASE);
    socket->ring.producer =
        (socket->ring.producer + 1u) % socket->ring.frame_count;
    packet_readiness_sequence_advance(&socket->ring_readiness_sequence);
    packet_readiness_sequence_advance(&g_packet_readiness_sequence);
}

int edge_linux_packet_socket_create(uint32_t socket_type,
                                    uint16_t protocol) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    int handle = -EDGE_PACKET_ENOSPC;

    for (uint32_t index = 0; index < EDGE_RUNTIME_MAX_SOCKETS; ++index) {
        struct edge_packet_socket *socket = &g_packet_sockets[index];
        if (socket->used) continue;
        memset(socket, 0, sizeof(*socket));
        socket->used = 1;
        socket->socket_type = (uint8_t)socket_type;
        socket->tpacket_version = EDGE_LINUX_TPACKET_V1;
        socket->protocol = protocol;
        __atomic_store_n(&socket->ring_readiness_sequence, 1u,
                         __ATOMIC_RELEASE);
        handle = (int)index;
        break;
    }
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return handle;
}

void edge_linux_packet_socket_release(int handle) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    struct edge_packet_socket *socket = packet_socket_locked(handle);

    if (socket) {
        packet_ring_release_locked(socket);
        memset(socket, 0, sizeof(*socket));
    }
    spin_unlock_irqrestore(&g_packet_lock, flags);
}

int edge_linux_packet_socket_bind(int handle, uint32_t network_namespace,
                                  int32_t ifindex, uint16_t protocol) {
    edge_net_device_snapshot_t snapshot;
    uint64_t flags;
    struct edge_packet_socket *socket;
    int result = 0;

    if (ifindex < 0) return -EDGE_PACKET_ENODEV;
    if (ifindex > 0 && edge_net_route_interface_snapshot(
            ifindex, network_namespace, &snapshot) != EDGE_NET_OK)
        return -EDGE_PACKET_ENODEV;
    flags = spin_lock_irqsave(&g_packet_lock);
    socket = packet_socket_locked(handle);
    if (!socket) {
        result = -EDGE_PACKET_EINVAL;
    } else {
        socket->ifindex = ifindex;
        socket->network_namespace = network_namespace;
        if (protocol) socket->protocol = protocol;
    }
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return result;
}

int edge_linux_packet_transmit_frame(uint32_t network_namespace,
                                     int32_t ifindex, const uint8_t *frame,
                                     uint32_t length) {
    edge_net_device_snapshot_t snapshot;
    edge_net_packet_segment_t segment;
    edge_net_packet_metadata_t metadata;
    edge_net_packet_t packet;
    int result;

    if (!frame || length < 14u || ifindex <= 0)
        return -EDGE_PACKET_EINVAL;
    if (edge_net_route_interface_snapshot(
            ifindex, network_namespace, &snapshot) != EDGE_NET_OK)
        return -EDGE_PACKET_ENODEV;
    segment.data = frame;
    segment.length = length;
    memset(&metadata, 0, sizeof(metadata));
    metadata.network_namespace = network_namespace;
    metadata.output_ifindex = ifindex;
    metadata.protocol = (uint16_t)(((uint16_t)frame[12] << 8u) | frame[13]);
    metadata.mac_header = 0u;
    metadata.network_header = 14u;
    if ((metadata.protocol == 0x8100u || metadata.protocol == 0x88a8u) &&
        length >= 18u) {
        metadata.vlan_tag_present = 1u;
        metadata.vlan_protocol = metadata.protocol;
        metadata.vlan_id = (uint16_t)(
            (((uint16_t)frame[14] << 8u) | frame[15]) & 0x0fffu);
        metadata.vlan_priority = (uint8_t)(frame[14] >> 5u);
        metadata.protocol =
            (uint16_t)(((uint16_t)frame[16] << 8u) | frame[17]);
        metadata.network_header = 18u;
    }
    metadata.timestamp_ns = boottime_monotonic_us() * 1000u;
    if (edge_net_packet_initialize(
            &packet, &segment, 1u, &metadata, 0, 0) != EDGE_NET_OK)
        return -EDGE_PACKET_EINVAL;
    result = edge_net_device_transmit(ifindex, &packet);
    if (result == EDGE_NET_OK) {
        edge_linux_packet_capture_tx(frame, length, ifindex);
        return 0;
    }
    if (result == EDGE_NET_NOT_FOUND ||
        result == EDGE_NET_WRONG_NAMESPACE)
        return -EDGE_PACKET_ENODEV;
    if (result == EDGE_NET_LINK_DOWN) return -EDGE_PACKET_ENETDOWN;
    if (result == EDGE_NET_MESSAGE_TOO_LARGE)
        return -EDGE_PACKET_EMSGSIZE;
    if (result == EDGE_NET_NO_SPACE) return -EDGE_PACKET_ENOBUFS;
    if (result == EDGE_NET_NOT_SUPPORTED)
        return -EDGE_PACKET_EOPNOTSUPP;
    return -EDGE_PACKET_EINVAL;
}

static int packet_membership_locked(struct edge_packet_socket *socket,
                                    const struct edge_linux_packet_mreq *request,
                                    int add) {
    int free_slot = -1;

    if (!socket || !request || request->mr_ifindex <= 0 ||
        request->mr_type > EDGE_LINUX_PACKET_MR_UNICAST ||
        request->mr_alen > sizeof(request->mr_address))
        return -EDGE_PACKET_EINVAL;
    for (uint32_t slot = 0; slot < EDGE_PACKET_MEMBERSHIP_MAX; ++slot) {
        struct edge_packet_membership *membership =
            &socket->memberships[slot];
        if (!membership->used) {
            if (free_slot < 0) free_slot = (int)slot;
            continue;
        }
        if (memcmp(&membership->request, request, sizeof(*request)) != 0)
            continue;
        if (add) return -EDGE_PACKET_EADDRINUSE;
        memset(membership, 0, sizeof(*membership));
        return 0;
    }
    if (!add) return -EDGE_PACKET_ENODEV;
    if (free_slot < 0) return -EDGE_PACKET_ENOSPC;
    socket->memberships[free_slot].used = 1;
    socket->memberships[free_slot].request = *request;
    return 0;
}

int edge_linux_packet_setsockopt(
    int handle, uint32_t option, const void *value, uint32_t value_length,
    const struct edge_linux_packet_page_allocator *allocator) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    struct edge_packet_socket *socket = packet_socket_locked(handle);
    int result = 0;
    int integer = 0;

    if (!socket) {
        result = -EDGE_PACKET_EINVAL;
        goto out;
    }
    if ((option == EDGE_LINUX_PACKET_ADD_MEMBERSHIP ||
         option == EDGE_LINUX_PACKET_DROP_MEMBERSHIP)) {
        if (!value || value_length < sizeof(struct edge_linux_packet_mreq)) {
            result = -EDGE_PACKET_EINVAL;
            goto out;
        }
        result = packet_membership_locked(
            socket, (const struct edge_linux_packet_mreq *)value,
            option == EDGE_LINUX_PACKET_ADD_MEMBERSHIP);
        goto out;
    }
    if (option == EDGE_LINUX_PACKET_RX_RING) {
        if (!value || value_length < sizeof(struct edge_linux_tpacket_req)) {
            result = -EDGE_PACKET_EINVAL;
            goto out;
        }
        result = packet_ring_configure_locked(
            socket, (const struct edge_linux_tpacket_req *)value, allocator);
        goto out;
    }
    if (!value || value_length < sizeof(integer)) {
        result = -EDGE_PACKET_EINVAL;
        goto out;
    }
    memcpy(&integer, value, sizeof(integer));
    switch (option) {
        case EDGE_LINUX_PACKET_VERSION:
            if (socket->ring.page_count) result = -EDGE_PACKET_EBUSY;
            else if (integer != EDGE_LINUX_TPACKET_V2)
                result = -EDGE_PACKET_EINVAL;
            else
                socket->tpacket_version = (uint8_t)integer;
            break;
        case EDGE_LINUX_PACKET_RESERVE:
            if (socket->ring.page_count) result = -EDGE_PACKET_EBUSY;
            else if (integer < 0 || integer > 65535)
                result = -EDGE_PACKET_EINVAL;
            else
                socket->reserve = (uint32_t)integer;
            break;
        case EDGE_LINUX_PACKET_AUXDATA:
            socket->auxdata = integer != 0;
            break;
        case EDGE_LINUX_PACKET_LOSS:
            socket->loss = integer != 0;
            break;
        case EDGE_LINUX_PACKET_QDISC_BYPASS:
            socket->qdisc_bypass = integer != 0;
            break;
        case EDGE_LINUX_PACKET_IGNORE_OUTGOING:
            socket->ignore_outgoing = integer != 0;
            break;
        default:
            result = -EDGE_PACKET_ENOPROTOOPT;
            break;
    }
out:
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return result;
}

int edge_linux_packet_getsockopt(int handle, uint32_t option, void *value,
                                 uint32_t value_capacity,
                                 uint32_t *value_length) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    struct edge_packet_socket *socket = packet_socket_locked(handle);
    uint32_t required = sizeof(int);
    int result = 0;
    int integer = 0;

    if (!socket || !value || !value_length) {
        result = -EDGE_PACKET_EINVAL;
        goto out;
    }
    switch (option) {
        case EDGE_LINUX_PACKET_HDRLEN:
            if (value_capacity < sizeof(integer)) {
                result = -EDGE_PACKET_EINVAL;
                break;
            }
            memcpy(&integer, value, sizeof(integer));
            if (integer != EDGE_LINUX_TPACKET_V2) {
                result = -EDGE_PACKET_EINVAL;
                break;
            }
            integer = sizeof(struct edge_linux_tpacket2_hdr);
            memcpy(value, &integer, sizeof(integer));
            break;
        case EDGE_LINUX_PACKET_VERSION:
            integer = socket->tpacket_version;
            if (value_capacity < sizeof(integer)) {
                result = -EDGE_PACKET_EINVAL;
                break;
            }
            memcpy(value, &integer, sizeof(integer));
            break;
        case EDGE_LINUX_PACKET_STATISTICS: {
            struct edge_linux_tpacket_stats statistics;
            required = sizeof(statistics);
            if (value_capacity < required) {
                result = -EDGE_PACKET_EINVAL;
                break;
            }
            statistics.tp_packets = socket->statistics_packets;
            statistics.tp_drops = socket->statistics_drops;
            memcpy(value, &statistics, sizeof(statistics));
            socket->statistics_packets = 0;
            socket->statistics_drops = 0;
            break;
        }
        default:
            result = -EDGE_PACKET_ENOPROTOOPT;
            break;
    }
    if (!result) *value_length = required;
out:
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return result;
}

int edge_linux_packet_attach_filter(
    int handle, const struct edge_linux_sock_filter *program,
    uint32_t program_length) {
    uint64_t flags;
    struct edge_packet_socket *socket;

    if (!edge_linux_bpf_validate(program, program_length))
        return -EDGE_PACKET_EINVAL;
    flags = spin_lock_irqsave(&g_packet_lock);
    socket = packet_socket_locked(handle);
    if (!socket) {
        spin_unlock_irqrestore(&g_packet_lock, flags);
        return -EDGE_PACKET_EINVAL;
    }
    memcpy(socket->filter, program,
           (uint64_t)program_length * sizeof(program[0]));
    socket->filter_length = (uint16_t)program_length;
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return 0;
}

int edge_linux_packet_detach_filter(int handle) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    struct edge_packet_socket *socket = packet_socket_locked(handle);

    if (!socket) {
        spin_unlock_irqrestore(&g_packet_lock, flags);
        return -EDGE_PACKET_EINVAL;
    }
    socket->filter_length = 0;
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return 0;
}

int edge_linux_packet_ring_mmap_info(int handle, uint64_t offset,
                                     uint64_t length,
                                     uint32_t *page_count) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    struct edge_packet_socket *socket = packet_socket_locked(handle);
    int result = 0;
    uint64_t ring_length;

    if (!socket || !page_count || !socket->ring.page_count) {
        result = -EDGE_PACKET_ENODEV;
        goto out;
    }
    ring_length = (uint64_t)socket->ring.page_count * EDGE_PACKET_PAGE_SIZE;
    if (offset != 0u || length != ring_length) {
        result = -EDGE_PACKET_EINVAL;
        goto out;
    }
    *page_count = socket->ring.page_count;
out:
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return result;
}

int edge_linux_packet_ring_page(int handle, uint32_t page_index,
                                void **kernel_address,
                                uint64_t *mapping_cookie) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    struct edge_packet_socket *socket = packet_socket_locked(handle);
    int result = 0;
    struct edge_packet_ring_page *page;

    if (!socket || page_index >= socket->ring.page_count ||
        !kernel_address || !mapping_cookie) {
        result = -EDGE_PACKET_EINVAL;
        goto out;
    }
    page = &g_packet_ring_pages[socket->ring.page_base + page_index];
    if (!page->used || !page->kernel_address) {
        result = -EDGE_PACKET_ENODEV;
        goto out;
    }
    *kernel_address = page->kernel_address;
    *mapping_cookie = page->mapping_cookie;
out:
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return result;
}

int edge_linux_packet_ring_ready(int handle) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    struct edge_packet_socket *socket = packet_socket_locked(handle);
    int ready = 0;

    if (socket && socket->ring.page_count) {
        for (uint32_t frame = 0; frame < socket->ring.frame_count; ++frame) {
            volatile uint32_t *status = packet_ring_status_locked(socket, frame);
            if (status && (__atomic_load_n(status, __ATOMIC_ACQUIRE) &
                           EDGE_LINUX_TP_STATUS_USER)) {
                ready = 1;
                break;
            }
        }
    }
    spin_unlock_irqrestore(&g_packet_lock, flags);
    return ready;
}

uint64_t edge_linux_packet_readiness_sequence(void) {
    return __atomic_load_n(&g_packet_readiness_sequence, __ATOMIC_ACQUIRE);
}

uint64_t edge_linux_packet_ring_readiness_sequence(int handle) {
    uint64_t flags = spin_lock_irqsave(&g_packet_lock);
    struct edge_packet_socket *socket = packet_socket_locked(handle);
    uint64_t sequence = socket ?
        __atomic_load_n(&socket->ring_readiness_sequence, __ATOMIC_ACQUIRE) :
        0u;

    spin_unlock_irqrestore(&g_packet_lock, flags);
    return sequence;
}

static void packet_capture_all(const uint8_t *frame, uint32_t length,
                               int32_t ifindex, int outgoing) {
    uint64_t flags;

    if (!frame || length < 14u) return;
    if (!__atomic_load_n(&g_packet_capture_count, __ATOMIC_ACQUIRE)) return;
    flags = spin_lock_irqsave(&g_packet_lock);
    for (uint32_t index = 0; index < EDGE_RUNTIME_MAX_SOCKETS; ++index)
        if (g_packet_sockets[index].used)
            packet_capture_locked(&g_packet_sockets[index], frame, length,
                                  ifindex, outgoing);
    spin_unlock_irqrestore(&g_packet_lock, flags);
}

void edge_linux_packet_capture_rx(const uint8_t *frame, uint32_t length,
                                  int32_t ifindex) {
    packet_capture_all(frame, length, ifindex, 0);
}

void edge_linux_packet_capture_tx(const uint8_t *frame, uint32_t length,
                                  int32_t ifindex) {
    packet_capture_all(frame, length, ifindex, 1);
}
