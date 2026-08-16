/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux-compatible seccomp filter storage and classic-BPF interpreter.  The
 * implementation is architecture-neutral: entry code supplies the Linux
 * audit architecture, syscall number, instruction pointer, and arguments.
 */
#include <kernel/seccomp.h>

#include <kernel/credentials.h>
#include <kernel/linux_errno.h>
#include <kernel/process_runtime.h>
#include <sys/spinlock.h>

#define EDGE_SECCOMP_MAX_INSNS 4096u
#define EDGE_SECCOMP_MAX_PATH_INSNS 32768u
#define EDGE_SECCOMP_FILTER_SLOTS 4096u
#define EDGE_SECCOMP_INSTRUCTION_SLOTS (64u * EDGE_SECCOMP_MAX_INSNS)
#define EDGE_SECCOMP_CHAIN_OVERHEAD 4u
#define EDGE_SECCOMP_MEMWORDS 16u

#define BPF_CLASS(code) ((code) & 0x07u)
#define BPF_SIZE(code)  ((code) & 0x18u)
#define BPF_MODE(code)  ((code) & 0xe0u)
#define BPF_OP(code)    ((code) & 0xf0u)
#define BPF_SRC(code)   ((code) & 0x08u)
#define BPF_RVAL(code)  ((code) & 0x18u)
#define BPF_MISCOP(code) ((code) & 0xf8u)

#define BPF_LD 0x00u
#define BPF_LDX 0x01u
#define BPF_ST 0x02u
#define BPF_STX 0x03u
#define BPF_ALU 0x04u
#define BPF_JMP 0x05u
#define BPF_RET 0x06u
#define BPF_MISC 0x07u
#define BPF_W 0x00u
#define BPF_IMM 0x00u
#define BPF_ABS 0x20u
#define BPF_MEM 0x60u
#define BPF_ADD 0x00u
#define BPF_SUB 0x10u
#define BPF_MUL 0x20u
#define BPF_DIV 0x30u
#define BPF_OR 0x40u
#define BPF_AND 0x50u
#define BPF_LSH 0x60u
#define BPF_RSH 0x70u
#define BPF_NEG 0x80u
#define BPF_MOD 0x90u
#define BPF_XOR 0xa0u
#define BPF_JA 0x00u
#define BPF_JEQ 0x10u
#define BPF_JGT 0x20u
#define BPF_JGE 0x30u
#define BPF_JSET 0x40u
#define BPF_K 0x00u
#define BPF_X 0x08u
#define BPF_A 0x10u
#define BPF_TAX 0x00u
#define BPF_TXA 0x80u

typedef struct {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
} edge_sock_filter_t;

typedef struct {
    uint16_t length;
    uint16_t pad[3];
    uint64_t filter;
} edge_sock_fprog_t;

typedef struct {
    uint32_t references;
    uint32_t instruction_offset;
    uint16_t length;
    uint16_t parent_id;
    uint8_t ready;
} edge_seccomp_filter_t;

static edge_seccomp_filter_t g_filters[EDGE_SECCOMP_FILTER_SLOTS];
static edge_sock_filter_t
    g_filter_instructions[EDGE_SECCOMP_INSTRUCTION_SLOTS];
static spinlock_t g_seccomp_lock;

static uint32_t action_precedence(uint32_t action) {
    switch (action & EDGE_SECCOMP_RET_ACTION_FULL) {
    case EDGE_SECCOMP_RET_KILL_PROCESS: return 0;
    case EDGE_SECCOMP_RET_KILL_THREAD: return 1;
    case EDGE_SECCOMP_RET_TRAP: return 2;
    case EDGE_SECCOMP_RET_ERRNO: return 3;
    case EDGE_SECCOMP_RET_TRACE: return 4;
    case EDGE_SECCOMP_RET_LOG: return 5;
    case EDGE_SECCOMP_RET_ALLOW: return 6;
    default: return 0;
    }
}

static void zero_bytes(void *pointer, uint64_t size) {
    uint8_t *bytes = (uint8_t *)pointer;
    while (size--) *bytes++ = 0;
}

static int filter_validate(const edge_sock_filter_t *program, uint32_t length) {
    uint32_t pc;
    if (!program || !length || length > EDGE_SECCOMP_MAX_INSNS) return -22;
    for (pc = 0; pc < length; ++pc) {
        uint16_t code = program[pc].code;
        uint32_t remaining = length - pc - 1u;
        switch (BPF_CLASS(code)) {
        case BPF_LD:
            if (code == (BPF_LD | BPF_W | BPF_ABS)) {
                if ((program[pc].k & 3u) ||
                    program[pc].k > sizeof(edge_seccomp_data_t) - 4u) return -22;
            } else if (code == (BPF_LD | BPF_W | BPF_IMM)) {
                /* valid */
            } else if (code == (BPF_LD | BPF_W | BPF_MEM)) {
                if (program[pc].k >= EDGE_SECCOMP_MEMWORDS) return -22;
            } else return -22;
            break;
        case BPF_LDX:
            if (code == (BPF_LDX | BPF_W | BPF_IMM)) {
                /* valid */
            } else if (code == (BPF_LDX | BPF_W | BPF_MEM)) {
                if (program[pc].k >= EDGE_SECCOMP_MEMWORDS) return -22;
            } else return -22;
            break;
        case BPF_ST:
        case BPF_STX:
            if (code != BPF_CLASS(code) || program[pc].k >= EDGE_SECCOMP_MEMWORDS)
                return -22;
            break;
        case BPF_ALU:
            if ((BPF_SRC(code) != BPF_K && BPF_SRC(code) != BPF_X) ||
                (BPF_OP(code) != BPF_ADD && BPF_OP(code) != BPF_SUB &&
                 BPF_OP(code) != BPF_MUL && BPF_OP(code) != BPF_DIV &&
                 BPF_OP(code) != BPF_OR && BPF_OP(code) != BPF_AND &&
                 BPF_OP(code) != BPF_LSH && BPF_OP(code) != BPF_RSH &&
                 BPF_OP(code) != BPF_NEG && BPF_OP(code) != BPF_MOD &&
                 BPF_OP(code) != BPF_XOR)) return -22;
            if (BPF_SRC(code) == BPF_K &&
                (BPF_OP(code) == BPF_DIV || BPF_OP(code) == BPF_MOD) &&
                !program[pc].k) return -22;
            break;
        case BPF_JMP:
            if (BPF_OP(code) == BPF_JA) {
                if (code != (BPF_JMP | BPF_JA) || program[pc].k >= remaining)
                    return -22;
            } else {
                if ((BPF_OP(code) != BPF_JEQ && BPF_OP(code) != BPF_JGT &&
                     BPF_OP(code) != BPF_JGE && BPF_OP(code) != BPF_JSET) ||
                    (BPF_SRC(code) != BPF_K && BPF_SRC(code) != BPF_X) ||
                    program[pc].jt >= remaining || program[pc].jf >= remaining)
                    return -22;
            }
            break;
        case BPF_RET:
            if (code != (BPF_RET | BPF_K) && code != (BPF_RET | BPF_A)) return -22;
            break;
        case BPF_MISC:
            if (BPF_MISCOP(code) != (BPF_MISC | BPF_TAX) &&
                BPF_MISCOP(code) != (BPF_MISC | BPF_TXA)) return -22;
            break;
        default:
            return -22;
        }
    }
    if (BPF_CLASS(program[length - 1u].code) != BPF_RET) return -22;
    return 0;
}

static uint32_t filter_run(const edge_seccomp_filter_t *filter,
                           const edge_seccomp_data_t *data) {
    const edge_sock_filter_t *program;
    uint32_t accumulator = 0, index = 0, memory[EDGE_SECCOMP_MEMWORDS];
    uint32_t pc;
    if (!filter || !filter->ready ||
        filter->instruction_offset > EDGE_SECCOMP_INSTRUCTION_SLOTS ||
        filter->length > EDGE_SECCOMP_INSTRUCTION_SLOTS -
                         filter->instruction_offset)
        return EDGE_SECCOMP_RET_KILL_PROCESS;
    program = &g_filter_instructions[filter->instruction_offset];
    zero_bytes(memory, sizeof(memory));
    for (pc = 0; pc < filter->length; ++pc) {
        const edge_sock_filter_t *instruction = &program[pc];
        uint16_t code = instruction->code;
        uint32_t source = BPF_SRC(code) == BPF_X ? index : instruction->k;
        switch (BPF_CLASS(code)) {
        case BPF_LD:
            if (BPF_MODE(code) == BPF_ABS) {
                const uint8_t *p = (const uint8_t *)data + instruction->k;
                accumulator = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                              ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            } else if (BPF_MODE(code) == BPF_MEM) accumulator = memory[instruction->k];
            else accumulator = instruction->k;
            break;
        case BPF_LDX:
            index = BPF_MODE(code) == BPF_MEM ? memory[instruction->k] : instruction->k;
            break;
        case BPF_ST: memory[instruction->k] = accumulator; break;
        case BPF_STX: memory[instruction->k] = index; break;
        case BPF_ALU:
            switch (BPF_OP(code)) {
            case BPF_ADD: accumulator += source; break;
            case BPF_SUB: accumulator -= source; break;
            case BPF_MUL: accumulator *= source; break;
            case BPF_DIV: if (!source) return EDGE_SECCOMP_RET_KILL_PROCESS; accumulator /= source; break;
            case BPF_OR: accumulator |= source; break;
            case BPF_AND: accumulator &= source; break;
            case BPF_LSH: accumulator = source < 32u ? accumulator << source : 0; break;
            case BPF_RSH: accumulator = source < 32u ? accumulator >> source : 0; break;
            case BPF_NEG: accumulator = 0u - accumulator; break;
            case BPF_MOD: if (!source) return EDGE_SECCOMP_RET_KILL_PROCESS; accumulator %= source; break;
            case BPF_XOR: accumulator ^= source; break;
            }
            break;
        case BPF_JMP:
            if (BPF_OP(code) == BPF_JA) pc += instruction->k;
            else {
                int condition = BPF_OP(code) == BPF_JEQ ? accumulator == source :
                    BPF_OP(code) == BPF_JGT ? accumulator > source :
                    BPF_OP(code) == BPF_JGE ? accumulator >= source :
                    (accumulator & source) != 0;
                pc += condition ? instruction->jt : instruction->jf;
            }
            break;
        case BPF_RET:
            return BPF_RVAL(code) == BPF_A ? accumulator : instruction->k;
        case BPF_MISC:
            if (BPF_MISCOP(code) == (BPF_MISC | BPF_TAX)) index = accumulator;
            else accumulator = index;
            break;
        }
    }
    return EDGE_SECCOMP_RET_KILL_PROCESS;
}

void edge_seccomp_state_init(edge_seccomp_state_t *state) {
    if (state) zero_bytes(state, sizeof(*state));
}

int edge_seccomp_state_retain(edge_seccomp_state_t *state) {
    edge_seccomp_filter_t *filter;
    uint64_t flags;

    if (!state) return -22;
    if (!state->length) return state->head_filter_id ? -22 : 0;
    if (!state->head_filter_id ||
        state->head_filter_id > EDGE_SECCOMP_FILTER_SLOTS)
        return -22;
    flags = spin_lock_irqsave(&g_seccomp_lock);
    filter = &g_filters[state->head_filter_id - 1u];
    if (!filter->references || !filter->ready ||
        filter->references == UINT32_MAX) {
        spin_unlock_irqrestore(&g_seccomp_lock, flags);
        return -22;
    }
    ++filter->references;
    spin_unlock_irqrestore(&g_seccomp_lock, flags);
    return 0;
}

void edge_seccomp_state_release(edge_seccomp_state_t *state) {
    uint16_t id;

    if (!state) return;
    id = state->head_filter_id;
    while (id && id <= EDGE_SECCOMP_FILTER_SLOTS) {
        edge_seccomp_filter_t *filter;
        uint16_t parent;
        uint64_t flags = spin_lock_irqsave(&g_seccomp_lock);

        filter = &g_filters[id - 1u];
        if (!filter->references) {
            spin_unlock_irqrestore(&g_seccomp_lock, flags);
            break;
        }
        if (--filter->references) {
            spin_unlock_irqrestore(&g_seccomp_lock, flags);
            break;
        }
        parent = filter->parent_id;
        zero_bytes(filter, sizeof(*filter));
        spin_unlock_irqrestore(&g_seccomp_lock, flags);
        id = parent;
    }
    edge_seccomp_state_init(state);
}

int edge_seccomp_state_is_ancestor(const edge_seccomp_state_t *ancestor,
                                   const edge_seccomp_state_t *descendant) {
    uint16_t id;
    uint32_t remaining;
    uint64_t flags;
    int matches = 0;

    if (!ancestor || !descendant || ancestor->length > descendant->length)
        return 0;
    if (!ancestor->length)
        return ancestor->head_filter_id == 0;
    if (!ancestor->head_filter_id || !descendant->head_filter_id)
        return 0;

    flags = spin_lock_irqsave(&g_seccomp_lock);
    id = descendant->head_filter_id;
    remaining = descendant->length;
    while (remaining > ancestor->length && id &&
           id <= EDGE_SECCOMP_FILTER_SLOTS) {
        const edge_seccomp_filter_t *filter = &g_filters[id - 1u];
        if (!filter->references || !filter->ready) {
            id = 0;
            break;
        }
        id = filter->parent_id;
        --remaining;
    }
    if (remaining == ancestor->length && id == ancestor->head_filter_id)
        matches = 1;
    spin_unlock_irqrestore(&g_seccomp_lock, flags);
    return matches;
}

static int filter_arena_reserve(uint32_t length, uint32_t *slot_out,
                                uint32_t *offset_out) {
    uint32_t candidate = 0;
    uint32_t slot;
    uint64_t flags;

    if (!length || !slot_out || !offset_out) return -22;
    flags = spin_lock_irqsave(&g_seccomp_lock);
    for (slot = 0; slot < EDGE_SECCOMP_FILTER_SLOTS; ++slot)
        if (!g_filters[slot].references) break;
    if (slot == EDGE_SECCOMP_FILTER_SLOTS) {
        spin_unlock_irqrestore(&g_seccomp_lock, flags);
        return -12;
    }
    while (candidate <= EDGE_SECCOMP_INSTRUCTION_SLOTS - length) {
        uint32_t index;
        int overlap = 0;

        for (index = 0; index < EDGE_SECCOMP_FILTER_SLOTS; ++index) {
            const edge_seccomp_filter_t *active = &g_filters[index];
            uint32_t active_end;
            if (!active->references) continue;
            active_end = active->instruction_offset + active->length;
            if (active->instruction_offset < candidate + length &&
                active_end > candidate) {
                candidate = active_end;
                overlap = 1;
                break;
            }
        }
        if (!overlap) break;
    }
    if (candidate > EDGE_SECCOMP_INSTRUCTION_SLOTS - length) {
        spin_unlock_irqrestore(&g_seccomp_lock, flags);
        return -12;
    }
    g_filters[slot].references = 1u;
    g_filters[slot].instruction_offset = candidate;
    g_filters[slot].length = (uint16_t)length;
    g_filters[slot].parent_id = 0;
    g_filters[slot].ready = 0;
    spin_unlock_irqrestore(&g_seccomp_lock, flags);
    *slot_out = slot;
    *offset_out = candidate;
    return 0;
}

static void filter_arena_abandon(uint32_t slot) {
    uint64_t flags;

    if (slot >= EDGE_SECCOMP_FILTER_SLOTS) return;
    flags = spin_lock_irqsave(&g_seccomp_lock);
    zero_bytes(&g_filters[slot], sizeof(g_filters[slot]));
    spin_unlock_irqrestore(&g_seccomp_lock, flags);
}

int edge_seccomp_install(edge_seccomp_state_t *state, uint64_t fprog_user,
                         edge_seccomp_copy_from_user_fn copy_from_user,
                         void *copy_context) {
    edge_sock_fprog_t fprog;
    edge_sock_filter_t *program;
    uint32_t offset;
    uint32_t path_instructions;
    uint32_t slot;
    int status;
    uint64_t flags;

    if (!state || !copy_from_user || !fprog_user) return -14;
    if (copy_from_user(copy_context, &fprog, fprog_user, sizeof(fprog)) < 0) return -14;
    if (!fprog.length || fprog.length > EDGE_SECCOMP_MAX_INSNS || !fprog.filter) return -22;
    path_instructions = state->total_instructions;
    if (state->length && path_instructions > UINT32_MAX -
        EDGE_SECCOMP_CHAIN_OVERHEAD)
        return -12;
    if (state->length) path_instructions += EDGE_SECCOMP_CHAIN_OVERHEAD;
    if (path_instructions > EDGE_SECCOMP_MAX_PATH_INSNS - fprog.length)
        return -12;
    status = filter_arena_reserve(fprog.length, &slot, &offset);
    if (status < 0) return status;
    program = &g_filter_instructions[offset];
    if (copy_from_user(copy_context, program, fprog.filter,
                       (uint64_t)fprog.length * sizeof(*program)) < 0) {
        filter_arena_abandon(slot);
        return -14;
    }
    if (filter_validate(program, fprog.length) < 0) {
        filter_arena_abandon(slot);
        return -22;
    }
    flags = spin_lock_irqsave(&g_seccomp_lock);
    g_filters[slot].parent_id = state->head_filter_id;
    g_filters[slot].ready = 1;
    state->head_filter_id = (uint16_t)(slot + 1u);
    ++state->length;
    state->total_instructions = path_instructions + fprog.length;
    spin_unlock_irqrestore(&g_seccomp_lock, flags);
    return 0;
}

int kernel_current_seccomp_filter_install(
    uint64_t user_program, edge_seccomp_copy_from_user_fn copy_from_user,
    void *copy_context) {
    edge_seccomp_state_t *state = kernel_arch_current_seccomp_state();
    if (!state) return -EDGE_LINUX_EINVAL;
    return edge_seccomp_install(state, user_program, copy_from_user,
                                copy_context);
}

int edge_linux_seccomp_filter_install_current(
    uint64_t fprog_user, edge_seccomp_copy_from_user_fn copy_from_user,
    void *copy_context) {
    return edge_linux_seccomp_filter_install_current_flags(
        fprog_user, 0, copy_from_user, copy_context);
}

int edge_linux_seccomp_filter_install_current_flags(
    uint64_t fprog_user, uint32_t flags,
    edge_seccomp_copy_from_user_fn copy_from_user, void *copy_context) {
    kernel_linux_identity_t identity;
    edge_seccomp_state_t *state;
    edge_seccomp_state_t previous;
    int status;

    if (!fprog_user) return -EDGE_LINUX_EFAULT;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_EINVAL;
    if (!kernel_current_no_new_privileges() &&
        !(identity.effective_capabilities &
          (1ull << EDGE_LINUX_CAP_SYS_ADMIN)))
        return -EDGE_LINUX_EACCES;
    if (!(flags & EDGE_LINUX_SECCOMP_FILTER_FLAG_TSYNC))
        return kernel_current_seccomp_filter_install(
            fprog_user, copy_from_user, copy_context);

    state = kernel_arch_current_seccomp_state();
    if (!state) return -EDGE_LINUX_EINVAL;
    previous = *state;
    status = edge_seccomp_state_retain(&previous);
    if (status < 0) return status;
    status = edge_seccomp_install(
        state, fprog_user, copy_from_user, copy_context);
    if (status < 0) {
        edge_seccomp_state_release(&previous);
        return status;
    }
    status = kernel_arch_seccomp_synchronize_thread_group(
        &previous, state, flags);
    if (status != 0) {
        edge_seccomp_state_release(state);
        *state = previous;
        return status;
    }
    edge_seccomp_state_release(&previous);
    return 0;
}

uint32_t edge_seccomp_evaluate(const edge_seccomp_state_t *state,
                               const edge_seccomp_data_t *data) {
    uint32_t result = EDGE_SECCOMP_RET_ALLOW;
    uint16_t id;
    uint32_t visited = 0;

    if (!state || !data) return EDGE_SECCOMP_RET_ALLOW;
    id = state->head_filter_id;
    while (id && visited++ < state->length) {
        const edge_seccomp_filter_t *filter;
        uint32_t candidate;
        if (id > EDGE_SECCOMP_FILTER_SLOTS)
            return EDGE_SECCOMP_RET_KILL_PROCESS;
        filter = &g_filters[id - 1u];
        if (!filter->references || !filter->ready)
            return EDGE_SECCOMP_RET_KILL_PROCESS;
        candidate = filter_run(filter, data);
        if (action_precedence(candidate) < action_precedence(result))
            result = candidate;
        id = filter->parent_id;
    }
    if (id || visited != state->length)
        return EDGE_SECCOMP_RET_KILL_PROCESS;
    return result;
}
