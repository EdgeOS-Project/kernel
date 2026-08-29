/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Linux-compatible FUSE transport and VFS client shared by every EdgeOS
 * architecture.  Network filesystems such as CephFS remain userspace policy:
 * the kernel supplies the standard /dev/fuse request/reply channel.
 */

#include "fs/fuse.h"
#include "fs/fuse_kernel.h"
#include "kernel/io_uring_runtime.h"
#include "kernel/mm_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/smp.h"
#include "mm/arch_vm.h"
#include "stdio.h"
#include "string.h"
#include "sys/spinlock.h"
#include "vfs/vfs.h"

#define FUSE_SESSION_MAX 4u
#define FUSE_REQUEST_MAX 16u
#define FUSE_REPLAY_MAX 256u
#define FUSE_MESSAGE_MAX 69632u
#define FUSE_MESSAGE_PAGES ((FUSE_MESSAGE_MAX + 4095u) / 4096u)
#define FUSE_READDIR_BUFFER 16384u
#define FUSE_SUPERBLOCK_PAGES ((sizeof(vfs_superblock_t) + 4095u) / 4096u)
#define FUSE_URING_ENTRY_MAX 128u
#define FUSE_URING_HEADER_LENGTH 288u
#define FUSE_URING_IN_OUT_OFFSET 0u
#define FUSE_URING_OP_OFFSET 128u
#define FUSE_URING_ENTRY_OFFSET 256u
#define FUSE_URING_MIN_PAYLOAD 8192u

#define LINUX_EIO 5
#define LINUX_EFAULT 14
#define LINUX_ENOMEM 12
#define LINUX_EBUSY 16
#define LINUX_ENODEV 19
#define LINUX_EINVAL 22
#define LINUX_ENOSPC 28
#define LINUX_EAGAIN 11
#define LINUX_ENOENT 2
#define LINUX_EEXIST 17
#define LINUX_ENOTDIR 20
#define LINUX_EISDIR 21
#define LINUX_ENOTEMPTY 39
#define LINUX_ENODATA 61
#define LINUX_ERANGE 34
#define LINUX_EOPNOTSUPP 95
#define LINUX_ENOTTY 25
#define LINUX_ENOTCONN 107

#define LINUX_O_RDONLY 0u
#define LINUX_O_WRONLY 1u
#define LINUX_O_RDWR 2u

enum fuse_request_state {
    FUSE_REQUEST_FREE = 0,
    FUSE_REQUEST_BUILDING,
    FUSE_REQUEST_QUEUED,
    FUSE_REQUEST_READING,
    FUSE_REQUEST_DELIVERED,
    FUSE_REQUEST_WRITING,
    FUSE_REQUEST_REPLIED
};

typedef struct edge_fuse_request {
    uint8_t state;
    uint8_t *message;
    uint32_t request_length;
    uint32_t input_length;
    uint32_t tail_length;
    uint32_t reply_length;
    uint64_t unique;
    uintptr_t owner_context;
    uint32_t owner_sequence;
    uint32_t opcode;
    uint64_t nodeid;
} edge_fuse_request_t;

enum fuse_uring_entry_state {
    FUSE_URING_ENTRY_FREE = 0,
    FUSE_URING_ENTRY_AVAILABLE,
    FUSE_URING_ENTRY_DELIVERING,
    FUSE_URING_ENTRY_USERSPACE
};

typedef struct edge_fuse_uring_entry {
    uint8_t state;
    uint8_t reserved;
    uint16_t qid;
    int32_t ring_id;
    int32_t descriptor;
    uint64_t command_id;
    uint64_t address_space;
    uint64_t headers_address;
    uint64_t payload_address;
    uint64_t commit_id;
    uint32_t headers_length;
    uint32_t payload_length;
} edge_fuse_uring_entry_t;

typedef struct edge_fuse_uring_ent_in_out {
    uint64_t flags;
    uint64_t commit_id;
    uint32_t payload_size;
    uint32_t padding;
    uint64_t reserved;
} edge_fuse_uring_ent_in_out_t;

_Static_assert(sizeof(edge_fuse_uring_ent_in_out_t) == 32u,
               "FUSE io_uring entry header size mismatch");

typedef struct edge_fuse_replay {
    uintptr_t context;
    uint32_t cursor;
    uint8_t active;
} edge_fuse_replay_t;

typedef struct edge_fuse_node {
    uint64_t nodeid;
    uint64_t read_fh;
    uint64_t write_fh;
    uint64_t dir_fh;
    uint32_t generation;
    uint8_t used;
    uint8_t read_fh_valid;
    uint8_t write_fh_valid;
    uint8_t dir_fh_valid;
} edge_fuse_node_t;

#define FUSE_NODES_PER_PAGE \
    ((4096u - sizeof(void *) - sizeof(uint32_t) * 2u) / \
     sizeof(edge_fuse_node_t))

typedef struct edge_fuse_node_page {
    struct edge_fuse_node_page *next;
    uint32_t base_index;
    uint32_t reserved;
    edge_fuse_node_t nodes[FUSE_NODES_PER_PAGE];
} edge_fuse_node_page_t;

_Static_assert(sizeof(edge_fuse_node_page_t) <= 4096u,
               "FUSE node page exceeds one kernel page");

typedef struct edge_fuse_session {
    spinlock_t lock;
    uint64_t description_identity;
    uint64_t next_unique;
    uint32_t references;
    uint32_t generation;
    uint32_t max_write;
    uint8_t used;
    uint8_t daemon_open;
    uint8_t mounted;
    uint8_t init_state;
    uint8_t sync_init;
    uintptr_t init_owner_context;
    edge_fuse_request_t requests[FUSE_REQUEST_MAX];
    edge_fuse_uring_entry_t uring_entries[FUSE_URING_ENTRY_MAX];
    edge_fuse_node_page_t *node_pages;
} edge_fuse_session_t;

static edge_fuse_session_t g_fuse_sessions[FUSE_SESSION_MAX];
static spinlock_t g_fuse_sessions_lock;
static uint32_t g_fuse_generation;
static edge_fuse_replay_t g_fuse_replays[FUSE_REPLAY_MAX];
static spinlock_t g_fuse_replays_lock;

static void fuse_free_pages(void *allocation, uint32_t pages);
static void fuse_uring_dispatch(edge_fuse_session_t *session);

static int fuse_replay_sequence(uintptr_t context, uint32_t *sequence) {
    uint64_t flags;
    int active = 0;
    if (!context || !sequence) return 0;
    flags = spin_lock_irqsave(&g_fuse_replays_lock);
    for (uint32_t index = 0; index < FUSE_REPLAY_MAX; ++index) {
        edge_fuse_replay_t *replay = &g_fuse_replays[index];
        if (!replay->active || replay->context != context) continue;
        *sequence = replay->cursor++;
        active = 1;
        break;
    }
    spin_unlock_irqrestore(&g_fuse_replays_lock, flags);
    return active;
}

static int fuse_replay_consume_cached(edge_fuse_session_t *session,
                                      uint32_t opcode, uint64_t nodeid) {
    uintptr_t owner_context = kernel_current_context_token();
    uint32_t owner_sequence = 0;
    uint64_t flags;

    if (!fuse_replay_sequence(owner_context, &owner_sequence))
        return 0;
    flags = spin_lock_irqsave(&session->lock);
    for (uint32_t index = 0; index < FUSE_REQUEST_MAX; ++index) {
        edge_fuse_request_t *request = &session->requests[index];
        if (request->state == FUSE_REQUEST_FREE ||
            request->owner_context != owner_context ||
            request->owner_sequence != owner_sequence)
            continue;
        if (request->opcode != opcode || request->nodeid != nodeid ||
            request->state != FUSE_REQUEST_REPLIED) {
            spin_unlock_irqrestore(&session->lock, flags);
            return -LINUX_EIO;
        }
        break;
    }
    spin_unlock_irqrestore(&session->lock, flags);
    return 0;
}

void edge_fuse_syscall_replay_begin(uintptr_t context) {
    edge_fuse_replay_t *available = 0;
    uint64_t flags;
    if (!context) return;
    flags = spin_lock_irqsave(&g_fuse_replays_lock);
    for (uint32_t index = 0; index < FUSE_REPLAY_MAX; ++index) {
        edge_fuse_replay_t *replay = &g_fuse_replays[index];
        if (replay->active && replay->context == context) {
            replay->cursor = 0;
            spin_unlock_irqrestore(&g_fuse_replays_lock, flags);
            return;
        }
        if (!replay->active && !available) available = replay;
    }
    if (available) {
        memset(available, 0, sizeof(*available));
        available->context = context;
        available->active = 1u;
    }
    spin_unlock_irqrestore(&g_fuse_replays_lock, flags);
}

void edge_fuse_syscall_replay_complete(uintptr_t context) {
    void *retired[FUSE_SESSION_MAX * FUSE_REQUEST_MAX];
    uint32_t retired_count = 0;
    uint64_t flags;
    if (!context) return;

    flags = spin_lock_irqsave(&g_fuse_replays_lock);
    for (uint32_t index = 0; index < FUSE_REPLAY_MAX; ++index) {
        edge_fuse_replay_t *replay = &g_fuse_replays[index];
        if (replay->active && replay->context == context) {
            memset(replay, 0, sizeof(*replay));
            break;
        }
    }
    spin_unlock_irqrestore(&g_fuse_replays_lock, flags);

    for (uint32_t session_index = 0;
         session_index < FUSE_SESSION_MAX; ++session_index) {
        edge_fuse_session_t *session = &g_fuse_sessions[session_index];
        flags = spin_lock_irqsave(&session->lock);
        for (uint32_t request_index = 0;
             request_index < FUSE_REQUEST_MAX; ++request_index) {
            edge_fuse_request_t *request =
                &session->requests[request_index];
            if (request->state == FUSE_REQUEST_FREE ||
                request->owner_context != context)
                continue;
            if (request->message)
                retired[retired_count++] = request->message;
            memset(request, 0, sizeof(*request));
        }
        spin_unlock_irqrestore(&session->lock, flags);
    }
    for (uint32_t index = 0; index < retired_count; ++index)
        fuse_free_pages(retired[index], FUSE_MESSAGE_PAGES);
}

static void fuse_free_pages(void *allocation, uint32_t pages) {
    uint8_t *base = (uint8_t *)allocation;
    if (!base) return;
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page(base + (uint64_t)page * 4096u);
}

static edge_fuse_node_page_t *fuse_node_page_allocate(uint32_t base_index) {
    edge_fuse_node_page_t *page =
        (edge_fuse_node_page_t *)arch_vm_alloc_pages(1u);
    if (!page) return 0;
    memset(page, 0, 4096u);
    page->base_index = base_index;
    return page;
}

static void fuse_node_pages_free(edge_fuse_node_page_t *page) {
    while (page) {
        edge_fuse_node_page_t *next = page->next;
        arch_vm_free_page(page);
        page = next;
    }
}

static edge_fuse_node_t *fuse_node_by_index(
        edge_fuse_session_t *session, uint32_t index) {
    edge_fuse_node_page_t *page;
    if (!session) return 0;
    for (page = session->node_pages; page; page = page->next) {
        if (index >= page->base_index &&
            index - page->base_index < FUSE_NODES_PER_PAGE)
            return &page->nodes[index - page->base_index];
    }
    return 0;
}

static edge_fuse_session_t *fuse_session_find(uint64_t identity) {
    edge_fuse_session_t *result = 0;
    uint64_t flags = spin_lock_irqsave(&g_fuse_sessions_lock);
    for (uint32_t index = 0; index < FUSE_SESSION_MAX; ++index) {
        if (g_fuse_sessions[index].used &&
            g_fuse_sessions[index].description_identity == identity) {
            result = &g_fuse_sessions[index];
            break;
        }
    }
    spin_unlock_irqrestore(&g_fuse_sessions_lock, flags);
    return result;
}

static edge_fuse_session_t *fuse_session_create(uint64_t identity) {
    edge_fuse_session_t *session = 0;
    edge_fuse_node_page_t *candidate;
    edge_fuse_node_page_t *retired_pages = 0;
    uint64_t flags;
    if (!identity) return 0;
    candidate = fuse_node_page_allocate(0u);
    if (!candidate) return 0;
    flags = spin_lock_irqsave(&g_fuse_sessions_lock);
    for (uint32_t index = 0; index < FUSE_SESSION_MAX; ++index) {
        if (g_fuse_sessions[index].used &&
            g_fuse_sessions[index].description_identity == identity) {
            session = &g_fuse_sessions[index];
            goto out;
        }
    }
    for (uint32_t index = 0; index < FUSE_SESSION_MAX; ++index) {
        if (g_fuse_sessions[index].used) continue;
        session = &g_fuse_sessions[index];
        retired_pages = session->node_pages;
        memset(session, 0, sizeof(*session));
        spinlock_init(&session->lock);
        session->description_identity = identity;
        session->next_unique = 1u;
        session->generation = ++g_fuse_generation;
        if (!session->generation) session->generation = ++g_fuse_generation;
        session->max_write = 65536u;
        session->used = 1u;
        session->daemon_open = 1u;
        session->node_pages = candidate;
        candidate = 0;
        session->node_pages->nodes[0].used = 1u;
        session->node_pages->nodes[0].nodeid = 1u;
        session->node_pages->nodes[0].generation = session->generation;
        break;
    }
out:
    spin_unlock_irqrestore(&g_fuse_sessions_lock, flags);
    fuse_node_pages_free(candidate);
    fuse_node_pages_free(retired_pages);
    return session;
}

static void fuse_session_retain(void *private_data) {
    edge_fuse_session_t *session = (edge_fuse_session_t *)private_data;
    if (session && session->used)
        (void)__sync_add_and_fetch(&session->references, 1u);
}

static void fuse_session_release(void *private_data) {
    edge_fuse_session_t *session = (edge_fuse_session_t *)private_data;
    if (!session || !session->used || !session->references) return;
    if (__sync_sub_and_fetch(&session->references, 1u) == 0) {
        uint64_t flags = spin_lock_irqsave(&session->lock);
        session->mounted = 0;
        if (!session->daemon_open) session->used = 0;
        spin_unlock_irqrestore(&session->lock, flags);
    }
}

static uint64_t fuse_nodeid(edge_fuse_session_t *session,
                            const vfs_inode_t *inode) {
    edge_fuse_node_t *node;
    uint32_t index;
    if (!session || !inode) return 0;
    index = inode->fs_private[0];
    node = fuse_node_by_index(session, index);
    if (!node || !node->used ||
        node->generation != inode->fs_private[1])
        return 0;
    return node->nodeid;
}

static int fuse_node_index(edge_fuse_session_t *session, uint64_t nodeid,
                           uint32_t *index_out) {
    edge_fuse_node_page_t *candidate = 0;
    if (!session || !nodeid || !index_out) return -1;

    for (;;) {
        edge_fuse_node_page_t *last = 0;
        edge_fuse_node_t *available = 0;
        uint32_t available_index = 0;
        uint64_t flags = spin_lock_irqsave(&session->lock);

        for (edge_fuse_node_page_t *page = session->node_pages;
             page; page = page->next) {
            last = page;
            for (uint32_t slot = 0; slot < FUSE_NODES_PER_PAGE; ++slot) {
                edge_fuse_node_t *node = &page->nodes[slot];
                if (node->used && node->nodeid == nodeid) {
                    *index_out = page->base_index + slot;
                    spin_unlock_irqrestore(&session->lock, flags);
                    fuse_node_pages_free(candidate);
                    return 0;
                }
                if (!node->used && !available) {
                    available = node;
                    available_index = page->base_index + slot;
                }
            }
        }

        if (available) {
            memset(available, 0, sizeof(*available));
            available->used = 1u;
            available->nodeid = nodeid;
            available->generation = session->generation;
            *index_out = available_index;
            spin_unlock_irqrestore(&session->lock, flags);
            fuse_node_pages_free(candidate);
            return 0;
        }
        if (candidate) {
            uint32_t base = last ? last->base_index + FUSE_NODES_PER_PAGE : 0u;
            if (last && base < last->base_index) {
                spin_unlock_irqrestore(&session->lock, flags);
                fuse_node_pages_free(candidate);
                return -1;
            }
            candidate->base_index = base;
            if (last) last->next = candidate;
            else session->node_pages = candidate;
            candidate->nodes[0].used = 1u;
            candidate->nodes[0].nodeid = nodeid;
            candidate->nodes[0].generation = session->generation;
            *index_out = base;
            candidate = 0;
            spin_unlock_irqrestore(&session->lock, flags);
            return 0;
        }
        spin_unlock_irqrestore(&session->lock, flags);
        candidate = fuse_node_page_allocate(0u);
        if (!candidate) return -1;
    }
}

static int fuse_fill_inode(edge_fuse_session_t *session, uint64_t nodeid,
                           const struct fuse_attr *attr, vfs_inode_t *out) {
    uint32_t index;
    if (!session || !nodeid || !attr || !out ||
        fuse_node_index(session, nodeid, &index) < 0)
        return -1;
    memset(out, 0, sizeof(*out));
    out->ino = (uint32_t)attr->ino;
    out->generation = session->generation;
    out->mode = (uint16_t)attr->mode;
    out->uid = attr->uid;
    out->gid = attr->gid;
    out->nlink = attr->nlink;
    out->nlink_valid = 1u;
    out->size = attr->size > UINT32_MAX ? UINT32_MAX : (uint32_t)attr->size;
    out->atime = attr->atime > UINT32_MAX ? UINT32_MAX : (uint32_t)attr->atime;
    out->mtime = attr->mtime > UINT32_MAX ? UINT32_MAX : (uint32_t)attr->mtime;
    out->ctime = attr->ctime > UINT32_MAX ? UINT32_MAX : (uint32_t)attr->ctime;
    out->rdev = attr->rdev;
    out->fs_private[0] = index;
    out->fs_private[1] = fuse_node_by_index(session, index)->generation;
    return 0;
}

static int fuse_rpc(edge_fuse_session_t *session, uint32_t opcode,
                    uint64_t nodeid, const void *input, uint32_t input_length,
                    const void *tail, uint32_t tail_length,
                    void *output, uint32_t output_capacity,
                    uint32_t *output_length) {
    edge_fuse_request_t *request = 0;
    struct fuse_in_header *header;
    struct fuse_out_header *reply;
    uint8_t *message = 0;
    uint64_t flags;
    uint32_t total = sizeof(*header) + input_length + tail_length;
    uintptr_t owner_context = kernel_current_context_token();
    uint32_t owner_sequence = 0;
    int replay_active =
        fuse_replay_sequence(owner_context, &owner_sequence);
    int error;
    int32_t pid = 0;
    uint32_t uid = 0, gid = 0;

    if (!session || (!nodeid && opcode != FUSE_INIT) ||
        total > FUSE_MESSAGE_MAX) return -LINUX_EINVAL;
    flags = spin_lock_irqsave(&session->lock);
    if (!session->used || !session->daemon_open) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_ENODEV;
    }
    if (replay_active) {
        for (uint32_t index = 0; index < FUSE_REQUEST_MAX; ++index) {
            edge_fuse_request_t *candidate = &session->requests[index];
            if (candidate->state == FUSE_REQUEST_FREE ||
                candidate->owner_context != owner_context ||
                candidate->owner_sequence != owner_sequence)
                continue;
            if (candidate->opcode != opcode || candidate->nodeid != nodeid) {
                spin_unlock_irqrestore(&session->lock, flags);
                return -LINUX_EIO;
            }
            request = candidate;
            message = candidate->message;
            break;
        }
    }
    if (request) {
        spin_unlock_irqrestore(&session->lock, flags);
        goto wait_for_reply;
    }
    spin_unlock_irqrestore(&session->lock, flags);

    message = (uint8_t *)arch_vm_alloc_pages(FUSE_MESSAGE_PAGES);
    if (!message) return -LINUX_ENOMEM;
    flags = spin_lock_irqsave(&session->lock);
    if (!session->used || !session->daemon_open) {
        spin_unlock_irqrestore(&session->lock, flags);
        fuse_free_pages(message, FUSE_MESSAGE_PAGES);
        return -LINUX_ENODEV;
    }
    for (uint32_t index = 0; index < FUSE_REQUEST_MAX; ++index) {
        if (session->requests[index].state != FUSE_REQUEST_FREE) continue;
        request = &session->requests[index];
        request->state = FUSE_REQUEST_BUILDING;
        request->message = message;
        request->unique = session->next_unique++;
        if (!request->unique) request->unique = session->next_unique++;
        request->owner_context = replay_active ? owner_context : 0;
        request->owner_sequence = owner_sequence;
        request->opcode = opcode;
        request->nodeid = nodeid;
        break;
    }
    spin_unlock_irqrestore(&session->lock, flags);
    if (!request) {
        fuse_free_pages(message, FUSE_MESSAGE_PAGES);
        return -LINUX_EAGAIN;
    }
    (void)kernel_current_identity(&pid, &uid, &gid);
    memset(message, 0, total);
    header = (struct fuse_in_header *)message;
    header->len = total;
    header->opcode = opcode;
    header->unique = request->unique;
    header->nodeid = nodeid;
    header->uid = uid;
    header->gid = gid;
    header->pid = pid > 0 ? (uint32_t)pid : (uint32_t)kernel_current_pid();
    if (input_length)
        memcpy(message + sizeof(*header), input, input_length);
    if (tail_length)
        memcpy(message + sizeof(*header) + input_length, tail, tail_length);
    flags = spin_lock_irqsave(&session->lock);
    request->request_length = total;
    request->input_length = input_length;
    request->tail_length = tail_length;
    request->reply_length = 0;
    request->state = FUSE_REQUEST_QUEUED;
    spin_unlock_irqrestore(&session->lock, flags);
    kernel_runtime_fuse_notify(session->description_identity);
    fuse_uring_dispatch(session);

wait_for_reply:
    for (;;) {
        uint8_t state;
        flags = spin_lock_irqsave(&session->lock);
        state = request->state;
        if (!session->daemon_open && state != FUSE_REQUEST_REPLIED) {
            memset(request, 0, sizeof(*request));
            spin_unlock_irqrestore(&session->lock, flags);
            fuse_free_pages(message, FUSE_MESSAGE_PAGES);
            return -LINUX_ENODEV;
        }
        spin_unlock_irqrestore(&session->lock, flags);
        if (state == FUSE_REQUEST_REPLIED) break;
        kernel_runtime_fuse_reply_wait(session->description_identity);
        kernel_runtime_fuse_notify(session->description_identity);
        (void)kernel_runtime_yield();
    }

    flags = spin_lock_irqsave(&session->lock);
    if (request->reply_length < sizeof(*reply)) {
        error = -LINUX_EIO;
    } else {
        uint32_t payload_length;
        reply = (struct fuse_out_header *)message;
        if (reply->unique != request->unique ||
            reply->len != request->reply_length ||
            reply->len < sizeof(*reply)) {
            error = -LINUX_EIO;
        } else if (reply->error) {
            error = reply->error;
        } else {
            payload_length = reply->len - sizeof(*reply);
            if (payload_length > output_capacity) {
                error = -LINUX_ERANGE;
            } else {
                if (payload_length && output)
                    memcpy(output, message + sizeof(*reply), payload_length);
                if (output_length) *output_length = payload_length;
                error = 0;
            }
        }
    }
    if (!replay_active) memset(request, 0, sizeof(*request));
    spin_unlock_irqrestore(&session->lock, flags);
    if (!replay_active) fuse_free_pages(message, FUSE_MESSAGE_PAGES);
    return error;
}

static int fuse_initialize(edge_fuse_session_t *session) {
    struct fuse_init_in input;
    struct fuse_init_out output;
    uint32_t length = 0;
    uint64_t flags;
    uintptr_t context = kernel_current_context_token();
    int result;
    if (!session) return -LINUX_EIO;
    for (;;) {
        flags = spin_lock_irqsave(&session->lock);
        if (session->init_state == 2u) {
            spin_unlock_irqrestore(&session->lock, flags);
            /*
             * Reserve the initialization position in every replay journal.
             * The first retry may still own a completed FUSE_INIT request;
             * later calls consume an empty position.  Either way, subsequent
             * operations keep identical sequence numbers before and after a
             * scheduler handoff.
             */
            return fuse_replay_consume_cached(session, FUSE_INIT, 0u);
        }
        if (session->init_state == 3u || !session->daemon_open) {
            spin_unlock_irqrestore(&session->lock, flags);
            return -LINUX_ENODEV;
        }
        if (session->init_state == 0u) {
            session->init_state = 1u;
            session->init_owner_context = context;
            spin_unlock_irqrestore(&session->lock, flags);
            break;
        }
        if (session->init_state == 1u &&
            session->init_owner_context == context) {
            spin_unlock_irqrestore(&session->lock, flags);
            break;
        }
        spin_unlock_irqrestore(&session->lock, flags);
        (void)kernel_runtime_yield();
    }
    memset(&input, 0, sizeof(input));
    input.major = FUSE_KERNEL_VERSION;
    input.minor = FUSE_KERNEL_MINOR_VERSION;
    input.max_readahead = 65536u;
    input.flags = FUSE_ASYNC_READ | FUSE_ATOMIC_O_TRUNC |
                  FUSE_BIG_WRITES | FUSE_AUTO_INVAL_DATA |
                  FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO |
                  FUSE_ASYNC_DIO | FUSE_MAX_PAGES;
    memset(&output, 0, sizeof(output));
    result = fuse_rpc(session, FUSE_INIT, 0u, &input, sizeof(input),
                      0, 0, &output, sizeof(output), &length);
    flags = spin_lock_irqsave(&session->lock);
    if (result == 0 && length >= 24u && output.major == FUSE_KERNEL_VERSION) {
        session->max_write = output.max_write;
        if (!session->max_write || session->max_write > 65536u)
            session->max_write = 65536u;
        session->init_state = 2u;
    } else {
        session->init_state = 3u;
        if (result == 0) result = -LINUX_EIO;
    }
    session->init_owner_context = 0;
    spin_unlock_irqrestore(&session->lock, flags);
    return result;
}

static int fuse_rpc_ready(edge_fuse_session_t *session, uint32_t opcode,
                          uint64_t nodeid, const void *input,
                          uint32_t input_length, const void *tail,
                          uint32_t tail_length, void *output,
                          uint32_t output_capacity, uint32_t *output_length) {
    int result = fuse_initialize(session);
    if (result < 0) return result;
    return fuse_rpc(session, opcode, nodeid, input, input_length,
                    tail, tail_length, output, output_capacity, output_length);
}

static edge_fuse_session_t *fuse_state(vfs_superblock_t *sb) {
    return sb ? (edge_fuse_session_t *)sb->fs_private : 0;
}

static int fuse_lookup(vfs_superblock_t *sb, vfs_inode_t *dir,
                       const char *name, vfs_inode_t *out) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_entry_out entry;
    uint64_t nodeid = fuse_nodeid(session, dir);
    uint32_t length = 0;
    int result;
    if (!name || !name[0] || strlen(name) >= VFS_NAME_MAX) return -1;
    result = fuse_rpc_ready(session, FUSE_LOOKUP, nodeid, 0, 0,
                            name, (uint32_t)strlen(name) + 1u,
                            &entry, sizeof(entry), &length);
    if (result < 0 || length < sizeof(entry) || !entry.nodeid) return -1;
    return fuse_fill_inode(session, entry.nodeid, &entry.attr, out);
}

static int fuse_getattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                        vfs_inode_t *out) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_getattr_in input;
    struct fuse_attr_out attr;
    uint64_t nodeid = fuse_nodeid(session, inode);
    uint32_t length = 0;
    memset(&input, 0, sizeof(input));
    if (fuse_rpc_ready(session, FUSE_GETATTR, nodeid, &input, sizeof(input),
                       0, 0, &attr, sizeof(attr), &length) < 0 ||
        length < sizeof(attr)) return -1;
    return fuse_fill_inode(session, nodeid, &attr.attr, out);
}

static int fuse_open_handle(edge_fuse_session_t *session,
                            const vfs_inode_t *inode, uint32_t flags_value,
                            int directory, uint64_t *handle) {
    struct fuse_open_in input;
    struct fuse_open_out output;
    edge_fuse_node_t *node;
    uint32_t index, length = 0;
    uint64_t nodeid;
    uint8_t *valid;
    uint64_t *stored;
    if (!session || !inode || !handle) return -LINUX_EIO;
    index = inode->fs_private[0];
    nodeid = fuse_nodeid(session, inode);
    node = fuse_node_by_index(session, index);
    if (!nodeid || !node) return -LINUX_EIO;
    if (directory) { valid = &node->dir_fh_valid; stored = &node->dir_fh; }
    else if ((flags_value & 3u) == LINUX_O_RDONLY) {
        valid = &node->read_fh_valid; stored = &node->read_fh;
    } else { valid = &node->write_fh_valid; stored = &node->write_fh; }
    if (__atomic_load_n(valid, __ATOMIC_ACQUIRE)) {
        int replay_result = fuse_initialize(session);
        if (replay_result < 0) return replay_result;
        replay_result = fuse_replay_consume_cached(
            session, directory ? FUSE_OPENDIR : FUSE_OPEN, nodeid);
        if (replay_result < 0) return replay_result;
        *handle = __atomic_load_n(stored, __ATOMIC_ACQUIRE);
        return 0;
    }
    memset(&input, 0, sizeof(input));
    input.flags = flags_value;
    memset(&output, 0, sizeof(output));
    if (fuse_rpc_ready(session, directory ? FUSE_OPENDIR : FUSE_OPEN,
                       nodeid, &input, sizeof(input), 0, 0,
                       &output, sizeof(output), &length) < 0 ||
        length < sizeof(output)) return -LINUX_EIO;
    __atomic_store_n(stored, output.fh, __ATOMIC_RELEASE);
    __atomic_store_n(valid, 1u, __ATOMIC_RELEASE);
    *handle = output.fh;
    return 0;
}

static int fuse_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off,
                     void *buffer, uint32_t length) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_read_in input;
    uint64_t handle, nodeid = fuse_nodeid(session, inode);
    uint32_t received = 0;
    if (!buffer && length) return -1;
    if (length > 65536u) length = 65536u;
    if (fuse_open_handle(session, inode, LINUX_O_RDONLY, 0, &handle) < 0)
        return -1;
    memset(&input, 0, sizeof(input));
    input.fh = handle;
    input.offset = off;
    input.size = length;
    if (fuse_rpc_ready(session, FUSE_READ, nodeid, &input, sizeof(input),
                       0, 0, buffer, length, &received) < 0) return -1;
    return (int)received;
}

static int fuse_write(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off,
                      const void *buffer, uint32_t length) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_write_in input;
    struct fuse_write_out output;
    uint64_t handle, nodeid = fuse_nodeid(session, inode);
    uint32_t output_length = 0;
    if (!buffer && length) return -1;
    if (length > session->max_write) length = session->max_write;
    if (fuse_open_handle(session, inode, LINUX_O_WRONLY, 0, &handle) < 0)
        return -1;
    memset(&input, 0, sizeof(input));
    input.fh = handle;
    input.offset = off;
    input.size = length;
    if (fuse_rpc_ready(session, FUSE_WRITE, nodeid, &input, sizeof(input),
                       buffer, length, &output, sizeof(output),
                       &output_length) < 0 || output_length < sizeof(output))
        return -1;
    return (int)output.size;
}

static int fuse_entry_operation(vfs_superblock_t *sb, vfs_inode_t *dir,
                                const char *name, uint32_t opcode,
                                const void *input, uint32_t input_length,
                                const char *extra, vfs_inode_t *out) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_entry_out entry;
    uint8_t names[VFS_NAME_MAX * 2u];
    uint32_t name_length, tail_length, length = 0;
    int result;
    if (!name || !name[0]) return VFS_PATH_ERR_INVALID;
    name_length = (uint32_t)strlen(name) + 1u;
    if (name_length > VFS_NAME_MAX) return VFS_PATH_ERR_INVALID;
    memcpy(names, name, name_length);
    tail_length = name_length;
    if (extra) {
        uint32_t extra_length = (uint32_t)strlen(extra) + 1u;
        if (tail_length + extra_length > sizeof(names))
            return VFS_PATH_ERR_INVALID;
        memcpy(names + tail_length, extra, extra_length);
        tail_length += extra_length;
    }
    memset(&entry, 0, sizeof(entry));
    result = fuse_rpc_ready(session, opcode, fuse_nodeid(session, dir),
                            input, input_length, names, tail_length,
                            &entry, sizeof(entry), &length);
    if (result == -LINUX_EEXIST) return VFS_PATH_ERR_EXISTS;
    if (result < 0 || length < sizeof(entry) || !entry.nodeid)
        return VFS_PATH_ERR_IO;
    return fuse_fill_inode(session, entry.nodeid, &entry.attr, out) < 0 ?
           VFS_PATH_ERR_IO : 0;
}

static int fuse_create(vfs_superblock_t *sb, vfs_inode_t *dir,
                       const char *name, uint16_t mode, vfs_inode_t *out) {
    struct fuse_create_in input;
    struct { struct fuse_entry_out entry; struct fuse_open_out open; } reply;
    edge_fuse_session_t *session = fuse_state(sb);
    uint32_t length = 0, name_length;
    int result;
    memset(&input, 0, sizeof(input));
    input.flags = LINUX_O_RDWR;
    input.mode = VFS_INODE_FILE | (mode & 07777u);
    name_length = (uint32_t)strlen(name) + 1u;
    if (name_length > VFS_NAME_MAX) return VFS_PATH_ERR_INVALID;
    result = fuse_rpc_ready(session, FUSE_CREATE, fuse_nodeid(session, dir),
                            &input, sizeof(input), name, name_length,
                            &reply, sizeof(reply), &length);
    if (result == -LINUX_EEXIST) return VFS_PATH_ERR_EXISTS;
    if (result < 0 || length < sizeof(reply)) return VFS_PATH_ERR_IO;
    if (fuse_fill_inode(session, reply.entry.nodeid,
                        &reply.entry.attr, out) < 0) return VFS_PATH_ERR_IO;
    {
        edge_fuse_node_t *node =
            fuse_node_by_index(session, out->fs_private[0]);
        if (!node) return VFS_PATH_ERR_IO;
        node->write_fh = reply.open.fh;
        node->write_fh_valid = 1u;
    }
    return 0;
}

static int fuse_mkdir(vfs_superblock_t *sb, vfs_inode_t *dir,
                      const char *name, uint16_t mode, vfs_inode_t *out) {
    struct fuse_mkdir_in input;
    memset(&input, 0, sizeof(input));
    input.mode = VFS_INODE_DIR | (mode & 07777u);
    return fuse_entry_operation(sb, dir, name, FUSE_MKDIR,
                                &input, sizeof(input), 0, out);
}

static int fuse_mknod(vfs_superblock_t *sb, vfs_inode_t *dir,
                      const char *name, uint16_t mode, uint64_t rdev,
                      vfs_inode_t *out) {
    struct fuse_mknod_in input;
    memset(&input, 0, sizeof(input));
    input.mode = mode;
    input.rdev = (uint32_t)rdev;
    return fuse_entry_operation(sb, dir, name, FUSE_MKNOD,
                                &input, sizeof(input), 0, out);
}

static int fuse_symlink(vfs_superblock_t *sb, vfs_inode_t *dir,
                        const char *name, const char *target, uint16_t mode,
                        vfs_inode_t *out) {
    (void)mode;
    return fuse_entry_operation(sb, dir, name, FUSE_SYMLINK,
                                0, 0, target, out);
}

static int fuse_name_operation(vfs_superblock_t *sb, vfs_inode_t *dir,
                               const char *name, uint32_t opcode) {
    edge_fuse_session_t *session = fuse_state(sb);
    uint32_t name_length = (uint32_t)strlen(name) + 1u;
    int result;
    if (name_length > VFS_NAME_MAX) return VFS_PATH_ERR_INVALID;
    result = fuse_rpc_ready(session, opcode, fuse_nodeid(session, dir),
                            0, 0, name, name_length, 0, 0, 0);
    if (result == -LINUX_ENOENT) return VFS_PATH_ERR_NOT_FOUND;
    if (result == -LINUX_ENOTEMPTY) return VFS_PATH_ERR_NOT_EMPTY;
    return result < 0 ? VFS_PATH_ERR_IO : 0;
}

static int fuse_unlink(vfs_superblock_t *sb, vfs_inode_t *dir,
                       const char *name) {
    return fuse_name_operation(sb, dir, name, FUSE_UNLINK);
}

static int fuse_rmdir(vfs_superblock_t *sb, vfs_inode_t *dir,
                      const char *name) {
    return fuse_name_operation(sb, dir, name, FUSE_RMDIR);
}

static int fuse_rename(vfs_superblock_t *sb, vfs_inode_t *old_dir,
                       const char *old_name, vfs_inode_t *new_dir,
                       const char *new_name) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_rename_in input;
    uint8_t names[VFS_NAME_MAX * 2u];
    uint32_t old_length = (uint32_t)strlen(old_name) + 1u;
    uint32_t new_length = (uint32_t)strlen(new_name) + 1u;
    if (old_length > VFS_NAME_MAX || new_length > VFS_NAME_MAX)
        return VFS_PATH_ERR_INVALID;
    input.newdir = fuse_nodeid(session, new_dir);
    memcpy(names, old_name, old_length);
    memcpy(names + old_length, new_name, new_length);
    return fuse_rpc_ready(session, FUSE_RENAME,
                          fuse_nodeid(session, old_dir), &input,
                          sizeof(input), names, old_length + new_length,
                          0, 0, 0) < 0 ? VFS_PATH_ERR_IO : 0;
}

static int fuse_link(vfs_superblock_t *sb, vfs_inode_t *inode,
                     vfs_inode_t *dir, const char *name) {
    struct fuse_link_in input;
    vfs_inode_t ignored;
    input.oldnodeid = fuse_nodeid(fuse_state(sb), inode);
    return fuse_entry_operation(sb, dir, name, FUSE_LINK,
                                &input, sizeof(input), 0, &ignored);
}

static int fuse_readlink(vfs_superblock_t *sb, vfs_inode_t *inode,
                         char *out, uint32_t maximum) {
    uint32_t length = 0;
    if (!out || maximum < 2u) return -1;
    if (fuse_rpc_ready(fuse_state(sb), FUSE_READLINK,
                       fuse_nodeid(fuse_state(sb), inode), 0, 0, 0, 0,
                       out, maximum - 1u, &length) < 0) return -1;
    out[length] = 0;
    return (int)length;
}

static int fuse_setattr_request(vfs_superblock_t *sb,
                                const vfs_inode_t *inode,
                                struct fuse_setattr_in *input) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_attr_out output;
    uint32_t length = 0;
    return fuse_rpc_ready(session, FUSE_SETATTR,
                          fuse_nodeid(session, inode), input, sizeof(*input),
                          0, 0, &output, sizeof(output), &length) < 0 ||
           length < sizeof(output) ? -1 : 0;
}

static int fuse_truncate(vfs_superblock_t *sb, vfs_inode_t *inode,
                         uint32_t length) {
    struct fuse_setattr_in input;
    memset(&input, 0, sizeof(input));
    input.valid = FUSE_SET_ATTR_SIZE;
    input.size = length;
    return fuse_setattr_request(sb, inode, &input) < 0 ?
           VFS_TRUNCATE_ERR_IO : 0;
}

static int fuse_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                        uint16_t mode, uint32_t uid, uint32_t gid,
                        uint32_t valid) {
    struct fuse_setattr_in input;
    memset(&input, 0, sizeof(input));
    if (valid & VFS_SETATTR_MODE) input.valid |= FUSE_SET_ATTR_MODE;
    if (valid & VFS_SETATTR_UID) input.valid |= FUSE_SET_ATTR_UID;
    if (valid & VFS_SETATTR_GID) input.valid |= FUSE_SET_ATTR_GID;
    input.mode = mode;
    input.uid = uid;
    input.gid = gid;
    return fuse_setattr_request(sb, inode, &input);
}

static int fuse_settimes(vfs_superblock_t *sb, const vfs_inode_t *inode,
                         uint32_t atime, uint32_t mtime,
                         int set_atime, int set_mtime) {
    struct fuse_setattr_in input;
    memset(&input, 0, sizeof(input));
    if (set_atime) input.valid |= FUSE_SET_ATTR_ATIME;
    if (set_mtime) input.valid |= FUSE_SET_ATTR_MTIME;
    input.atime = atime;
    input.mtime = mtime;
    return fuse_setattr_request(sb, inode, &input);
}

static int fuse_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t index,
                        char *name_out, vfs_inode_t *inode_out) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_read_in input;
    uint8_t *buffer;
    uint64_t handle, nodeid = fuse_nodeid(session, dir);
    uint32_t length = 0, position = 0, ordinal = 0;
    int result = -1;
    if (!name_out || !inode_out ||
        fuse_open_handle(session, dir, LINUX_O_RDONLY, 1, &handle) < 0)
        return -1;
    buffer = (uint8_t *)arch_vm_alloc_pages(
        (FUSE_READDIR_BUFFER + 4095u) / 4096u);
    if (!buffer) return -1;
    memset(&input, 0, sizeof(input));
    input.fh = handle;
    input.size = FUSE_READDIR_BUFFER;
    if (fuse_rpc_ready(session, FUSE_READDIR, nodeid, &input, sizeof(input),
                       0, 0, buffer, FUSE_READDIR_BUFFER, &length) < 0)
        goto out;
    while (position + sizeof(struct fuse_dirent) <= length) {
        struct fuse_dirent *entry = (struct fuse_dirent *)(buffer + position);
        uint32_t size = FUSE_DIRENT_SIZE(entry->namelen);
        if (!entry->namelen || entry->namelen >= VFS_NAME_MAX ||
            position + size > length) break;
        if (ordinal++ == index) {
            vfs_inode_t found;
            memcpy(name_out, entry->name, entry->namelen);
            name_out[entry->namelen] = 0;
            if (fuse_lookup(sb, dir, name_out, &found) == 0) {
                *inode_out = found;
                result = 0;
            }
            break;
        }
        position += size;
    }
out:
    fuse_free_pages(buffer, (FUSE_READDIR_BUFFER + 4095u) / 4096u);
    return result;
}

static int fuse_statfs(vfs_superblock_t *sb, uint32_t *total_kb,
                       uint32_t *used_kb) {
    struct fuse_statfs_out output;
    uint32_t length = 0;
    uint64_t total, free_blocks;
    if (fuse_rpc_ready(fuse_state(sb), FUSE_STATFS, 1u, 0, 0, 0, 0,
                       &output, sizeof(output), &length) < 0 ||
        length < sizeof(output)) return -1;
    total = output.st.blocks * output.st.bsize / 1024u;
    free_blocks = output.st.bfree * output.st.bsize / 1024u;
    if (total_kb) *total_kb = total > UINT32_MAX ? UINT32_MAX : (uint32_t)total;
    if (used_kb) {
        uint64_t used = total > free_blocks ? total - free_blocks : 0;
        *used_kb = used > UINT32_MAX ? UINT32_MAX : (uint32_t)used;
    }
    return 0;
}

static int fuse_sync_inode(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           int data_only) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_fsync_in input;
    edge_fuse_node_t *node;
    uint32_t index = inode->fs_private[0];
    node = fuse_node_by_index(session, index);
    if (!node) return -1;
    if (!node->read_fh_valid && !node->write_fh_valid) return 0;
    memset(&input, 0, sizeof(input));
    input.fh = node->write_fh_valid ? node->write_fh : node->read_fh;
    input.fsync_flags = data_only ? 1u : 0u;
    return fuse_rpc_ready(session, FUSE_FSYNC, fuse_nodeid(session, inode),
                          &input, sizeof(input), 0, 0, 0, 0, 0);
}

static int fuse_sync(vfs_superblock_t *sb) {
    edge_fuse_session_t *session = fuse_state(sb);

    if (!session) return -1;
    for (edge_fuse_node_page_t *page = session->node_pages;
         page; page = page->next) {
        for (uint32_t slot = 0; slot < FUSE_NODES_PER_PAGE; ++slot) {
            edge_fuse_node_t *node = &page->nodes[slot];
            vfs_inode_t inode;
            if (!node->used ||
                (!node->read_fh_valid && !node->write_fh_valid))
                continue;
            memset(&inode, 0, sizeof(inode));
            inode.fs_private[0] = page->base_index + slot;
            inode.fs_private[1] = node->generation;
            if (fuse_sync_inode(sb, &inode, 0) < 0) return -1;
        }
    }
    return 0;
}

static int fuse_fallocate(vfs_superblock_t *sb, vfs_inode_t *inode,
                          uint32_t mode, uint64_t offset, uint64_t length) {
    edge_fuse_session_t *session = fuse_state(sb);
    struct fuse_fallocate_in input;
    uint64_t handle;
    if (fuse_open_handle(session, inode, LINUX_O_WRONLY, 0, &handle) < 0)
        return VFS_FALLOCATE_ERR_IO;
    memset(&input, 0, sizeof(input));
    input.fh = handle;
    input.offset = offset;
    input.length = length;
    input.mode = mode;
    return fuse_rpc_ready(session, FUSE_FALLOCATE,
                          fuse_nodeid(session, inode), &input, sizeof(input),
                          0, 0, 0, 0, 0) < 0 ? VFS_FALLOCATE_ERR_IO : 0;
}

static int fuse_xattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                      uint32_t opcode, const char *name, const void *input,
                      uint32_t input_length, const void *value,
                      uint32_t value_length, void *output,
                      uint32_t output_capacity) {
    edge_fuse_session_t *session = fuse_state(sb);
    uint8_t *tail;
    uint32_t name_length = name ? (uint32_t)strlen(name) + 1u : 0u;
    uint32_t tail_length = name_length + value_length;
    uint32_t output_length = 0;
    int result;
    if (tail_length > FUSE_MESSAGE_MAX - 256u) return -LINUX_ERANGE;
    tail = (uint8_t *)arch_vm_alloc_pages((tail_length + 4095u) / 4096u);
    if (!tail && tail_length) return -LINUX_ENOMEM;
    if (name_length) memcpy(tail, name, name_length);
    if (value_length) memcpy(tail + name_length, value, value_length);
    result = fuse_rpc_ready(session, opcode, fuse_nodeid(session, inode),
                            input, input_length, tail, tail_length,
                            output, output_capacity, &output_length);
    fuse_free_pages(tail, (tail_length + 4095u) / 4096u);
    return result < 0 ? result : (int)output_length;
}

static int fuse_setxattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                         const char *name, const void *value, uint32_t size,
                         uint32_t flags) {
    struct fuse_setxattr_in input;
    memset(&input, 0, sizeof(input));
    input.size = size;
    input.flags = flags;
    return fuse_xattr(sb, inode, FUSE_SETXATTR, name, &input, sizeof(input),
                      value, size, 0, 0) < 0 ? VFS_XATTR_ERR_IO : 0;
}

static int fuse_getxattr_common(vfs_superblock_t *sb,
                                const vfs_inode_t *inode, uint32_t opcode,
                                const char *name, void *value, uint32_t size) {
    struct fuse_getxattr_in input;
    struct fuse_getxattr_out output;
    int result;
    memset(&input, 0, sizeof(input));
    input.size = size;
    if (!size) {
        result = fuse_xattr(sb, inode, opcode, name, &input, sizeof(input),
                            0, 0, &output, sizeof(output));
        return result < (int)sizeof(output) ? VFS_XATTR_ERR_IO :
               (int)output.size;
    }
    result = fuse_xattr(sb, inode, opcode, name, &input, sizeof(input),
                        0, 0, value, size);
    if (result == -LINUX_ENODATA) return VFS_XATTR_ERR_NO_DATA;
    if (result == -LINUX_ERANGE) return VFS_XATTR_ERR_RANGE;
    return result < 0 ? VFS_XATTR_ERR_IO : result;
}

static int fuse_getxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                         const char *name, void *value, uint32_t size) {
    return fuse_getxattr_common(sb, inode, FUSE_GETXATTR,
                                name, value, size);
}

static int fuse_listxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                          char *list, uint32_t size) {
    return fuse_getxattr_common(sb, inode, FUSE_LISTXATTR, 0, list, size);
}

static int fuse_removexattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                            const char *name) {
    return fuse_xattr(sb, inode, FUSE_REMOVEXATTR, name, 0, 0,
                      0, 0, 0, 0) < 0 ? VFS_XATTR_ERR_IO : 0;
}

static filesystem_ops_t g_fuse_ops = {
    .lookup = fuse_lookup, .read = fuse_read, .write = fuse_write,
    .create = fuse_create, .mkdir = fuse_mkdir, .symlink = fuse_symlink,
    .readlink = fuse_readlink, .unlink = fuse_unlink, .rename = fuse_rename,
    .truncate = fuse_truncate, .readdir = fuse_readdir,
    .statfs = fuse_statfs, .sync = fuse_sync, .link = fuse_link,
    .rmdir = fuse_rmdir, .mknod = fuse_mknod,
    .fallocate = fuse_fallocate, .setxattr = fuse_setxattr,
    .getxattr = fuse_getxattr, .listxattr = fuse_listxattr,
    .removexattr = fuse_removexattr, .getattr = fuse_getattr,
    .settimes = fuse_settimes, .setattr = fuse_setattr,
    .sync_inode = fuse_sync_inode,
};

static int fuse_mount_option_u32(const char *options, const char *key,
                                 uint32_t base, uint32_t *value,
                                 int *present) {
    const char *cursor = options;
    uint32_t key_length;

    if (!key || !key[0] || !value || !present ||
        (base != 8u && base != 10u))
        return -1;
    key_length = (uint32_t)strlen(key);
    *present = 0;
    while (cursor && *cursor) {
        const char *field = cursor;
        uint64_t parsed = 0;
        uint32_t digits = 0;

        while (*cursor && *cursor != ',') ++cursor;
        if ((uint32_t)(cursor - field) > key_length &&
            strncmp(field, key, key_length) == 0 &&
            field[key_length] == '=') {
            const char *number = field + key_length + 1u;
            while (number < cursor) {
                uint32_t digit;
                if (*number < '0' || *number > '9') return -1;
                digit = (uint32_t)(*number++ - '0');
                if (digit >= base || parsed > (UINT32_MAX - digit) / base)
                    return -1;
                parsed = parsed * base + digit;
                ++digits;
            }
            if (!digits) return -1;
            *value = (uint32_t)parsed;
            *present = 1;
            return 0;
        }
        if (*cursor == ',') ++cursor;
    }
    return 0;
}

int edge_fuse_is_device(uint64_t linux_rdev) {
    uint32_t major = (uint32_t)((linux_rdev >> 8) & 0xfffu) |
                     (uint32_t)((linux_rdev >> 32) & ~0xfffull);
    uint32_t minor = (uint32_t)(linux_rdev & 0xffu) |
                     (uint32_t)((linux_rdev >> 12) & ~0xffull);
    return major == EDGE_FUSE_DEVICE_MAJOR && minor == EDGE_FUSE_DEVICE_MINOR;
}

static void fuse_uring_command_cancel(
        int32_t ring_id, uint64_t command_id, uint64_t token) {
    edge_fuse_uring_entry_t *entry =
        (edge_fuse_uring_entry_t *)(uintptr_t)token;
    edge_fuse_session_t *session = 0;
    uint64_t flags;

    if (!entry || !command_id) return;
    for (uint32_t index = 0; index < FUSE_SESSION_MAX; ++index) {
        uintptr_t candidate = (uintptr_t)entry;
        uintptr_t first = (uintptr_t)
            &g_fuse_sessions[index].uring_entries[0];
        uintptr_t last = (uintptr_t)
            &g_fuse_sessions[index].uring_entries[FUSE_URING_ENTRY_MAX];

        if (candidate >= first && candidate < last) {
            session = &g_fuse_sessions[index];
            break;
        }
    }
    if (!session) return;
    flags = spin_lock_irqsave(&session->lock);
    if (entry->state != FUSE_URING_ENTRY_FREE &&
        entry->ring_id == ring_id &&
        (!entry->command_id || entry->command_id == command_id))
        memset(entry, 0, sizeof(*entry));
    spin_unlock_irqrestore(&session->lock, flags);
}

static int fuse_uring_copy_request(
        const edge_fuse_uring_entry_t *entry,
        const edge_fuse_request_t *request) {
    edge_fuse_uring_ent_in_out_t ring_header;
    uint8_t headers[FUSE_URING_HEADER_LENGTH];

    if (!entry || !request || !request->message ||
        request->request_length < sizeof(struct fuse_in_header) ||
        request->input_length > 128u ||
        request->tail_length > entry->payload_length)
        return -LINUX_EINVAL;
    memset(headers, 0, sizeof(headers));
    memcpy(headers + FUSE_URING_IN_OUT_OFFSET, request->message,
           sizeof(struct fuse_in_header));
    if (request->input_length)
        memcpy(headers + FUSE_URING_OP_OFFSET,
               request->message + sizeof(struct fuse_in_header),
               request->input_length);
    memset(&ring_header, 0, sizeof(ring_header));
    ring_header.commit_id = request->unique;
    ring_header.payload_size = request->tail_length;
    memcpy(headers + FUSE_URING_ENTRY_OFFSET,
           &ring_header, sizeof(ring_header));
    if (kernel_mm_address_space_copy(
            entry->address_space, entry->headers_address,
            headers, sizeof(headers),
            KERNEL_MM_PROCESS_VM_WRITE) < 0)
        return -LINUX_EFAULT;
    if (request->tail_length && kernel_mm_address_space_copy(
            entry->address_space, entry->payload_address,
            request->message + sizeof(struct fuse_in_header) +
                request->input_length,
            request->tail_length,
            KERNEL_MM_PROCESS_VM_WRITE) < 0)
        return -LINUX_EFAULT;
    return 0;
}

static void fuse_uring_dispatch(edge_fuse_session_t *session) {
    for (;;) {
        edge_fuse_uring_entry_t entry_snapshot;
        edge_fuse_uring_entry_t *entry = 0;
        edge_fuse_request_t *request = 0;
        uint64_t flags;
        uint64_t command_id;
        int32_t ring_id;
        int result;

        if (!session) return;
        flags = spin_lock_irqsave(&session->lock);
        for (uint32_t index = 0;
             index < FUSE_URING_ENTRY_MAX; ++index) {
            if (session->uring_entries[index].state ==
                    FUSE_URING_ENTRY_AVAILABLE &&
                session->uring_entries[index].command_id) {
                entry = &session->uring_entries[index];
                break;
            }
        }
        for (uint32_t index = 0; entry && index < FUSE_REQUEST_MAX;
             ++index) {
            if (session->requests[index].state == FUSE_REQUEST_QUEUED) {
                request = &session->requests[index];
                break;
            }
        }
        if (!entry || !request) {
            spin_unlock_irqrestore(&session->lock, flags);
            return;
        }
        entry->state = FUSE_URING_ENTRY_DELIVERING;
        request->state = FUSE_REQUEST_READING;
        entry_snapshot = *entry;
        spin_unlock_irqrestore(&session->lock, flags);

        result = fuse_uring_copy_request(&entry_snapshot, request);
        command_id = entry_snapshot.command_id;
        ring_id = entry_snapshot.ring_id;

        flags = spin_lock_irqsave(&session->lock);
        if (entry->state == FUSE_URING_ENTRY_DELIVERING &&
            entry->command_id == command_id &&
            request->state == FUSE_REQUEST_READING) {
            if (result == 0) {
                entry->state = FUSE_URING_ENTRY_USERSPACE;
                entry->commit_id = request->unique;
                entry->command_id = 0u;
                request->state = FUSE_REQUEST_DELIVERED;
            } else {
                memset(entry, 0, sizeof(*entry));
                request->state = FUSE_REQUEST_QUEUED;
            }
        }
        spin_unlock_irqrestore(&session->lock, flags);

        if (kernel_io_uring_command_complete(
                ring_id, command_id, result, 0u) < 0 && result == 0) {
            flags = spin_lock_irqsave(&session->lock);
            if (entry->state == FUSE_URING_ENTRY_USERSPACE &&
                entry->commit_id == request->unique) {
                memset(entry, 0, sizeof(*entry));
                if (request->state == FUSE_REQUEST_DELIVERED)
                    request->state = FUSE_REQUEST_QUEUED;
            }
            spin_unlock_irqrestore(&session->lock, flags);
        }
    }
}

static int fuse_uring_register(
        edge_fuse_session_t *session,
        const edge_fuse_uring_command_t *command) {
    edge_fuse_uring_entry_t *entry = 0;
    uint64_t command_id = 0u;
    uint64_t flags;
    uint32_t cpu_count = edge_smp_present_count();
    int result;

    if (!session || !command) return -LINUX_EINVAL;
    if (!cpu_count) cpu_count = 1u;
    if (command->qid >= cpu_count ||
        command->headers_length < FUSE_URING_HEADER_LENGTH ||
        command->payload_length < FUSE_URING_MIN_PAYLOAD ||
        command->payload_length < session->max_write)
        return -LINUX_EINVAL;
    flags = spin_lock_irqsave(&session->lock);
    if (!session->daemon_open) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_ENODEV;
    }
    if (session->init_state != 2u) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_EAGAIN;
    }
    for (uint32_t index = 0; index < FUSE_URING_ENTRY_MAX; ++index) {
        if (session->uring_entries[index].state !=
            FUSE_URING_ENTRY_FREE)
            continue;
        entry = &session->uring_entries[index];
        memset(entry, 0, sizeof(*entry));
        entry->state = FUSE_URING_ENTRY_AVAILABLE;
        entry->qid = command->qid;
        entry->ring_id = command->ring_id;
        entry->descriptor = command->descriptor;
        entry->address_space = command->address_space;
        entry->headers_address = command->headers_address;
        entry->payload_address = command->payload_address;
        entry->headers_length = command->headers_length;
        entry->payload_length = command->payload_length;
        break;
    }
    spin_unlock_irqrestore(&session->lock, flags);
    if (!entry) return -LINUX_ENOMEM;

    result = kernel_io_uring_command_add(
        command->ring_id, command->user_data,
        command->descriptor, 46u, fuse_uring_command_cancel,
        (uint64_t)(uintptr_t)entry, &command_id);
    flags = spin_lock_irqsave(&session->lock);
    if (result == 0 && entry->state == FUSE_URING_ENTRY_AVAILABLE)
        entry->command_id = command_id;
    else
        memset(entry, 0, sizeof(*entry));
    spin_unlock_irqrestore(&session->lock, flags);
    if (result < 0) return result;
    fuse_uring_dispatch(session);
    return 0;
}

static int fuse_uring_commit_fetch(
        edge_fuse_session_t *session,
        const edge_fuse_uring_command_t *command) {
    edge_fuse_uring_ent_in_out_t ring_header;
    struct fuse_out_header output_header;
    edge_fuse_uring_entry_t *entry = 0;
    edge_fuse_request_t *request = 0;
    uint64_t command_id = 0u;
    uint64_t flags;
    int result;

    uint32_t cpu_count = edge_smp_present_count();

    if (!session || !command || !command->commit_id)
        return -LINUX_EINVAL;
    if (!cpu_count) cpu_count = 1u;
    if (command->qid >= cpu_count ||
        command->headers_length < FUSE_URING_HEADER_LENGTH ||
        command->payload_length < FUSE_URING_MIN_PAYLOAD ||
        command->payload_length < session->max_write)
        return -LINUX_EINVAL;
    flags = spin_lock_irqsave(&session->lock);
    if (!session->daemon_open) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_ENODEV;
    }
    for (uint32_t index = 0; index < FUSE_URING_ENTRY_MAX; ++index) {
        edge_fuse_uring_entry_t *candidate =
            &session->uring_entries[index];
        if (candidate->state == FUSE_URING_ENTRY_USERSPACE &&
            candidate->qid == command->qid &&
            candidate->commit_id == command->commit_id) {
            entry = candidate;
            break;
        }
    }
    for (uint32_t index = 0; entry && index < FUSE_REQUEST_MAX; ++index) {
        if (session->requests[index].state == FUSE_REQUEST_DELIVERED &&
            session->requests[index].unique == command->commit_id) {
            request = &session->requests[index];
            break;
        }
    }
    if (!entry || !request) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_ENOENT;
    }
    entry->state = FUSE_URING_ENTRY_DELIVERING;
    spin_unlock_irqrestore(&session->lock, flags);

    if (kernel_mm_address_space_copy(
            command->address_space,
            command->headers_address + FUSE_URING_IN_OUT_OFFSET,
            &output_header, sizeof(output_header),
            KERNEL_MM_PROCESS_VM_READ) < 0 ||
        kernel_mm_address_space_copy(
            command->address_space,
            command->headers_address + FUSE_URING_ENTRY_OFFSET,
            &ring_header, sizeof(ring_header),
            KERNEL_MM_PROCESS_VM_READ) < 0) {
        result = -LINUX_EFAULT;
        goto restore;
    }
    if (ring_header.flags || ring_header.padding || ring_header.reserved ||
        ring_header.commit_id != command->commit_id ||
        ring_header.payload_size > command->payload_length ||
        output_header.unique != command->commit_id ||
        output_header.len != sizeof(output_header) +
            ring_header.payload_size ||
        output_header.len > FUSE_MESSAGE_MAX) {
        result = -LINUX_EINVAL;
        goto restore;
    }
    if (ring_header.payload_size && kernel_mm_address_space_copy(
            command->address_space,
            command->payload_address,
            request->message + sizeof(output_header),
            ring_header.payload_size,
            KERNEL_MM_PROCESS_VM_READ) < 0) {
        result = -LINUX_EFAULT;
        goto restore;
    }
    memcpy(request->message, &output_header, sizeof(output_header));

    result = kernel_io_uring_command_add(
        command->ring_id, command->user_data,
        command->descriptor, 46u, fuse_uring_command_cancel,
        (uint64_t)(uintptr_t)entry, &command_id);
    if (result < 0) goto restore;

    flags = spin_lock_irqsave(&session->lock);
    request->reply_length = output_header.len;
    request->state = FUSE_REQUEST_REPLIED;
    entry->state = FUSE_URING_ENTRY_AVAILABLE;
    entry->ring_id = command->ring_id;
    entry->descriptor = command->descriptor;
    entry->command_id = command_id;
    entry->address_space = command->address_space;
    entry->headers_address = command->headers_address;
    entry->payload_address = command->payload_address;
    entry->headers_length = command->headers_length;
    entry->payload_length = command->payload_length;
    entry->commit_id = 0u;
    spin_unlock_irqrestore(&session->lock, flags);
    kernel_runtime_fuse_reply_notify(
        session->description_identity, request->owner_context);
    fuse_uring_dispatch(session);
    return 0;

restore:
    flags = spin_lock_irqsave(&session->lock);
    if (entry && entry->state == FUSE_URING_ENTRY_DELIVERING)
        entry->state = FUSE_URING_ENTRY_USERSPACE;
    spin_unlock_irqrestore(&session->lock, flags);
    return result;
}

int edge_fuse_device_uring_cmd(
        uint64_t identity,
        const edge_fuse_uring_command_t *command) {
    edge_fuse_session_t *session = fuse_session_find(identity);

    if (!session) session = fuse_session_create(identity);
    if (!session) return -LINUX_ENOSPC;
    if (!command || command->reserved)
        return -LINUX_EINVAL;
    switch (command->operation) {
    case EDGE_FUSE_IO_URING_CMD_REGISTER:
        return fuse_uring_register(session, command);
    case EDGE_FUSE_IO_URING_CMD_COMMIT_AND_FETCH:
        return fuse_uring_commit_fetch(session, command);
    default:
        return -LINUX_EINVAL;
    }
}

int edge_fuse_device_read(uint64_t identity, void *buffer, uint32_t length) {
    edge_fuse_session_t *session = fuse_session_find(identity);
    edge_fuse_request_t *request = 0;
    uint8_t *message;
    uint32_t request_length;
    uint64_t flags;
    if (!session) session = fuse_session_create(identity);
    if (!session) return -LINUX_ENOSPC;
    if (!buffer && length) return -LINUX_EINVAL;
    flags = spin_lock_irqsave(&session->lock);
    for (uint32_t index = 0; index < FUSE_REQUEST_MAX; ++index) {
        if (session->requests[index].state == FUSE_REQUEST_QUEUED) {
            request = &session->requests[index];
            break;
        }
    }
    if (!request) {
        int result = session->daemon_open ? -LINUX_EAGAIN : -LINUX_ENODEV;
        spin_unlock_irqrestore(&session->lock, flags);
        return result;
    }
    if (length < request->request_length) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_EINVAL;
    }
    request->state = FUSE_REQUEST_READING;
    message = request->message;
    request_length = request->request_length;
    spin_unlock_irqrestore(&session->lock, flags);
    memcpy(buffer, message, request_length);
    flags = spin_lock_irqsave(&session->lock);
    if (request->state == FUSE_REQUEST_READING)
        request->state = FUSE_REQUEST_DELIVERED;
    spin_unlock_irqrestore(&session->lock, flags);
    return (int)request_length;
}

static int fuse_device_notification(
        const struct fuse_out_header *header, const uint8_t *payload,
        uint32_t payload_length) {
    uint32_t name_length;

    if (!header || header->unique || header->error <= 0)
        return -LINUX_EINVAL;
    switch ((uint32_t)header->error) {
        case FUSE_NOTIFY_INVAL_INODE:
            if (payload_length !=
                sizeof(struct fuse_notify_inval_inode_out))
                return -LINUX_EINVAL;
            break;
        case FUSE_NOTIFY_INVAL_ENTRY:
            if (payload_length <
                sizeof(struct fuse_notify_inval_entry_out))
                return -LINUX_EINVAL;
            name_length =
                ((const struct fuse_notify_inval_entry_out *)payload)->namelen;
            if (!name_length || name_length >= VFS_NAME_MAX ||
                payload_length !=
                    sizeof(struct fuse_notify_inval_entry_out) + name_length)
                return -LINUX_EINVAL;
            break;
        case FUSE_NOTIFY_DELETE:
            if (payload_length < sizeof(struct fuse_notify_delete_out))
                return -LINUX_EINVAL;
            name_length =
                ((const struct fuse_notify_delete_out *)payload)->namelen;
            if (!name_length || name_length >= VFS_NAME_MAX ||
                payload_length !=
                    sizeof(struct fuse_notify_delete_out) + name_length)
                return -LINUX_EINVAL;
            break;
        default:
            return -LINUX_EOPNOTSUPP;
    }

    /*
     * EdgeOS currently keeps one global pathname cache.  Invalidating it is
     * intentionally broader than Linux's per-dentry action, but preserves the
     * required coherence when a distributed filesystem changes remotely.
     */
    vfs_path_cache_invalidate_all();
    return (int)header->len;
}

int edge_fuse_device_write(uint64_t identity, const void *buffer,
                           uint32_t length) {
    edge_fuse_session_t *session = fuse_session_find(identity);
    const struct fuse_out_header *header =
        (const struct fuse_out_header *)buffer;
    edge_fuse_request_t *request = 0;
    uint8_t *message;
    uintptr_t owner_context;
    uint64_t flags;
    if (!session) session = fuse_session_create(identity);
    if (!session) return -LINUX_ENOSPC;
    if (!buffer || length < sizeof(*header) || header->len != length ||
        length > FUSE_MESSAGE_MAX) return -LINUX_EINVAL;
    if (!header->unique)
        return fuse_device_notification(
            header, (const uint8_t *)buffer + sizeof(*header),
            length - sizeof(*header));
    flags = spin_lock_irqsave(&session->lock);
    for (uint32_t index = 0; index < FUSE_REQUEST_MAX; ++index) {
        if (session->requests[index].state == FUSE_REQUEST_DELIVERED &&
            session->requests[index].unique == header->unique) {
            request = &session->requests[index];
            break;
        }
    }
    if (!request) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_EINVAL;
    }
    request->state = FUSE_REQUEST_WRITING;
    message = request->message;
    owner_context = request->owner_context;
    spin_unlock_irqrestore(&session->lock, flags);
    memcpy(message, buffer, length);
    flags = spin_lock_irqsave(&session->lock);
    request->reply_length = length;
    request->state = FUSE_REQUEST_REPLIED;
    spin_unlock_irqrestore(&session->lock, flags);
    kernel_runtime_fuse_reply_notify(identity, owner_context);
    return (int)length;
}

int edge_fuse_device_poll(uint64_t identity, uint32_t events) {
    edge_fuse_session_t *session = fuse_session_find(identity);
    uint32_t result = 0;
    uint64_t flags;
    if (!session) session = fuse_session_create(identity);
    if (!session) return -LINUX_ENOSPC;
    flags = spin_lock_irqsave(&session->lock);
    if (events & 0x0001u) {
        for (uint32_t index = 0; index < FUSE_REQUEST_MAX; ++index)
            if (session->requests[index].state == FUSE_REQUEST_QUEUED) {
                result |= 0x0001u;
                break;
            }
    }
    if (events & 0x0004u) result |= 0x0004u;
    if (!session->daemon_open) result |= 0x0010u;
    spin_unlock_irqrestore(&session->lock, flags);
    return (int)result;
}

int edge_fuse_device_ioctl(uint64_t identity, uint32_t command) {
    edge_fuse_session_t *session;
    uint64_t flags;

    if (command != EDGE_FUSE_DEV_IOC_SYNC_INIT)
        return -LINUX_ENOTTY;
    session = fuse_session_find(identity);
    if (!session) session = fuse_session_create(identity);
    if (!session) return -LINUX_ENOSPC;
    flags = spin_lock_irqsave(&session->lock);
    if (session->mounted) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_EINVAL;
    }
    session->sync_init = 1u;
    spin_unlock_irqrestore(&session->lock, flags);
    return 0;
}

void edge_fuse_device_close(uint64_t identity) {
    edge_fuse_session_t *session = fuse_session_find(identity);
    int32_t rings[FUSE_URING_ENTRY_MAX];
    uint64_t commands[FUSE_URING_ENTRY_MAX];
    uint32_t command_count = 0u;
    uint64_t flags;
    if (!session) return;
    flags = spin_lock_irqsave(&session->lock);
    session->daemon_open = 0;
    for (uint32_t index = 0; index < FUSE_URING_ENTRY_MAX; ++index) {
        edge_fuse_uring_entry_t *entry = &session->uring_entries[index];

        if (entry->command_id) {
            rings[command_count] = entry->ring_id;
            commands[command_count++] = entry->command_id;
        }
        memset(entry, 0, sizeof(*entry));
    }
    if (!session->references) session->used = 0;
    spin_unlock_irqrestore(&session->lock, flags);
    kernel_runtime_fuse_notify(identity);
    for (uint32_t index = 0; index < command_count; ++index)
        (void)kernel_io_uring_command_complete(
            rings[index], commands[index],
            -LINUX_ENOTCONN, 0u);
}

int edge_fuse_mount(uint64_t identity, const char *target,
                    const char *filesystem, const char *options) {
    edge_fuse_session_t *session;
    vfs_superblock_t *superblock;
    uint64_t flags;
    uint32_t root_mode = VFS_INODE_DIR | 0755u;
    uint32_t root_uid = 0;
    uint32_t root_gid = 0;
    uint32_t parsed;
    int present;
    int result;

    if (!identity || !target || target[0] != '/') return -LINUX_EINVAL;
    if (fuse_mount_option_u32(
            options, "rootmode", 8u, &parsed, &present) < 0)
        return -LINUX_EINVAL;
    if (present && (parsed & 0170000u) != 0u &&
        (parsed & 0170000u) != VFS_INODE_DIR)
        return -LINUX_EINVAL;
    if (present)
        root_mode = (parsed & 0177777u) | VFS_INODE_DIR;
    if (fuse_mount_option_u32(
            options, "user_id", 10u, &root_uid, &present) < 0 ||
        fuse_mount_option_u32(
            options, "group_id", 10u, &root_gid, &present) < 0)
        return -LINUX_EINVAL;
    session = fuse_session_create(identity);
    if (!session) return -LINUX_ENOSPC;
    flags = spin_lock_irqsave(&session->lock);
    if (session->mounted) {
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_EBUSY;
    }
    session->mounted = 1u;
    spin_unlock_irqrestore(&session->lock, flags);
    superblock = (vfs_superblock_t *)arch_vm_alloc_pages(
        FUSE_SUPERBLOCK_PAGES);
    if (!superblock) {
        flags = spin_lock_irqsave(&session->lock);
        session->mounted = 0;
        spin_unlock_irqrestore(&session->lock, flags);
        return -LINUX_ENOMEM;
    }
    memset(superblock, 0, sizeof(*superblock));
    strncpy(superblock->fs_name,
            filesystem && filesystem[0] ? filesystem : "fuse",
            sizeof(superblock->fs_name) - 1u);
    strcpy(superblock->dev_name, "fuse");
    strncpy(superblock->mountpoint, target,
            sizeof(superblock->mountpoint) - 1u);
    superblock->root.ino = 1u;
    superblock->root.mode = (uint16_t)root_mode;
    superblock->root.uid = root_uid;
    superblock->root.gid = root_gid;
    superblock->root.nlink = 2u;
    superblock->root.nlink_valid = 1u;
    superblock->root.fs_private[0] = 0u;
    superblock->root.fs_private[1] = session->generation;
    superblock->ops = &g_fuse_ops;
    superblock->fs_private = session;
    superblock->runtime_flags = VFS_SUPERBLOCK_DYNAMIC_LOOKUP;
    superblock->retain = fuse_session_retain;
    superblock->release = fuse_session_release;
    result = vfs_add_superblock(superblock);
    if (result < 0) {
        flags = spin_lock_irqsave(&session->lock);
        session->mounted = 0;
        spin_unlock_irqrestore(&session->lock, flags);
        fuse_free_pages(superblock, FUSE_SUPERBLOCK_PAGES);
        return -LINUX_EIO;
    }
    fuse_free_pages(superblock, FUSE_SUPERBLOCK_PAGES);
    printf("[fuse] mounted %s on %s session=%u\n",
           filesystem && filesystem[0] ? filesystem : "fuse",
           target, session->generation);
    return 0;
}
