/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD sysctl interface for unmodified driver sources. */

#ifndef _SYS_SYSCTL_H_
#define _SYS_SYSCTL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "counter.h"

typedef __UINTPTR_TYPE__ __uintptr_t;

#include <sys/queue.h>
#include <sys/tree.h>

#define CTLTYPE 0xf
#define CTLTYPE_NODE 1
#define CTLTYPE_INT 2
#define CTLTYPE_STRING 3
#define CTLTYPE_S64 4
#define CTLTYPE_OPAQUE 5
#define CTLTYPE_STRUCT CTLTYPE_OPAQUE
#define CTLTYPE_UINT 6
#define CTLTYPE_LONG 7
#define CTLTYPE_ULONG 8
#define CTLTYPE_U64 9
#define CTLTYPE_U8 0xa
#define CTLTYPE_U16 0xb
#define CTLTYPE_S8 0xc
#define CTLTYPE_S16 0xd
#define CTLTYPE_S32 0xe
#define CTLTYPE_U32 0xf

#define CTLFLAG_RD 0x80000000U
#define CTLFLAG_WR 0x40000000U
#define CTLFLAG_RW (CTLFLAG_RD | CTLFLAG_WR)
#define CTLFLAG_DORMANT 0x20000000U
#define CTLFLAG_ANYBODY 0x10000000U
#define CTLFLAG_SECURE 0x08000000U
#define CTLFLAG_PRISON 0x04000000U
#define CTLFLAG_DYN 0x02000000U
#define CTLFLAG_SKIP 0x01000000U
#define CTLFLAG_TUN 0x00080000U
#define CTLFLAG_RDTUN (CTLFLAG_RD | CTLFLAG_TUN)
#define CTLFLAG_RWTUN (CTLFLAG_RW | CTLFLAG_TUN)
#define CTLFLAG_MPSAFE 0x00040000U
#define CTLFLAG_VNET 0x00020000U
#define CTLFLAG_DYING 0x00010000U
#define CTLFLAG_CAPRD 0x00008000U
#define CTLFLAG_CAPWR 0x00004000U
#define CTLFLAG_STATS 0x00002000U
#define CTLFLAG_NOFETCH 0x00001000U
#define CTLFLAG_NEEDGIANT 0x00000800U

#define OID_AUTO (-1)
#define CTL_AUTO_START 0x100

struct thread;
struct sysctl_req {
    struct thread *td;
    int lock;
    void *oldptr;
    size_t oldlen;
    size_t oldidx;
    int (*oldfunc)(struct sysctl_req *, const void *, size_t);
    const void *newptr;
    size_t newlen;
    size_t newidx;
    int (*newfunc)(struct sysctl_req *, void *, size_t);
    size_t validlen;
    int flags;
};

struct sysctl_oid;
RB_HEAD(sysctl_oid_list, sysctl_oid);

#define SYSCTL_HANDLER_ARGS struct sysctl_oid *oidp, void *arg1, \
    intmax_t arg2, struct sysctl_req *req

struct sysctl_oid {
    struct sysctl_oid_list oid_children;
    struct sysctl_oid_list *oid_parent;
    RB_ENTRY(sysctl_oid) oid_link;
    int oid_number;
    unsigned int oid_kind;
    void *oid_arg1;
    intmax_t oid_arg2;
    const char *oid_name;
    int (*oid_handler)(SYSCTL_HANDLER_ARGS);
    const char *oid_fmt;
    int oid_refcnt;
    unsigned int oid_running;
    const char *oid_descr;
    const char *oid_label;
};

static inline int
cmp_sysctl_oid(struct sysctl_oid *left, struct sysctl_oid *right)
{
    if (left->oid_number > right->oid_number)
        return 1;
    if (left->oid_number < right->oid_number)
        return -1;
    return 0;
}

RB_PROTOTYPE(sysctl_oid_list, sysctl_oid, oid_link, cmp_sysctl_oid);

struct sysctl_ctx_entry {
    struct sysctl_oid *entry;
    TAILQ_ENTRY(sysctl_ctx_entry) link;
};
TAILQ_HEAD(sysctl_ctx_list, sysctl_ctx_entry);

extern struct sysctl_oid_list sysctl__children;
extern struct sysctl_oid sysctl___kern;
extern struct sysctl_oid sysctl___kern_features;
extern struct sysctl_oid sysctl___debug;
extern struct sysctl_oid sysctl___debug_acpi;
extern struct sysctl_oid sysctl___hw;
extern struct sysctl_oid sysctl___hw_pci;
extern struct sysctl_oid sysctl___machdep;
extern struct sysctl_oid sysctl___dev;
extern struct sysctl_oid sysctl___net;
extern const char kern_ident[];

#define SYSCTL_DECL(name) extern struct sysctl_oid sysctl__##name
#define SYSCTL_CHILDREN(oid) (&(oid)->oid_children)
#define SYSCTL_STATIC_CHILDREN(name) (&sysctl__##name.oid_children)
#define SYSCTL_NODE_CHILDREN(parent, name) \
    sysctl__##parent##_##name.oid_children

#define SYSCTL_OID_RAW(id, parent, number, oid_name_value, kind_value, \
    argument, argument_value, handler_value, format_value, description, \
    label_value) \
    struct sysctl_oid id __attribute__((used)) = { \
        .oid_parent = (parent), \
        .oid_children = RB_INITIALIZER(&id.oid_children), \
        .oid_number = (number), \
        .oid_kind = (kind_value), \
        .oid_arg1 = (argument), \
        .oid_arg2 = (argument_value), \
        .oid_name = (oid_name_value), \
        .oid_handler = (handler_value), \
        .oid_fmt = (format_value), \
        .oid_refcnt = 1, \
        .oid_descr = (description), \
        .oid_label = (label_value), \
    }

#define SYSCTL_OID_WITH_LABEL(parent, number, name, kind, argument, \
    argument_value, handler, format, description, label) \
    static SYSCTL_OID_RAW(sysctl__##parent##_##name, \
        SYSCTL_CHILDREN(&sysctl__##parent), number, #name, kind, \
        argument, argument_value, handler, format, description, label)

#define SYSCTL_OID(parent, number, name, kind, argument, argument_value, \
    handler, format, description) \
    SYSCTL_OID_WITH_LABEL(parent, number, name, kind, argument, \
        argument_value, handler, format, description, 0)

#define FEATURE(name, description) \
    SYSCTL_OID_WITH_LABEL(_kern_features, OID_AUTO, name, \
        CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_CAPRD | CTLFLAG_MPSAFE, \
        0, 1, sysctl_handle_int, "I", description, "feature")

#define SYSCTL_NODE(parent, number, name, access, handler, description) \
    SYSCTL_OID_RAW(sysctl__##parent##_##name, \
        SYSCTL_CHILDREN(&sysctl__##parent), number, #name, \
        CTLTYPE_NODE | (access), 0, 0, handler, "N", description, 0)

#define SYSCTL_INT(parent, number, name, access, pointer, value, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_INT | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_int, "I", description)

#define SYSCTL_UINT(parent, number, name, access, pointer, value, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_UINT | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_int, "IU", description)

#define SYSCTL_LONG(parent, number, name, access, pointer, value, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_LONG | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_long, "L", description)

#define SYSCTL_ULONG(parent, number, name, access, pointer, value, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_ULONG | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_long, "LU", description)

#define SYSCTL_UQUAD(parent, number, name, access, pointer, value, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_U64 | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_64, "QU", description)

#define SYSCTL_SBINTIME_MSEC(parent, number, name, access, pointer, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_S64 | CTLFLAG_MPSAFE | CTLFLAG_RD | (access), \
        pointer, 0, sysctl_msec_to_sbintime, "Q", description)

#define SYSCTL_BOOL(parent, number, name, access, pointer, value, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_U8 | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_bool, "CU", description)

#define SYSCTL_U16(parent, number, name, access, pointer, value, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_U16 | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_u16, "SU", description)

#define SYSCTL_PROC(parent, number, name, access, pointer, value, \
    handler, format, description) \
    SYSCTL_OID(parent, number, name, access, pointer, value, \
        handler, format, description)

#define SYSCTL_ADD_INT(context, parent, number, name, access, pointer, \
    value, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_INT | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_int, "I", description, 0)

#define SYSCTL_ADD_UINT(context, parent, number, name, access, pointer, \
    value, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_UINT | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_int, "IU", description, 0)

#define SYSCTL_ADD_NODE(context, parent, number, name, access, handler, \
    description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_NODE | (access), 0, 0, handler, "N", description, 0)

#define SYSCTL_ADD_NODE_WITH_LABEL(context, parent, number, name, access, \
    handler, description, label) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_NODE | (access), 0, 0, handler, "N", description, label)

#define SYSCTL_ADD_UQUAD(context, parent, number, name, access, pointer, \
    description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_U64 | CTLFLAG_MPSAFE | (access), pointer, 0, \
        sysctl_handle_64, "QU", description, 0)

#define SYSCTL_ADD_U64(context, parent, number, name, access, pointer, \
    value, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_U64 | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_64, "QU", description, 0)
#define SYSCTL_NULL_U64_PTR ((uint64_t *)0)
#define SYSCTL_NULL_U32_PTR ((uint32_t *)0)

#define SYSCTL_ADD_QUAD(context, parent, number, name, access, pointer, \
    description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_S64 | CTLFLAG_MPSAFE | (access), pointer, 0, \
        sysctl_handle_64, "Q", description, 0)

#define SYSCTL_ADD_ULONG(context, parent, number, name, access, pointer, \
    description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_ULONG | CTLFLAG_MPSAFE | (access), pointer, 0, \
        sysctl_handle_long, "LU", description, 0)

#define SYSCTL_ADD_LONG(context, parent, number, name, access, pointer, \
    description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_LONG | CTLFLAG_MPSAFE | (access), pointer, 0, \
        sysctl_handle_long, "L", description, 0)

#define SYSCTL_ADD_PROC(context, parent, number, name, access, pointer, \
    argument, handler, format, description) \
    sysctl_add_oid(context, parent, number, name, access, pointer, \
        argument, handler, format, description, 0)

#define SYSCTL_ADD_CONST_STRING(context, parent, number, name, access, \
    pointer, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_STRING | CTLFLAG_MPSAFE | (access), \
        (void *)(uintptr_t)(pointer), 0, sysctl_handle_string, \
        "A", description, 0)

#define SYSCTL_CONST_STRING(parent, number, name, access, pointer, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_STRING | CTLFLAG_MPSAFE | (access), \
        (void *)(uintptr_t)(pointer), 0, sysctl_handle_string, \
        "A", description); \
    _Static_assert(((access) & CTLFLAG_WR) == 0, \
        "constant sysctl strings must be read-only")

#define SYSCTL_STRING(parent, number, name, access, pointer, length, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_STRING | CTLFLAG_MPSAFE | (access), pointer, length, \
        sysctl_handle_string, "A", description)

#define SYSCTL_ADD_STRING(context, parent, number, name, access, pointer, \
    length, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_STRING | CTLFLAG_MPSAFE | (access), pointer, length, \
        sysctl_handle_string, "A", description, 0)

#define SYSCTL_ADD_OPAQUE(context, parent, number, name, access, pointer, \
    length, format, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_OPAQUE | CTLFLAG_MPSAFE | (access), pointer, length, \
        sysctl_handle_opaque, format, description, 0)

#define SYSCTL_ADD_BOOL(context, parent, number, name, access, pointer, \
    value, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_U8 | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_bool, "CU", description, 0)
#define SYSCTL_NULL_BOOL_PTR ((bool *)0)

#define SYSCTL_ADD_U8(context, parent, number, name, access, pointer, \
    value, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_U8 | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_u8, "CU", description, 0)

#define SYSCTL_ADD_U16(context, parent, number, name, access, pointer, \
    value, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_U16 | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_u16, "SU", description, 0)

#define SYSCTL_ADD_U32(context, parent, number, name, access, pointer, \
    value, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_U32 | CTLFLAG_MPSAFE | (access), pointer, value, \
        sysctl_handle_32, "IU", description, 0)

#define SYSCTL_ADD_COUNTER_U64(context, parent, number, name, access, \
    pointer, description) \
    sysctl_add_oid(context, parent, number, name, \
        CTLTYPE_U64 | CTLFLAG_MPSAFE | (access), pointer, 0, \
        sysctl_handle_counter_u64, "QU", description, 0)

#define SYSCTL_COUNTER_U64(parent, number, name, access, pointer, \
    description) \
    SYSCTL_OID(parent, number, name, \
        CTLTYPE_U64 | CTLFLAG_MPSAFE | CTLFLAG_STATS | (access), \
        pointer, 0, sysctl_handle_counter_u64, "QU", description)

#define SYSCTL_IN(request, data, length) \
    ((request)->newfunc((request), (data), (length)))
#define SYSCTL_OUT(request, data, length) \
    ((request)->oldfunc((request), (data), (length)))
#define SYSCTL_OUT_STR(request, string) \
    ((request)->oldfunc((request), (string), \
        __builtin_strlen(string) + 1u))

int sysctl_handle_int(SYSCTL_HANDLER_ARGS);
int sysctl_handle_8(SYSCTL_HANDLER_ARGS);
int sysctl_handle_16(SYSCTL_HANDLER_ARGS);
int sysctl_handle_32(SYSCTL_HANDLER_ARGS);
int sysctl_handle_64(SYSCTL_HANDLER_ARGS);
int sysctl_handle_long(SYSCTL_HANDLER_ARGS);
int sysctl_handle_bool(SYSCTL_HANDLER_ARGS);
int sysctl_handle_u8(SYSCTL_HANDLER_ARGS);
int sysctl_handle_u16(SYSCTL_HANDLER_ARGS);
int sysctl_handle_string(SYSCTL_HANDLER_ARGS);
int sysctl_handle_opaque(SYSCTL_HANDLER_ARGS);
int sysctl_handle_counter_u64(SYSCTL_HANDLER_ARGS);
int sysctl_msec_to_sbintime(SYSCTL_HANDLER_ARGS);
int sysctl_wire_old_buffer(struct sysctl_req *request, size_t length);

struct sysctl_oid *sysctl_add_oid(struct sysctl_ctx_list *,
    struct sysctl_oid_list *, int, const char *, int, void *, intmax_t,
    int (*)(SYSCTL_HANDLER_ARGS), const char *, const char *, const char *);
int sysctl_remove_oid(struct sysctl_oid *, int, int);
void sysctl_wlock(void);
void sysctl_wunlock(void);
void sysctl_register_oid(struct sysctl_oid *);
void sysctl_unregister_oid(struct sysctl_oid *);
int sysctl_ctx_init(struct sysctl_ctx_list *);
int sysctl_ctx_free(struct sysctl_ctx_list *);
struct sysctl_ctx_entry *sysctl_ctx_entry_add(struct sysctl_ctx_list *,
    struct sysctl_oid *);
struct sysctl_ctx_entry *sysctl_ctx_entry_find(struct sysctl_ctx_list *,
    struct sysctl_oid *);
int sysctl_ctx_entry_del(struct sysctl_ctx_list *, struct sysctl_oid *);

struct sbuf;
struct sbuf *sbuf_new_for_sysctl(struct sbuf *, char *, int,
    struct sysctl_req *);

#endif
