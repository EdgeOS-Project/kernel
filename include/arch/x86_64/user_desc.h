/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x86 user_desc layout and descriptor conversion helpers. */

#ifndef EDGEOS_ARCH_X86_64_USER_DESC_H
#define EDGEOS_ARCH_X86_64_USER_DESC_H

#include <stdint.h>

struct edge_x86_user_desc {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t flags;
};

#define EDGE_X86_USER_DESC_SEG_32BIT (1u << 0)
#define EDGE_X86_USER_DESC_CONTENTS_MASK (3u << 1)
#define EDGE_X86_USER_DESC_READ_EXEC_ONLY (1u << 3)
#define EDGE_X86_USER_DESC_LIMIT_IN_PAGES (1u << 4)
#define EDGE_X86_USER_DESC_SEG_NOT_PRESENT (1u << 5)
#define EDGE_X86_USER_DESC_USEABLE (1u << 6)

_Static_assert(sizeof(struct edge_x86_user_desc) == 16u,
               "Linux x86 user_desc layout");

static inline uint32_t edge_x86_user_desc_contents(
        const struct edge_x86_user_desc *description) {
    return (description->flags & EDGE_X86_USER_DESC_CONTENTS_MASK) >> 1;
}

static inline int edge_x86_user_desc_empty(
        const struct edge_x86_user_desc *description) {
    uint32_t expected = EDGE_X86_USER_DESC_READ_EXEC_ONLY |
                        EDGE_X86_USER_DESC_SEG_NOT_PRESENT;

    return description->base_addr == 0 && description->limit == 0 &&
           (description->flags & 0x7fu) == expected;
}

static inline int edge_x86_user_desc_zero(
        const struct edge_x86_user_desc *description) {
    return description->base_addr == 0 && description->limit == 0 &&
           (description->flags & 0x7fu) == 0;
}

static inline int edge_x86_tls_description_valid(
        const struct edge_x86_user_desc *description) {
    if (!description || (description->flags & ~0x7fu)) return 0;
    if (edge_x86_user_desc_empty(description) ||
        edge_x86_user_desc_zero(description))
        return 1;
    if (!(description->flags & EDGE_X86_USER_DESC_SEG_32BIT)) return 0;
    if (edge_x86_user_desc_contents(description) > 1u) return 0;
    return !(description->flags & EDGE_X86_USER_DESC_SEG_NOT_PRESENT);
}

static inline uint64_t edge_x86_pack_ldt_descriptor(
        const struct edge_x86_user_desc *description, int old_mode) {
    uint64_t descriptor = 0;
    uint32_t contents = edge_x86_user_desc_contents(description);
    uint32_t type = ((description->flags &
                      EDGE_X86_USER_DESC_READ_EXEC_ONLY) ? 0u : 2u) |
                    (contents << 2) | 1u;

    descriptor |= description->limit & 0xffffu;
    descriptor |= ((uint64_t)description->base_addr & 0xffffu) << 16;
    descriptor |= ((uint64_t)(description->base_addr >> 16) & 0xffu) << 32;
    descriptor |= (uint64_t)type << 40;
    descriptor |= UINT64_C(1) << 44;
    descriptor |= UINT64_C(3) << 45;
    if (!(description->flags & EDGE_X86_USER_DESC_SEG_NOT_PRESENT))
        descriptor |= UINT64_C(1) << 47;
    descriptor |= ((uint64_t)(description->limit >> 16) & 0x0fu) << 48;
    if (!old_mode && (description->flags & EDGE_X86_USER_DESC_USEABLE))
        descriptor |= UINT64_C(1) << 52;
    if (description->flags & EDGE_X86_USER_DESC_SEG_32BIT)
        descriptor |= UINT64_C(1) << 54;
    if (description->flags & EDGE_X86_USER_DESC_LIMIT_IN_PAGES)
        descriptor |= UINT64_C(1) << 55;
    descriptor |= ((uint64_t)(description->base_addr >> 24) & 0xffu) << 56;
    return descriptor;
}

static inline void edge_x86_unpack_tls_descriptor(
        struct edge_x86_user_desc *description, uint32_t entry,
        uint64_t descriptor) {
    uint32_t type;

    description->entry_number = entry;
    description->base_addr = 0;
    description->limit = 0;
    description->flags = 0;
    if (!descriptor) {
        description->flags = EDGE_X86_USER_DESC_READ_EXEC_ONLY |
                             EDGE_X86_USER_DESC_SEG_NOT_PRESENT;
        return;
    }
    description->base_addr =
        (uint32_t)((descriptor >> 16) & 0xffffu) |
        (uint32_t)((descriptor >> 32) & 0xffu) << 16 |
        (uint32_t)(descriptor >> 56) << 24;
    description->limit = (uint32_t)(descriptor & 0xffffu) |
        (uint32_t)((descriptor >> 48) & 0x0fu) << 16;
    type = (uint32_t)((descriptor >> 40) & 0x0fu);
    if (descriptor & (UINT64_C(1) << 54))
        description->flags |= EDGE_X86_USER_DESC_SEG_32BIT;
    description->flags |= ((type >> 2) & 3u) << 1;
    if (!(type & 2u))
        description->flags |= EDGE_X86_USER_DESC_READ_EXEC_ONLY;
    if (descriptor & (UINT64_C(1) << 55))
        description->flags |= EDGE_X86_USER_DESC_LIMIT_IN_PAGES;
    if (!(descriptor & (UINT64_C(1) << 47)))
        description->flags |= EDGE_X86_USER_DESC_SEG_NOT_PRESENT;
    if (descriptor & (UINT64_C(1) << 52))
        description->flags |= EDGE_X86_USER_DESC_USEABLE;
}

#endif
