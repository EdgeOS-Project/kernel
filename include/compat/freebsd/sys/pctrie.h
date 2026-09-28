/* SPDX-License-Identifier: BSD-2-Clause */
/* Pointer-key trie contract implemented as an ordered bridge index. */

#ifndef _SYS_PCTRIE_H_
#define _SYS_PCTRIE_H_

#include <stddef.h>
#include <stdint.h>

struct pctrie_node {
    struct pctrie_node *next;
    uint64_t key;
    void *value;
};

struct pctrie {
    struct pctrie_node *root;
};

static inline void
pctrie_init(struct pctrie *tree)
{
    tree->root = 0;
}

static inline int
pctrie_is_empty(const struct pctrie *tree)
{
    return tree->root == 0;
}

static inline size_t
pctrie_node_size(void)
{
    return sizeof(struct pctrie_node);
}

static inline int
pctrie_zone_init(void *memory, int size, int flags)
{
    struct pctrie_node *node = memory;

    (void)size;
    (void)flags;
    node->next = 0;
    node->key = 0;
    node->value = 0;
    return 0;
}

#define PCTRIE_DEFINE(name, type, field, allocate, release) \
static int name##_PCTRIE_INSERT(struct pctrie *tree, struct type *value) \
{ \
    struct pctrie_node **link = &tree->root; \
    struct pctrie_node *node; \
    uint64_t key = (uint64_t)value->field; \
    while (*link && (*link)->key < key) \
        link = &(*link)->next; \
    if (*link && (*link)->key == key) \
        return 17; \
    node = (allocate)(tree); \
    if (!node) \
        return 12; \
    node->key = key; \
    node->value = value; \
    node->next = *link; \
    *link = node; \
    return 0; \
} \
static struct type *name##_PCTRIE_LOOKUP(struct pctrie *tree, uint64_t key) \
{ \
    struct pctrie_node *node; \
    for (node = tree->root; node && node->key <= key; node = node->next) { \
        if (node->key == key) \
            return node->value; \
    } \
    return 0; \
} \
static struct type *name##_PCTRIE_REMOVE(struct pctrie *tree, uint64_t key) \
{ \
    struct pctrie_node **link = &tree->root; \
    struct pctrie_node *node; \
    struct type *value; \
    while (*link && (*link)->key < key) \
        link = &(*link)->next; \
    if (!*link || (*link)->key != key) \
        return 0; \
    node = *link; \
    *link = node->next; \
    value = node->value; \
    (release)(tree, node); \
    return value; \
} \
static void name##_PCTRIE_RECLAIM(struct pctrie *tree) \
{ \
    while (tree->root) { \
        struct pctrie_node *node = tree->root; \
        tree->root = node->next; \
        (release)(tree, node); \
    } \
}

#endif
