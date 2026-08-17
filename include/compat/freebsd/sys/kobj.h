/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD-compatible kernel object dispatch for the EdgeOS BSD bridge. */

#ifndef _SYS_KOBJ_H_
#define _SYS_KOBJ_H_

#include <stddef.h>

typedef struct kobj *kobj_t;
typedef struct kobj_class *kobj_class_t;
typedef const struct kobj_method kobj_method_t;
typedef void (*kobjop_t)(void);
typedef struct kobj_ops *kobj_ops_t;
typedef struct kobjop_desc *kobjop_desc_t;
struct malloc_type;

struct kobj_method {
    kobjop_desc_t desc;
    kobjop_t func;
};

#define KOBJ_CLASS_FIELDS                                               \
    const char *name;                                                   \
    kobj_method_t *methods;                                             \
    size_t size;                                                        \
    kobj_class_t *baseclasses;                                          \
    unsigned int refs;                                                  \
    kobj_ops_t ops

struct kobj_class {
    KOBJ_CLASS_FIELDS;
};

#define KOBJ_FIELDS kobj_ops_t ops

struct kobj {
    KOBJ_FIELDS;
};

#define KOBJ_CACHE_SIZE 256

struct kobj_ops {
    kobj_method_t *cache[KOBJ_CACHE_SIZE];
    kobj_class_t cls;
};

struct kobjop_desc {
    unsigned int id;
    kobj_method_t deflt;
};

#define KOBJMETHOD(name, function)                                      \
    { &(name##_desc), (kobjop_t)(1 ? (function) : (name##_t *)0) }
#define KOBJMETHOD_END { 0, 0 }

#define DECLARE_CLASS(name) extern struct kobj_class name

#define DEFINE_CLASS(name, methods, size)                               \
    DEFINE_CLASS_0(name, name##_class, methods, size)

#define DEFINE_CLASS_0(name, class_variable, methods, object_size)      \
    struct kobj_class class_variable = {                                \
        #name, methods, object_size, 0, 0, 0                            \
    }

#define DEFINE_CLASS_1(name, class_variable, methods, object_size,      \
    base1)                                                              \
    static kobj_class_t name##_baseclasses[] = { &(base1), 0 };         \
    struct kobj_class class_variable = {                                \
        #name, methods, object_size, name##_baseclasses, 0, 0           \
    }

#define DEFINE_CLASS_2(name, class_variable, methods, object_size,      \
    base1, base2)                                                       \
    static kobj_class_t name##_baseclasses[] = {                        \
        &(base1), &(base2), 0                                           \
    };                                                                  \
    struct kobj_class class_variable = {                                \
        #name, methods, object_size, name##_baseclasses, 0, 0           \
    }

#define DEFINE_CLASS_3(name, class_variable, methods, object_size,      \
    base1, base2, base3)                                                \
    static kobj_class_t name##_baseclasses[] = {                        \
        &(base1), &(base2), &(base3), 0                                 \
    };                                                                  \
    struct kobj_class class_variable = {                                \
        #name, methods, object_size, name##_baseclasses, 0, 0           \
    }

void kobj_class_compile(kobj_class_t class_object);
void kobj_class_compile_static(kobj_class_t class_object, kobj_ops_t ops);
void kobj_class_retain(kobj_class_t class_object);
void kobj_class_release(kobj_class_t class_object);
void kobj_class_free(kobj_class_t class_object);
kobj_t kobj_create(kobj_class_t class_object, struct malloc_type *type,
    int flags);
void kobj_init(kobj_t object, kobj_class_t class_object);
void kobj_init_static(kobj_t object, kobj_class_t class_object);
void kobj_delete(kobj_t object, struct malloc_type *type);
kobj_method_t *kobj_lookup_method(kobj_class_t class_object,
    kobj_method_t **cache_entry, kobjop_desc_t descriptor);
int kobj_error_method(void);

#define KOBJOPLOOKUP(ops_table, operation) do {                         \
    kobjop_desc_t _descriptor = &(operation##_desc);                    \
    kobj_method_t **_cache_entry =                                      \
        &(ops_table)->cache[_descriptor->id & (KOBJ_CACHE_SIZE - 1)];    \
    kobj_method_t *_cached_method = *_cache_entry;                      \
    if (_cached_method->desc != _descriptor)                            \
        _cached_method = kobj_lookup_method(                            \
            (ops_table)->cls, _cache_entry, _descriptor);               \
    _m = _cached_method->func;                                          \
} while (0)

#endif
