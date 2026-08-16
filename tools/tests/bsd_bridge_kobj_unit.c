/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD bridge kobj method dispatcher. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/sys/kobj.h"

typedef int test_value_t(kobj_t object);

static struct kobjop_desc test_value_desc = {
    0, { &test_value_desc, (kobjop_t)kobj_error_method }
};
static struct kobjop_desc test_missing_desc = {
    0, { &test_missing_desc, (kobjop_t)kobj_error_method }
};

typedef struct {
    struct kobj object;
    int value;
} test_object_t;

static int
test_value_base(kobj_t object)
{
    test_object_t *test_object = (test_object_t *)object;

    return test_object->value;
}

static int
test_value_derived(kobj_t object)
{
    test_object_t *test_object = (test_object_t *)object;

    return test_object->value * 2;
}

static const struct kobj_method test_base_methods[] = {
    { &test_value_desc, (kobjop_t)test_value_base },
    KOBJMETHOD_END,
};

static const struct kobj_method test_derived_methods[] = {
    { &test_value_desc, (kobjop_t)test_value_derived },
    KOBJMETHOD_END,
};

static const struct kobj_method test_inherited_methods[] = {
    KOBJMETHOD_END,
};

DEFINE_CLASS_0(test_base, test_base_class, test_base_methods,
    sizeof(test_object_t));
DEFINE_CLASS_1(test_derived, test_derived_class, test_derived_methods,
    sizeof(test_object_t), test_base_class);
DEFINE_CLASS_1(test_inherited, test_inherited_class, test_inherited_methods,
    sizeof(test_object_t), test_base_class);

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U, (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static int
dispatch(kobj_t object, struct kobjop_desc *descriptor)
{
    kobjop_t _m;
    kobj_method_t **cache_entry =
        &object->ops->cache[descriptor->id & (KOBJ_CACHE_SIZE - 1)];
    kobj_method_t *method = *cache_entry;

    if (method->desc != descriptor)
        method = kobj_lookup_method(object->ops->cls, cache_entry,
            descriptor);
    _m = method->func;
    return ((test_value_t *)_m)(object);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    test_object_t *derived;
    test_object_t *inherited;

    assert(bsd_allocator_initialize(&allocator_ops) == 0);

    derived = (test_object_t *)kobj_create(&test_derived_class, M_DEVBUF,
        M_WAITOK);
    inherited = (test_object_t *)kobj_create(&test_inherited_class, M_DEVBUF,
        M_WAITOK);
    assert(derived != 0);
    assert(inherited != 0);
    derived->value = 21;
    inherited->value = 19;
    assert(dispatch(&derived->object, &test_value_desc) == 42);
    assert(dispatch(&inherited->object, &test_value_desc) == 19);
    assert(dispatch(&inherited->object, &test_missing_desc) == 6);
    assert(test_value_desc.id != 0);

    kobj_delete(&derived->object, M_DEVBUF);
    kobj_delete(&inherited->object, M_DEVBUF);
    assert(test_derived_class.refs == 0);
    assert(test_inherited_class.refs == 0);
    return 0;
}
