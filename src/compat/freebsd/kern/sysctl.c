/* SPDX-License-Identifier: MPL-2.0 */
/* Shared sysctl registry for imported FreeBSD drivers. */

#include "compat/freebsd/sys/sbuf.h"
#include "compat/freebsd/sys/sysctl.h"

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/sysctl.h"
#include "compat/freebsd/edgeos/systm.h"

#define BSD_SYSCTL_EPERM 1
#define BSD_SYSCTL_ENOENT 2
#define BSD_SYSCTL_ENOMEM 12
#define BSD_SYSCTL_EEXIST 17
#define BSD_SYSCTL_EINVAL 22

struct bsd_sysctl_device_state {
    struct sysctl_ctx_list context;
    struct sysctl_oid *tree;
};

struct sysctl_oid_list sysctl__children =
    RB_INITIALIZER(&sysctl__children);

struct sysctl_oid sysctl___kern = {
    .oid_children = RB_INITIALIZER(&sysctl___kern.oid_children),
    .oid_parent = &sysctl__children,
    .oid_number = 1,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RW | CTLFLAG_MPSAFE,
    .oid_name = "kern",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "kernel",
};

struct sysctl_oid sysctl___kern_features = {
    .oid_children = RB_INITIALIZER(&sysctl___kern_features.oid_children),
    .oid_parent = &sysctl___kern.oid_children,
    .oid_number = 33,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RD | CTLFLAG_MPSAFE,
    .oid_name = "features",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "optional kernel features",
};

struct sysctl_oid sysctl___debug = {
    .oid_children = RB_INITIALIZER(&sysctl___debug.oid_children),
    .oid_parent = &sysctl__children,
    .oid_number = 5,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RW | CTLFLAG_MPSAFE,
    .oid_name = "debug",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "debugging",
};

struct sysctl_oid sysctl___debug_acpi = {
    .oid_children = RB_INITIALIZER(&sysctl___debug_acpi.oid_children),
    .oid_parent = &sysctl___debug.oid_children,
    .oid_number = 1,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RW | CTLFLAG_MPSAFE,
    .oid_name = "acpi",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "ACPI debugging",
};

struct sysctl_oid sysctl___hw = {
    .oid_children = RB_INITIALIZER(&sysctl___hw.oid_children),
    .oid_parent = &sysctl__children,
    .oid_number = 6,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RW | CTLFLAG_MPSAFE,
    .oid_name = "hw",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "hardware",
};

struct sysctl_oid sysctl___hw_pci = {
    .oid_children = RB_INITIALIZER(&sysctl___hw_pci.oid_children),
    .oid_parent = &sysctl___hw.oid_children,
    .oid_number = 1,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RW | CTLFLAG_MPSAFE,
    .oid_name = "pci",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "PCI",
};

struct sysctl_oid sysctl___machdep = {
    .oid_children = RB_INITIALIZER(&sysctl___machdep.oid_children),
    .oid_parent = &sysctl__children,
    .oid_number = 7,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RW | CTLFLAG_MPSAFE,
    .oid_name = "machdep",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "machine dependent",
};

struct sysctl_oid sysctl___dev = {
    .oid_children = RB_INITIALIZER(&sysctl___dev.oid_children),
    .oid_parent = &sysctl__children,
    .oid_number = 1000,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RD | CTLFLAG_MPSAFE,
    .oid_name = "dev",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "device tree",
};

struct sysctl_oid sysctl___net = {
    .oid_children = RB_INITIALIZER(&sysctl___net.oid_children),
    .oid_parent = &sysctl__children,
    .oid_number = 4,
    .oid_kind = CTLTYPE_NODE | CTLFLAG_RW | CTLFLAG_MPSAFE,
    .oid_name = "net",
    .oid_fmt = "N",
    .oid_refcnt = 1,
    .oid_descr = "network",
};

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
RB_GENERATE(sysctl_oid_list, sysctl_oid, oid_link, cmp_sysctl_oid);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static volatile unsigned int g_sysctl_guard;
static int g_sysctl_roots_initialized;

static void
sysctl_lock(void)
{
    while (__atomic_test_and_set(&g_sysctl_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
sysctl_unlock(void)
{
    __atomic_clear(&g_sysctl_guard, __ATOMIC_RELEASE);
}

void
sysctl_wlock(void)
{
    sysctl_lock();
}

void
sysctl_wunlock(void)
{
    sysctl_unlock();
}

void
sysctl_register_oid(struct sysctl_oid *oid)
{
    struct sysctl_oid *existing;

    if (!oid || !oid->oid_parent)
        return;
    existing = RB_INSERT(sysctl_oid_list, oid->oid_parent, oid);
    if (existing && existing != oid) {
        /*
         * FreeBSD preserves the first registered OID when an overlapping
         * leaf is encountered.  Shared nodes are reference counted there;
         * imported drivers only re-register their original leaf object.
         */
        if ((existing->oid_kind & CTLTYPE) == CTLTYPE_NODE)
            existing->oid_refcnt++;
    }
}

void
sysctl_unregister_oid(struct sysctl_oid *oid)
{
    if (!oid || !oid->oid_parent || oid->oid_number == OID_AUTO)
        return;
    (void)RB_REMOVE(sysctl_oid_list, oid->oid_parent, oid);
}

static char *
sysctl_string_duplicate(const char *text)
{
    size_t length;
    char *copy;

    if (!text)
        return 0;
    length = bsd_strlen(text) + 1;
    copy = bsd_malloc(length, M_TEMP, M_WAITOK);
    if (copy)
        bsd_memcpy(copy, text, length);
    return copy;
}

static void
sysctl_roots_initialize(void)
{
    sysctl_lock();
    if (!g_sysctl_roots_initialized) {
        (void)RB_INSERT(sysctl_oid_list, &sysctl__children,
            &sysctl___kern);
        (void)RB_INSERT(sysctl_oid_list, &sysctl___kern.oid_children,
            &sysctl___kern_features);
        (void)RB_INSERT(sysctl_oid_list, &sysctl__children,
            &sysctl___debug);
        (void)RB_INSERT(sysctl_oid_list, &sysctl___debug.oid_children,
            &sysctl___debug_acpi);
        (void)RB_INSERT(sysctl_oid_list, &sysctl__children,
            &sysctl___hw);
        (void)RB_INSERT(sysctl_oid_list, &sysctl___hw.oid_children,
            &sysctl___hw_pci);
        (void)RB_INSERT(sysctl_oid_list, &sysctl__children,
            &sysctl___machdep);
        (void)RB_INSERT(sysctl_oid_list, &sysctl__children,
            &sysctl___dev);
        (void)RB_INSERT(sysctl_oid_list, &sysctl__children,
            &sysctl___net);
        g_sysctl_roots_initialized = 1;
    }
    sysctl_unlock();
}

int
sysctl_ctx_init(struct sysctl_ctx_list *context)
{
    if (!context)
        return BSD_SYSCTL_EINVAL;
    TAILQ_INIT(context);
    return 0;
}

struct sysctl_ctx_entry *
sysctl_ctx_entry_find(struct sysctl_ctx_list *context,
    struct sysctl_oid *oid)
{
    struct sysctl_ctx_entry *entry;

    if (!context || !oid)
        return 0;
    TAILQ_FOREACH(entry, context, link) {
        if (entry->entry == oid)
            return entry;
    }
    return 0;
}

struct sysctl_ctx_entry *
sysctl_ctx_entry_add(struct sysctl_ctx_list *context,
    struct sysctl_oid *oid)
{
    struct sysctl_ctx_entry *entry;

    if (!context || !oid)
        return 0;
    entry = bsd_malloc(sizeof(*entry), M_TEMP, M_WAITOK | M_ZERO);
    if (!entry)
        return 0;
    entry->entry = oid;
    TAILQ_INSERT_HEAD(context, entry, link);
    return entry;
}

int
sysctl_ctx_entry_del(struct sysctl_ctx_list *context,
    struct sysctl_oid *oid)
{
    struct sysctl_ctx_entry *entry =
        sysctl_ctx_entry_find(context, oid);

    if (!entry)
        return BSD_SYSCTL_ENOENT;
    TAILQ_REMOVE(context, entry, link);
    bsd_free(entry, M_TEMP);
    return 0;
}

static int
sysctl_next_number(struct sysctl_oid_list *parent)
{
    struct sysctl_oid *current;
    int number = CTL_AUTO_START;

    RB_FOREACH(current, sysctl_oid_list, parent) {
        if (current->oid_number >= number)
            number = current->oid_number + 1;
    }
    return number;
}

struct sysctl_oid *
sysctl_add_oid(struct sysctl_ctx_list *context,
    struct sysctl_oid_list *parent, int number, const char *name, int kind,
    void *argument, intmax_t argument_value,
    int (*handler)(SYSCTL_HANDLER_ARGS), const char *format,
    const char *description, const char *label)
{
    struct sysctl_oid *oid;

    if (!parent || !name || name[0] == '\0')
        return 0;
    sysctl_roots_initialize();
    oid = bsd_malloc(sizeof(*oid), M_TEMP, M_WAITOK | M_ZERO);
    if (!oid)
        return 0;
    oid->oid_name = sysctl_string_duplicate(name);
    oid->oid_fmt = sysctl_string_duplicate(format ? format : "");
    oid->oid_descr = sysctl_string_duplicate(
        description ? description : "");
    oid->oid_label = label ? sysctl_string_duplicate(label) : 0;
    if (!oid->oid_name || !oid->oid_fmt || !oid->oid_descr ||
        (label && !oid->oid_label)) {
        bsd_free((void *)oid->oid_name, M_TEMP);
        bsd_free((void *)oid->oid_fmt, M_TEMP);
        bsd_free((void *)oid->oid_descr, M_TEMP);
        bsd_free((void *)oid->oid_label, M_TEMP);
        bsd_free(oid, M_TEMP);
        return 0;
    }
    RB_INIT(&oid->oid_children);
    oid->oid_parent = parent;
    oid->oid_kind = (unsigned int)kind | CTLFLAG_DYN;
    oid->oid_arg1 = argument;
    oid->oid_arg2 = argument_value;
    oid->oid_handler = handler;
    oid->oid_refcnt = 1;

    sysctl_lock();
    oid->oid_number = number == OID_AUTO ?
        sysctl_next_number(parent) : number;
    if (RB_INSERT(sysctl_oid_list, parent, oid) != 0) {
        sysctl_unlock();
        bsd_free((void *)oid->oid_name, M_TEMP);
        bsd_free((void *)oid->oid_fmt, M_TEMP);
        bsd_free((void *)oid->oid_descr, M_TEMP);
        bsd_free((void *)oid->oid_label, M_TEMP);
        bsd_free(oid, M_TEMP);
        return 0;
    }
    sysctl_unlock();
    if (context && !sysctl_ctx_entry_add(context, oid)) {
        (void)sysctl_remove_oid(oid, 1, 1);
        return 0;
    }
    return oid;
}

static void
sysctl_free_oid(struct sysctl_oid *oid)
{
    bsd_free((void *)oid->oid_name, M_TEMP);
    bsd_free((void *)oid->oid_fmt, M_TEMP);
    bsd_free((void *)oid->oid_descr, M_TEMP);
    bsd_free((void *)oid->oid_label, M_TEMP);
    bsd_free(oid, M_TEMP);
}

int
sysctl_remove_oid(struct sysctl_oid *oid, int destroy, int recurse)
{
    struct sysctl_oid *child;

    if (!oid || (oid->oid_kind & CTLFLAG_DYN) == 0)
        return BSD_SYSCTL_EINVAL;
    if (!recurse && !RB_EMPTY(&oid->oid_children))
        return BSD_SYSCTL_EEXIST;
    while ((child = RB_MIN(sysctl_oid_list, &oid->oid_children)) != 0) {
        int result = sysctl_remove_oid(child, destroy, 1);

        if (result != 0)
            return result;
    }
    sysctl_lock();
    (void)RB_REMOVE(sysctl_oid_list, oid->oid_parent, oid);
    sysctl_unlock();
    if (destroy)
        sysctl_free_oid(oid);
    return 0;
}

int
sysctl_ctx_free(struct sysctl_ctx_list *context)
{
    struct sysctl_ctx_entry *entry;

    if (!context)
        return BSD_SYSCTL_EINVAL;
    while ((entry = TAILQ_FIRST(context)) != 0) {
        struct sysctl_oid *oid = entry->entry;

        TAILQ_REMOVE(context, entry, link);
        bsd_free(entry, M_TEMP);
        if (oid && (oid->oid_kind & CTLFLAG_DYN) != 0)
            (void)sysctl_remove_oid(oid, 1, 1);
    }
    return 0;
}

static int
sysctl_request_output(struct sysctl_req *request, const void *data,
    size_t length)
{
    if (!request || !request->oldfunc)
        return 0;
    return request->oldfunc(request, data, length);
}

static int
sysctl_request_input(struct sysctl_req *request, void *data, size_t length)
{
    if (!request || !request->newptr)
        return 0;
    if (!request->newfunc)
        return BSD_SYSCTL_EINVAL;
    return request->newfunc(request, data, length);
}

static int sysctl_handle_small_integer(struct sysctl_req *, void *,
    uint64_t, size_t);

int
sysctl_handle_int(SYSCTL_HANDLER_ARGS)
{
    int value = arg1 ? *(int *)arg1 : (int)arg2;
    int result;

    (void)oidp;
    if (!req)
        return BSD_SYSCTL_EINVAL;
    result = sysctl_request_output(req, &value, sizeof(value));
    if (result != 0 || !req->newptr)
        return result;
    result = sysctl_request_input(req, &value, sizeof(value));
    if (result == 0 && arg1)
        *(int *)arg1 = value;
    return result;
}

int
sysctl_handle_64(SYSCTL_HANDLER_ARGS)
{
    uint64_t value = arg1 ? *(uint64_t *)arg1 : (uint64_t)arg2;
    int result;

    (void)oidp;
    if (!req)
        return BSD_SYSCTL_EINVAL;
    result = sysctl_request_output(req, &value, sizeof(value));
    if (result != 0 || !req->newptr)
        return result;
    result = sysctl_request_input(req, &value, sizeof(value));
    if (result == 0 && arg1)
        *(uint64_t *)arg1 = value;
    return result;
}

int
sysctl_msec_to_sbintime(SYSCTL_HANDLER_ARGS)
{
    const int64_t units_per_second = INT64_C(4294967296);
    const int64_t minimum_milliseconds = INT64_C(-2147483648000);
    const int64_t maximum_milliseconds = INT64_C(2147483647999);
    int64_t seconds;
    int64_t remainder;
    int64_t milliseconds;
    uint64_t fraction;
    int result;

    (void)arg2;
    if (!arg1)
        return BSD_SYSCTL_EINVAL;
    seconds = *(int64_t *)arg1 / units_per_second;
    remainder = *(int64_t *)arg1 % units_per_second;
    if (remainder < 0) {
        seconds--;
        remainder += units_per_second;
    }
    milliseconds = seconds * 1000 +
        (int64_t)(((uint64_t)remainder * 1000) /
        (uint64_t)units_per_second);
    result = sysctl_handle_64(oidp, &milliseconds, 0, req);
    if (result != 0 || !req->newptr)
        return result;
    if (milliseconds < minimum_milliseconds ||
        milliseconds > maximum_milliseconds)
        return BSD_SYSCTL_EINVAL;
    seconds = milliseconds / 1000;
    remainder = milliseconds % 1000;
    if (remainder < 0) {
        seconds--;
        remainder += 1000;
    }
    fraction = ((uint64_t)remainder *
        (uint64_t)units_per_second + 999) / 1000;
    *(int64_t *)arg1 = seconds * units_per_second +
        (int64_t)fraction;
    return 0;
}

int
sysctl_handle_8(SYSCTL_HANDLER_ARGS)
{
    (void)oidp;
    return sysctl_handle_small_integer(req, arg1, (uint64_t)arg2,
        sizeof(int8_t));
}

int
sysctl_handle_16(SYSCTL_HANDLER_ARGS)
{
    (void)oidp;
    return sysctl_handle_small_integer(req, arg1, (uint64_t)arg2,
        sizeof(int16_t));
}

int
sysctl_handle_32(SYSCTL_HANDLER_ARGS)
{
    (void)oidp;
    return sysctl_handle_small_integer(req, arg1, (uint64_t)arg2,
        sizeof(int32_t));
}

int
sysctl_handle_long(SYSCTL_HANDLER_ARGS)
{
    (void)oidp;
    return sysctl_handle_small_integer(req, arg1, (uint64_t)arg2,
        sizeof(long));
}

static int
sysctl_handle_small_integer(struct sysctl_req *request, void *pointer,
    uint64_t immediate, size_t size)
{
    uint64_t value = immediate;
    int result;

    if (!request || size == 0 || size > sizeof(value))
        return BSD_SYSCTL_EINVAL;
    if (pointer)
        bsd_memcpy(&value, pointer, size);
    result = sysctl_request_output(request, &value, size);
    if (result != 0 || !request->newptr)
        return result;
    if (!pointer)
        return BSD_SYSCTL_EPERM;
    result = sysctl_request_input(request, &value, size);
    if (result == 0 && pointer)
        bsd_memcpy(pointer, &value, size);
    return result;
}

int
sysctl_handle_bool(SYSCTL_HANDLER_ARGS)
{
    (void)oidp;
    return sysctl_handle_small_integer(req, arg1, (uint64_t)arg2,
        sizeof(uint8_t));
}

int
sysctl_handle_u8(SYSCTL_HANDLER_ARGS)
{
    return sysctl_handle_bool(oidp, arg1, arg2, req);
}

int
sysctl_handle_u16(SYSCTL_HANDLER_ARGS)
{
    (void)oidp;
    return sysctl_handle_small_integer(req, arg1, (uint64_t)arg2,
        sizeof(uint16_t));
}

int
sysctl_handle_string(SYSCTL_HANDLER_ARGS)
{
    char *text = arg1;
    size_t capacity;
    size_t input_length;
    size_t length;
    int result;

    if (!req || !text)
        return BSD_SYSCTL_EINVAL;
    capacity = arg2 > 0 ? (size_t)arg2 : bsd_strlen(text) + 1u;
    length = arg2 > 0 ?
        bsd_strnlen(text, capacity - 1u) + 1u : capacity;
    result = sysctl_request_output(req, text, length);
    if (result != 0 || !req->newptr)
        return result;
    if (arg2 <= 0 ||
        (oidp && (oidp->oid_kind & (CTLFLAG_WR | CTLFLAG_TUN)) == 0))
        return BSD_SYSCTL_EPERM;
    if (req->newidx > req->newlen)
        return BSD_SYSCTL_EINVAL;
    input_length = req->newlen - req->newidx;
    if (input_length >= capacity)
        return BSD_SYSCTL_EINVAL;
    if (input_length == 0) {
        text[0] = '\0';
        return 0;
    }
    result = sysctl_request_input(req, text, input_length);
    if (result == 0)
        text[input_length] = '\0';
    return result;
}

int
sysctl_handle_opaque(SYSCTL_HANDLER_ARGS)
{
    size_t length;
    int result;

    (void)oidp;
    if (!req || !arg1 || arg2 < 0)
        return BSD_SYSCTL_EINVAL;
    length = (size_t)arg2;
    result = sysctl_request_output(req, arg1, length);
    if (result != 0 || !req->newptr)
        return result;
    return sysctl_request_input(req, arg1, length);
}

int
sysctl_handle_counter_u64(SYSCTL_HANDLER_ARGS)
{
    counter_u64_t counter =
        arg1 ? *(counter_u64_t *)arg1 : 0;
    uint64_t value = counter_u64_fetch(counter);

    (void)oidp;
    (void)arg2;
    if (!req)
        return BSD_SYSCTL_EINVAL;
    return sysctl_request_output(req, &value, sizeof(value));
}

int
sysctl_wire_old_buffer(struct sysctl_req *request, size_t length)
{
    (void)length;
    return request ? 0 : BSD_SYSCTL_EINVAL;
}

static int
sbuf_sysctl_drain(void *argument, const char *data, int length)
{
    struct sysctl_req *request = argument;
    int result;

    result = sysctl_request_output(request, data, (size_t)length);
    return result == 0 ? length : -result;
}

struct sbuf *
sbuf_new_for_sysctl(struct sbuf *buffer, char *storage, int length,
    struct sysctl_req *request)
{
    struct sbuf *result = sbuf_new(buffer, storage, length,
        SBUF_AUTOEXTEND);

    if (result)
        sbuf_set_drain(result, sbuf_sysctl_drain, request);
    return result;
}

static struct bsd_sysctl_device_state *
bsd_sysctl_device_state_get(void **state, const char *name)
{
    struct bsd_sysctl_device_state *device_state;

    if (!state)
        return 0;
    if (*state)
        return *state;
    device_state = bsd_malloc(sizeof(*device_state), M_TEMP,
        M_WAITOK | M_ZERO);
    if (!device_state)
        return 0;
    (void)sysctl_ctx_init(&device_state->context);
    device_state->tree = sysctl_add_oid(&device_state->context,
        SYSCTL_CHILDREN(&sysctl___dev), OID_AUTO,
        name ? name : "unnamed", CTLTYPE_NODE | CTLFLAG_RD |
        CTLFLAG_MPSAFE, 0, 0, 0, "N", "device", 0);
    if (!device_state->tree) {
        bsd_free(device_state, M_TEMP);
        return 0;
    }
    *state = device_state;
    return device_state;
}

struct sysctl_ctx_list *
bsd_sysctl_device_context(void **state, const char *name)
{
    struct bsd_sysctl_device_state *device_state =
        bsd_sysctl_device_state_get(state, name);

    return device_state ? &device_state->context : 0;
}

struct sysctl_oid *
bsd_sysctl_device_tree(void **state, const char *name)
{
    struct bsd_sysctl_device_state *device_state =
        bsd_sysctl_device_state_get(state, name);

    return device_state ? device_state->tree : 0;
}

void
bsd_sysctl_device_destroy(void **state)
{
    struct bsd_sysctl_device_state *device_state;

    if (!state || !*state)
        return;
    device_state = *state;
    (void)sysctl_ctx_free(&device_state->context);
    bsd_free(device_state, M_TEMP);
    *state = 0;
}
