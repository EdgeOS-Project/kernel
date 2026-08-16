/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Shared TTY and character-device runtime for unmodified FreeBSD drivers.
 *
 * Imported drivers retain the FreeBSD bottom-half contract.  EdgeOS exposes
 * the resulting devices through a small native registry consumed by every
 * architecture's common character-device path.
 */

#include "compat/freebsd/sys/tty.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/cdev.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/fcntl.h"
#include "compat/freebsd/sys/kassert.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/malloc.h"
#include "compat/freebsd/sys/poll.h"
#include "compat/freebsd/sys/selinfo.h"
#include "compat/freebsd/sys/uio.h"
#include "compat/freebsd/vm/vm_object.h"
#include "compat/freebsd/vm/vm_page.h"

#define BSD_TTY_BUFFER_CAPACITY 16384u
#define BSD_TTY_CANONICAL_CAPACITY 4096u
#define BSD_CDEV_MAX_NODES 1024u
#define BSD_CDEV_SESSION_TABLE_SIZE 2048u
#define BSD_CDEV_LINUX_MAJOR 229u
#define BSD_IOCTL_LENGTH_MASK 0x1fffu
#define BSD_IOCTL_VOID 0x20000000u
#define BSD_IOCTL_OUTPUT 0x40000000u
#define BSD_IOCTL_INPUT 0x80000000u
#define BSD_IOCTL_DIRECTION_MASK \
    (BSD_IOCTL_VOID | BSD_IOCTL_OUTPUT | BSD_IOCTL_INPUT)
#define LINUX_IOCTL_LENGTH_MASK 0x3fffu
#define LINUX_IOCTL_WRITE 0x40000000u
#define LINUX_IOCTL_READ 0x80000000u
#define LINUX_IOCTL_DIRECTION_MASK \
    (LINUX_IOCTL_WRITE | LINUX_IOCTL_READ)

#if defined(BSD_BRIDGE_FORCE_LLP64_V4L2_ABI) || \
    (__SIZEOF_LONG__ == 4 && __SIZEOF_POINTER__ == 8)
#define BSD_CDEV_LLP64_V4L2_ABI 1
#define LINUX_V4L2_BUFFER_SIZE 88u
#define FREEBSD_LLP64_V4L2_BUFFER_SIZE 80u
#define V4L2_IOCTL_GROUP 0x56u
#define V4L2_QUERYBUF_NUMBER 9u
#define V4L2_QBUF_NUMBER 15u
#define V4L2_DQBUF_NUMBER 17u
#endif

#define BSD_EAGAIN 11
#define BSD_EBADF 9
#define BSD_EBUSY 16
#define BSD_EINVAL 22
#define BSD_EINTR 4
#define BSD_ENOSPC 28
#define BSD_ENXIO 6
#define BSD_EOVERFLOW 84
#define BSD_ERESTART 85

#define BSD_CDEV_SESSION_EMPTY UINT64_C(0)
#define BSD_CDEV_SESSION_TOMBSTONE UINT64_MAX
#define BSD_CDEV_SESSION_OPENING 1u
#define BSD_CDEV_SESSION_OPEN 2u
#define BSD_CDEV_SESSION_CLOSING 3u

extern unsigned long maxphys;

#define BSD_LINUX_INLCR 0x0040u
#define BSD_LINUX_IGNCR 0x0080u
#define BSD_LINUX_ICRNL 0x0100u
#define BSD_LINUX_IGNBRK 0x0001u
#define BSD_LINUX_BRKINT 0x0002u
#define BSD_LINUX_IGNPAR 0x0004u
#define BSD_LINUX_PARMRK 0x0008u
#define BSD_LINUX_INPCK 0x0010u
#define BSD_LINUX_ISTRIP 0x0020u
#define BSD_LINUX_IXON 0x0400u
#define BSD_LINUX_IXANY 0x0800u
#define BSD_LINUX_IXOFF 0x1000u
#define BSD_LINUX_IMAXBEL 0x2000u
#define BSD_LINUX_IUTF8 0x4000u
#define BSD_LINUX_OPOST 0x0001u
#define BSD_LINUX_ONLCR 0x0004u
#define BSD_LINUX_OCRNL 0x0008u
#define BSD_LINUX_ONOCR 0x0010u
#define BSD_LINUX_ONLRET 0x0020u
#define BSD_LINUX_CS6 0x0010u
#define BSD_LINUX_CS7 0x0020u
#define BSD_LINUX_CS8 0x0030u
#define BSD_LINUX_CSIZE 0x0030u
#define BSD_LINUX_CSTOPB 0x0040u
#define BSD_LINUX_CREAD 0x0080u
#define BSD_LINUX_PARENB 0x0100u
#define BSD_LINUX_PARODD 0x0200u
#define BSD_LINUX_HUPCL 0x0400u
#define BSD_LINUX_CLOCAL 0x0800u
#define BSD_LINUX_CBAUD 0x100fu
#define BSD_LINUX_CRTSCTS 0x80000000u
#define BSD_LINUX_ISIG 0x0001u
#define BSD_LINUX_ICANON 0x0002u
#define BSD_LINUX_ECHO 0x0008u
#define BSD_LINUX_ECHOE 0x0010u
#define BSD_LINUX_ECHOK 0x0020u
#define BSD_LINUX_ECHONL 0x0040u
#define BSD_LINUX_NOFLSH 0x0080u
#define BSD_LINUX_TOSTOP 0x0100u
#define BSD_LINUX_ECHOCTL 0x0200u
#define BSD_LINUX_ECHOPRT 0x0400u
#define BSD_LINUX_ECHOKE 0x0800u
#define BSD_LINUX_IEXTEN 0x8000u

#define BSD_LINUX_VINTR 0u
#define BSD_LINUX_VQUIT 1u
#define BSD_LINUX_VERASE 2u
#define BSD_LINUX_VKILL 3u
#define BSD_LINUX_VEOF 4u
#define BSD_LINUX_VTIME 5u
#define BSD_LINUX_VMIN 6u
#define BSD_LINUX_VSTART 8u
#define BSD_LINUX_VSTOP 9u
#define BSD_LINUX_VSUSP 10u
#define BSD_LINUX_VEOL 11u
#define BSD_LINUX_VREPRINT 12u
#define BSD_LINUX_VDISCARD 13u
#define BSD_LINUX_VWERASE 14u
#define BSD_LINUX_VLNEXT 15u
#define BSD_LINUX_VEOL2 16u

typedef struct bsd_tty_runtime {
    uint8_t input[BSD_TTY_BUFFER_CAPACITY];
    uint8_t output[BSD_TTY_BUFFER_CAPACITY];
    uint8_t canonical[BSD_TTY_CANONICAL_CAPACITY];
    uint32_t input_head;
    uint32_t input_count;
    uint32_t output_head;
    uint32_t output_count;
    uint32_t canonical_count;
    bsd_bridge_linux_termios_t termios;
    volatile uint64_t read_sequence;
    volatile uint64_t write_sequence;
    volatile uint32_t poll_events;
    uint32_t open_sessions;
    uint8_t opened;
    uint8_t eof_pending;
    uint8_t carrier_present;
    uint8_t hangup;
    uint8_t break_channel;
} bsd_tty_runtime_t;

typedef struct bsd_cdev_session {
    uint64_t identity;
    int64_t offset;
    struct cdev *device;
    struct thread thread;
    struct proc process;
    uint32_t bsd_flags;
    uint32_t active_operations;
    uint8_t state;
} bsd_cdev_session_t;

typedef struct bsd_clone_entry {
    struct cdevsw *driver;
    struct cdev *device;
    int unit;
    struct bsd_clone_entry *next;
} bsd_clone_entry_t;

struct clonedevs {
    bsd_clone_entry_t *entries;
    struct clonedevs *global_next;
};

static struct cdev *g_cdev_nodes[BSD_CDEV_MAX_NODES];
static bsd_cdev_session_t
    g_cdev_sessions[BSD_CDEV_SESSION_TABLE_SIZE];
static volatile uint32_t g_cdev_guard;
static volatile uint32_t g_cdev_next_minor;
static volatile uint64_t g_cdev_change_sequence;
static struct clonedevs *g_clone_lists;

_Static_assert(
    (BSD_CDEV_SESSION_TABLE_SIZE &
    (BSD_CDEV_SESSION_TABLE_SIZE - 1u)) == 0u,
    "BSD cdev session table must be a power of two");

void __attribute__((weak))
bsd_bridge_devtmpfs_changed(void)
{
}

static void
processor_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static uint64_t
interrupt_save_disable(void)
{
#if defined(BSD_BRIDGE_HOST_TEST)
    return 0;
#elif defined(__x86_64__)
    uint64_t state;

    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(state) :: "memory");
    return state;
#elif defined(__aarch64__)
    uint64_t state;

    __asm__ __volatile__("mrs %0, daif; msr daifset, #0xf"
        : "=r"(state) :: "memory");
    return state;
#else
#error "BSD character devices require an interrupt-state implementation"
#endif
}

static void
interrupt_restore(uint64_t state)
{
#if defined(BSD_BRIDGE_HOST_TEST)
    (void)state;
#elif defined(__x86_64__)
    if ((state & (1ull << 9)) != 0)
        __asm__ __volatile__("sti" ::: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("msr daif, %0" :: "r"(state) : "memory");
#endif
}

static uint64_t
cdev_lock(void)
{
    uint64_t state = interrupt_save_disable();

    while (__atomic_test_and_set(&g_cdev_guard, __ATOMIC_ACQUIRE))
        processor_relax();
    return state;
}

static void
cdev_unlock(uint64_t state)
{
    __atomic_clear(&g_cdev_guard, __ATOMIC_RELEASE);
    interrupt_restore(state);
}

static uint32_t
cdev_session_hash(uint64_t identity)
{
    identity ^= identity >> 33;
    identity *= UINT64_C(0xff51afd7ed558ccd);
    identity ^= identity >> 33;
    return (uint32_t)identity &
        (BSD_CDEV_SESSION_TABLE_SIZE - 1u);
}

static bsd_cdev_session_t *
cdev_session_find_locked(uint64_t identity)
{
    uint32_t first;

    if (identity == BSD_CDEV_SESSION_EMPTY ||
        identity == BSD_CDEV_SESSION_TOMBSTONE)
        return 0;
    first = cdev_session_hash(identity);
    for (uint32_t probe = 0;
        probe < BSD_CDEV_SESSION_TABLE_SIZE; ++probe) {
        bsd_cdev_session_t *session =
            &g_cdev_sessions[(first + probe) &
                (BSD_CDEV_SESSION_TABLE_SIZE - 1u)];

        if (session->identity == identity)
            return session;
        if (session->identity == BSD_CDEV_SESSION_EMPTY)
            return 0;
    }
    return 0;
}

static bsd_cdev_session_t *
cdev_session_insert_locked(uint64_t identity)
{
    bsd_cdev_session_t *tombstone = 0;
    uint32_t first = cdev_session_hash(identity);

    for (uint32_t probe = 0;
        probe < BSD_CDEV_SESSION_TABLE_SIZE; ++probe) {
        bsd_cdev_session_t *session =
            &g_cdev_sessions[(first + probe) &
                (BSD_CDEV_SESSION_TABLE_SIZE - 1u)];

        if (session->identity == identity)
            return 0;
        if (session->identity == BSD_CDEV_SESSION_TOMBSTONE) {
            if (!tombstone)
                tombstone = session;
            continue;
        }
        if (session->identity == BSD_CDEV_SESSION_EMPTY)
            return tombstone ? tombstone : session;
    }
    return tombstone;
}

static void
cdev_session_remove_locked(bsd_cdev_session_t *session)
{
    if (!session)
        return;
    bsd_memset(session, 0, sizeof(*session));
    session->identity = BSD_CDEV_SESSION_TOMBSTONE;
}

static int
append_byte(char *destination, size_t capacity, size_t *length, char byte)
{
    if (!destination || !length || *length + 1 >= capacity)
        return BSD_ENOSPC;
    destination[(*length)++] = byte;
    destination[*length] = 0;
    return 0;
}

static int
append_text(char *destination, size_t capacity, size_t *length,
    const char *text, size_t limit)
{
    size_t copied = 0;

    if (!text)
        text = "(null)";
    while (*text && copied < limit) {
        int error = append_byte(destination, capacity, length, *text++);

        if (error)
            return error;
        ++copied;
    }
    return 0;
}

static int
append_unsigned(char *destination, size_t capacity, size_t *length,
    unsigned int value, int negative)
{
    char reversed[16];
    size_t digits = 0;
    int error;

    if (negative) {
        error = append_byte(destination, capacity, length, '-');
        if (error)
            return error;
    }
    do {
        reversed[digits++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value != 0 && digits < sizeof(reversed));
    while (digits != 0) {
        error = append_byte(destination, capacity, length,
            reversed[--digits]);
        if (error)
            return error;
    }
    return 0;
}

/*
 * FreeBSD device formats use %r for unit numbers.  The bridge formatter also
 * accepts the ordinary integer, string, character, and exact-length %*s forms
 * used by upstream driver names.
 */
static int
format_device_name(char *destination, size_t capacity, const char *format,
    va_list arguments)
{
    size_t length = 0;

    if (!destination || capacity == 0 || !format)
        return BSD_EINVAL;
    destination[0] = 0;
    while (*format) {
        int error;

        if (*format != '%') {
            error = append_byte(destination, capacity, &length, *format++);
            if (error)
                return error;
            continue;
        }
        ++format;
        if (*format == '%') {
            error = append_byte(destination, capacity, &length, '%');
            ++format;
        } else if (*format == 's') {
            error = append_text(destination, capacity, &length,
                va_arg(arguments, const char *), SIZE_MAX);
            ++format;
        } else if (*format == '*' && format[1] == 's') {
            int width = va_arg(arguments, int);
            const char *text = va_arg(arguments, const char *);

            if (width < 0)
                return BSD_EINVAL;
            error = append_text(destination, capacity, &length, text,
                (size_t)width);
            format += 2;
        } else if (*format == 'c') {
            error = append_byte(destination, capacity, &length,
                (char)va_arg(arguments, int));
            ++format;
        } else if (*format == 'd' || *format == 'i' || *format == 'r') {
            int value = va_arg(arguments, int);
            unsigned int magnitude =
                value < 0 ? 0u - (unsigned int)value : (unsigned int)value;

            error = append_unsigned(destination, capacity, &length,
                magnitude, value < 0);
            ++format;
        } else if (*format == 'u') {
            error = append_unsigned(destination, capacity, &length,
                va_arg(arguments, unsigned int), 0);
            ++format;
        } else {
            return BSD_EINVAL;
        }
        if (error)
            return error;
    }
    return length == 0 ? BSD_EINVAL : 0;
}

static int
device_name_valid(const char *name)
{
    const char *component;

    if (!name || !name[0] || name[0] == '/')
        return 0;
    component = name;
    for (const char *cursor = name;; ++cursor) {
        unsigned char byte = (unsigned char)*cursor;

        if (byte != 0 && (byte < 0x21u || byte > 0x7eu))
            return 0;
        if (byte == '/' || byte == 0) {
            size_t length = (size_t)(cursor - component);

            if (length == 0 ||
                (length == 1 && component[0] == '.') ||
                (length == 2 && component[0] == '.' &&
                component[1] == '.'))
                return 0;
            if (byte == 0)
                break;
            component = cursor + 1;
        }
    }
    return 1;
}

static int
cdev_register(struct cdev *device)
{
    uint64_t state;
    uint32_t available = BSD_CDEV_MAX_NODES;
    int result = BSD_ENOSPC;

    if (!device || !device_name_valid(device->si_name))
        return BSD_EINVAL;
    state = cdev_lock();
    for (uint32_t index = 0; index < BSD_CDEV_MAX_NODES; ++index) {
        struct cdev *candidate = g_cdev_nodes[index];

        if (candidate &&
            bsd_strcmp(candidate->si_name, device->si_name) == 0) {
            result = BSD_EINVAL;
            break;
        }
        if (!candidate && available == BSD_CDEV_MAX_NODES)
            available = index;
    }
    if (result != BSD_EINVAL && available != BSD_CDEV_MAX_NODES) {
        g_cdev_nodes[available] = device;
        device->si_flags |= SI_NAMED;
        device->edgeos_delisted = 0;
        if (device->si_parent) {
            device->edgeos_alias_next =
                device->si_parent->edgeos_alias_head;
            device->si_parent->edgeos_alias_head = device;
        }
        result = 0;
    }
    cdev_unlock(state);
    if (!result) {
        (void)__atomic_fetch_add(&g_cdev_change_sequence, 1,
            __ATOMIC_RELEASE);
        bsd_bridge_devtmpfs_changed();
    }
    return result;
}

static int
cdev_unregister(struct cdev *device)
{
    uint64_t state;
    int found = 0;

    if (!device)
        return 0;
    state = cdev_lock();
    for (uint32_t index = 0; index < BSD_CDEV_MAX_NODES; ++index) {
        struct cdev *candidate = g_cdev_nodes[index];

        if (!candidate)
            continue;
        if (candidate != device &&
            (!device || (device->si_flags & SI_ALIAS) != 0 ||
            candidate->si_parent != device))
            continue;
        g_cdev_nodes[index] = 0;
        candidate->si_flags &= ~SI_NAMED;
        candidate->edgeos_delisted = 1;
        found = 1;
    }
    cdev_unlock(state);
    if (found) {
        (void)__atomic_fetch_add(&g_cdev_change_sequence, 1,
            __ATOMIC_RELEASE);
        bsd_bridge_devtmpfs_changed();
    }
    return found;
}

static void
cdev_unregister_tty(struct tty *tty)
{
    struct cdev *removed[BSD_CDEV_MAX_NODES];
    uint32_t removed_count = 0;
    uint64_t state;

    state = cdev_lock();
    for (uint32_t index = 0; index < BSD_CDEV_MAX_NODES; ++index) {
        struct cdev *device = g_cdev_nodes[index];

        if (!device || device->si_tty != tty)
            continue;
        g_cdev_nodes[index] = 0;
        device->si_flags &= ~SI_NAMED;
        device->edgeos_delisted = 1;
        removed[removed_count++] = device;
    }
    cdev_unlock(state);
    if (removed_count != 0) {
        (void)__atomic_fetch_add(&g_cdev_change_sequence, 1,
            __ATOMIC_RELEASE);
        bsd_bridge_devtmpfs_changed();
    }
    for (uint32_t index = 0; index < removed_count; ++index) {
        while (__atomic_load_n(&removed[index]->edgeos_references,
            __ATOMIC_ACQUIRE) != 0)
            processor_relax();
        bsd_free(removed[index], M_DEVBUF);
    }
}

static struct cdev *
cdev_lookup(uint64_t linux_rdev)
{
    uint32_t major = (uint32_t)((linux_rdev >> 8) & 0xfffu) |
        (uint32_t)((linux_rdev >> 32) & ~0xfffull);
    uint32_t minor = (uint32_t)(linux_rdev & 0xffu) |
        (uint32_t)((linux_rdev >> 12) & ~0xffull);
    struct cdev *result = 0;
    uint64_t state = cdev_lock();

    for (uint32_t index = 0; index < BSD_CDEV_MAX_NODES; ++index) {
        struct cdev *device = g_cdev_nodes[index];

        if (!device || (device->si_flags & SI_ALIAS) != 0 ||
            device->si_linux_major != major ||
            device->si_linux_minor != minor)
            continue;
        (void)__atomic_fetch_add(&device->edgeos_references, 1,
            __ATOMIC_RELAXED);
        result = device;
        break;
    }
    cdev_unlock(state);
    return result;
}

static int
cdev_matches_rdev(const struct cdev *device, uint64_t linux_rdev)
{
    uint32_t major = (uint32_t)((linux_rdev >> 8) & 0xfffu) |
        (uint32_t)((linux_rdev >> 32) & ~0xfffull);
    uint32_t minor = (uint32_t)(linux_rdev & 0xffu) |
        (uint32_t)((linux_rdev >> 12) & ~0xfffull);

    return device && device->si_linux_major == major &&
        device->si_linux_minor == minor;
}

static void
cdev_release(struct cdev *device)
{
    if (device)
        (void)__atomic_fetch_sub(&device->edgeos_references, 1,
            __ATOMIC_RELEASE);
}

static int
cdev_transition_enter(struct cdev *device, int allow_delisted)
{
    if (!device)
        return BSD_ENXIO;
    for (;;) {
        uint64_t state = cdev_lock();

        if (!allow_delisted && device->edgeos_delisted) {
            cdev_unlock(state);
            return BSD_ENXIO;
        }
        if (!device->edgeos_transition_active) {
            device->edgeos_transition_active = 1;
            cdev_unlock(state);
            return 0;
        }
        cdev_unlock(state);
        bsd_kthread_pump();
        processor_relax();
    }
}

static void
cdev_transition_leave(struct cdev *device)
{
    uint64_t state;

    if (!device)
        return;
    state = cdev_lock();
    device->edgeos_transition_active = 0;
    cdev_unlock(state);
}

static uint32_t
cdev_flags_from_linux(uint32_t linux_flags)
{
    uint32_t result;

    switch (linux_flags & 3u) {
    case 0u:
        result = FREAD;
        break;
    case 1u:
        result = FWRITE;
        break;
    case 2u:
        result = FREAD | FWRITE;
        break;
    default:
        result = 0;
        break;
    }
    if ((linux_flags & 0x800u) != 0)
        result |= FNONBLOCK;
    if ((linux_flags & 0x400u) != 0)
        result |= FAPPEND;
    return result;
}

static bsd_cdev_session_t *
cdev_session_acquire(uint64_t identity, uint64_t linux_rdev)
{
    bsd_cdev_session_t *session;
    uint64_t state;

    if (!identity)
        return 0;
    state = cdev_lock();
    session = cdev_session_find_locked(identity);
    if (!session || session->state != BSD_CDEV_SESSION_OPEN ||
        !cdev_matches_rdev(session->device, linux_rdev) ||
        session->active_operations == UINT32_MAX) {
        session = 0;
    } else {
        ++session->active_operations;
    }
    cdev_unlock(state);
    return session;
}

static void
cdev_session_release(bsd_cdev_session_t *session)
{
    uint64_t state;

    if (!session)
        return;
    state = cdev_lock();
    if (session->active_operations != 0)
        --session->active_operations;
    cdev_unlock(state);
}

static int
cdev_missing_session_result(uint64_t linux_rdev)
{
    struct cdev *device = cdev_lookup(linux_rdev);

    if (!device)
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    cdev_release(device);
    return -BSD_EBADF;
}

static int
cdev_callback_error(int error)
{
    return error == BSD_ERESTART ? BSD_EINTR : error;
}

static uint32_t
ring_write(uint8_t *ring, uint32_t head, uint32_t count,
    const uint8_t *source, uint32_t length)
{
    uint32_t available = BSD_TTY_BUFFER_CAPACITY - count;
    uint32_t written = length < available ? length : available;
    uint32_t tail = (head + count) % BSD_TTY_BUFFER_CAPACITY;

    for (uint32_t index = 0; index < written; ++index)
        ring[(tail + index) % BSD_TTY_BUFFER_CAPACITY] = source[index];
    return written;
}

static uint32_t
ring_read(uint8_t *ring, uint32_t *head, uint32_t *count,
    uint8_t *destination, uint32_t length)
{
    uint32_t read = length < *count ? length : *count;

    for (uint32_t index = 0; index < read; ++index)
        destination[index] =
            ring[(*head + index) % BSD_TTY_BUFFER_CAPACITY];
    *head = (*head + read) % BSD_TTY_BUFFER_CAPACITY;
    *count -= read;
    return read;
}

static void
tty_poll_snapshot_update(bsd_tty_runtime_t *runtime)
{
    uint32_t events = 0;

    if (!runtime)
        return;
    if (runtime->input_count != 0 || runtime->eof_pending)
        events |= BSD_BRIDGE_CDEV_POLL_READ;
    if (runtime->output_count < BSD_TTY_BUFFER_CAPACITY)
        events |= BSD_BRIDGE_CDEV_POLL_WRITE;
    if (runtime->hangup)
        events |= BSD_BRIDGE_CDEV_POLL_HANGUP;
    __atomic_store_n(&runtime->poll_events, events, __ATOMIC_RELEASE);
}

static void
tty_publish_change(bsd_tty_runtime_t *runtime, int readable, int writable)
{
    if (runtime) {
        tty_poll_snapshot_update(runtime);
        if (readable)
            (void)__atomic_fetch_add(&runtime->read_sequence, 1,
                __ATOMIC_RELEASE);
        if (writable)
            (void)__atomic_fetch_add(&runtime->write_sequence, 1,
                __ATOMIC_RELEASE);
    }
    (void)__atomic_fetch_add(&g_cdev_change_sequence, 1,
        __ATOMIC_RELEASE);
}

static void
tty_termios_initialize(bsd_bridge_linux_termios_t *termios)
{
    if (!termios)
        return;
    bsd_memset(termios, 0, sizeof(*termios));
    termios->iflag = 0x500u;
    termios->oflag = 0x5u;
    termios->cflag = 0xbfu;
    termios->lflag = 0x8a3bu;
    termios->cc[BSD_LINUX_VINTR] = 3u;
    termios->cc[BSD_LINUX_VQUIT] = 28u;
    termios->cc[BSD_LINUX_VERASE] = 127u;
    termios->cc[BSD_LINUX_VKILL] = 21u;
    termios->cc[BSD_LINUX_VEOF] = 4u;
    termios->cc[BSD_LINUX_VTIME] = 0u;
    termios->cc[BSD_LINUX_VMIN] = 1u;
    termios->cc[BSD_LINUX_VSTART] = 17u;
    termios->cc[BSD_LINUX_VSTOP] = 19u;
    termios->cc[BSD_LINUX_VSUSP] = 26u;
}

static speed_t
tty_linux_speed(uint32_t control_flags)
{
    switch (control_flags & BSD_LINUX_CBAUD) {
    case 0x0000u: return B0;
    case 0x0001u: return B50;
    case 0x0002u: return B75;
    case 0x0003u: return B110;
    case 0x0004u: return B134;
    case 0x0005u: return B150;
    case 0x0006u: return B200;
    case 0x0007u: return B300;
    case 0x0008u: return B600;
    case 0x0009u: return B1200;
    case 0x000au: return B1800;
    case 0x000bu: return B2400;
    case 0x000cu: return B4800;
    case 0x000du: return B9600;
    case 0x000eu: return B19200;
    case 0x000fu: return B38400;
    case 0x1001u: return B57600;
    case 0x1002u: return B115200;
    case 0x1003u: return B230400;
    case 0x1004u: return B460800;
    case 0x1005u: return B500000;
    case 0x1006u: return 576000u;
    case 0x1007u: return B921600;
    case 0x1008u: return B1000000;
    case 0x1009u: return 1152000u;
    case 0x100au: return B1500000;
    case 0x100bu: return B2000000;
    case 0x100cu: return B2500000;
    case 0x100du: return B3000000;
    case 0x100eu: return B3500000;
    case 0x100fu: return B4000000;
    default: return B38400;
    }
}

static void
tty_linux_termios_to_freebsd(
    const bsd_bridge_linux_termios_t *linux_termios,
    struct termios *freebsd_termios)
{
    uint32_t input;
    uint32_t output;
    uint32_t control;
    uint32_t local;

    if (!linux_termios || !freebsd_termios)
        return;
    bsd_memset(freebsd_termios, 0, sizeof(*freebsd_termios));
    input = linux_termios->iflag;
    output = linux_termios->oflag;
    control = linux_termios->cflag;
    local = linux_termios->lflag;

    if (input & BSD_LINUX_IGNBRK) freebsd_termios->c_iflag |= IGNBRK;
    if (input & BSD_LINUX_BRKINT) freebsd_termios->c_iflag |= BRKINT;
    if (input & BSD_LINUX_IGNPAR) freebsd_termios->c_iflag |= IGNPAR;
    if (input & BSD_LINUX_PARMRK) freebsd_termios->c_iflag |= PARMRK;
    if (input & BSD_LINUX_INPCK) freebsd_termios->c_iflag |= INPCK;
    if (input & BSD_LINUX_ISTRIP) freebsd_termios->c_iflag |= ISTRIP;
    if (input & BSD_LINUX_INLCR) freebsd_termios->c_iflag |= INLCR;
    if (input & BSD_LINUX_IGNCR) freebsd_termios->c_iflag |= IGNCR;
    if (input & BSD_LINUX_ICRNL) freebsd_termios->c_iflag |= ICRNL;
    if (input & BSD_LINUX_IXON) freebsd_termios->c_iflag |= IXON;
    if (input & BSD_LINUX_IXANY) freebsd_termios->c_iflag |= IXANY;
    if (input & BSD_LINUX_IXOFF) freebsd_termios->c_iflag |= IXOFF;
    if (input & BSD_LINUX_IMAXBEL) freebsd_termios->c_iflag |= IMAXBEL;
    if (input & BSD_LINUX_IUTF8) freebsd_termios->c_iflag |= IUTF8;

    if (output & BSD_LINUX_OPOST) freebsd_termios->c_oflag |= OPOST;
    if (output & BSD_LINUX_ONLCR) freebsd_termios->c_oflag |= ONLCR;
    if (output & BSD_LINUX_OCRNL) freebsd_termios->c_oflag |= OCRNL;
    if (output & BSD_LINUX_ONOCR) freebsd_termios->c_oflag |= ONOCR;
    if (output & BSD_LINUX_ONLRET) freebsd_termios->c_oflag |= ONLRET;

    switch (control & BSD_LINUX_CSIZE) {
    case BSD_LINUX_CS6: freebsd_termios->c_cflag |= CS6; break;
    case BSD_LINUX_CS7: freebsd_termios->c_cflag |= CS7; break;
    case BSD_LINUX_CS8: freebsd_termios->c_cflag |= CS8; break;
    default: freebsd_termios->c_cflag |= CS5; break;
    }
    if (control & BSD_LINUX_CSTOPB) freebsd_termios->c_cflag |= CSTOPB;
    if (control & BSD_LINUX_CREAD) freebsd_termios->c_cflag |= CREAD;
    if (control & BSD_LINUX_PARENB) freebsd_termios->c_cflag |= PARENB;
    if (control & BSD_LINUX_PARODD) freebsd_termios->c_cflag |= PARODD;
    if (control & BSD_LINUX_HUPCL) freebsd_termios->c_cflag |= HUPCL;
    if (control & BSD_LINUX_CLOCAL) freebsd_termios->c_cflag |= CLOCAL;
    if (control & BSD_LINUX_CRTSCTS) freebsd_termios->c_cflag |= CRTSCTS;

    if (local & BSD_LINUX_ISIG) freebsd_termios->c_lflag |= ISIG;
    if (local & BSD_LINUX_ICANON) freebsd_termios->c_lflag |= ICANON;
    if (local & BSD_LINUX_ECHO) freebsd_termios->c_lflag |= ECHO;
    if (local & BSD_LINUX_ECHOE) freebsd_termios->c_lflag |= ECHOE;
    if (local & BSD_LINUX_ECHOK) freebsd_termios->c_lflag |= ECHOK;
    if (local & BSD_LINUX_ECHONL) freebsd_termios->c_lflag |= ECHONL;
    if (local & BSD_LINUX_NOFLSH) freebsd_termios->c_lflag |= NOFLSH;
    if (local & BSD_LINUX_TOSTOP) freebsd_termios->c_lflag |= TOSTOP;
    if (local & BSD_LINUX_ECHOCTL) freebsd_termios->c_lflag |= ECHOCTL;
    if (local & BSD_LINUX_ECHOPRT) freebsd_termios->c_lflag |= ECHOPRT;
    if (local & BSD_LINUX_ECHOKE) freebsd_termios->c_lflag |= ECHOKE;
    if (local & BSD_LINUX_IEXTEN) freebsd_termios->c_lflag |= IEXTEN;

    freebsd_termios->c_cc[VINTR] =
        linux_termios->cc[BSD_LINUX_VINTR];
    freebsd_termios->c_cc[VQUIT] =
        linux_termios->cc[BSD_LINUX_VQUIT];
    freebsd_termios->c_cc[VERASE] =
        linux_termios->cc[BSD_LINUX_VERASE];
    freebsd_termios->c_cc[VKILL] =
        linux_termios->cc[BSD_LINUX_VKILL];
    freebsd_termios->c_cc[VEOF] =
        linux_termios->cc[BSD_LINUX_VEOF];
    freebsd_termios->c_cc[VTIME] =
        linux_termios->cc[BSD_LINUX_VTIME];
    freebsd_termios->c_cc[VMIN] =
        linux_termios->cc[BSD_LINUX_VMIN];
    freebsd_termios->c_cc[VSTART] =
        linux_termios->cc[BSD_LINUX_VSTART];
    freebsd_termios->c_cc[VSTOP] =
        linux_termios->cc[BSD_LINUX_VSTOP];
    freebsd_termios->c_cc[VSUSP] =
        linux_termios->cc[BSD_LINUX_VSUSP];
    freebsd_termios->c_cc[VEOL] =
        linux_termios->cc[BSD_LINUX_VEOL];
    freebsd_termios->c_cc[VREPRINT] =
        linux_termios->cc[BSD_LINUX_VREPRINT];
    freebsd_termios->c_cc[VDISCARD] =
        linux_termios->cc[BSD_LINUX_VDISCARD];
    freebsd_termios->c_cc[VWERASE] =
        linux_termios->cc[BSD_LINUX_VWERASE];
    freebsd_termios->c_cc[VLNEXT] =
        linux_termios->cc[BSD_LINUX_VLNEXT];
    freebsd_termios->c_cc[VEOL2] =
        linux_termios->cc[BSD_LINUX_VEOL2];
    freebsd_termios->c_ispeed = tty_linux_speed(control);
    freebsd_termios->c_ospeed = freebsd_termios->c_ispeed;
}

static int
tty_queue_output_byte(bsd_tty_runtime_t *runtime, uint8_t byte)
{
    uint8_t translated[2];
    uint32_t length = 1;

    if (!runtime)
        return 0;
    translated[0] = byte;
    if (byte == '\n' &&
        (runtime->termios.oflag &
        (BSD_LINUX_OPOST | BSD_LINUX_ONLCR)) ==
        (BSD_LINUX_OPOST | BSD_LINUX_ONLCR)) {
        translated[0] = '\r';
        translated[1] = '\n';
        length = 2;
    }
    if (BSD_TTY_BUFFER_CAPACITY - runtime->output_count < length)
        return 0;
    runtime->output_count += ring_write(runtime->output,
        runtime->output_head, runtime->output_count, translated, length);
    return 1;
}

static void
tty_echo_byte(bsd_tty_runtime_t *runtime, uint8_t byte)
{
    if (!runtime || (runtime->termios.lflag & BSD_LINUX_ECHO) == 0)
        return;
    if (byte < 0x20u && byte != '\n' && byte != '\t' &&
        (runtime->termios.lflag & BSD_LINUX_ECHOCTL) != 0) {
        (void)tty_queue_output_byte(runtime, '^');
        (void)tty_queue_output_byte(runtime, (uint8_t)(byte + '@'));
        return;
    }
    (void)tty_queue_output_byte(runtime, byte);
}

static void
tty_echo_erase(bsd_tty_runtime_t *runtime)
{
    if (!runtime || (runtime->termios.lflag & BSD_LINUX_ECHO) == 0)
        return;
    if ((runtime->termios.lflag & BSD_LINUX_ECHOE) != 0) {
        (void)tty_queue_output_byte(runtime, '\b');
        (void)tty_queue_output_byte(runtime, ' ');
        (void)tty_queue_output_byte(runtime, '\b');
    } else {
        tty_echo_byte(runtime,
            runtime->termios.cc[BSD_LINUX_VERASE]);
    }
}

static void
tty_publish_canonical(bsd_tty_runtime_t *runtime)
{
    uint32_t written;

    if (!runtime || runtime->canonical_count == 0)
        return;
    written = ring_write(runtime->input, runtime->input_head,
        runtime->input_count, runtime->canonical,
        runtime->canonical_count);
    runtime->input_count += written;
    if (written < runtime->canonical_count)
        bsd_memmove(runtime->canonical, runtime->canonical + written,
            runtime->canonical_count - written);
    runtime->canonical_count -= written;
    if (written != 0)
        tty_publish_change(runtime, 1, 0);
}

static int
tty_input_byte(bsd_tty_runtime_t *runtime, uint8_t byte)
{
    uint8_t eof;
    uint8_t erase;
    uint8_t kill;

    if (!runtime)
        return 0;
    if (byte == '\r') {
        if ((runtime->termios.iflag & BSD_LINUX_IGNCR) != 0)
            return 1;
        if ((runtime->termios.iflag & BSD_LINUX_ICRNL) != 0)
            byte = '\n';
    } else if (byte == '\n' &&
        (runtime->termios.iflag & BSD_LINUX_INLCR) != 0) {
        byte = '\r';
    }
    if ((runtime->termios.lflag & BSD_LINUX_ICANON) == 0) {
        uint32_t written = ring_write(runtime->input,
            runtime->input_head, runtime->input_count, &byte, 1);

        runtime->input_count += written;
        if (written != 0) {
            tty_echo_byte(runtime, byte);
            tty_publish_change(runtime, 1, 0);
        }
        return written == 1;
    }

    eof = runtime->termios.cc[BSD_LINUX_VEOF];
    erase = runtime->termios.cc[BSD_LINUX_VERASE];
    kill = runtime->termios.cc[BSD_LINUX_VKILL];
    if (byte == erase) {
        if (runtime->canonical_count != 0) {
            --runtime->canonical_count;
            tty_echo_erase(runtime);
        }
        return 1;
    }
    if (byte == kill) {
        runtime->canonical_count = 0;
        if ((runtime->termios.lflag &
            (BSD_LINUX_ECHO | BSD_LINUX_ECHOK)) ==
            (BSD_LINUX_ECHO | BSD_LINUX_ECHOK))
            (void)tty_queue_output_byte(runtime, '\n');
        return 1;
    }
    if (byte == eof) {
        if (runtime->canonical_count != 0) {
            tty_publish_canonical(runtime);
        } else {
            runtime->eof_pending = 1;
            tty_publish_change(runtime, 1, 0);
        }
        return 1;
    }
    if (runtime->canonical_count >= BSD_TTY_CANONICAL_CAPACITY ||
        runtime->input_count + runtime->canonical_count >=
        BSD_TTY_BUFFER_CAPACITY)
        return 0;
    runtime->canonical[runtime->canonical_count++] = byte;
    tty_echo_byte(runtime, byte);
    if (byte == '\n')
        tty_publish_canonical(runtime);
    return 1;
}

struct tty *
tty_alloc(struct ttydevsw *driver, void *softc)
{
    return tty_alloc_mutex(driver, softc, 0);
}

struct tty *
tty_alloc_mutex(struct ttydevsw *driver, void *softc, struct mtx *mutex)
{
    struct tty *tty;
    bsd_tty_runtime_t *runtime;

    if (!driver)
        return 0;
    tty = bsd_malloc(sizeof(*tty), M_DEVBUF, M_WAITOK | M_ZERO);
    runtime = bsd_malloc(sizeof(*runtime), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!tty || !runtime) {
        bsd_free(runtime, M_DEVBUF);
        bsd_free(tty, M_DEVBUF);
        return 0;
    }
    tty->t_devsw = driver;
    tty->t_devswsoftc = softc;
    tty->t_flags = driver->tsw_flags;
    tty->edgeos_state = runtime;
    tty_termios_initialize(&runtime->termios);
    tty_linux_termios_to_freebsd(&runtime->termios, &tty->t_termios);
    tty->t_termios_init_in = tty->t_termios;
    tty->t_termios_init_out = tty->t_termios;
    runtime->read_sequence = 1;
    runtime->write_sequence = 1;
    runtime->poll_events = BSD_BRIDGE_CDEV_POLL_WRITE;
    runtime->carrier_present = 1;
    if (mutex) {
        tty->t_mtx = mutex;
    } else {
        mtx_init(&tty->t_mtxobj, "bsdtty", 0, MTX_DEF);
        tty->t_mtx = &tty->t_mtxobj;
    }
    tty->t_winsize.ws_col = 80;
    tty->t_winsize.ws_row = 25;
    return tty;
}

int
tty_makedevf(struct tty *tty, void *credential, int flags,
    const char *format, ...)
{
    struct cdev *device;
    struct cdev *callout = 0;
    char suffix[128];
    size_t prefix_length;
    va_list arguments;
    int error;

    (void)credential;
    (void)flags;
    if (!tty || tty->t_dev || tty_gone(tty))
        return BSD_EINVAL;
    va_start(arguments, format);
    error = format_device_name(suffix, sizeof(suffix), format, arguments);
    va_end(arguments);
    if (error)
        return error;
    device = bsd_malloc(sizeof(*device), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!device)
        return BSD_ENOSPC;
    prefix_length = (tty->t_flags & TF_NOPREFIX) != 0 ? 0u : 3u;
    if (prefix_length + bsd_strlen(suffix) >= sizeof(device->si_name)) {
        bsd_free(device, M_DEVBUF);
        return BSD_ENOSPC;
    }
    if (prefix_length != 0)
        bsd_strlcpy(device->si_name, "tty", sizeof(device->si_name));
    bsd_strlcat(device->si_name, suffix, sizeof(device->si_name));
    device->si_uid = 0;
    device->si_gid = 5;
    device->si_mode = 0620;
    device->si_tty = tty;
    device->si_drv1 = tty;
    device->si_linux_major = BSD_CDEV_LINUX_MAJOR;
    device->si_linux_minor = __atomic_fetch_add(&g_cdev_next_minor, 1,
        __ATOMIC_RELAXED);
    error = cdev_register(device);
    if (error) {
        bsd_free(device, M_DEVBUF);
        return error;
    }
    tty->t_dev = device;
    if ((tty->t_flags & TF_CALLOUT) != 0) {
        error = make_dev_alias_p(MAKEDEV_WAITOK | MAKEDEV_CHECKNAME,
            &callout, device, "cua%s", suffix);
        if (error) {
            tty->t_dev = 0;
            destroy_dev(device);
            return error;
        }
    }
    return 0;
}

int
make_dev_alias_p(int flags, struct cdev **result, struct cdev *parent,
    const char *format, ...)
{
    struct cdev *alias;
    va_list arguments;
    int error;

    if (result)
        *result = 0;
    if (!parent || !format)
        return BSD_EINVAL;
    alias = bsd_malloc(sizeof(*alias), M_DEVBUF,
        (flags & MAKEDEV_NOWAIT) != 0 ? M_NOWAIT | M_ZERO :
        M_WAITOK | M_ZERO);
    if (!alias)
        return BSD_ENOSPC;
    va_start(arguments, format);
    error = format_device_name(alias->si_name, sizeof(alias->si_name),
        format, arguments);
    va_end(arguments);
    if (!error && (flags & MAKEDEV_CHECKNAME) != 0 &&
        !device_name_valid(alias->si_name))
        error = BSD_EINVAL;
    if (error) {
        bsd_free(alias, M_DEVBUF);
        return error;
    }
    alias->si_flags = SI_ALIAS;
    alias->si_uid = parent->si_uid;
    alias->si_gid = parent->si_gid;
    alias->si_mode = parent->si_mode;
    alias->si_parent = parent;
    alias->si_tty = parent->si_tty;
    alias->si_devsw = parent->si_devsw;
    alias->si_unit = parent->si_unit;
    alias->si_iosize_max = parent->si_iosize_max;
    alias->si_drv1 = parent->si_drv1;
    alias->si_drv2 = parent->si_drv2;
    alias->si_linux_major = parent->si_linux_major;
    alias->si_linux_minor = parent->si_linux_minor;
    error = cdev_register(alias);
    if (error) {
        bsd_free(alias, M_DEVBUF);
        return error;
    }
    if (result)
        *result = alias;
    return 0;
}

static int
cdev_create_formatted(const struct make_dev_args *arguments,
    struct cdev **result, const char *format, va_list values)
{
    struct cdev *device;
    int error;

    if (result)
        *result = 0;
    if (!arguments || arguments->mda_size != sizeof(*arguments) ||
        !arguments->mda_devsw || !format)
        return BSD_EINVAL;
    device = bsd_malloc(sizeof(*device), M_DEVBUF,
        (arguments->mda_flags & MAKEDEV_NOWAIT) != 0 ?
        M_NOWAIT | M_ZERO : M_WAITOK | M_ZERO);
    if (!device)
        return BSD_ENOSPC;
    error = format_device_name(device->si_name, sizeof(device->si_name),
        format, values);
    if (!error && (arguments->mda_flags & MAKEDEV_CHECKNAME) != 0 &&
        !device_name_valid(device->si_name))
        error = BSD_EINVAL;
    if (error) {
        bsd_free(device, M_DEVBUF);
        return error;
    }
    device->si_uid = arguments->mda_uid;
    device->si_gid = arguments->mda_gid;
    device->si_mode = arguments->mda_mode;
    device->si_devsw = arguments->mda_devsw;
    device->si_unit = arguments->mda_unit;
    device->si_drv0 = arguments->mda_unit;
    device->si_iosize_max = (int)maxphys;
    device->si_drv1 = arguments->mda_si_drv1;
    device->si_drv2 = arguments->mda_si_drv2;
    device->si_linux_major = BSD_CDEV_LINUX_MAJOR;
    device->si_linux_minor = __atomic_fetch_add(&g_cdev_next_minor, 1,
        __ATOMIC_RELAXED);
    error = cdev_register(device);
    if (error) {
        bsd_free(device, M_DEVBUF);
        return error;
    }
    if (result)
        *result = device;
    return 0;
}

int
make_dev_s(const struct make_dev_args *arguments, struct cdev **result,
    const char *format, ...)
{
    va_list values;
    int error;

    va_start(values, format);
    error = cdev_create_formatted(arguments, result, format, values);
    va_end(values);
    return error;
}

int
make_dev_p(int flags, struct cdev **result, struct cdevsw *driver,
    struct ucred *credential, uid_t uid, gid_t gid, int mode,
    const char *format, ...)
{
    struct make_dev_args arguments;
    va_list values;
    int error;

    make_dev_args_init(&arguments);
    arguments.mda_flags = flags & (MAKEDEV_NOWAIT | MAKEDEV_CHECKNAME);
    arguments.mda_devsw = driver;
    arguments.mda_uid = uid;
    arguments.mda_gid = gid;
    arguments.mda_mode = (mode_t)mode;
    arguments.mda_cr = credential;
    va_start(values, format);
    error = cdev_create_formatted(&arguments, result, format, values);
    va_end(values);
    if (!error && result && *result && (flags & MAKEDEV_REF) != 0)
        dev_ref(*result);
    return error;
}

struct cdev *
make_dev(struct cdevsw *driver, int unit, uid_t uid, gid_t gid, int mode,
    const char *format, ...)
{
    struct make_dev_args arguments;
    struct cdev *device = 0;
    va_list values;

    make_dev_args_init(&arguments);
    arguments.mda_devsw = driver;
    arguments.mda_unit = unit;
    arguments.mda_uid = uid;
    arguments.mda_gid = gid;
    arguments.mda_mode = (mode_t)mode;
    va_start(values, format);
    (void)cdev_create_formatted(&arguments, &device, format, values);
    va_end(values);
    return device;
}

static void
clone_assign_device(struct cdevsw *driver, int unit, struct cdev *device)
{
    struct clonedevs *clones;
    uint64_t state;

    state = cdev_lock();
    for (clones = g_clone_lists; clones; clones = clones->global_next) {
        bsd_clone_entry_t *entry;

        for (entry = clones->entries; entry; entry = entry->next) {
            if (entry->driver == driver && entry->unit == unit &&
                !entry->device) {
                entry->device = device;
                cdev_unlock(state);
                return;
            }
        }
    }
    cdev_unlock(state);
}

struct cdev *
make_dev_credf(int flags, struct cdevsw *driver, int unit,
    struct ucred *credential, uid_t uid, gid_t gid, int mode,
    const char *format, ...)
{
    struct make_dev_args arguments;
    struct cdev *device = 0;
    va_list values;

    (void)credential;
    make_dev_args_init(&arguments);
    arguments.mda_flags = flags & (MAKEDEV_NOWAIT | MAKEDEV_CHECKNAME);
    arguments.mda_devsw = driver;
    arguments.mda_unit = unit;
    arguments.mda_uid = uid;
    arguments.mda_gid = gid;
    arguments.mda_mode = (mode_t)mode;
    va_start(values, format);
    (void)cdev_create_formatted(&arguments, &device, format, values);
    va_end(values);
    if (!device)
        return 0;
    clone_assign_device(driver, unit, device);
    if ((flags & MAKEDEV_REF) != 0)
        dev_ref(device);
    return device;
}

int
dev_stdclone(char *name, char **name_end, const char *stem, int *unit)
{
    size_t index;
    int value = 0;

    if (!name || !stem || !unit)
        return 0;
    index = bsd_strlen(stem);
    if (bsd_strncmp(stem, name, index) != 0 ||
        name[index] < '0' || name[index] > '9')
        return 0;
    if (name[index] == '0' &&
        name[index + 1] >= '0' && name[index + 1] <= '9')
        return 0;
    while (name[index] >= '0' && name[index] <= '9') {
        if (value > 0x0ffffff)
            return 0;
        value = value * 10 + name[index++] - '0';
    }
    if (value > 0x0ffffff)
        return 0;
    *unit = value;
    if (name_end)
        *name_end = &name[index];
    return name[index] ? 2 : 1;
}

void
clone_setup(struct clonedevs **clones)
{
    struct clonedevs *created;
    uint64_t state;

    if (!clones || *clones)
        return;
    created = bsd_malloc(sizeof(*created), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!created)
        return;
    state = cdev_lock();
    created->global_next = g_clone_lists;
    g_clone_lists = created;
    *clones = created;
    cdev_unlock(state);
}

int
clone_create(struct clonedevs **clone_pointer, struct cdevsw *driver,
    int *unit, struct cdev **device, int extra)
{
    bsd_clone_entry_t *created;
    struct clonedevs *clones;
    bsd_clone_entry_t *entry;
    int selected;
    uint64_t state;

    if (device)
        *device = 0;
    if (!clone_pointer || !(clones = *clone_pointer) || !driver ||
        !unit || !device || (extra & 0x0fffff) != 0 ||
        *unit > 0x0fffff)
        return 0;
    created = bsd_malloc(sizeof(*created), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!created)
        return 0;
    state = cdev_lock();
    selected = *unit;
    if (selected < 0) {
        selected = extra;
        for (;;) {
            int occupied = 0;

            for (entry = clones->entries; entry; entry = entry->next) {
                if (entry->unit == selected) {
                    occupied = 1;
                    ++selected;
                    break;
                }
            }
            if (!occupied)
                break;
        }
    } else {
        selected |= extra;
        for (entry = clones->entries; entry; entry = entry->next) {
            if (entry->driver == driver && entry->unit == selected) {
                *device = entry->device;
                cdev_unlock(state);
                bsd_free(created, M_DEVBUF);
                return 0;
            }
        }
    }
    created->driver = driver;
    created->unit = selected;
    created->next = clones->entries;
    clones->entries = created;
    *unit = selected & 0x0fffff;
    cdev_unlock(state);
    return 1;
}

void
clone_cleanup(struct clonedevs **clone_pointer)
{
    struct clonedevs *clones;
    bsd_clone_entry_t *entries;
    struct clonedevs **cursor;
    uint64_t state;

    if (!clone_pointer || !(clones = *clone_pointer))
        return;
    state = cdev_lock();
    cursor = &g_clone_lists;
    while (*cursor && *cursor != clones)
        cursor = &(*cursor)->global_next;
    if (*cursor == clones)
        *cursor = clones->global_next;
    entries = clones->entries;
    clones->entries = 0;
    *clone_pointer = 0;
    cdev_unlock(state);
    while (entries) {
        bsd_clone_entry_t *next = entries->next;

        if (entries->device)
            destroy_dev(entries->device);
        bsd_free(entries, M_DEVBUF);
        entries = next;
    }
    bsd_free(clones, M_DEVBUF);
}

struct cdev *
make_dev_alias(struct cdev *parent, const char *format, ...)
{
    struct cdev *alias = 0;
    va_list values;
    int error;

    if (!parent || !format)
        return 0;
    va_start(values, format);
    alias = bsd_malloc(sizeof(*alias), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!alias) {
        va_end(values);
        return 0;
    }
    error = format_device_name(alias->si_name, sizeof(alias->si_name),
        format, values);
    va_end(values);
    if (error) {
        bsd_free(alias, M_DEVBUF);
        return 0;
    }
    alias->si_flags = SI_ALIAS;
    alias->si_uid = parent->si_uid;
    alias->si_gid = parent->si_gid;
    alias->si_mode = parent->si_mode;
    alias->si_parent = parent;
    alias->si_tty = parent->si_tty;
    alias->si_devsw = parent->si_devsw;
    alias->si_unit = parent->si_unit;
    alias->si_drv1 = parent->si_drv1;
    alias->si_drv2 = parent->si_drv2;
    alias->si_linux_major = parent->si_linux_major;
    alias->si_linux_minor = parent->si_linux_minor;
    if (cdev_register(alias) != 0) {
        bsd_free(alias, M_DEVBUF);
        return 0;
    }
    return alias;
}

void
delist_dev(struct cdev *device)
{
    if (!device)
        return;
    if (cdev_unregister(device))
        device->edgeos_delisted = 1;
}

void
destroy_dev(struct cdev *device)
{
    struct cdev *alias;

    if (!device)
        return;
    (void)cdev_unregister(device);
    device->edgeos_delisted = 1;
    while (__atomic_load_n(&device->edgeos_references,
        __ATOMIC_ACQUIRE) != 0)
        processor_relax();
    if ((device->si_flags & SI_ALIAS) != 0 && device->si_parent) {
        uint64_t state = cdev_lock();
        struct cdev **cursor =
            &device->si_parent->edgeos_alias_head;

        while (*cursor && *cursor != device)
            cursor = &(*cursor)->edgeos_alias_next;
        if (*cursor == device)
            *cursor = device->edgeos_alias_next;
        cdev_unlock(state);
    } else {
        alias = device->edgeos_alias_head;
        device->edgeos_alias_head = 0;
        while (alias) {
            struct cdev *next = alias->edgeos_alias_next;

            while (__atomic_load_n(&alias->edgeos_references,
                __ATOMIC_ACQUIRE) != 0)
                processor_relax();
            bsd_free(alias, M_DEVBUF);
            alias = next;
        }
    }
    bsd_free(device, M_DEVBUF);
}

int
destroy_dev_sched(struct cdev *device)
{
    if (!device)
        return 0;
    destroy_dev(device);
    return 1;
}

void
dev_ref(struct cdev *device)
{
    if (!device || device->edgeos_delisted)
        return;
    (void)__atomic_fetch_add(&device->edgeos_references, 1,
        __ATOMIC_ACQ_REL);
}

void
dev_rel(struct cdev *device)
{
    if (!device)
        return;
    KASSERT(__atomic_load_n(&device->edgeos_references,
        __ATOMIC_ACQUIRE) != 0,
        ("%s reference count is zero", devtoname(device)));
    (void)__atomic_fetch_sub(&device->edgeos_references, 1,
        __ATOMIC_RELEASE);
}

struct cdevsw *
dev_refthread(struct cdev *device, int *reference)
{
    struct cdevsw *driver = 0;
    uint64_t state;

    if (reference)
        *reference = 0;
    if (!device || !reference)
        return 0;
    state = cdev_lock();
    if (!device->edgeos_delisted && device->si_devsw) {
        (void)__atomic_fetch_add(&device->edgeos_references, 1,
            __ATOMIC_ACQ_REL);
        driver = device->si_devsw;
        *reference = 1;
    }
    cdev_unlock(state);
    return driver;
}

void
dev_relthread(struct cdev *device, int reference)
{
    if (!device || !reference)
        return;
    KASSERT(__atomic_load_n(&device->edgeos_references,
        __ATOMIC_ACQUIRE) != 0,
        ("%s reference count is zero", devtoname(device)));
    (void)__atomic_fetch_sub(&device->edgeos_references, 1,
        __ATOMIC_RELEASE);
}

const char *
devtoname(const struct cdev *device)
{
    return device ? device->si_name : "";
}

void
tty_rel_gone(struct tty *tty)
{
    bsd_tty_runtime_t *runtime;
    struct ttydevsw *driver;
    void *softc;
    int destroy_mutex;

    if (!tty)
        return;
    tty_assert_locked(tty);
    if (tty_gone(tty)) {
        tty_unlock(tty);
        return;
    }
    runtime = tty->edgeos_state;
    driver = tty->t_devsw;
    softc = tty->t_devswsoftc;
    (void)__atomic_fetch_or(&tty->t_flags, TF_GONE,
        __ATOMIC_RELEASE);
    if (runtime && runtime->opened && driver && driver->tsw_close)
        driver->tsw_close(tty);
    tty->t_flags &= ~TF_OPENED;
    destroy_mutex = tty->t_mtx == &tty->t_mtxobj;
    tty_unlock(tty);

    cdev_unregister_tty(tty);
    if (destroy_mutex)
        mtx_destroy(&tty->t_mtxobj);
    if (driver && driver->tsw_free)
        driver->tsw_free(softc);
    bsd_free(runtime, M_DEVBUF);
    bsd_free(tty, M_DEVBUF);
}

void
tty_set_winsize(struct tty *tty, const struct winsize *size)
{
    if (tty && size)
        tty->t_winsize = *size;
}

void
tty_init_console(struct tty *tty, speed_t speed)
{
    bsd_tty_runtime_t *runtime;

    if (!tty)
        return;
    runtime = tty->edgeos_state;
    tty->t_termios.c_cflag = CS8 | CREAD | CLOCAL;
    tty->t_termios.c_ispeed = speed;
    tty->t_termios.c_ospeed = speed;
    tty->t_termios_init_in = tty->t_termios;
    tty->t_termios_init_out = tty->t_termios;
    tty->t_flags |= TF_OPENED_CONS;
    if (runtime) {
        runtime->carrier_present = 1;
        runtime->hangup = 0;
        tty_poll_snapshot_update(runtime);
    }
}

int
ttydisc_rint(struct tty *tty, char byte, int flags)
{
    bsd_tty_runtime_t *runtime;

    (void)flags;
    if (!tty || tty_gone(tty))
        return -1;
    tty_assert_locked(tty);
    runtime = tty->edgeos_state;
    return tty_input_byte(runtime, (uint8_t)byte) ? 0 : -1;
}

size_t
ttydisc_rint_simple(struct tty *tty, const void *buffer, size_t length)
{
    bsd_tty_runtime_t *runtime;
    uint32_t requested;
    uint32_t consumed = 0;
    const uint8_t *source = buffer;

    if (!tty || !buffer || tty_gone(tty))
        return 0;
    tty_assert_locked(tty);
    runtime = tty->edgeos_state;
    requested = length > UINT32_MAX ? UINT32_MAX : (uint32_t)length;
    while (consumed < requested &&
        tty_input_byte(runtime, source[consumed]))
        ++consumed;
    return consumed;
}

size_t
ttydisc_rint_bypass(struct tty *tty, const void *buffer, size_t length)
{
    return ttydisc_rint_simple(tty, buffer, length);
}

void
ttydisc_modem(struct tty *tty, int open)
{
    bsd_tty_runtime_t *runtime;

    if (!tty || tty_gone(tty))
        return;
    tty_assert_locked(tty);
    runtime = tty->edgeos_state;
    if (!runtime)
        return;
    runtime->carrier_present = open != 0;
    runtime->hangup =
        open == 0 && (tty->t_termios.c_cflag & CLOCAL) == 0;
    tty_publish_change(runtime, runtime->hangup, 0);
}

void
ttydisc_rint_done(struct tty *tty)
{
    bsd_tty_runtime_t *runtime;

    if (!tty || tty_gone(tty))
        return;
    tty_assert_locked(tty);
    runtime = tty->edgeos_state;
    tty_poll_snapshot_update(runtime);
    if (runtime && runtime->output_count != 0 &&
        tty->t_devsw && tty->t_devsw->tsw_outwakeup)
        tty->t_devsw->tsw_outwakeup(tty);
}

size_t
ttydisc_rint_poll(struct tty *tty)
{
    bsd_tty_runtime_t *runtime;

    if (!tty || tty_gone(tty))
        return 0;
    tty_assert_locked(tty);
    runtime = tty->edgeos_state;
    if ((runtime->termios.lflag & BSD_LINUX_ICANON) != 0) {
        uint32_t total = runtime->input_count + runtime->canonical_count;
        uint32_t canonical_space =
            BSD_TTY_CANONICAL_CAPACITY - runtime->canonical_count;
        uint32_t total_space = BSD_TTY_BUFFER_CAPACITY - total;

        return canonical_space < total_space ?
            canonical_space : total_space;
    }
    return BSD_TTY_BUFFER_CAPACITY - runtime->input_count;
}

size_t
ttydisc_getc(struct tty *tty, void *buffer, size_t length)
{
    bsd_tty_runtime_t *runtime;
    uint32_t requested;

    if (!tty || !buffer || tty_gone(tty) ||
        (tty->t_flags & TF_STOPPED) != 0)
        return 0;
    tty_assert_locked(tty);
    runtime = tty->edgeos_state;
    requested = length > UINT32_MAX ? UINT32_MAX : (uint32_t)length;
    {
        uint32_t read = ring_read(runtime->output,
            &runtime->output_head, &runtime->output_count,
            buffer, requested);

        if (read != 0)
            tty_publish_change(runtime, 0, 1);
        return read;
    }
}

size_t
ttydisc_getc_poll(struct tty *tty)
{
    bsd_tty_runtime_t *runtime;

    if (!tty || tty_gone(tty) || (tty->t_flags & TF_STOPPED) != 0)
        return 0;
    tty_assert_locked(tty);
    runtime = tty->edgeos_state;
    return runtime->output_count;
}

uint32_t
bsd_bridge_cdev_node_count(void)
{
    uint32_t count = 0;
    uint64_t state = cdev_lock();

    for (uint32_t index = 0; index < BSD_CDEV_MAX_NODES; ++index) {
        if (g_cdev_nodes[index])
            ++count;
    }
    cdev_unlock(state);
    return count;
}

int
bsd_bridge_cdev_node_at(uint32_t ordinal, bsd_bridge_cdev_node_t *node)
{
    uint32_t current = 0;
    int result = -1;
    uint64_t state;

    if (!node)
        return -1;
    bsd_memset(node, 0, sizeof(*node));
    state = cdev_lock();
    for (uint32_t index = 0; index < BSD_CDEV_MAX_NODES; ++index) {
        struct cdev *device = g_cdev_nodes[index];

        if (!device)
            continue;
        if (current++ != ordinal)
            continue;
        bsd_strlcpy(node->name, device->si_name, sizeof(node->name));
        node->major = device->si_linux_major;
        node->minor = device->si_linux_minor;
        node->mode = (uint16_t)device->si_mode;
        node->uid = (uint16_t)device->si_uid;
        node->gid = (uint16_t)device->si_gid;
        node->alias = (device->si_flags & SI_ALIAS) != 0;
        result = 0;
        break;
    }
    cdev_unlock(state);
    return result;
}

static int
tty_open_locked(struct tty *tty, bsd_tty_runtime_t *runtime)
{
    int error;

    if (runtime->opened)
        return 0;
    error = tty->t_devsw && tty->t_devsw->tsw_open ?
        tty->t_devsw->tsw_open(tty) : 0;
    if (error)
        return error;
    runtime->opened = 1;
    tty->t_flags |= TF_OPENED_IN | TF_OPENED_OUT;
    return 0;
}

static int
tty_session_open_locked(struct tty *tty, bsd_tty_runtime_t *runtime)
{
    int error;

    if (!tty || !runtime || runtime->open_sessions == UINT32_MAX)
        return BSD_EOVERFLOW;
    error = tty_open_locked(tty, runtime);
    if (error)
        return error;
    ++runtime->open_sessions;
    return 0;
}

static void
tty_session_close(struct tty *tty)
{
    bsd_tty_runtime_t *runtime;

    if (!tty)
        return;
    tty_lock(tty);
    runtime = tty->edgeos_state;
    if (!runtime || runtime->open_sessions == 0) {
        tty_unlock(tty);
        return;
    }
    --runtime->open_sessions;
    if (runtime->open_sessions == 0 && runtime->opened &&
        !tty_gone(tty)) {
        if (tty->t_devsw && tty->t_devsw->tsw_close)
            tty->t_devsw->tsw_close(tty);
        runtime->opened = 0;
        tty->t_flags &= ~(TF_OPENED | TF_OPENED_IN | TF_OPENED_OUT);
    }
    tty_unlock(tty);
}

int
bsd_bridge_cdev_open(uint64_t linux_rdev, uint32_t linux_flags,
    uint64_t description_identity, int32_t process_id,
    int32_t process_group_id)
{
    bsd_cdev_session_t *session;
    struct cdev *device;
    struct thread *previous;
    uint64_t state;
    int error;

    if (!description_identity ||
        description_identity == BSD_CDEV_SESSION_TOMBSTONE)
        return -BSD_EINVAL;
    device = cdev_lookup(linux_rdev);
    if (!device)
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    error = cdev_transition_enter(device, 0);
    if (error) {
        cdev_release(device);
        return -error;
    }

    state = cdev_lock();
    session = cdev_session_insert_locked(description_identity);
    if (!session) {
        cdev_unlock(state);
        cdev_transition_leave(device);
        cdev_release(device);
        return -BSD_EBUSY;
    }
    bsd_memset(session, 0, sizeof(*session));
    session->identity = description_identity;
    session->device = device;
    session->bsd_flags = cdev_flags_from_linux(linux_flags);
    session->state = BSD_CDEV_SESSION_OPENING;
    session->thread.td_proc = &session->process;
    session->process.p_ucred = &session->process.p_ucred_storage;
    session->process.p_ucred_storage.cr_ngroups = 1;
    session->process.p_ucred_storage.cr_ref = 1;
    session->thread.td_ucred = session->process.p_ucred;
    session->process.p_edgeos_thread = &session->thread;
    session->process.p_pid = process_id;
    session->process.p_pgid = process_group_id;
    if (device->si_devsw && device->si_devsw->d_name)
        (void)bsd_strlcpy(session->process.p_comm,
            device->si_devsw->d_name,
            sizeof(session->process.p_comm));
    cdev_unlock(state);

    previous = bsd_kthread_public_context_enter(&session->thread);
    if (device->si_tty) {
        struct tty *tty = device->si_tty;

        tty_lock(tty);
        if (tty_gone(tty))
            error = BSD_ENXIO;
        else
            error = tty_session_open_locked(
                tty, tty->edgeos_state);
        tty_unlock(tty);
    } else if (device->si_devsw &&
        device->si_devsw->d_open) {
        error = device->si_devsw->d_open(
            device, (int)session->bsd_flags, 0020000,
            &session->thread);
    } else {
        error = 0;
    }
    error = cdev_callback_error(error);
    if (error)
        devfs_clear_cdevpriv();
    bsd_kthread_public_context_leave(previous);

    state = cdev_lock();
    if (error) {
        cdev_session_remove_locked(session);
    } else {
        session->state = BSD_CDEV_SESSION_OPEN;
        ++device->edgeos_open_sessions;
    }
    cdev_unlock(state);
    cdev_transition_leave(device);
    if (error)
        cdev_release(device);
    return error ? -error : 0;
}

int
bsd_bridge_cdev_close(uint64_t description_identity)
{
    bsd_cdev_session_t *session;
    struct cdev *device;
    struct thread *previous;
    uint32_t close_flags;
    uint64_t state;
    int call_close;
    int error = 0;
    int last_close;

    if (!description_identity)
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    state = cdev_lock();
    session = cdev_session_find_locked(description_identity);
    if (!session) {
        cdev_unlock(state);
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    }
    if (session->state != BSD_CDEV_SESSION_OPEN) {
        cdev_unlock(state);
        return -BSD_EBADF;
    }
    session->state = BSD_CDEV_SESSION_CLOSING;
    device = session->device;
    cdev_unlock(state);

    for (;;) {
        state = cdev_lock();
        if (session->active_operations == 0) {
            cdev_unlock(state);
            break;
        }
        cdev_unlock(state);
        bsd_kthread_pump();
        processor_relax();
    }
    error = cdev_transition_enter(device, 1);
    if (error)
        return -error;

    state = cdev_lock();
    if (device->edgeos_open_sessions != 0)
        --device->edgeos_open_sessions;
    last_close = device->edgeos_open_sessions == 0;
    close_flags = session->bsd_flags |
        (last_close ? FLASTCLOSE : 0u);
    call_close = !device->si_tty && device->si_devsw &&
        device->si_devsw->d_close &&
        (last_close ||
        (device->si_devsw->d_flags & D_TRACKCLOSE) != 0);
    cdev_unlock(state);

    previous = bsd_kthread_public_context_enter(&session->thread);
    if (device->si_tty) {
        tty_session_close(device->si_tty);
    } else if (call_close) {
        error = cdev_callback_error(device->si_devsw->d_close(
            device, (int)close_flags, 0020000, &session->thread));
    }
    devfs_clear_cdevpriv();
    bsd_kthread_public_context_leave(previous);

    state = cdev_lock();
    cdev_session_remove_locked(session);
    cdev_unlock(state);
    cdev_transition_leave(device);
    cdev_release(device);
    return error ? -error : 0;
}

int
devfs_foreach_cdevpriv(struct cdev *device,
    int (*callback)(void *data, void *argument), void *argument)
{
    if (!device || !callback)
        return BSD_EINVAL;
    for (uint32_t index = 0;
        index < BSD_CDEV_SESSION_TABLE_SIZE; ++index) {
        bsd_cdev_session_t *session = &g_cdev_sessions[index];
        void *data;
        uint64_t state = cdev_lock();

        if (session->identity == BSD_CDEV_SESSION_EMPTY ||
            session->identity == BSD_CDEV_SESSION_TOMBSTONE ||
            session->state != BSD_CDEV_SESSION_OPEN ||
            session->device != device ||
            !session->thread.td_cdevpriv) {
            cdev_unlock(state);
            continue;
        }
        ++session->active_operations;
        data = session->thread.td_cdevpriv;
        cdev_unlock(state);
        {
            int error = callback(data, argument);

            cdev_session_release(session);
            if (error)
                return error;
        }
    }
    return 0;
}

int
bsd_bridge_cdev_read(uint64_t linux_rdev, void *buffer, uint32_t length)
{
    struct cdev *device = cdev_lookup(linux_rdev);
    struct tty *tty;
    bsd_tty_runtime_t *runtime;
    uint32_t read;
    int error;

    if (!device)
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    tty = device->si_tty;
    if (!tty || (!buffer && length != 0)) {
        cdev_release(device);
        return -BSD_EINVAL;
    }
    tty_lock(tty);
    if (tty_gone(tty)) {
        tty_unlock(tty);
        cdev_release(device);
        return -BSD_ENXIO;
    }
    runtime = tty->edgeos_state;
    error = tty_open_locked(tty, runtime);
    if (error) {
        tty_unlock(tty);
        cdev_release(device);
        return -error;
    }
    if (length == 0) {
        tty_unlock(tty);
        cdev_release(device);
        return 0;
    }
    read = ring_read(runtime->input, &runtime->input_head,
        &runtime->input_count, buffer, length);
    if (read != 0 && tty->t_devsw && tty->t_devsw->tsw_inwakeup)
        tty->t_devsw->tsw_inwakeup(tty);
    if (read == 0 && runtime->eof_pending) {
        runtime->eof_pending = 0;
        tty_poll_snapshot_update(runtime);
        tty_unlock(tty);
        cdev_release(device);
        return 0;
    }
    tty_poll_snapshot_update(runtime);
    tty_unlock(tty);
    cdev_release(device);
    return read != 0 ? (int)read : -BSD_EAGAIN;
}

int
bsd_bridge_cdev_write(uint64_t linux_rdev, const void *buffer,
    uint32_t length)
{
    struct cdev *device = cdev_lookup(linux_rdev);
    struct tty *tty;
    bsd_tty_runtime_t *runtime;
    uint32_t written = 0;
    const uint8_t *source = buffer;
    int error;

    if (!device)
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    tty = device->si_tty;
    if (!tty || (!buffer && length != 0)) {
        cdev_release(device);
        return -BSD_EINVAL;
    }
    tty_lock(tty);
    if (tty_gone(tty)) {
        tty_unlock(tty);
        cdev_release(device);
        return -BSD_ENXIO;
    }
    runtime = tty->edgeos_state;
    error = tty_open_locked(tty, runtime);
    if (error) {
        tty_unlock(tty);
        cdev_release(device);
        return -error;
    }
    if (length == 0) {
        tty_unlock(tty);
        cdev_release(device);
        return 0;
    }
    while (written < length &&
        tty_queue_output_byte(runtime, source[written]))
        ++written;
    if (written != 0 && tty->t_devsw && tty->t_devsw->tsw_outwakeup)
        tty->t_devsw->tsw_outwakeup(tty);
    tty_poll_snapshot_update(runtime);
    tty_unlock(tty);
    cdev_release(device);
    return written != 0 ? (int)written : -BSD_EAGAIN;
}

int
bsd_bridge_cdev_read_session(uint64_t linux_rdev,
    uint64_t description_identity, void *buffer, uint32_t length)
{
    bsd_cdev_session_t *session =
        cdev_session_acquire(description_identity, linux_rdev);
    struct thread *previous;
    struct iovec vector;
    struct uio operation;
    uint32_t transferred;
    int error;

    if (!session)
        return description_identity ?
            cdev_missing_session_result(linux_rdev) :
            bsd_bridge_cdev_read(linux_rdev, buffer, length);
    if (session->device->si_tty) {
        previous = bsd_kthread_public_context_enter(&session->thread);
        error = bsd_bridge_cdev_read(linux_rdev, buffer, length);
        bsd_kthread_public_context_leave(previous);
        cdev_session_release(session);
        return error;
    }
    if ((!buffer && length != 0) || !session->device->si_devsw ||
        !session->device->si_devsw->d_read) {
        cdev_session_release(session);
        return -BSD_ENXIO;
    }
    vector.iov_base = buffer;
    vector.iov_len = length;
    operation.uio_iov = &vector;
    operation.uio_iovcnt = 1;
    operation.uio_offset = __atomic_load_n(
        &session->offset, __ATOMIC_ACQUIRE);
    operation.uio_resid = length;
    operation.uio_segflg = UIO_SYSSPACE;
    operation.uio_rw = UIO_READ;
    operation.uio_td = &session->thread;
    previous = bsd_kthread_public_context_enter(&session->thread);
    error = cdev_callback_error(session->device->si_devsw->d_read(
        session->device, &operation, (int)session->bsd_flags));
    bsd_kthread_public_context_leave(previous);
    if (operation.uio_resid < 0 ||
        (uint64_t)operation.uio_resid > length) {
        operation.uio_resid = length;
        error = BSD_EINVAL;
    }
    transferred = length - (uint32_t)operation.uio_resid;
    __atomic_store_n(&session->offset, operation.uio_offset,
        __ATOMIC_RELEASE);
    cdev_session_release(session);
    return transferred != 0 ? (int)transferred :
        (error ? -error : 0);
}

int
bsd_bridge_cdev_write_session(uint64_t linux_rdev,
    uint64_t description_identity, const void *buffer, uint32_t length)
{
    bsd_cdev_session_t *session =
        cdev_session_acquire(description_identity, linux_rdev);
    struct thread *previous;
    struct iovec vector;
    struct uio operation;
    uint32_t transferred;
    int error;

    if (!session)
        return description_identity ?
            cdev_missing_session_result(linux_rdev) :
            bsd_bridge_cdev_write(linux_rdev, buffer, length);
    if (session->device->si_tty) {
        previous = bsd_kthread_public_context_enter(&session->thread);
        error = bsd_bridge_cdev_write(
            linux_rdev, buffer, length);
        bsd_kthread_public_context_leave(previous);
        cdev_session_release(session);
        return error;
    }
    if ((!buffer && length != 0) || !session->device->si_devsw ||
        !session->device->si_devsw->d_write) {
        cdev_session_release(session);
        return -BSD_ENXIO;
    }
    vector.iov_base = (void *)(uintptr_t)buffer;
    vector.iov_len = length;
    operation.uio_iov = &vector;
    operation.uio_iovcnt = 1;
    operation.uio_offset = __atomic_load_n(
        &session->offset, __ATOMIC_ACQUIRE);
    operation.uio_resid = length;
    operation.uio_segflg = UIO_SYSSPACE;
    operation.uio_rw = UIO_WRITE;
    operation.uio_td = &session->thread;
    previous = bsd_kthread_public_context_enter(&session->thread);
    error = cdev_callback_error(session->device->si_devsw->d_write(
        session->device, &operation, (int)session->bsd_flags));
    bsd_kthread_public_context_leave(previous);
    if (operation.uio_resid < 0 ||
        (uint64_t)operation.uio_resid > length) {
        operation.uio_resid = length;
        error = BSD_EINVAL;
    }
    transferred = length - (uint32_t)operation.uio_resid;
    __atomic_store_n(&session->offset, operation.uio_offset,
        __ATOMIC_RELEASE);
    cdev_session_release(session);
    return transferred != 0 ? (int)transferred :
        (error ? -error : 0);
}

int
bsd_bridge_cdev_poll(uint64_t linux_rdev, uint32_t *events)
{
    struct cdev *device = cdev_lookup(linux_rdev);
    struct tty *tty;
    bsd_tty_runtime_t *runtime;
    uint32_t result;

    if (!events)
        return -BSD_EINVAL;
    if (!device)
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    tty = device->si_tty;
    if (!tty) {
        cdev_release(device);
        return -BSD_ENXIO;
    }
    if ((__atomic_load_n(&tty->t_flags, __ATOMIC_ACQUIRE) &
        TF_GONE) != 0) {
        result = BSD_BRIDGE_CDEV_POLL_HANGUP;
    } else {
        runtime = tty->edgeos_state;
        result = __atomic_load_n(&runtime->poll_events,
            __ATOMIC_ACQUIRE);
    }
    cdev_release(device);
    *events = result;
    return 0;
}

int
bsd_bridge_cdev_poll_session(uint64_t linux_rdev,
    uint64_t description_identity, uint32_t *events)
{
    bsd_cdev_session_t *session;
    struct thread *previous;
    int result;

    if (!events)
        return -BSD_EINVAL;
    session = cdev_session_acquire(
        description_identity, linux_rdev);
    if (!session)
        return description_identity ?
            cdev_missing_session_result(linux_rdev) :
            bsd_bridge_cdev_poll(linux_rdev, events);
    if (session->device->si_tty) {
        previous = bsd_kthread_public_context_enter(&session->thread);
        result = bsd_bridge_cdev_poll(linux_rdev, events);
        bsd_kthread_public_context_leave(previous);
        cdev_session_release(session);
        return result;
    }
    if (session->device->edgeos_delisted) {
        *events = BSD_BRIDGE_CDEV_POLL_HANGUP;
        cdev_session_release(session);
        return 0;
    }
    if (session->device->si_devsw &&
        session->device->si_devsw->d_poll) {
        previous = bsd_kthread_public_context_enter(&session->thread);
        result = session->device->si_devsw->d_poll(
            session->device,
            POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM |
                POLLPRI,
            &session->thread);
        bsd_kthread_public_context_leave(previous);
    } else {
        result = 0;
        if (session->device->si_devsw &&
            session->device->si_devsw->d_read)
            result |= POLLIN | POLLRDNORM;
        if (session->device->si_devsw &&
            session->device->si_devsw->d_write)
            result |= POLLOUT | POLLWRNORM;
    }
    *events = 0;
    if ((result & (POLLIN | POLLRDNORM | POLLPRI)) != 0)
        *events |= BSD_BRIDGE_CDEV_POLL_READ;
    if ((result & (POLLOUT | POLLWRNORM)) != 0)
        *events |= BSD_BRIDGE_CDEV_POLL_WRITE;
    if ((result & (POLLHUP | POLLERR | POLLNVAL)) != 0)
        *events |= BSD_BRIDGE_CDEV_POLL_HANGUP;
    cdev_session_release(session);
    return 0;
}

int
bsd_bridge_cdev_present(uint64_t linux_rdev)
{
    struct cdev *device = cdev_lookup(linux_rdev);

    if (!device)
        return 0;
    cdev_release(device);
    return 1;
}

int
bsd_bridge_cdev_is_tty(uint64_t linux_rdev)
{
    struct cdev *device = cdev_lookup(linux_rdev);
    int result;

    if (!device)
        return 0;
    result = device->si_tty != 0;
    cdev_release(device);
    return result;
}

int
bsd_bridge_cdev_mmap_supported(uint64_t linux_rdev)
{
    struct cdev *device = cdev_lookup(linux_rdev);
    int result;

    if (!device)
        return 0;
    result = device->si_devsw &&
        (device->si_devsw->d_mmap || device->si_devsw->d_mmap_single);
    cdev_release(device);
    return result;
}

int
bsd_bridge_cdev_mmap_page(uint64_t linux_rdev,
    uint64_t description_identity, uint64_t offset,
    uint32_t protection, uint64_t *physical_address,
    int32_t *memory_attribute)
{
    bsd_cdev_session_t *session =
        cdev_session_acquire(description_identity, linux_rdev);
    struct thread *previous;
    vm_paddr_t physical = 0;
    vm_memattr_t attribute = BSD_BRIDGE_CDEV_MEMORY_DEFAULT;
    int error;

    if (!physical_address || !memory_attribute)
        return -BSD_EINVAL;
    if (!session)
        return description_identity ?
            cdev_missing_session_result(linux_rdev) :
            -BSD_EBADF;
    if (!session->device->si_devsw ||
        (!session->device->si_devsw->d_mmap &&
         !session->device->si_devsw->d_mmap_single)) {
        cdev_session_release(session);
        return -BSD_ENXIO;
    }
    previous = bsd_kthread_public_context_enter(&session->thread);
    if (session->device->si_devsw->d_mmap) {
        error = cdev_callback_error(session->device->si_devsw->d_mmap(
            session->device, (vm_ooffset_t)offset, &physical,
            (int)protection, &attribute));
    } else {
        vm_ooffset_t object_offset = (vm_ooffset_t)offset;
        vm_object_t object = 0;

        error = cdev_callback_error(
            session->device->si_devsw->d_mmap_single(
                session->device, &object_offset, PAGE_SIZE, &object,
                (int)protection));
        if (error == 0 && !object)
            error = BSD_ENXIO;
        if (error == 0)
            error = vm_object_pager_physical_address(object,
                object_offset, &physical);
        if (object)
            vm_object_deallocate(object);
    }
    bsd_kthread_public_context_leave(previous);
    cdev_session_release(session);
    if (error)
        return -error;
    *physical_address = (uint64_t)physical;
    *memory_attribute = (int32_t)attribute;
    return 0;
}

int
bsd_bridge_cdev_poll_sequences(uint64_t linux_rdev,
    uint64_t *read_sequence, uint64_t *write_sequence)
{
    struct cdev *device = cdev_lookup(linux_rdev);
    struct tty *tty;
    bsd_tty_runtime_t *runtime;

    if (!device)
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    tty = device->si_tty;
    if (!tty) {
        uint64_t sequence = bsd_selinfo_change_sequence();

        if (read_sequence)
            *read_sequence = sequence;
        if (write_sequence)
            *write_sequence = sequence;
        cdev_release(device);
        return 0;
    }
    runtime = tty->edgeos_state;
    if (read_sequence)
        *read_sequence = runtime ?
            __atomic_load_n(&runtime->read_sequence,
                __ATOMIC_ACQUIRE) : 0;
    if (write_sequence)
        *write_sequence = runtime ?
            __atomic_load_n(&runtime->write_sequence,
                __ATOMIC_ACQUIRE) : 0;
    cdev_release(device);
    return 0;
}

uint64_t
bsd_bridge_cdev_change_sequence(void)
{
    return __atomic_load_n(&g_cdev_change_sequence, __ATOMIC_ACQUIRE);
}

int
bsd_bridge_cdev_ioctl_supported(uint32_t command)
{
    switch (command) {
    case BSD_BRIDGE_LINUX_TCGETS:
    case BSD_BRIDGE_LINUX_TCSETS:
    case BSD_BRIDGE_LINUX_TCSETSW:
    case BSD_BRIDGE_LINUX_TCSETSF:
    case BSD_BRIDGE_LINUX_TCSBRK:
    case BSD_BRIDGE_LINUX_TCXONC:
    case BSD_BRIDGE_LINUX_TCFLSH:
    case BSD_BRIDGE_LINUX_TIOCGWINSZ:
    case BSD_BRIDGE_LINUX_TIOCSWINSZ:
    case BSD_BRIDGE_LINUX_FIONREAD:
    case BSD_BRIDGE_LINUX_TCSBRKP:
        return 1;
    default:
        return ((command & LINUX_IOCTL_DIRECTION_MASK) != 0 ||
                ((command & 0xffff0000u) == 0 &&
                 (command & 0x0000ff00u) != 0)) &&
            ((command >> 16) & LINUX_IOCTL_LENGTH_MASK) <=
                BSD_BRIDGE_CDEV_IOCTL_MAX_PAYLOAD;
    }
}

uint32_t
bsd_bridge_cdev_ioctl_input_size(uint32_t command)
{
    switch (command) {
    case BSD_BRIDGE_LINUX_TCSETS:
    case BSD_BRIDGE_LINUX_TCSETSW:
    case BSD_BRIDGE_LINUX_TCSETSF:
        return sizeof(bsd_bridge_linux_termios_t);
    case BSD_BRIDGE_LINUX_TIOCSWINSZ:
        return sizeof(bsd_bridge_linux_winsize_t);
    default:
        return (command & LINUX_IOCTL_WRITE) != 0 ?
            (command >> 16) & LINUX_IOCTL_LENGTH_MASK : 0;
    }
}

uint32_t
bsd_bridge_cdev_ioctl_output_size(uint32_t command)
{
    switch (command) {
    case BSD_BRIDGE_LINUX_TCGETS:
        return sizeof(bsd_bridge_linux_termios_t);
    case BSD_BRIDGE_LINUX_TIOCGWINSZ:
        return sizeof(bsd_bridge_linux_winsize_t);
    case BSD_BRIDGE_LINUX_FIONREAD:
        return sizeof(int32_t);
    default:
        return (command & LINUX_IOCTL_READ) != 0 ?
            (command >> 16) & LINUX_IOCTL_LENGTH_MASK : 0;
    }
}

static unsigned long
cdev_linux_to_freebsd_ioctl(uint32_t command)
{
    uint32_t translated =
        command & ~BSD_IOCTL_DIRECTION_MASK;
    uint32_t direction =
        command & LINUX_IOCTL_DIRECTION_MASK;

    if ((direction & LINUX_IOCTL_WRITE) != 0)
        translated |= BSD_IOCTL_INPUT;
    if ((direction & LINUX_IOCTL_READ) != 0)
        translated |= BSD_IOCTL_OUTPUT;
    if (direction == 0)
        translated |= BSD_IOCTL_VOID;
#ifdef BSD_CDEV_LLP64_V4L2_ABI
    if (((command >> 8) & 0xffu) == V4L2_IOCTL_GROUP &&
        ((command & 0xffu) == V4L2_QUERYBUF_NUMBER ||
         (command & 0xffu) == V4L2_QBUF_NUMBER ||
         (command & 0xffu) == V4L2_DQBUF_NUMBER) &&
        ((command >> 16) & LINUX_IOCTL_LENGTH_MASK) ==
            LINUX_V4L2_BUFFER_SIZE) {
        translated &= ~(LINUX_IOCTL_LENGTH_MASK << 16);
        translated |= FREEBSD_LLP64_V4L2_BUFFER_SIZE << 16;
    }
#endif
    return translated;
}

#ifdef BSD_CDEV_LLP64_V4L2_ABI
static int
cdev_linux_v4l2_buffer_ioctl(uint32_t command)
{
    uint32_t number = command & 0xffu;

    return ((command >> 8) & 0xffu) == V4L2_IOCTL_GROUP &&
        (number == V4L2_QUERYBUF_NUMBER ||
         number == V4L2_QBUF_NUMBER ||
         number == V4L2_DQBUF_NUMBER) &&
        ((command >> 16) & LINUX_IOCTL_LENGTH_MASK) ==
            LINUX_V4L2_BUFFER_SIZE;
}

static void
cdev_linux_v4l2_buffer_to_freebsd(uint8_t *freebsd_buffer,
    const uint8_t *linux_buffer)
{
    bsd_memset(freebsd_buffer, 0, FREEBSD_LLP64_V4L2_BUFFER_SIZE);
    bsd_memcpy(freebsd_buffer, linux_buffer, 64u);
    bsd_memcpy(freebsd_buffer + 64u, linux_buffer + 64u, 4u);
    bsd_memcpy(freebsd_buffer + 68u, linux_buffer + 72u, 4u);
    bsd_memcpy(freebsd_buffer + 72u, linux_buffer + 76u, 4u);
    bsd_memcpy(freebsd_buffer + 76u, linux_buffer + 80u, 4u);
}

static void
cdev_freebsd_v4l2_buffer_to_linux(uint8_t *linux_buffer,
    const uint8_t *freebsd_buffer)
{
    bsd_memset(linux_buffer, 0, LINUX_V4L2_BUFFER_SIZE);
    bsd_memcpy(linux_buffer, freebsd_buffer, 64u);
    bsd_memcpy(linux_buffer + 64u, freebsd_buffer + 64u, 4u);
    bsd_memcpy(linux_buffer + 72u, freebsd_buffer + 68u, 4u);
    bsd_memcpy(linux_buffer + 76u, freebsd_buffer + 72u, 4u);
    bsd_memcpy(linux_buffer + 80u, freebsd_buffer + 76u, 4u);
}
#endif

static int
tty_apply_termios(struct tty *tty, bsd_tty_runtime_t *runtime,
    const bsd_bridge_linux_termios_t *termios)
{
    struct termios parameters;
    int error = 0;

    if (!tty || !runtime || !termios)
        return BSD_EINVAL;
    tty_linux_termios_to_freebsd(termios, &parameters);
    if (tty->t_devsw && tty->t_devsw->tsw_param)
        error = tty->t_devsw->tsw_param(tty, &parameters);
    if (error)
        return error;
    tty->t_termios = parameters;
    runtime->termios = *termios;
    runtime->hangup =
        !runtime->carrier_present &&
        (parameters.c_cflag & CLOCAL) == 0;
    if ((runtime->termios.lflag & BSD_LINUX_ICANON) == 0)
        tty_publish_canonical(runtime);
    return 0;
}

static int
tty_send_break_locked(struct tty *tty, bsd_tty_runtime_t *runtime,
    uint32_t command, uint64_t duration)
{
    uint64_t ticks;
    int error;
    int stop_error;

    if (!tty || !runtime || !tty->t_devsw ||
        !tty->t_devsw->tsw_ioctl)
        return 0;
    if (command == BSD_BRIDGE_LINUX_TCSBRK && duration != 0)
        return 0;
    if (duration == 0) {
        ticks = ((uint64_t)hz + 3u) / 4u;
    } else {
        ticks = duration > (UINT64_MAX - 9u) / (uint64_t)hz ?
            UINT64_MAX :
            (duration * (uint64_t)hz + 9u) / 10u;
    }
    if (ticks == 0)
        ticks = 1;
    if (ticks > INT32_MAX)
        ticks = INT32_MAX;

    error = tty->t_devsw->tsw_ioctl(tty, TIOCSBRK, 0,
        bsd_kthread_current_public());
    if (error)
        return error;
    (void)bsd_msleep(&runtime->break_channel, tty->t_mtx, 0,
        "ttybrk", (int)ticks);
    if (tty_gone(tty))
        return BSD_ENXIO;
    stop_error = tty->t_devsw->tsw_ioctl(tty, TIOCCBRK, 0,
        bsd_kthread_current_public());
    return stop_error;
}

int
bsd_bridge_cdev_ioctl(uint64_t linux_rdev, uint32_t command,
    uint64_t scalar_argument, void *payload, uint32_t payload_size)
{
    struct cdev *device = cdev_lookup(linux_rdev);
    struct tty *tty;
    bsd_tty_runtime_t *runtime;
    uint32_t input_size;
    uint32_t output_size;
    int error;

    if (!device)
        return BSD_BRIDGE_CDEV_NOT_HANDLED;
    tty = device->si_tty;
    if (!tty || !bsd_bridge_cdev_ioctl_supported(command)) {
        cdev_release(device);
        return -BSD_ENXIO;
    }
    input_size = bsd_bridge_cdev_ioctl_input_size(command);
    output_size = bsd_bridge_cdev_ioctl_output_size(command);
    if ((input_size != 0 || output_size != 0) &&
        (!payload || payload_size < input_size ||
        payload_size < output_size)) {
        cdev_release(device);
        return -BSD_EINVAL;
    }

    tty_lock(tty);
    if (tty_gone(tty)) {
        tty_unlock(tty);
        cdev_release(device);
        return -BSD_ENXIO;
    }
    runtime = tty->edgeos_state;
    error = tty_open_locked(tty, runtime);
    if (error) {
        tty_unlock(tty);
        cdev_release(device);
        return -error;
    }

    switch (command) {
    case BSD_BRIDGE_LINUX_TCGETS:
        *(bsd_bridge_linux_termios_t *)payload = runtime->termios;
        error = 0;
        break;
    case BSD_BRIDGE_LINUX_TCSETS:
    case BSD_BRIDGE_LINUX_TCSETSW:
    case BSD_BRIDGE_LINUX_TCSETSF:
        error = tty_apply_termios(tty, runtime,
            (const bsd_bridge_linux_termios_t *)payload);
        if (!error && command == BSD_BRIDGE_LINUX_TCSETSF) {
            runtime->input_head = 0;
            runtime->input_count = 0;
            runtime->canonical_count = 0;
            runtime->eof_pending = 0;
            tty_publish_change(runtime, 1, 0);
        }
        break;
    case BSD_BRIDGE_LINUX_TIOCGWINSZ: {
        bsd_bridge_linux_winsize_t *size = payload;

        size->rows = tty->t_winsize.ws_row;
        size->columns = tty->t_winsize.ws_col;
        size->xpixel = tty->t_winsize.ws_xpixel;
        size->ypixel = tty->t_winsize.ws_ypixel;
        error = 0;
        break;
    }
    case BSD_BRIDGE_LINUX_TIOCSWINSZ: {
        const bsd_bridge_linux_winsize_t *size = payload;

        tty->t_winsize.ws_row = size->rows;
        tty->t_winsize.ws_col = size->columns;
        tty->t_winsize.ws_xpixel = size->xpixel;
        tty->t_winsize.ws_ypixel = size->ypixel;
        error = 0;
        break;
    }
    case BSD_BRIDGE_LINUX_FIONREAD:
        *(int32_t *)payload = (int32_t)runtime->input_count;
        error = 0;
        break;
    case BSD_BRIDGE_LINUX_TCFLSH:
        if (scalar_argument > 2u) {
            error = BSD_EINVAL;
            break;
        }
        if (scalar_argument == 0u || scalar_argument == 2u) {
            runtime->input_head = 0;
            runtime->input_count = 0;
            runtime->canonical_count = 0;
            runtime->eof_pending = 0;
            tty_publish_change(runtime, 1, 0);
        }
        if (scalar_argument == 1u || scalar_argument == 2u) {
            runtime->output_head = 0;
            runtime->output_count = 0;
            tty_publish_change(runtime, 0, 1);
        }
        error = 0;
        break;
    case BSD_BRIDGE_LINUX_TCXONC:
        if (scalar_argument > 3u) {
            error = BSD_EINVAL;
            break;
        }
        if (scalar_argument == 0u) {
            tty->t_flags |= TF_STOPPED;
        } else if (scalar_argument == 1u) {
            tty->t_flags &= ~TF_STOPPED;
            if (runtime->output_count != 0 &&
                tty->t_devsw && tty->t_devsw->tsw_outwakeup)
                tty->t_devsw->tsw_outwakeup(tty);
        }
        error = 0;
        break;
    case BSD_BRIDGE_LINUX_TCSBRK:
    case BSD_BRIDGE_LINUX_TCSBRKP:
        error = tty_send_break_locked(
            tty, runtime, command, scalar_argument);
        break;
    default:
        error = BSD_EINVAL;
        break;
    }
    tty_unlock(tty);
    cdev_release(device);
    return error ? -error : 0;
}

int
bsd_bridge_cdev_ioctl_session(uint64_t linux_rdev,
    uint64_t description_identity, uint32_t command,
    uint64_t scalar_argument, void *payload, uint32_t payload_size)
{
    bsd_cdev_session_t *session =
        cdev_session_acquire(description_identity, linux_rdev);
    struct thread *previous;
    caddr_t data;
    int error;
#ifdef BSD_CDEV_LLP64_V4L2_ABI
    union {
        uint64_t alignment;
        uint8_t bytes[FREEBSD_LLP64_V4L2_BUFFER_SIZE];
    } compatibility_payload;
    int translate_v4l2_buffer = 0;
#endif

    if (!session)
        return description_identity ?
            cdev_missing_session_result(linux_rdev) :
            bsd_bridge_cdev_ioctl(linux_rdev, command,
                scalar_argument, payload, payload_size);
    if (session->device->si_tty) {
        previous = bsd_kthread_public_context_enter(&session->thread);
        error = bsd_bridge_cdev_ioctl(linux_rdev, command,
            scalar_argument, payload, payload_size);
        bsd_kthread_public_context_leave(previous);
        cdev_session_release(session);
        return error;
    }
    if (!session->device->si_devsw ||
        !session->device->si_devsw->d_ioctl) {
        cdev_session_release(session);
        return -BSD_ENXIO;
    }
    data = payload && payload_size != 0 ? (caddr_t)payload :
        (caddr_t)(uintptr_t)&scalar_argument;
#ifdef BSD_CDEV_LLP64_V4L2_ABI
    translate_v4l2_buffer =
        cdev_linux_v4l2_buffer_ioctl(command);
    if (translate_v4l2_buffer) {
        if (!payload || payload_size < LINUX_V4L2_BUFFER_SIZE) {
            cdev_session_release(session);
            return -BSD_EINVAL;
        }
        cdev_linux_v4l2_buffer_to_freebsd(
            compatibility_payload.bytes, payload);
        data = (caddr_t)compatibility_payload.bytes;
    }
#endif
    previous = bsd_kthread_public_context_enter(&session->thread);
    error = cdev_callback_error(session->device->si_devsw->d_ioctl(
        session->device, cdev_linux_to_freebsd_ioctl(command), data,
        (int)session->bsd_flags, &session->thread));
    bsd_kthread_public_context_leave(previous);
#ifdef BSD_CDEV_LLP64_V4L2_ABI
    if (error == 0 && translate_v4l2_buffer)
        cdev_freebsd_v4l2_buffer_to_linux(
            payload, compatibility_payload.bytes);
#endif
    cdev_session_release(session);
    return error ? -error : 0;
}
