/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD eventfd object used by LinuxKPI fence notification paths. */

#include <sys/errno.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/malloc.h>

struct eventfd {
    volatile uint32_t references;
    volatile uint64_t counter;
};

static int
eventfd_file_close(struct file *file, struct thread *thread)
{
    (void)thread;
    if (file && file->f_data) {
        eventfd_put(file->f_data);
        file->f_data = NULL;
    }
    return 0;
}

static const struct fileops eventfd_file_operations = {
    .fo_close = eventfd_file_close,
};

int
eventfd_create_file(struct thread *thread, struct file *file,
    uint32_t initial_value, int flags)
{
    struct eventfd *eventfd;

    (void)thread;
    (void)flags;
    if (!file)
        return EINVAL;
    eventfd = malloc(sizeof(*eventfd), M_TEMP, M_WAITOK | M_ZERO);
    if (!eventfd)
        return ENOMEM;
    eventfd->references = 1;
    eventfd->counter = initial_value;
    finit(file, 0, DTYPE_DEV, eventfd, &eventfd_file_operations);
    return 0;
}

struct eventfd *
eventfd_get(struct file *file)
{
    struct eventfd *eventfd;

    if (!file || file->f_ops != &eventfd_file_operations)
        return NULL;
    eventfd = file->f_data;
    if (eventfd)
        __atomic_add_fetch(&eventfd->references, 1u, __ATOMIC_ACQUIRE);
    return eventfd;
}

void
eventfd_put(struct eventfd *eventfd)
{
    if (eventfd && __atomic_sub_fetch(&eventfd->references, 1u,
            __ATOMIC_ACQ_REL) == 0)
        free(eventfd, M_TEMP);
}

void
eventfd_signal(struct eventfd *eventfd)
{
    if (eventfd)
        __atomic_add_fetch(&eventfd->counter, 1u, __ATOMIC_RELEASE);
}
