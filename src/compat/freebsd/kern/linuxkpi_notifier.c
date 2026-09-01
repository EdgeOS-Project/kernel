/* SPDX-License-Identifier: MPL-2.0 */
/* LinuxKPI atomic notifier support for BSD bridge drivers. */

#include <stddef.h>

#include <sys/errno.h>

/* Keep this runtime independent from the LinuxKPI header include graph. */
#define NOTIFY_DONE 0
#define NOTIFY_STOP_MASK 0x8000

struct notifier_block {
    int (*notifier_call)(struct notifier_block *, unsigned long, void *);
    struct notifier_block *next;
    int priority;
};

struct atomic_notifier_head {
    struct notifier_block *head;
};

struct atomic_notifier_head panic_notifier_list;

int
atomic_notifier_chain_register(struct atomic_notifier_head *head,
    struct notifier_block *notifier)
{
    struct notifier_block **position;

    if (head == NULL || notifier == NULL || notifier->notifier_call == NULL)
        return (-EINVAL);

    position = &head->head;
    while (*position != NULL && (*position)->priority >= notifier->priority)
        position = &(*position)->next;
    notifier->next = *position;
    *position = notifier;
    return (0);
}

int
atomic_notifier_chain_unregister(struct atomic_notifier_head *head,
    struct notifier_block *notifier)
{
    struct notifier_block **position;

    if (head == NULL || notifier == NULL)
        return (-EINVAL);

    position = &head->head;
    while (*position != NULL && *position != notifier)
        position = &(*position)->next;
    if (*position == NULL)
        return (-ENOENT);
    *position = notifier->next;
    notifier->next = NULL;
    return (0);
}

int
atomic_notifier_call_chain(struct atomic_notifier_head *head,
    unsigned long action, void *data)
{
    struct notifier_block *notifier;
    int result;

    if (head == NULL)
        return (NOTIFY_DONE);

    result = NOTIFY_DONE;
    for (notifier = head->head; notifier != NULL; notifier = notifier->next) {
        result = notifier->notifier_call(notifier, action, data);
        if ((result & NOTIFY_STOP_MASK) != 0)
            break;
    }
    return (result);
}
