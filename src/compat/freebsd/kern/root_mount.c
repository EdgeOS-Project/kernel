/* SPDX-License-Identifier: MPL-2.0 */
/* Root readiness holds shared by imported storage and bus drivers. */

#include <stdint.h>

#include "compat/freebsd/edgeos/root_mount.h"
#include "compat/freebsd/edgeos/systm.h"

#define BSD_ROOT_HOLD_MAX 64u
#define BSD_ROOT_HOLD_NAME_MAX 32u

struct root_hold_token {
    uint32_t generation;
    uint8_t active;
    char identifier[BSD_ROOT_HOLD_NAME_MAX];
};

static struct root_hold_token g_root_holds[BSD_ROOT_HOLD_MAX];
static volatile uint32_t g_root_hold_guard;
static volatile uint32_t g_root_hold_count;
static volatile uint32_t g_root_hold_generation;
static volatile uint64_t g_root_hold_sequence;

static void
root_hold_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void
root_hold_lock(void)
{
    while (__atomic_test_and_set(&g_root_hold_guard, __ATOMIC_ACQUIRE))
        root_hold_relax();
}

static void
root_hold_unlock(void)
{
    __atomic_clear(&g_root_hold_guard, __ATOMIC_RELEASE);
}

struct root_hold_token *
root_mount_hold(const char *identifier)
{
    struct root_hold_token *token = 0;

    root_hold_lock();
    for (uint32_t index = 0; index < BSD_ROOT_HOLD_MAX; ++index) {
        if (!g_root_holds[index].active) {
            token = &g_root_holds[index];
            break;
        }
    }
    if (token) {
        token->generation = ++g_root_hold_generation;
        token->active = 1;
        bsd_strlcpy(token->identifier,
            identifier ? identifier : "driver",
            sizeof(token->identifier));
        ++g_root_hold_count;
        ++g_root_hold_sequence;
    }
    root_hold_unlock();
    return token;
}

void
root_mount_rel(struct root_hold_token *token)
{
    root_hold_lock();
    if (token && token >= &g_root_holds[0] &&
        token < &g_root_holds[BSD_ROOT_HOLD_MAX] && token->active) {
        token->active = 0;
        token->identifier[0] = 0;
        if (g_root_hold_count != 0)
            --g_root_hold_count;
        ++g_root_hold_sequence;
    }
    root_hold_unlock();
}

uint32_t
bsd_root_mount_hold_count(void)
{
    return __atomic_load_n(&g_root_hold_count, __ATOMIC_ACQUIRE);
}

uint64_t
bsd_root_mount_hold_sequence(void)
{
    return __atomic_load_n(&g_root_hold_sequence, __ATOMIC_ACQUIRE);
}
